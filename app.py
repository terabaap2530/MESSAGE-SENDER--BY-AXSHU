import threading
import time
import uuid
import os
import requests
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_very_secret_key_here' # Change this!
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('logs.txt')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
app.logger.addHandler(file_handler)

active_tasks = {}
total_messages_sent = 0

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    thread_id = db.Column(db.String(255), nullable=False)
    prefix = db.Column(db.String(255), nullable=False)
    interval = db.Column(db.Integer, nullable=False)
    tokens = db.Column(db.Text, nullable=False)
    messages = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Running')
    messages_sent = db.Column(db.Integer, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def setup_database():
    with app.app_context():
        if not os.path.exists('database.db'):
            db.create_all()
            app.logger.info("Database created.")
            
            # Check if admin user exists, create if not
            if not User.query.filter_by(username='admin').first():
                hashed_password = generate_password_hash('axshu143')
                admin_user = User(username='admin', password=hashed_password, is_admin=True)
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info("Admin user created.")

def check_token(token):
    try:
        response = requests.get(f'https://graph.facebook.com/v19.0/me?access_token={token}')
        if response.status_code == 200:
            return True, "Valid"
        else:
            return False, response.json().get('error', {}).get('message', 'Unknown error')
    except Exception as e:
        return False, f"Connection error: {e}"

def send_message(token, thread_id, message):
    try:
        url = f"https://graph.facebook.com/v19.0/t_{thread_id}"
        data = {
            "messaging_type": "UPDATE",
            "message": {"text": message},
            "access_token": token
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            app.logger.info(f"Message sent successfully to {thread_id} from token {token[:10]}...")
            return True
        else:
            app.logger.error(f"Failed to send message to {thread_id}. Status: {response.status_code}, Response: {response.text}")
            return False
    except Exception as e:
        app.logger.error(f"Error sending message to {thread_id}: {e}")
        return False

def message_sender_task(task_id):
    with app.app_context():
        task = Task.query.get(task_id)
        if not task:
            app.logger.error(f"Task {task_id} not found.")
            return

        tokens = task.tokens.split('\n')
        messages = task.messages.split('\n')
        token_index = 0
        message_index = 0

        while active_tasks.get(task_id, {}).get('status') == 'Running':
            token = tokens[token_index % len(tokens)]
            message = messages[message_index % len(messages)]
            
            full_message = f"{task.prefix}\n{message}"
            
            if send_message(token, task.thread_id, full_message):
                task.messages_sent += 1
                db.session.commit()
                global total_messages_sent
                total_messages_sent += 1
            
            token_index += 1
            message_index += 1
            
            time.sleep(task.interval)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_service', methods=['POST'])
def start_service():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    user_id = session['user_id']
    
    tokens = request.form['tokens']
    thread_id = request.form['threadId']
    prefix = request.form['kidx']
    interval = int(request.form['time'])
    
    if 'txtFile' in request.files:
        messages_file = request.files['txtFile']
        messages = messages_file.read().decode('utf-8')
    else:
        return "Error: Message file not provided", 400

    new_task = Task(
        thread_id=thread_id,
        prefix=prefix,
        interval=interval,
        tokens=tokens,
        messages=messages,
        owner_id=user_id
    )
    db.session.add(new_task)
    db.session.commit()
    
    active_tasks[new_task.id] = {
        'status': 'Running',
        'thread': threading.Thread(target=message_sender_task, args=(new_task.id,))
    }
    active_tasks[new_task.id]['thread'].daemon = True
    active_tasks[new_task.id]['thread'].start()
    
    return render_template('index.html', task_id=new_task.id)

@app.route('/stop_task', methods=['POST'])
def stop_task():
    task_id = request.form.get('taskId')
    if task_id in active_tasks:
        active_tasks[task_id]['status'] = 'Stopped'
        with app.app_context():
            task = Task.query.get(task_id)
            if task:
                task.status = 'Stopped'
                db.session.commit()
        del active_tasks[task_id]
        app.logger.info(f"Task {task_id} stopped.")
    return redirect(url_for('admin_panel'))

@app.route('/pause_task/<task_id>', methods=['POST'])
def pause_task(task_id):
    if task_id in active_tasks:
        active_tasks[task_id]['status'] = 'Paused'
        with app.app_context():
            task = Task.query.get(task_id)
            if task:
                task.status = 'Paused'
                db.session.commit()
        app.logger.info(f"Task {task_id} paused.")
    return redirect(url_for('admin_panel'))

@app.route('/resume_task/<task_id>', methods=['POST'])
def resume_task(task_id):
    if task_id in active_tasks:
        active_tasks[task_id]['status'] = 'Running'
        with app.app_context():
            task = Task.query.get(task_id)
            if task:
                task.status = 'Running'
                db.session.commit()
        app.logger.info(f"Task {task_id} resumed.")
    return redirect(url_for('admin_panel'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            if user.is_admin:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_panel'))
        return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/logs')
def get_admin_logs():
    if 'user_id' not in session:
        return ""
    try:
        with open('logs.txt', 'r') as f:
            logs = f.read()
        return logs
    except FileNotFoundError:
        return "Log file not found."

@app.route('/admin/check_tokens', methods=['POST'])
def check_tokens_route():
    if 'user_id' not in session:
        return jsonify([])

    data = request.json
    tokens_to_check = data.get('tokens', '').splitlines()
    results = []
    for token in tokens_to_check:
        token = token.strip()
        if token:
            is_valid, message = check_token(token)
            results.append({'token': token, 'is_valid': is_valid, 'message': message})
    return jsonify(results)

@app.route('/admin/panel')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return "Unauthorized", 403
    
    with app.app_context():
        tasks = Task.query.all()
    
    active_threads = sum(1 for task in tasks if task.status == 'Running')
    global total_messages_sent
    
    return render_template(
        'admin.html',
        tasks=tasks,
        total_messages_sent=total_messages_sent,
        active_threads=active_threads
    )

@app.route('/user/panel')
def user_panel():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    user_id = session['user_id']
    with app.app_context():
        tasks = Task.query.filter_by(owner_id=user_id).all()
        user_tasks = Task.query.filter_by(owner_id=user_id).all()

    total_messages_sent_by_user = sum(task.messages_sent for task in user_tasks)
    active_threads_by_user = sum(1 for task in user_tasks if task.status == 'Running')

    return render_template(
        'user_panel.html',
        tasks=tasks,
        total_messages_sent=total_messages_sent_by_user,
        active_threads=active_threads_by_user
    )

if __name__ == '__main__':
    setup_database()
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
