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
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_very_secret_key_here' # Change this!
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.getLogger('werkzeug')
file_handler.setLevel(logging.INFO)
file_handler.addHandler(logging.FileHandler('logs.txt'))

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
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    is_valid = db.Column(db.Boolean, default=True)
    last_checked = db.Column(db.DateTime, default=db.func.now())
    is_page_token = db.Column(db.Boolean, default=False)

def setup_database():
    with app.app_context():
        db.create_all()
        app.logger.info("Database created.")
        
        # Check if admin user exists, create if not
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('AXSHU143')
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_panel')
def user_panel_page():
    # This page now directly opens the user panel content
    return render_template('user_panel.html')

@app.route('/user_service')
def user_service_page():
    return render_template('user_service.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user and check_password_hash(admin_user.password, password):
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        return render_template('admin_login.html', error="Invalid Password")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('index'))

@app.route('/admin/panel')
def admin_panel():
    if 'is_admin' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    with app.app_context():
        tasks = Task.query.all()
        users = User.query.all()
        valid_tokens = Token.query.filter_by(is_valid=True, is_page_token=False).all()
        page_tokens = Token.query.filter_by(is_valid=True, is_page_token=True).all()
        
    active_threads = sum(1 for task in tasks if task.status == 'Running')
    global total_messages_sent
    
    return render_template(
        'admin.html',
        tasks=tasks,
        total_messages_sent=total_messages_sent,
        active_threads=active_threads,
        users=users,
        valid_tokens=valid_tokens,
        page_tokens=page_tokens
    )

@app.route('/start_service', methods=['POST'])
def start_service():
    tokens_str = request.form['tokens']
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
        tokens=tokens_str,
        messages=messages
    )
    db.session.add(new_task)
    db.session.commit()
    
    active_tasks[new_task.id] = {
        'status': 'Running',
        'thread': threading.Thread(target=message_sender_task, args=(new_task.id,))
    }
    active_tasks[new_task.id]['thread'].daemon = True
    active_tasks[new_task.id]['thread'].start()
    
    return redirect(url_for('user_panel_page'))

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
    return redirect(url_for('user_panel_page'))

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
    return redirect(url_for('user_panel_page'))

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
    return redirect(url_for('user_panel_page'))

@app.route('/token_checker', methods=['POST'])
def token_checker():
    tokens_to_check = request.json.get('tokens', '').splitlines()
    results = []
    with app.app_context():
        for token_str in tokens_to_check:
            token_str = token_str.strip()
            if not token_str:
                continue
            is_valid, message = check_token(token_str)
            results.append({'token': token_str, 'is_valid': is_valid, 'message': message})
            if is_valid:
                # Save valid tokens to database if not already present
                existing_token = Token.query.filter_by(token=token_str).first()
                if not existing_token:
                    new_token = Token(token=token_str, is_valid=True)
                    db.session.add(new_token)
            else:
                # Remove invalid tokens
                Token.query.filter_by(token=token_str).delete()
        db.session.commit()
    return jsonify(results)

@app.route('/page_token_extractor', methods=['POST'])
def page_token_extractor():
    access_token = request.json.get('accessToken')
    results = []
    try:
        pages_url = f"https://graph.facebook.com/v19.0/me/accounts?access_token={access_token}"
        response = requests.get(pages_url)
        pages = response.json().get('data', [])
        
        with app.app_context():
            for page in pages:
                page_token = page.get('access_token')
                page_name = page.get('name')
                if page_token:
                    results.append({'name': page_name, 'token': page_token})
                    # Save page tokens to database
                    existing_token = Token.query.filter_by(token=page_token).first()
                    if not existing_token:
                        new_token = Token(token=page_token, is_valid=True, is_page_token=True)
                        db.session.add(new_token)
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error extracting page tokens: {e}")
        return jsonify({'error': str(e)}), 500
    return jsonify(results)

@app.route('/post_uid_extractor', methods=['POST'])
def post_uid_extractor():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL not provided'}), 400
    try:
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.split('/')
        if 'permalink' in path_parts:
            # For permalink URLs
            index = path_parts.index('permalink')
            if index + 1 < len(path_parts):
                post_id = path_parts[index+1].strip()
                return jsonify({'uid': post_id, 'message': 'UID extracted successfully'})
        
        elif 'posts' in path_parts:
            # For posts URLs
            query_params = parse_qs(parsed_url.query)
            if 'fbid' in query_params:
                post_id = query_params['fbid'][0]
                return jsonify({'uid': post_id, 'message': 'UID extracted successfully'})
            
            # Handles URL like /<profile_name>/posts/<post_id>
            try:
                post_id = path_parts[path_parts.index('posts') + 1]
                return jsonify({'uid': post_id, 'message': 'UID extracted successfully'})
            except (ValueError, IndexError):
                pass
        
        return jsonify({'uid': None, 'message': 'Could not extract UID from URL'}), 200

    except Exception as e:
        app.logger.error(f"Error extracting UID: {e}")
        return jsonify({'uid': None, 'message': f'Error: {str(e)}'}), 500

@app.route('/get_session_details', methods=['POST'])
def get_session_details():
    task_id = request.json.get('taskId')
    if task_id in active_tasks:
        with app.app_context():
            task = Task.query.get(task_id)
            if task:
                return jsonify({
                    'status': active_tasks[task_id]['status'],
                    'thread_id': task.thread_id,
                    'prefix': task.prefix,
                    'messages_sent': task.messages_sent,
                    'is_valid': True
                })
    return jsonify({'is_valid': False, 'message': 'Session not found or has been stopped.'})

if __name__ == '__main__':
    with app.app_context():
        setup_database()
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
