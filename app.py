import threading
import uuid
import time
import requests
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_super_secret_key_here' # Change this to a secure key

db = SQLAlchemy(app)

# ====================
# Database Models
# ====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    thread_id = db.Column(db.String(255), nullable=False)
    prefix = db.Column(db.String(255), nullable=False)
    interval = db.Column(db.Integer, nullable=False)
    tokens = db.Column(db.Text, nullable=False)
    messages = db.Column(db.Text, nullable=False)
    messages_sent = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default='Stopped')
    
    # Store token status as JSON
    token_status = db.Column(db.Text, default='{}')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ====================
# In-memory storage for logs and active threads
# ====================
logs = []
active_threads = {}
total_messages_sent = 0

# ====================
# Initial Setup
# ====================
def setup_database():
    with app.app_context():
        db.create_all()
        
        # Check if admin user exists, create if not
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('axshu143')
            admin_user = User(username='admin', password=hashed_password)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created.")

# ====================
# Helper Functions
# ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def add_log(message):
    global logs
    logs.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    if len(logs) > 500:
        logs = logs[-500:]

def send_message(token, thread_id, text, prefix):
    global total_messages_sent
    url = f"https://graph.facebook.com/v16.0/t_{thread_id}"
    params = {
        'access_token': token,
        'message': f"{prefix} {text}"
    }
    try:
        response = requests.post(url, params=params, timeout=10)
        response.raise_for_status()
        total_messages_sent += 1
        return True, response.json()
    except requests.exceptions.HTTPError as http_err:
        error_data = http_err.response.json().get('error', {})
        error_message = error_data.get('message', 'Unknown HTTP error')
        add_log(f"Error sending message with token {token[:10]}...: {error_message}")
        
        if "Invalid OAuth access token" in error_message or "account is disabled" in error_message:
            return False, {"error_type": "InvalidToken"}
        if "The thread is not a valid thread" in error_message:
            return False, {"error_type": "InvalidThread"}
        if "block the message" in error_message:
            return False, {"error_type": "MessageBlocked"}
        
        return False, {"error_type": "Other"}
    except Exception as e:
        add_log(f"An unexpected error occurred with token {token[:10]}...: {e}")
        return False, {"error_type": "Other"}

def check_token_health(token):
    """Checks the validity of a single token without sending a message."""
    url = "https://graph.facebook.com/v16.0/me"
    params = {'access_token': token}
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        return True, "Token is valid."
    except requests.exceptions.HTTPError as http_err:
        error_data = http_err.response.json().get('error', {})
        error_message = error_data.get('message', 'Unknown HTTP error')
        if "Invalid OAuth access token" in error_message or "session has expired" in error_message:
            return False, "Token is invalid or expired."
        else:
            return False, f"Error: {error_message}"
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"

def send_messages_thread(task_id):
    with app.app_context():
        task = Task.query.get(task_id)
        if not task:
            add_log(f"Task {task_id} not found in database. Thread stopped.")
            return

        tokens = json.loads(task.tokens)
        messages = json.loads(task.messages)
        token_status = json.loads(task.token_status)

        add_log(f"Task {task_id}: Started sending messages to thread {task.thread_id}...")

        while task.status == 'Running':
            token_sent_count = {token: 0 for token in tokens}
            for message in messages:
                with app.app_context():
                    task = Task.query.get(task_id)
                    if not task or task.status != 'Running':
                        break

                    active_tokens = [t for t in tokens if token_status.get(t) != 'Invalid']
                    if not active_tokens:
                        add_log(f"Task {task_id}: All tokens are invalid or expired. Stopping task.")
                        task.status = 'Stopped'
                        db.session.commit()
                        return

                    current_token = min(active_tokens, key=lambda t: token_sent_count[t])
                    
                    success, response = send_message(current_token, task.thread_id, message, task.prefix)
                    
                    if success:
                        add_log(f"Task {task_id}: Message sent successfully with token {current_token[:10]}...")
                        task.messages_sent += 1
                        token_sent_count[current_token] += 1
                        db.session.commit()
                    else:
                        error_type = response.get('error_type')
                        if error_type == 'InvalidToken':
                            add_log(f"Task {task_id}: Token {current_token[:10]}... is invalid or expired. Stopping token use for this task.")
                            token_status[current_token] = 'Invalid'
                            task.token_status = json.dumps(token_status)
                            db.session.commit()
                        elif error_type == 'InvalidThread':
                            add_log(f"Task {task_id}: Thread ID is invalid. Stopping task.")
                            task.status = 'Stopped'
                            db.session.commit()
                            return
                        elif error_type == 'MessageBlocked':
                            add_log(f"Task {task_id}: Message blocked. Retrying with next token.")
                        else:
                            add_log(f"Task {task_id}: Failed to send message with token {current_token[:10]}...")
                    
                    time.sleep(task.interval)
        
        add_log(f"Task {task_id}: Thread stopped.")

# ====================
# Routes
# ====================
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))

    task_id = request.args.get('task_id')
    if request.method == 'POST':
        if 'tokens' in request.form:
            user_id = session['user_id']
            tokens_raw = request.form.get('tokens').strip()
            tokens_list = [token.strip() for token in tokens_raw.split('\n') if token.strip()]
            thread_id = request.form.get('threadId').strip()
            prefix = request.form.get('kidx').strip()
            time_interval = int(request.form.get('time'))
            
            txt_file = request.files.get('txtFile')
            messages_list = []
            if txt_file and txt_file.filename != '':
                messages_list = [line.decode('utf-8').strip() for line in txt_file.readlines() if line.strip()]
            
            if not tokens_list or not thread_id or not prefix or not messages_list:
                return "Error: Missing required fields.", 400

            new_task = Task(
                thread_id=thread_id,
                prefix=prefix,
                interval=time_interval,
                tokens=json.dumps(tokens_list),
                messages=json.dumps(messages_list),
                status='Running',
                token_status=json.dumps({token: 'Valid' for token in tokens_list}),
                user_id=user_id
            )
            
            db.session.add(new_task)
            db.session.commit()
            
            thread = threading.Thread(target=send_messages_thread, args=(new_task.id,))
            thread.daemon = True
            thread.start()
            active_threads[new_task.id] = thread
            
            return redirect(url_for('user_panel', task_id=new_task.id))
    
    return render_template('index.html', task_id=task_id)

@app.route('/stop_task', methods=['POST'])
@login_required
def stop_task():
    task_id = request.form.get('taskId')
    task_to_stop = Task.query.get(task_id)
    if task_to_stop and task_to_stop.user_id == session.get('user_id'):
        task_to_stop.status = 'Stopped'
        db.session.commit()
        add_log(f"User {session['username']} stopped task: {task_id}")
    return redirect(url_for('user_panel'))

@app.route('/pause_task/<task_id>', methods=['POST'])
@login_required
def pause_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == session.get('user_id'):
        task.status = 'Paused'
        db.session.commit()
        add_log(f"User {session['username']} paused task: {task_id}")
    return redirect(url_for('user_panel'))

@app.route('/resume_task/<task_id>', methods=['POST'])
@login_required
def resume_task(task_id):
    task = Task.query.get(task_id)
    if task and task.status == 'Paused' and task.user_id == session.get('user_id'):
        task.status = 'Running'
        db.session.commit()
        thread = threading.Thread(target=send_messages_thread, args=(task_id,))
        thread.daemon = True
        thread.start()
        active_threads[task.id] = thread
        add_log(f"User {session['username']} resumed task: {task_id}")
    return redirect(url_for('user_panel'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            
            if user.username == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_panel'))
        else:
            return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_panel():
    if session.get('username') != 'admin':
        return redirect(url_for('user_panel'))
        
    tasks_from_db = Task.query.all()
    total_messages_sent = sum(task.messages_sent for task in tasks_from_db)
    active_threads_count = sum(1 for task in tasks_from_db if task.status == 'Running' or task.status == 'Paused')
    return render_template('admin.html', tasks=tasks_from_db, total_messages_sent=total_messages_sent, active_threads=active_threads_count)

@app.route('/user_panel')
@login_required
def user_panel():
    tasks_from_db = Task.query.filter_by(user_id=session.get('user_id')).all()
    total_messages_sent = sum(task.messages_sent for task in tasks_from_db)
    active_threads_count = sum(1 for task in tasks_from_db if task.status == 'Running' or task.status == 'Paused')
    return render_template('user_panel.html', tasks=tasks_from_db, total_messages_sent=total_messages_sent, active_threads=active_threads_count)

@app.route('/admin/logs')
@login_required
def admin_logs():
    return '\n'.join(logs)

@app.route('/admin/check_tokens', methods=['POST'])
@login_required
def check_tokens_route():
    tokens_raw = request.json.get('tokens', '')
    tokens_list = [t.strip() for t in tokens_raw.split('\n') if t.strip()]
    
    results = []
    for token in tokens_list:
        is_valid, message = check_token_health(token)
        results.append({
            'token': token,
            'is_valid': is_valid,
            'message': message
        })
    
    return jsonify(results)

if __name__ == '__main__':
    setup_database()
    app.run(host='0.0.0.0', port=5000)
