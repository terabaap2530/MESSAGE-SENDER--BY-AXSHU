import os
import re
import threading
import uuid
import time
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_you_should_change')

tasks = {}  # Dictionary to store running tasks

ADMIN_PASSWORD = 'AXSHU143'

def get_tokens(tokens_str):
    """
    Given a string of tokens, returns a list of cleaned tokens.
    """
    return [token.strip() for token in tokens_str.split('\n') if token.strip()]

def get_messages(file):
    """
    Given a file object, returns a list of messages.
    """
    messages = []
    if file and file.filename.endswith('.txt'):
        content = file.read().decode('utf-8')
        messages = [line.strip() for line in content.split('\n') if line.strip()]
    return messages

def send_message_with_token(token, thread_id, message):
    """
    Sends a single message to a Facebook Messenger thread using a token.
    """
    url = f"https://graph.facebook.com/v19.0/t_{thread_id}"
    params = {
        "access_token": token,
        "message": message
    }
    try:
        response = requests.post(url, data=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Response: {http_err.response.text}")
    except Exception as err:
        print(f"Other error occurred: {err}")
    return None

def start_sending(task_id, tokens, thread_id, prefix, time_sleep, messages):
    """
    Sends messages in a loop using a separate thread.
    This function has been improved based on the logic you provided.
    It handles tokens, messages, and a sleep interval.
    """
    tasks[task_id] = {
        'status': 'Running',
        'tokens': tokens,
        'thread_id': thread_id,
        'prefix': prefix,
        'time_sleep': time_sleep,
        'messages': messages,
        'messages_sent': 0,
        'timestamp': time.time()
    }
    
    while tasks[task_id]['status'] == 'Running':
        if not tasks[task_id]['tokens']:
            tasks[task_id]['status'] = 'Completed'
            break
        
        for message_content in tasks[task_id]['messages']:
            if tasks[task_id]['status'] != 'Running':
                break
            
            for access_token in tasks[task_id]['tokens']:
                if tasks[task_id]['status'] != 'Running':
                    break
                
                full_message = f"{tasks[task_id]['prefix']} {message_content}"
                result = send_message_with_token(access_token, tasks[task_id]['thread_id'], full_message)
                
                if result:
                    tasks[task_id]['messages_sent'] += 1
                
                # Wait for the specified time interval
                time.sleep(tasks[task_id]['time_sleep'])
                
        # To avoid an infinite loop if messages and tokens are exhausted
        if tasks[task_id]['status'] == 'Running' and tasks[task_id]['messages_sent'] > 1000:
             break

def check_auth(password):
    return password == ADMIN_PASSWORD

@app.before_request
def admin_authentication():
    """Checks if the user is authenticated before allowing access to admin pages."""
    if request.path == url_for('admin_login'):
        return
    
    if request.path.startswith('/admin') and 'is_admin' not in session:
        return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Renders a simple login form for the admin panel and handles login."""
    if request.method == 'POST':
        password = request.form.get('password')
        if check_auth(password):
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error="Invalid password.")
    return render_template('admin_login.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_panel')
def user_panel():
    return render_template('user_panel.html')

@app.route('/user_service')
def user_service():
    return render_template('user_service.html')

@app.route('/admin_panel')
def admin_panel():
    tasks_list = tasks.values() if tasks else []
    total_messages_sent = sum(task.get('messages_sent', 0) for task in tasks_list)
    active_threads = len([task for task in tasks_list if task['status'] == 'Running'])
    
    valid_tokens = []
    page_tokens = []
    logs_content = ["This is a placeholder log line.", "Another placeholder log line."]

    return render_template('admin_panel.html', 
                           users=[1, 2, 3],
                           total_messages_sent=total_messages_sent, 
                           active_threads=active_threads,
                           tasks=tasks_list,
                           valid_tokens=valid_tokens,
                           page_tokens=page_tokens,
                           logs_content=logs_content)

@app.route('/get_session_details', methods=['POST'])
def get_session_details():
    data = request.get_json()
    task_id = data.get('taskId')
    task_info = tasks.get(task_id)

    if task_info:
        return jsonify({
            "is_valid": True,
            "status": task_info['status'],
            "thread_id": task_info['thread_id'],
            "prefix": task_info['prefix'],
            "messages_sent": task_info['messages_sent']
        })
    else:
        return jsonify({"is_valid": False, "message": "Invalid Session ID."})

@app.route('/stop_task', methods=['POST'])
def stop_task():
    task_id = request.form.get('taskId')
    if task_id in tasks:
        tasks[task_id]['status'] = 'Stopped'
        return jsonify({"message": f"Task {task_id} has been stopped."})
    return jsonify({"message": "Task not found."}), 404

@app.route('/pause_task/<task_id>', methods=['POST'])
def pause_task(task_id):
    if task_id in tasks:
        tasks[task_id]['status'] = 'Paused'
        return jsonify({"message": f"Task {task_id} has been paused."})
    return jsonify({"message": "Task not found."}), 404

@app.route('/resume_task/<task_id>', methods=['POST'])
def resume_task(task_id):
    if task_id in tasks and tasks[task_id]['status'] == 'Paused':
        tasks[task_id]['status'] = 'Running'
        new_thread = threading.Thread(target=start_sending, args=(
            task_id, 
            tasks[task_id]['tokens'], 
            tasks[task_id]['thread_id'], 
            tasks[task_id]['prefix'], 
            tasks[task_id]['time_sleep'], 
            tasks[task_id]['messages']
        ))
        new_thread.daemon = True
        new_thread.start()
        return jsonify({"message": f"Task {task_id} has been resumed."})
    return jsonify({"message": "Task not found or not paused."}), 404

@app.route('/start_service', methods=['POST'])
def start_service():
    tokens_str = request.form.get('tokens')
    threadId = request.form.get('threadId')
    kidx = request.form.get('kidx')
    time_sleep_str = request.form.get('time')
    txtFile = request.files.get('txtFile')

    try:
        time_sleep = int(time_sleep_str) if time_sleep_str else 0
    except (ValueError, TypeError):
        return "Invalid time format.", 400

    tokens = get_tokens(tokens_str)
    messages = get_messages(txtFile)
    
    if not tokens or not messages or not threadId or not kidx:
        return "Missing required fields", 400

    task_id = str(uuid.uuid4())
    
    thread = threading.Thread(target=start_sending, args=(task_id, tokens, threadId, kidx, time_sleep, messages))
    thread.daemon = True
    thread.start()
    
    return render_template('token_checker.html', taskId=task_id)

@app.route('/token_checker', methods=['POST'])
def check_tokens():
    token_string = request.form.get('tokens')
    tokens = [t.strip() for t in token_string.split('\n') if t.strip()]
    
    working_tokens = []
    
    for token in tokens:
        test_url = f"https://graph.facebook.com/v19.0/me?access_token={token}"
        try:
            response = requests.get(test_url, timeout=5)
            response.raise_for_status()
            if response.status_code == 200:
                working_tokens.append(token)
        except requests.exceptions.RequestException as e:
            print(f"Token failed: {e}")
            
    return render_template('token_checker.html', working_tokens=working_tokens)

@app.route('/page_token_extractor', methods=['POST'])
def extract_page_token():
    try:
        url = request.form.get('url')
        if 'access_token' in url:
            access_token = url.split('access_token=')[1].split('&')[0]
            return render_template('token_checker.html', extracted_token=access_token)
    except Exception as e:
        return render_template('token_checker.html', extracted_token="Error extracting token.")
    return render_template('token_checker.html', extracted_token="Invalid URL or no token found.")

@app.route('/post_uid_extractor', methods=['POST'])
def post_uid_extractor():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({"uid": None, "message": "Please provide a valid URL."})

    uid = None
    try:
        match = re.search(r'/posts/(\d+)', url)
        if match:
            uid = match.group(1)
        if not uid:
            match = re.search(r'/permalink/(\d+)', url)
            if match:
                uid = match.group(1)
        if not uid:
            match = re.search(r'fbid=(\d+)', url)
            if match:
                uid = match.group(1)
        if not uid:
            match = re.search(r'story_fbid=(\d+)', url)
            if match:
                uid = match.group(1)

        if uid:
            return jsonify({"uid": uid, "message": "UID extracted successfully."})
        else:
            return jsonify({"uid": None, "message": "Could not find a valid UID in the provided URL."})
    except Exception as e:
        return jsonify({"uid": None, "message": f"An error occurred: {str(e)}"})

@app.route('/message_sender')
def render_message_sender():
    return render_template('message_sender.html')

@app.route('/post_loader')
def render_post_loader():
    return render_template('post_loader.html')

@app.route('/session_manager')
def render_session_manager():
    return render_template('session_manager.html')

if __name__ == '__main__':
    app.run(debug=True)

