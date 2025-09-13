import os
import re
import uuid
import time
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from dotenv import load_dotenv
from tasks import start_sending_task, app as celery_app

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_you_should_change')

ADMIN_PASSWORD = 'AXSHU143'

# We don't need a local tasks dictionary anymore, as Celery handles this.
# tasks = {}

def check_auth(password):
    return password == ADMIN_PASSWORD

@app.before_request
def admin_authentication():
    """Checks if the user is authenticated before allowing access to admin pages."""
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
    i = celery_app.control.inspect()
    active_tasks = i.active() if i else {}
    reserved_tasks = i.reserved() if i else {}

    tasks_list = []
    total_messages_sent = 0

    if active_tasks:
        for worker, tasks in active_tasks.items():
            for task_info in tasks:
                meta = celery_app.AsyncResult(task_info['id']).info
                if meta:
                    tasks_list.append({
                        'id': task_info['id'],
                        'status': meta.get('status', 'Unknown'),
                        'thread_id': meta.get('thread_id', 'N/A'),
                        'prefix': meta.get('prefix', 'N/A'),
                        'messages_sent': meta.get('messages_sent', 0)
                    })
                    total_messages_sent += meta.get('messages_sent', 0)

    if reserved_tasks:
        for worker, tasks in reserved_tasks.items():
            for task_info in tasks:
                meta = celery_app.AsyncResult(task_info['id']).info
                if meta:
                    tasks_list.append({
                        'id': task_info['id'],
                        'status': 'Queued',
                        'thread_id': meta.get('thread_id', 'N/A'),
                        'prefix': meta.get('prefix', 'N/A'),
                        'messages_sent': meta.get('messages_sent', 0)
                    })

    active_threads = len(tasks_list)
    
    return render_template('admin_panel.html', 
                           users=[1, 2, 3],
                           total_messages_sent=total_messages_sent, 
                           active_threads=active_threads,
                           tasks=tasks_list)

@app.route('/get_session_details', methods=['POST'])
def get_session_details():
    data = request.get_json()
    task_id = data.get('taskId')
    
    task_result = celery_app.AsyncResult(task_id)
    if task_result and task_result.info:
        info = task_result.info
        return jsonify({
            "is_valid": True,
            "status": info.get('status', 'Unknown'),
            "thread_id": info.get('thread_id', 'N/A'),
            "prefix": info.get('prefix', 'N/A'),
            "messages_sent": info.get('messages_sent', 0)
        })
    else:
        return jsonify({"is_valid": False, "message": "Invalid Session ID or task not found."})

@app.route('/stop_task', methods=['POST'])
def stop_task():
    task_id = request.form.get('taskId')
    celery_app.control.revoke(task_id, terminate=True)
    return jsonify({"message": f"Task {task_id} has been stopped."})

@app.route('/pause_task/<task_id>', methods=['POST'])
def pause_task(task_id):
    celery_app.control.revoke(task_id, signal='PAUSE')
    return jsonify({"message": f"Task {task_id} has been paused."})

@app.route('/resume_task/<task_id>', methods=['POST'])
def resume_task(task_id):
    celery_app.control.resume(task_id)
    return jsonify({"message": f"Task {task_id} has been resumed."})

@app.route('/start_service', methods=['POST'])
def start_service():
    tokens_str = request.form.get('tokens')
    thread_id = request.form.get('threadId')
    prefix = request.form.get('kidx')
    time_sleep_str = request.form.get('time')
    txtFile = request.files.get('txtFile')

    try:
        time_sleep = int(time_sleep_str) if time_sleep_str else 0
    except (ValueError, TypeError):
        return "Invalid time format.", 400

    messages = [line.strip() for line in txtFile.read().decode('utf-8').split('\n') if line.strip()]

    if not tokens_str or not messages or not thread_id or not prefix:
        return "Missing required fields", 400

    task = start_sending_task.apply_async(args=[tokens_str, thread_id, prefix, time_sleep, messages])
    
    return jsonify({"taskId": task.id})

@app.route('/token_checker', methods=['POST'])
def check_tokens():
    data = request.get_json()
    token_string = data.get('tokens')
    tokens = [t.strip() for t in token_string.split('\n') if t.strip()]
    
    results = []
    
    for token in tokens:
        test_url = f"https://graph.facebook.com/v19.0/me?access_token={token}"
        is_valid = False
        message = ""
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                is_valid = True
                message = "Valid"
            else:
                is_valid = False
                message = f"Invalid: {response.json().get('error', {}).get('message', 'Unknown error')}"
        except requests.exceptions.RequestException as e:
            is_valid = False
            message = f"Failed to connect: {str(e)}"
            
        results.append({"token": token, "is_valid": is_valid, "message": message})
            
    return jsonify(results)

@app.route('/page_token_extractor', methods=['POST'])
def extract_page_token():
    data = request.get_json()
    access_token = data.get('accessToken')
    if not access_token:
        return jsonify({"error": "No access token provided."})

    url = f"https://graph.facebook.com/v19.0/me/accounts?access_token={access_token}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        pages_data = response.json().get('data', [])
        
        page_tokens = []
        for page in pages_data:
            page_tokens.append({
                "name": page.get('name'),
                "token": page.get('access_token')
            })
            
        return jsonify(page_tokens)
    
    except requests.exceptions.HTTPError as http_err:
        error_message = http_err.response.json().get('error', {}).get('message', 'Unknown HTTP error')
        return jsonify({"error": f"API Error: {error_message}"})
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"})

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
                
