import os
import re
import uuid
import time
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
from celery import Celery
import asyncio

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Configure Celery
app.config['CELERY_BROKER_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Store tasks and their states
tasks = {}

@celery.task(bind=True)
def start_sending_task(self, tokens_str, thread_id, prefix, time_sleep, messages):
    tokens = [token.strip() for token in tokens_str.split('\n') if token.strip()]
    self.update_state(state='RUNNING', meta={
        'thread_id': thread_id,
        'prefix': prefix,
        'messages_sent': 0,
    })
    
    current_messages_sent = 0
    
    while self.request.is_valid(): # check if the task is still valid
        for message in messages:
            if not self.request.is_valid():
                break
            
            for token in tokens:
                if not self.request.is_valid():
                    break
                
                full_message = f"{prefix} {message}"
                result = send_message_with_token(token, thread_id, full_message)
                
                if result:
                    current_messages_sent += 1
                    self.update_state(state='RUNNING', meta={
                        'thread_id': thread_id,
                        'prefix': prefix,
                        'messages_sent': current_messages_sent
                    })
                
                time.sleep(time_sleep)

def send_message_with_token(token, thread_id, message):
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_panel')
def user_panel():
    return render_template('user_panel.html')

@app.route('/get_session_details', methods=['POST'])
def get_session_details():
    data = request.get_json()
    task_id = data.get('taskId')
    
    task_result = start_sending_task.AsyncResult(task_id)
    
    if task_result.state == 'PENDING':
        return jsonify({"is_valid": False, "message": "Invalid Session ID."})

    status_meta = task_result.info
    status = task_result.state
    
    return jsonify({
        "is_valid": True,
        "status": status,
        "thread_id": status_meta.get('thread_id'),
        "prefix": status_meta.get('prefix'),
        "messages_sent": status_meta.get('messages_sent', 0)
    })

@app.route('/stop_task', methods=['POST'])
def stop_task():
    task_id = request.form.get('taskId')
    task_result = start_sending_task.AsyncResult(task_id)
    if task_result.state in ['PENDING', 'RUNNING']:
        task_result.revoke(terminate=True)
        return jsonify({"message": f"Task {task_id} has been stopped."})
    return jsonify({"message": "Task not found."}), 404

@app.route('/pause_task/<task_id>', methods=['POST'])
def pause_task(task_id):
    task_result = start_sending_task.AsyncResult(task_id)
    if task_result.state == 'RUNNING':
        task_result.revoke(terminate=False, signal='PAUSE')
        return jsonify({"message": f"Task {task_id} has been paused."})
    return jsonify({"message": "Task not found or not running."}), 404

@app.route('/resume_task/<task_id>', methods=['POST'])
def resume_task(task_id):
    # This is a placeholder. Resume logic for Celery needs a bit more setup.
    return jsonify({"message": "Resume functionality is not yet fully implemented with this method."})

@app.route('/start_service', methods=['POST'])
def start_service():
    tokens_str = request.form.get('tokens')
    threadId = request.form.get('threadId')
    kidx = request.form.get('kidx')
    time_sleep = request.form.get('time', type=int)
    txtFile = request.files.get('txtFile')

    messages = []
    if txtFile and txtFile.filename.endswith('.txt'):
        content = txtFile.read().decode('utf-8')
        messages = [line.strip() for line in content.split('\n') if line.strip()]
    
    if not tokens_str or not messages or not threadId or not kidx or time_sleep is None:
        return "Missing required fields", 400

    task = start_sending_task.delay(tokens_str, threadId, kidx, time_sleep, messages)
    
    return render_template('token_checker.html', taskId=task.id)

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
