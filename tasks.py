import os
import re
import uuid
import time
import requests
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

# Configure Celery (same as app.py)
app = Celery('tasks', broker=os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

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

@app.task(bind=True)
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

    return {'status': 'COMPLETED'}
