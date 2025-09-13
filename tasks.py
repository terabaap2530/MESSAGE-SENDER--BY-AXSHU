import os
import re
import uuid
import time
import requests
from celery import Celery
from dotenv import load_dotenv
from requests.exceptions import RequestException

load_dotenv()

# Configure Celery (same as app.py)
app = Celery('tasks', broker=os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

def send_message_with_token(token, thread_id, message):
    """
    Sends a message to a Facebook thread using the Graph API.
    """
    url = f"https://graph.facebook.com/v19.0/t_{thread_id}"
    params = {
        "access_token": token,
        "message": message
    }
    try:
        response = requests.post(url, data=params, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except RequestException as e:
        print(f"Error sending message: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

@app.task(bind=True)
def start_sending_task(self, tokens_str, thread_id, prefix, time_sleep, messages):
    """
    A Celery task to send messages with multiple tokens.
    """
    tokens = [token.strip() for token in tokens_str.split('\n') if token.strip()]
    
    self.update_state(state='RUNNING', meta={
        'thread_id': thread_id,
        'prefix': prefix,
        'messages_sent': 0,
        'status': 'Running'
    })
    
    current_messages_sent = 0
    
    # Loop through all messages and tokens
    for message in messages:
        for token in tokens:
            # Check if the task has been revoked (stopped)
            if self.request.is_revoked():
                self.update_state(state='REVOKED', meta={
                    'thread_id': thread_id,
                    'prefix': prefix,
                    'messages_sent': current_messages_sent,
                    'status': 'Stopped'
                })
                return {'status': 'Task Revoked'}
            
            full_message = f"{prefix} {message}"
            result = send_message_with_token(token, thread_id, full_message)
            
            if result:
                current_messages_sent += 1
                self.update_state(state='RUNNING', meta={
                    'thread_id': thread_id,
                    'prefix': prefix,
                    'messages_sent': current_messages_sent,
                    'status': 'Running'
                })
            
            time.sleep(time_sleep)

    self.update_state(state='COMPLETED', meta={
        'thread_id': thread_id,
        'prefix': prefix,
        'messages_sent': current_messages_sent,
        'status': 'Completed'
    })
    return {'status': 'Task Completed'}
    
