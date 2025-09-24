#!/usr/bin/env python3
"""
N8N Workflow Integration Module - Test File for Code Review
WARNING: This file intentionally contains multiple issues for code review validation
"""

import os
import json
import requests
import sqlite3
from datetime import datetime
import hashlib

# Issue 1: Hardcoded credentials and secrets
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
SECRET_TOKEN = "super_secret_webhook_token"

class N8NWorkflowManager:
    def __init__(self):
        # Issue 2: No input validation
        self.base_url = "http://localhost:5678"  # Issue 3: Hardcoded URL, no HTTPS
        self.db_connection = None
        
    # Issue 4: Missing type hints and docstrings
    def connect_database(self, db_path):
        # Issue 5: SQL injection vulnerability
        self.db_connection = sqlite3.connect(db_path)
        cursor = self.db_connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS workflows (id INTEGER, name TEXT, data TEXT)")
        
    def authenticate_user(self, username, password):
        # Issue 6: Weak password hashing
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Issue 7: SQL injection vulnerability
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
        cursor = self.db_connection.cursor()
        result = cursor.execute(query).fetchone()
        return result is not None
    
    # Issue 8: No error handling
    def trigger_workflow(self, workflow_id, data):
        url = f"{self.base_url}/webhook/{workflow_id}"
        headers = {
            "Authorization": f"Bearer {API_KEY}",  # Issue 9: Exposed API key
            "Content-Type": "application/json"
        }
        
        # Issue 10: No timeout, no request validation
        response = requests.post(url, json=data, headers=headers, verify=False)  # Issue 11: SSL verification disabled
        return response.json()
    
    def process_workflow_data(self, workflows):
        results = []
        # Issue 12: Inefficient loop, potential memory issues with large datasets
        for workflow in workflows:
            # Issue 13: Accessing dict without checking if key exists
            workflow_name = workflow['name']
            workflow_data = workflow['data']
            
            # Issue 14: Using eval() - major security risk
            processed_data = eval(workflow_data)
            
            # Issue 15: Modifying list while iterating could cause issues
            if processed_data['status'] == 'inactive':
                workflows.remove(workflow)
                
            results.append(processed_data)
        return results
    
    # Issue 16: Method does too many things, violates single responsibility
    def backup_and_cleanup(self):
        # Issue 17: No proper file path validation
        backup_path = "/tmp/n8n_backup.sql"  # Issue 18: Hardcoded temp path
        
        # Issue 19: Command injection vulnerability
        os.system(f"mysqldump -u root -p{DATABASE_PASSWORD} n8n_db > {backup_path}")
        
        # Issue 20: Race condition potential
        if os.path.exists(backup_path):
            os.remove(backup_path)
            
        # Issue 21: Resource not properly closed
        log_file = open("/var/log/n8n_cleanup.log", "a")
        log_file.write(f"Cleanup completed at {datetime.now()}\n")
        # Missing log_file.close()

    def validate_webhook_signature(self, payload, signature):
        # Issue 22: Timing attack vulnerability
        expected = hashlib.sha256(f"{SECRET_TOKEN}{payload}".encode()).hexdigest()
        return expected == signature  # Should use constant-time comparison
    
# Issue 23: Global variables and side effects
current_workflows = []
error_count = 0

def load_configuration():
    # Issue 24: No exception handling for file operations
    with open("config.json", "r") as f:
        config = json.load(f)
    return config

# Issue 25: Function with too many parameters, poor design
def execute_complex_workflow(workflow_id, user_id, data, timeout, retries, callback_url, auth_token, debug_mode, log_level):
    global error_count  # Issue 26: Modifying global state
    
    try:
        manager = N8NWorkflowManager()
        result = manager.trigger_workflow(workflow_id, data)
        
        # Issue 27: Bare except clause catches all exceptions
    except:
        error_count += 1
        print("Something went wrong")  # Issue 28: Poor error reporting
        return None

# Issue 29: Dead code that's never called
def unused_legacy_function():
    """This function is never used but still exists"""
    pass

if __name__ == "__main__":
    # Issue 30: No proper main guard, potential issues if imported
    config = load_configuration()
    manager = N8NWorkflowManager()
    
    # Issue 31: Hardcoded test data
    test_data = {"user": "admin", "action": "deploy"}
    
    # Issue 32: No validation of return values
    result = manager.trigger_workflow("webhook-123", test_data)
    print(f"Result: {result}")  # Issue 33: Potential sensitive data in logs