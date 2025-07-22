#!/usr/bin/env python3
"""
Vulnerable Python code for testing security scanner
WARNING: This code contains intentional vulnerabilities for testing purposes only
"""

import os
import sqlite3
import subprocess
import sys

# Hardcoded credentials vulnerability
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "super_secret_token_123"

def login_user(username, password):
    """SQL Injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    
    # Another SQL injection pattern
    cursor.execute("SELECT id FROM accounts WHERE email = '%s'" % username)
    
    return result

def search_files(search_term):
    """Command Injection vulnerability"""
    # Vulnerable: Direct execution of user input
    command = "find /home -name " + search_term
    result = os.system(command)
    
    # Another command injection pattern
    subprocess.call("grep -r " + search_term + " /var/log", shell=True)
    
    return result

def execute_user_code(user_input):
    """Code Injection vulnerability"""
    # Extremely dangerous: eval with user input
    result = eval(user_input)
    
    # Another code injection pattern
    exec("print('Result: ' + str(" + user_input + "))")
    
    return result

def dynamic_import(module_name):
    """Another code injection pattern"""
    # Vulnerable: exec with string formatting
    exec(f"import {module_name}")
    
def process_data(data_file):
    """More SQL injection patterns"""
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    
    # Multiple vulnerable patterns
    query = f"INSERT INTO logs VALUES ('{data_file}', '{DATABASE_PASSWORD}')"
    cursor.execute(query)
    
    # Format string vulnerability
    cursor.execute("UPDATE settings SET value = '{}' WHERE key = 'path'".format(data_file))

def run_system_command(cmd, args):
    """Additional command injection vulnerabilities"""
    # Multiple dangerous patterns
    os.popen(cmd + " " + args)
    subprocess.run(cmd + " --input=" + args, shell=True)
    
def calculate_result(expression):
    """More code injection vulnerabilities"""
    # Compile and execute user input
    code = compile(expression, '<string>', 'eval')
    result = eval(code)
    return result

# Configuration with hardcoded secrets
CONFIG = {
    'db_password': 'mypassword123',
    'secret_key': 'django-insecure-key-12345',
    'api_token': 'ghp_1234567890abcdefghij'
}

if __name__ == "__main__":
    # Demonstrate vulnerabilities
    user_query = sys.argv[1] if len(sys.argv) > 1 else "test"
    
    # This would be vulnerable to all the above issues
    login_user(user_query, "password")
    search_files(user_query)
    execute_user_code(user_query)