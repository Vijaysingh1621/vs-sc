# Test file with various Python vulnerabilities for the scanner

import os
import subprocess
import sqlite3
import hashlib
import pickle
import yaml
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# OWASP A02: Cryptographic Failures
PASSWORD = "admin123"  # Hardcoded password
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
SECRET_KEY = "my-secret-key"  # Hardcoded secret

# SANS CWE-327: Weak Cryptography
def hash_password_weak(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak MD5 hashing

def sha1_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()  # Weak SHA-1

# OWASP A03 & SANS CWE-89: SQL Injection
def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    cursor.execute(query)
    return cursor.fetchall()

def update_user(name, email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    sql = f"UPDATE users SET email = '{email}' WHERE name = '{name}'"  # SQL Injection
    cursor.execute(sql)
    conn.commit()

# SANS CWE-78: OS Command Injection
def execute_command(user_input):
    os.system(f"ping {user_input}")  # Command injection

def run_subprocess(filename):
    subprocess.call(f"cat {filename}", shell=True)  # Command injection

# SANS CWE-94: Code Injection
def execute_code(user_code):
    exec(user_code)  # Code injection vulnerability

def evaluate_expression(expression):
    return eval(expression)  # Code injection through eval

# SANS CWE-22: Path Traversal
def read_file(filename):
    with open(filename, 'r') as f:  # No path validation
        return f.read()

def write_file(filename, content):
    with open(filename, 'w') as f:  # Path traversal vulnerability
        f.write(content)

# OWASP A07: Authentication Failures
def authenticate(username, password):
    if password == "password123":  # Weak password check
        return True
    return False

def is_admin(session_data):
    if session_data:  # Insufficient authorization
        return True
    return False

# SANS CWE-79: Cross-site Scripting
@app.route('/display')
def display_message():
    message = request.args.get('message')
    return f"<div>{message}</div>"  # XSS vulnerability - no escaping

@app.route('/template')
def render_template():
    template = request.args.get('template')
    return render_template_string(template)  # Template injection

# SANS CWE-352: CSRF
@app.route('/update_profile', methods=['POST'])
def update_profile():
    # Missing CSRF token validation
    name = request.form.get('name')
    email = request.form.get('email')
    # Update profile without CSRF protection
    return "Profile updated"

# SANS CWE-434: Unrestricted Upload
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    # No file type validation
    file.save(f"/uploads/{file.filename}")
    return "File uploaded"

# SANS CWE-285: Improper Authorization
@app.route('/admin')
def admin_panel():
    user = request.args.get('user')
    if user:  # Weak authorization check
        return "Admin panel access granted"
    return "Access denied"

# SANS CWE-732: Incorrect Permission Assignment
def create_file_with_permissions(filename):
    with open(filename, 'w') as f:
        f.write("sensitive data")
    os.chmod(filename, 0o777)  # World-readable and writable

# SANS CWE-209: Information Exposure
def handle_error():
    try:
        risky_operation()
    except Exception as e:
        print(f"Error details: {e}")  # Exposing error information
        import traceback
        traceback.print_exc()  # Stack trace exposure

# SANS CWE-190: Integer Overflow
def calculate_size(input_str):
    size = int(input_str)  # No bounds checking
    return size * 1024  # Potential overflow

# SANS CWE-476: NULL Pointer Dereference (Python equivalent)
def process_user(user):
    return user.upper()  # No None check

# SANS CWE-502: Deserialization
def deserialize_data(serialized_data):
    return pickle.loads(serialized_data)  # Unsafe deserialization

def load_yaml_unsafe(yaml_data):
    return yaml.load(yaml_data)  # Unsafe YAML loading

# SANS CWE-918: SSRF
def fetch_url(url):
    response = requests.get(url)  # No URL validation - SSRF vulnerability
    return response.text

# SANS CWE-125: Out-of-bounds Read
def get_char_at(input_str, index):
    return input_str[index]  # No bounds checking

# SANS CWE-20: Improper Input Validation
def process_input(user_input):
    # No input validation
    print(f"Processing: {user_input}")
    # Direct use without sanitization

# OWASP A09: Logging Failures
def log_sensitive_data(password, token):
    print(f"User password: {password}")  # Logging sensitive data
    print(f"API token: {token}")

# OWASP A05: Security Misconfiguration
DEBUG = True  # Debug mode enabled
app.config['DEBUG'] = True

# OWASP A06: Vulnerable Components
# Using outdated packages (would be detected by dependency scanner)
# requests==2.6.0  # Outdated version with vulnerabilities

# Additional vulnerabilities
def weak_random():
    import random
    return random.random()  # Weak randomness for security purposes

def hardcoded_crypto():
    key = b"1234567890123456"  # Hardcoded encryption key
    return key

# SANS CWE-611: XML External Entities
def parse_xml_unsafe(xml_data):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_data)  # Vulnerable to XXE
    return root

# Insecure file permissions
def create_temp_file():
    import tempfile
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    os.chmod(temp_file.name, 0o666)  # Insecure permissions
    return temp_file.name

# Race condition vulnerability
import threading
shared_resource = 0

def unsafe_increment():
    global shared_resource
    temp = shared_resource
    # Race condition here
    shared_resource = temp + 1

# Memory disclosure
def get_memory_info():
    import gc
    return str(gc.get_objects())  # Potential memory disclosure

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Insecure configuration