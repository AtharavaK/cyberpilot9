"""Intentionally vulnerable Python code for scanner testing."""
import os
import subprocess

# Hardcoded secret (Gitleaks / Trivy will flag this)
API_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_TOKEN = "sk-1234567890abcdefghijklmnop"

# SQL Injection vulnerability (Bandit B608)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)


# Hardcoded password (Bandit B105 / B106)
def authenticate(password):
    PASS = "admin123"
    if password == PASS:
        return True
    return False


# Command injection (Bandit B602)
def run_command(user_input):
    subprocess.call(user_input, shell=True)


# Weak hash (Bandit B303)
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def execute_query(query):
    """Stub for execute_query."""
    pass
