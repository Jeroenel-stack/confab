# initialize_system.py
import sqlite3
import hashlib
import secrets

# SECURITY PROTOCOL 1: Password Hashing using 'hashlib'
# This satisfies the requirement for storing passwords securely.
# We will never store plain text passwords like 'command123'.
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    
    # Create the 'users' table (Access Control requirement)
    # The 'role' column decides who can access the Admin Dashboard.
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT)''')
    
    # Create the 'reports' table (Data Encryption & Integrity requirements)
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (id INTEGER PRIMARY KEY, agent_name TEXT, sector TEXT, threat_level TEXT, encrypted_data BYTES, integrity_hash TEXT)''')
    
    # Add default users if they don't exist
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # Add the Admin account
        admin_pw_hash = hash_password("command123") # Real password is command123
        c.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (admin_pw_hash,))
        
        # Add the Field Agent account
        agent_pw_hash = hash_password("agent123") # Real password is agent123
        c.execute("INSERT INTO users (username, password_hash, role) VALUES ('agent_alpha', ?, 'user')", (agent_pw_hash,))
        
        print("Initial users created: 'admin' (command123) and 'agent_alpha' (agent123)")
    
    conn.commit()
    conn.close()

init_db()