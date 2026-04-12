# app.py
from flask import Flask, render_template, request, session, redirect, flash
import sqlite3
import hashlib
import secrets
from cryptography.fernet import Fernet
import os
from datetime import datetime
import random
import time # <-- ADD THIS


# --- ANTI-BRUTE FORCE TRACKER ---
failed_attempts = {}
LOCKOUT_TIME = 300 # 5 minutes in seconds

app = Flask(__name__)

# ==========================================
# SECURITY REQUIREMENT 5: Secure Token Generation
# ==========================================
# We save the session key to a file so Flask doesn't log you out 
# when SQLite updates the database file (Protocol Zero fix).
if not os.path.exists("session.key"):
    with open("session.key", "w") as key_file:
        key_file.write(secrets.token_hex(32))

with open("session.key", "r") as key_file:
    app.secret_key = key_file.read()

# ==========================================
# SECURITY REQUIREMENT 3: Data Encryption & Decryption
# ==========================================
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("secret.key", "rb") as key_file:
    cipher_suite = Fernet(key_file.read())

# --- Database Setup (SQLite) ---
def init_db():
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    # Create Tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, agent_name TEXT, sector TEXT, threat_level TEXT, encrypted_data BYTES, integrity_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, action TEXT)''')
    
    # Create default accounts if they don't exist
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # SECURITY REQUIREMENT 1: Password Hashing
        admin_pw_hash = hashlib.sha256(b"command123").hexdigest()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (admin_pw_hash,))
        
        agent_pw_hash = hashlib.sha256(b"agent123").hexdigest()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES ('agent_alpha', ?, 'agent')", (agent_pw_hash,))
        
        c.execute("INSERT INTO audit_logs (action) VALUES ('SYSTEM INITIALIZED. Default accounts created.')")
        
    conn.commit()
    conn.close()

init_db()

# Helper function to write to the Audit Log
def log_action(action_text):
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    c.execute("INSERT INTO audit_logs (action) VALUES (?)", (action_text,))
    conn.commit()
    conn.close()

# ==========================================
# LOCAL "AI" THREAT ANALYZER
# ==========================================
def analyze_threat_level(intelligence_text):
    text = intelligence_text.lower()
    score = 0
    tags = []
    
    critical_keywords = ['casualties', 'ambush', 'hostile', 'firefight', 'breach', 'bomb', 'enemy']
    urgent_keywords = ['medical', 'supplies', 'evac', 'shortage', 'civilians']
    
    for word in critical_keywords:
        if word in text:
            score += 35
            tags.append("COMBAT")
            
    for word in urgent_keywords:
        if word in text:
            score += 20
            tags.append("LOGISTICS")
            
    if score > 100: score = 100
    if score == 0: tags.append("ROUTINE")
    
    if score >= 70:
        recommendation = "IMMEDIATE RESPONSE REQUIRED"
    elif score >= 40:
        recommendation = "DISPATCH SUPPORT"
    else:
        recommendation = "MONITOR SITUATION"
        
    return score, ", ".join(set(tags)), recommendation

# ==========================================
# ROUTES & LOGIC
# ==========================================

@app.route('/')
def home():
    if 'username' in session:
        # BUG FIX: If an admin goes to the homepage, force them to the database view!
        if session.get('role') == 'admin':
            return redirect('/admin_view')
        return render_template('index.html', logged_in=True, role=session['role'], username=session['username'])
    return render_template('index.html', logged_in=False)

# SECURITY REQUIREMENT 2: Login Authentication & Anti-Brute Force
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # 1. ANTI-BRUTE FORCE CHECK (Check if user is already locked out)
    if username in failed_attempts:
        attempts, lockout_start = failed_attempts[username]
        if attempts >= 3:
            if time.time() - lockout_start < LOCKOUT_TIME:
                log_action(f"SECURITY ALERT: Brute force prevented. {username} is currently locked out.")
                flash("CRITICAL: Account locked due to multiple failed attempts. Try again in 5 minutes.")
                return redirect('/')
            else:
                failed_attempts.pop(username, None) # Time expired, unlock them

    # 2. Proceed with checking credentials
    attempt_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=? AND password_hash=?", (username, attempt_hash))
    user = c.fetchone()
    conn.close()
    
    if user:
        # Success! Clear any previous failed attempts
        failed_attempts.pop(username, None) 
        
        # Generate a random 6-digit PIN for 2FA
        pin = str(random.randint(100000, 999999))
        session['pending_user'] = username
        session['pending_role'] = user[0]
        session['2fa_pin'] = pin
        
        print("\n" + "="*45)
        print(f"🔐 UPLINK INTERCEPTED: 2FA Token Generated")
        print(f"👤 Operative: {username.upper()}")
        print(f"🔑 SECURE PIN: {pin}")
        print("="*45 + "\n")
        
        log_action(f"2FA token generated for {username}")
        return render_template('index.html', requires_2fa=True, pending_user=username)
    else:
        # 3. RECORD FAILED ATTEMPT
        if username not in failed_attempts:
            failed_attempts[username] = [1, time.time()]
        else:
            failed_attempts[username][0] += 1
            failed_attempts[username][1] = time.time()
            
        # Check if this failure triggered the lockout
        if failed_attempts[username][0] >= 3:
            log_action(f"CRITICAL: Maximum failed logins reached for {username}. Account locked.")
            flash("CRITICAL: Maximum attempts reached. Account locked for 5 minutes.")
        else:
            log_action(f"WARNING: Failed login attempt for username: {username}")
            flash(f"System: Authentication Failed. Attempt {failed_attempts[username][0]} of 3.")
        return redirect('/')

# --- NEW ROUTE FOR 2FA VERIFICATION ---
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    entered_pin = request.form.get('pin')
    real_pin = session.get('2fa_pin')
    
    if entered_pin == real_pin:
        # 2FA Success! Log them in for real.
        session['username'] = session.pop('pending_user')
        session['role'] = session.pop('pending_role')
        session.pop('2fa_pin') # Clear the PIN for security
        
        log_action(f"Successful 2FA login: {session['username']}")
        
        if session['role'] == 'admin':
            return redirect('/admin_view')
        else:
            return redirect('/')
    else:
        # 2FA Failed
        log_action(f"WARNING: Failed 2FA attempt for {session.get('pending_user')}")
        flash("CRITICAL: Invalid 2FA Token. Access Denied.")
        # Send them back to the 2FA screen to try again
        return render_template('index.html', requires_2fa=True, pending_user=session.get('pending_user'))

@app.route('/logout')
def logout():
    log_action(f"Session terminated: {session.get('username')}")
    session.clear() 
    return redirect('/')

@app.route('/submit_report', methods=['POST'])
def submit_report():
    if session.get('role') != 'agent':
        return "Access Denied", 403

    sector = request.form['sector']
    threat_level = request.form['threat_level']
    raw_intelligence = request.form['intelligence']
    
    # Run AI Analytics
    ai_score, ai_tags, ai_rec = analyze_threat_level(raw_intelligence)
    enhanced_intelligence = f"[{ai_tags}] {raw_intelligence} | AI REC: {ai_rec}"
    
    # Encrypt and Hash
    encrypted_payload = cipher_suite.encrypt(enhanced_intelligence.encode())
    payload_hash = hashlib.sha256(enhanced_intelligence.encode()).hexdigest()
    
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    c.execute("INSERT INTO reports (agent_name, sector, threat_level, encrypted_data, integrity_hash) VALUES (?, ?, ?, ?, ?)", 
              (session['username'], sector, threat_level, encrypted_payload, payload_hash))
    conn.commit()
    conn.close()
    
    log_action(f"New encrypted report transmitted by {session['username']} for {sector}. AI Threat Score: {ai_score}%")
    flash(f"Report Transmitted Securely. AI Threat Score: {ai_score}%")
    return redirect('/')

@app.route('/admin_view')
def admin_view():
    if session.get('role') != 'admin':
        return "Access Denied", 403
        
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    
    # Fetch newest reports first
    c.execute("SELECT * FROM reports ORDER BY id DESC")
    reports = c.fetchall()
    
    # Fetch last 10 audit logs
    c.execute("SELECT timestamp, action FROM audit_logs ORDER BY id DESC LIMIT 10")
    audit_logs = c.fetchall()
    conn.close()
    
    decrypted_reports = []
    for rep in reports:
        rep_id, agent, sector, threat, enc_data, saved_hash = rep
        try:
            # Decrypt and Verify Integrity
            decrypted_text = cipher_suite.decrypt(enc_data).decode()
            current_hash = hashlib.sha256(decrypted_text.encode()).hexdigest()
            status = "✔️ VERIFIED" if current_hash == saved_hash else "❌ TAMPERED"
        except Exception:
            decrypted_text = "[DECRYPTION FAILED]"
            status = "❌ DATA CORRUPTED"

        decrypted_reports.append({
            'id': rep_id, 'agent': agent, 'sector': sector, 'threat': threat, 
            'encrypted_preview': enc_data[:15].decode('utf-8', errors='ignore') + "...",
            'decrypted_text': decrypted_text, 'status': status
        })
        
    log_action("Admin accessed the Command Center Dashboard.")
    return render_template('index.html', logged_in=True, role='admin', reports=decrypted_reports, audit_logs=audit_logs, username=session['username'])

@app.route('/purge/<int:report_id>', methods=['POST'])
def purge_report(report_id):
    if session.get('role') != 'admin':
        return "Access Denied", 403
        
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    c.execute("DELETE FROM reports WHERE id=?", (report_id,))
    conn.commit()
    conn.close()
    
    log_action(f"ADMIN ACTION: Purged compromised report ID #{report_id} from database.")
    flash("Compromised data purged from system successfully.")
    return redirect('/admin_view')

# ==========================================
# ADMIN FUNCTION: CREATE NEW AGENT
# ==========================================
@app.route('/create_agent', methods=['POST'])
def create_agent():
    # Enforce strict access control
    if session.get('role') != 'admin':
        return "Access Denied", 403
        
    new_username = request.form['new_username']
    new_password = request.form['new_password']
    
    # Hash the new password securely
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    
    try:
        # Check if user already exists
        c.execute("SELECT * FROM users WHERE username=?", (new_username,))
        if c.fetchone():
            flash(f"Registration Failed: Username '{new_username}' already exists.")
        else:
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'agent')", 
                      (new_username, hashed_password))
            conn.commit()
            log_action(f"ADMIN COMMAND: Registered new field operative -> {new_username}")
            flash(f"Operative '{new_username}' registered successfully.")
    except Exception as e:
        flash(f"Database Error: {e}")
    finally:
        conn.close()
        
    return redirect('/admin_view')
# ==========================================
# PROTOCOL ZERO: EMERGENCY DATABASE WIPE
# ==========================================
@app.route('/protocol_zero', methods=['POST'])
def protocol_zero():
    if session.get('role') != 'admin':
        return "Access Denied", 403
        
    conn = sqlite3.connect('intelligence.db')
    c = conn.cursor()
    
    # Incinerate all intelligence and history
    c.execute("DELETE FROM reports")
    c.execute("DELETE FROM audit_logs")
    
    conn.commit()
    conn.close()
    
    # Leave a single chilling log
    log_action("CRITICAL: PROTOCOL ZERO INITIATED. ALL INTELLIGENCE AND SYSTEM LOGS INCINERATED.")
    flash("PROTOCOL ZERO EXECUTED. DATABASE WIPED.")
    
    return redirect('/admin_view')

if __name__ == '__main__':
    app.run(debug=True, port=5000)