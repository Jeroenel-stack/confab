from flask import Flask, render_template, request, redirect, session, flash
import hashlib
from datetime import datetime
import random
import time
import os
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from supabase import create_client, Client
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "osiris_super_secret_session_key"

# --- FILE UPLOAD CONFIGURATION ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================================
# 1. SUPABASE CLOUD CONNECTION
# ==========================================
# PASTE YOUR SUPABASE URL AND KEY HERE:
SUPABASE_URL = "https://twsknocrijyjaveewlhd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR3c2tub2NyaWp5amF2ZWV3bGhkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY0NjQxNzcsImV4cCI6MjA5MjA0MDE3N30.S5bKO3urNsPx7BEzHTKASlxEC5k-rttLjzrJ-T9_OUE"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==========================================
# 2. ENCRYPTION SETUP (AES-256 Fernet)
# ==========================================
ENCRYPTION_KEY = b'v_T_6Rk_Q7J5-XkG8J-G9b_rP9M-K_6Qv_T_6Rk_Q7I=' 
cipher_suite = Fernet(ENCRYPTION_KEY)

# ==========================================
# 3. SECURITY TRACKERS & EMAIL SETUP
# ==========================================
failed_attempts = {}
LOCKOUT_TIME = 300 

# --- GMAIL SMTP CONFIGURATION ---
# The Gmail address that will SEND the 2FA codes
SENDER_EMAIL = "jeroenelaltamera383@gmail.com" 
# The 16-letter Google App Password (NO SPACES)
SENDER_PASSWORD = "xlxf cxwr kfco lzpv" 

# ==========================================
# 4. HELPER FUNCTIONS
# ==========================================
def log_action(action_text):
    """Writes a secure audit log directly to the Supabase cloud."""
    try:
        supabase.table('audit_logs').insert({"action": action_text}).execute()
    except:
        pass

def send_2fa_email(recipient_email, pin, username):
    """Transmits the 2FA PIN via secure SMTP email to the linked address."""
    print("\n" + "="*45)
    print(f"🔐 UPLINK INTERCEPTED: 2FA Token Generated")
    print(f"👤 Operative: {username.upper()}")
    print(f"🔑 SECURE PIN: {pin}")
    
    if not recipient_email:
        print("⚠️ WARNING: No email address linked to this account!")
        print("Fallback: Using terminal display for PIN.")
        print("="*45 + "\n")
        return False
        
    msg = MIMEText(f"OPERATIVE AUTHORIZATION REQUIRED.\n\nYour OSIRIS Command Center secure connection PIN is: {pin}\n\nThis token will expire shortly. Do not share this code with anyone.")
    msg['Subject'] = 'OSIRIS Security: 2FA Token'
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email

    try:
        # Connect to Gmail's secure SMTP server
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        print(f"📧 UPLINK SUCCESS: Email dispatched to {recipient_email}")
        print("="*45 + "\n")
        return True
    except Exception as e:
        print(f"📧 UPLINK FAILED: Could not send email. Error: {e}")
        print("="*45 + "\n")
        return False

# ==========================================
# 5. ROUTES & LOGIC
# ==========================================

@app.route('/')
def home():
    if 'username' in session:
        if session['role'] == 'admin':
            return redirect('/admin_view')
            
        # Fetch current operative's email to display in Settings
        user_res = supabase.table('users').select('email').eq('username', session['username']).execute()
        current_email = user_res.data[0].get('email') if user_res.data else None
        
        return render_template('index.html', logged_in=True, username=session['username'], role=session['role'], current_email=current_email)
    return render_template('index.html', logged_in=False)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # 1. ANTI-BRUTE FORCE CHECK
    if username in failed_attempts:
        attempts, lockout_start = failed_attempts[username]
        if attempts >= 3:
            if time.time() - lockout_start < LOCKOUT_TIME:
                log_action(f"SECURITY ALERT: Brute force prevented. {username} is currently locked out.")
                flash("CRITICAL: Account locked due to multiple failed attempts. Try again in 5 minutes.")
                return redirect('/')
            else:
                failed_attempts.pop(username, None)

    # 2. Hash password and check Supabase Database (Fetch Role AND Email)
    attempt_hash = hashlib.sha256(password.encode()).hexdigest()
    response = supabase.table('users').select('role, email').eq('username', username).eq('password_hash', attempt_hash).execute()
    
    if len(response.data) > 0: 
        user_data = response.data[0]
        user_role = user_data['role']
        user_email = user_data.get('email') # Pull the linked email!
        
        failed_attempts.pop(username, None) 
        
        # Generate the PIN
        pin = str(random.randint(100000, 999999))
        session['pending_user'] = username
        session['pending_role'] = user_role
        session['2fa_pin'] = pin
        
        # Transmit the PIN via Email
        send_2fa_email(user_email, pin, username)
        
        log_action(f"2FA token generated for {username}")
        return render_template('index.html', requires_2fa=True, pending_user=username)
    else:
        # 3. RECORD FAILED ATTEMPT
        if username not in failed_attempts:
            failed_attempts[username] = [1, time.time()]
        else:
            failed_attempts[username][0] += 1
            failed_attempts[username][1] = time.time()
            
        if failed_attempts[username][0] >= 3:
            log_action(f"CRITICAL: Maximum failed logins reached for {username}. Account locked.")
            flash("CRITICAL: Maximum attempts reached. Account locked for 5 minutes.")
        else:
            log_action(f"WARNING: Failed login attempt for username: {username}")
            flash(f"System: Authentication Failed. Attempt {failed_attempts[username][0]} of 3.")
        return redirect('/')

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    entered_pin = request.form.get('pin')
    real_pin = session.get('2fa_pin')
    
    if entered_pin == real_pin:
        session['username'] = session.pop('pending_user')
        session['role'] = session.pop('pending_role')
        session.pop('2fa_pin', None) 
        
        log_action(f"Successful 2FA login: {session['username']}")
        
        if session['role'] == 'admin':
            return redirect('/admin_view')
        else:
            return redirect('/')
    else:
        log_action(f"WARNING: Failed 2FA attempt for {session.get('pending_user')}")
        flash("CRITICAL: Invalid 2FA Token. Access Denied.")
        return render_template('index.html', requires_2fa=True, pending_user=session.get('pending_user'))

@app.route('/logout')
def logout():
    user = session.get('username', 'Unknown')
    session.clear()
    log_action(f"User {user} terminated session.")
    flash("Session Terminated Securely.")
    return redirect('/')

@app.route('/update_email', methods=['POST'])
def update_email():
    if 'username' not in session:
        return redirect('/')
        
    new_email = request.form.get('email')
    
    try:
        # Save the new email to Supabase for this specific user
        supabase.table('users').update({'email': new_email}).eq('username', session['username']).execute()
        log_action(f"Operative {session['username']} updated their secure email link.")
        flash("Communication Uplink Secured. Email updated successfully.")
    except Exception as e:
        flash("Error: Could not link email to database.")
        
    if session.get('role') == 'admin':
        return redirect('/admin_view')
    return redirect('/')

@app.route('/submit_report', methods=['POST'])
def submit_report():
    if 'username' not in session or session['role'] != 'agent':
        return redirect('/')
        
    sector = request.form['sector']
    threat_level = request.form['threat_level']
    raw_intel = request.form['intelligence']
    
    # FILE UPLOAD LOGIC
    file = request.files.get('attachment')
    attachment_path = None
    
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        unique_filename = f"{int(time.time())}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        attachment_path = f"/static/uploads/{unique_filename}"
    
    encrypted_payload = cipher_suite.encrypt(raw_intel.encode()).decode()
    integrity_hash = hashlib.sha256(encrypted_payload.encode()).hexdigest()
    
    supabase.table('reports').insert({
        'agent': session['username'],
        'sector': sector,
        'threat_level': threat_level,
        'encrypted_intel': encrypted_payload,
        'hash_checksum': integrity_hash,
        'attachment': attachment_path
    }).execute()
    
    log_action(f"Encrypted intelligence transmitted by {session['username']} for {sector}")
    flash("Transmission Successful. Payload and Files Secured.")
    return redirect('/')

@app.route('/admin_view')
def admin_view():
    if session.get('role') != 'admin':
        return redirect('/')
        
    reports_response = supabase.table('reports').select('*').order('timestamp', desc=True).execute()
    raw_reports = reports_response.data
    
    processed_reports = []
    
    for report in raw_reports:
        current_hash = hashlib.sha256(report['encrypted_intel'].encode()).hexdigest()
        
        if current_hash == report['hash_checksum']:
            try:
                decrypted = cipher_suite.decrypt(report['encrypted_intel'].encode()).decode()
                report['decrypted_text'] = decrypted
                report['status'] = 'VERIFIED'
            except:
                report['decrypted_text'] = "[DECRYPTION FAILED - KEY MISMATCH]"
                report['status'] = 'TAMPERED'
        else:
            report['decrypted_text'] = "[CRITICAL: DATA TAMPERING DETECTED]"
            report['status'] = 'TAMPERED'
            
        processed_reports.append(report)
        
    logs_response = supabase.table('audit_logs').select('*').order('timestamp', desc=True).limit(50).execute()
    audit_logs = [(log['timestamp'], log['action']) for log in logs_response.data]
        
    agents_response = supabase.table('users').select('id, username').eq('role', 'agent').execute()
    agents = agents_response.data
    
    # Fetch Admin's Email
    user_res = supabase.table('users').select('email').eq('username', session['username']).execute()
    current_email = user_res.data[0].get('email') if user_res.data else None
        
    return render_template('index.html', 
                           logged_in=True, 
                           username=session['username'], 
                           role=session['role'],
                           reports=processed_reports,
                           audit_logs=audit_logs,
                           agents=agents,
                           current_email=current_email)

@app.route('/create_agent', methods=['POST'])
def create_agent():
    if session.get('role') != 'admin':
        return redirect('/')
        
    new_user = request.form['new_username']
    new_pass = request.form['new_password']
    hashed_pass = hashlib.sha256(new_pass.encode()).hexdigest()
    
    try:
        supabase.table('users').insert({
            'username': new_user,
            'password_hash': hashed_pass,
            'role': 'agent'
        }).execute()
        log_action(f"Admin provisioned new operative access: {new_user}")
        flash(f"Success: Operative {new_user} provisioned.")
    except Exception as e:
        flash("Error: Operative ID may already exist.")
        
    return redirect('/admin_view')

@app.route('/edit_agent', methods=['POST'])
def edit_agent():
    if session.get('role') != 'admin':
        return redirect('/')
        
    agent_id = request.form['agent_id']
    new_username = request.form['username']
    new_password = request.form['password']
    
    update_data = {'username': new_username}
    if new_password.strip():
        update_data['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        
    try:
        supabase.table('users').update(update_data).eq('id', agent_id).execute()
        log_action(f"Admin updated operative ID: {agent_id}")
        flash("Operative profile updated successfully.")
    except Exception as e:
        flash("Error: Username may already be in use.")
        
    return redirect('/admin_view')

@app.route('/delete_agent/<int:agent_id>', methods=['POST'])
def delete_agent(agent_id):
    if session.get('role') != 'admin':
        return redirect('/')
        
    supabase.table('users').delete().eq('id', agent_id).execute()
    log_action(f"Admin revoked access and deleted operative ID: {agent_id}")
    flash("Operative access permanently revoked.")
    return redirect('/admin_view')

@app.route('/edit_report', methods=['POST'])
def edit_report():
    if session.get('role') != 'admin':
        return redirect('/')
        
    report_id = request.form['report_id']
    new_sector = request.form['sector']
    new_threat = request.form['threat_level']
    raw_intel = request.form['intelligence']
    
    new_encrypted_payload = cipher_suite.encrypt(raw_intel.encode()).decode()
    new_integrity_hash = hashlib.sha256(new_encrypted_payload.encode()).hexdigest()
    
    supabase.table('reports').update({
        'sector': new_sector,
        'threat_level': new_threat,
        'encrypted_intel': new_encrypted_payload,
        'hash_checksum': new_integrity_hash
    }).eq('id', report_id).execute()
    
    log_action(f"Admin updated and re-encrypted report ID: {report_id}")
    flash("Record updated successfully. New encryption keys applied.")
    return redirect('/admin_view')

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if session.get('role') != 'admin':
        return redirect('/')
        
    supabase.table('reports').delete().eq('id', report_id).execute()
    log_action(f"Admin manually deleted report ID: {report_id}")
    flash("Record successfully incinerated from database.")
    return redirect('/admin_view')

@app.route('/purge/<int:report_id>', methods=['POST'])
def purge_report(report_id):
    if session.get('role') != 'admin':
        return redirect('/')
        
    supabase.table('reports').delete().eq('id', report_id).execute()
    log_action(f"SECURITY PURGE: Admin destroyed compromised report ID: {report_id}")
    flash("Compromised Data Purged from System.")
    return redirect('/admin_view')

@app.route('/protocol_zero', methods=['POST'])
def protocol_zero():
    if session.get('role') != 'admin':
        return redirect('/')
        
    supabase.table('reports').delete().neq('id', 0).execute()
    supabase.table('audit_logs').delete().neq('id', 0).execute()
    
    log_action("CRITICAL: PROTOCOL ZERO INITIATED. ALL INTELLIGENCE INCINERATED.")
    flash("PROTOCOL ZERO EXECUTED. DATABASE WIPED.")
    return redirect('/admin_view')

if __name__ == '__main__':
    app.run(debug=True)