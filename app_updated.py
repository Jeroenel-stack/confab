from flask import Flask, render_template, request, redirect, session, flash, jsonify, Response
import hashlib
from datetime import datetime
import random
import time
import os
import csv
import io
from functools import wraps
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from supabase import create_client, Client
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from google import genai

# ==========================================
# 1. OPEN THE VAULT FIRST
# ==========================================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise ValueError("Missing FLASK_SECRET_KEY environment variable!")

# ==========================================
# 2. AI CORE CONFIGURATION
# ==========================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ai_client = None

if GEMINI_API_KEY:
    ai_client = genai.Client(api_key=GEMINI_API_KEY)

# ==========================================
# 3. FILE UPLOAD CONFIGURATION
# ==========================================
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "txt", "csv"}
MAX_UPLOAD_MB = 10

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================================
# 4. SUPABASE CLOUD CONNECTION
# ==========================================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing essential Supabase Environment Variables!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==========================================
# 5. ENCRYPTION SETUP AES-256 FERNET
# ==========================================
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("Missing ENCRYPTION_KEY environment variable!")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# ==========================================
# 6. SECURITY TRACKERS & EMAIL SETUP
# ==========================================
failed_attempts = {}
LOCKOUT_TIME = 300

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

REPORT_STATUSES = ["OPEN", "REVIEWING", "RESOLVED", "ARCHIVED"]
PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ==========================================
# 7. HELPER FUNCTIONS
# ==========================================
def log_action(action_text):
    """Writes a secure audit log directly to the Supabase cloud."""
    try:
        supabase.table("audit_logs").insert({"action": action_text}).execute()
    except Exception as exc:
        print(f"AUDIT LOG FAILED: {exc}")


def require_login(role=None):
    """Protects routes and optionally enforces a required role."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect("/")
            if role and session.get("role") != role:
                log_action(
                    f"ACCESS DENIED: {session.get('username', 'Unknown')} attempted {request.path}"
                )
                flash("ACCESS DENIED: Insufficient clearance level.")
                return redirect("/")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def utc_now_iso():
    return datetime.utcnow().isoformat()


def decrypt_report(report):
    """Decrypts report intelligence and separates integrity status from workflow status."""
    encrypted_intel = report.get("encrypted_intel", "")
    stored_hash = report.get("hash_checksum", "")
    current_hash = hashlib.sha256(encrypted_intel.encode()).hexdigest()

    if current_hash != stored_hash:
        report["decrypted_text"] = "[CRITICAL: DATA TAMPERING DETECTED]"
        report["status_flag"] = "TAMPERED"
        return report

    try:
        report["decrypted_text"] = cipher_suite.decrypt(encrypted_intel.encode()).decode()
        report["status_flag"] = "VERIFIED"
    except Exception:
        report["decrypted_text"] = "[DECRYPTION FAILED - KEY MISMATCH]"
        report["status_flag"] = "TAMPERED"

    report["status"] = report.get("status") or "OPEN"
    report["priority"] = report.get("priority") or "MEDIUM"
    return report


def send_2fa_email(recipient_email, pin, username):
    """Transmits the 2FA PIN via secure SMTP email to the linked address."""
    print("\n" + "=" * 45)
    print("🔐 UPLINK INTERCEPTED: 2FA Token Generated")
    print(f"👤 Operative: {username.upper()}")
    print(f"🔑 SECURE PIN: {pin}")

    if not recipient_email:
        print("⚠️ WARNING: No email address linked to this account!")
        print("Fallback: Using terminal display for PIN.")
        print("=" * 45 + "\n")
        return False

    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("⚠️ WARNING: Gmail SMTP credentials are missing.")
        print("Fallback: Using terminal display for PIN.")
        print("=" * 45 + "\n")
        return False

    msg = MIMEText(
        "OPERATIVE AUTHORIZATION REQUIRED.\n\n"
        f"Your OSIRIS Command Center secure connection PIN is: {pin}\n\n"
        "This token will expire shortly. Do not share this code with anyone."
    )
    msg["Subject"] = "OSIRIS Security: 2FA Token"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        print(f"📧 UPLINK SUCCESS: Email dispatched to {recipient_email}")
        print("=" * 45 + "\n")
        return True
    except Exception as exc:
        print(f"📧 UPLINK FAILED: Could not send email. Error: {exc}")
        print("=" * 45 + "\n")
        return False

# ==========================================
# 8. ROUTES & LOGIC
# ==========================================
@app.route("/")
def home():
    if "username" in session:
        if session["role"] == "admin":
            return redirect("/admin_view")

        user_res = (
            supabase.table("users")
            .select("email")
            .eq("username", session["username"])
            .execute()
        )
        current_email = user_res.data[0].get("email") if user_res.data else None

        return render_template(
            "index.html",
            logged_in=True,
            username=session["username"],
            role=session["role"],
            current_email=current_email,
        )

    return render_template("index.html", logged_in=False)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]

    if username in failed_attempts:
        attempts, lockout_start = failed_attempts[username]
        if attempts >= 3:
            if time.time() - lockout_start < LOCKOUT_TIME:
                log_action(
                    f"SECURITY ALERT: Brute force prevented. {username} is currently locked out."
                )
                flash("CRITICAL: Account locked due to multiple failed attempts. Try again in 5 minutes.")
                return redirect("/")
            failed_attempts.pop(username, None)

    attempt_hash = hashlib.sha256(password.encode()).hexdigest()
    response = (
        supabase.table("users")
        .select("role, email")
        .eq("username", username)
        .eq("password_hash", attempt_hash)
        .execute()
    )

    if response.data:
        user_data = response.data[0]
        user_role = user_data["role"]
        user_email = user_data.get("email")

        failed_attempts.pop(username, None)

        pin = str(random.randint(100000, 999999))
        session["pending_user"] = username
        session["pending_role"] = user_role
        session["2fa_pin"] = pin
        session["2fa_created_at"] = time.time()

        send_2fa_email(user_email, pin, username)

        log_action(f"2FA token generated for {username}")
        return render_template("index.html", requires_2fa=True, pending_user=username)

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

    return redirect("/")


@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    entered_pin = request.form.get("pin")
    real_pin = session.get("2fa_pin")
    created_at = session.get("2fa_created_at")

    if created_at and time.time() - created_at > 300:
        log_action(f"WARNING: Expired 2FA attempt for {session.get('pending_user')}")
        session.pop("2fa_pin", None)
        session.pop("2fa_created_at", None)
        flash("CRITICAL: 2FA Token expired. Please log in again.")
        return redirect("/")

    if entered_pin == real_pin:
        session["username"] = session.pop("pending_user")
        session["role"] = session.pop("pending_role")
        session.pop("2fa_pin", None)
        session.pop("2fa_created_at", None)

        log_action(f"Successful 2FA login: {session['username']}")

        if session["role"] == "admin":
            return redirect("/admin_view")
        return redirect("/")

    log_action(f"WARNING: Failed 2FA attempt for {session.get('pending_user')}")
    flash("CRITICAL: Invalid 2FA Token. Access Denied.")
    return render_template(
        "index.html",
        requires_2fa=True,
        pending_user=session.get("pending_user"),
    )


@app.route("/logout")
def logout():
    user = session.get("username", "Unknown")
    session.clear()
    log_action(f"User {user} terminated session.")
    flash("Session Terminated Securely.")
    return redirect("/")


@app.route("/update_email", methods=["POST"])
@require_login()
def update_email():
    new_email = request.form.get("email", "").strip()

    try:
        supabase.table("users").update({"email": new_email}).eq(
            "username", session["username"]
        ).execute()
        log_action(f"Operative {session['username']} updated their secure email link.")
        flash("Communication Uplink Secured. Email updated successfully.")
    except Exception as exc:
        print(exc)
        flash("Error: Could not link email to database.")

    if session.get("role") == "admin":
        return redirect("/admin_view")
    return redirect("/")


@app.route("/submit_report", methods=["POST"])
@require_login("agent")
def submit_report():
    sector = request.form["sector"]
    threat_level = request.form["threat_level"]
    raw_intel = request.form["intelligence"]

    file = request.files.get("attachment")
    attachment_path = None

    if file and file.filename != "":
        if not allowed_file(file.filename):
            flash("Upload blocked: unsupported file type.")
            return redirect("/")

        filename = secure_filename(file.filename)
        unique_filename = f"{int(time.time())}_{filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        file.save(filepath)
        attachment_path = f"/static/uploads/{unique_filename}"

    encrypted_payload = cipher_suite.encrypt(raw_intel.encode()).decode()
    integrity_hash = hashlib.sha256(encrypted_payload.encode()).hexdigest()

    insert_data = {
        "agent": session["username"],
        "sector": sector,
        "threat_level": threat_level,
        "encrypted_intel": encrypted_payload,
        "hash_checksum": integrity_hash,
        "attachment": attachment_path,
        "status": "OPEN",
        "priority": "MEDIUM",
        "updated_at": utc_now_iso(),
    }

    try:
        supabase.table("reports").insert(insert_data).execute()
    except Exception:
        # Compatibility fallback for databases that have not yet run the new SQL migration.
        insert_data.pop("status", None)
        insert_data.pop("priority", None)
        insert_data.pop("updated_at", None)
        supabase.table("reports").insert(insert_data).execute()

    log_action(f"Encrypted intelligence transmitted by {session['username']} for {sector}")
    flash("Transmission Successful. Payload and Files Secured.")
    return redirect("/")


@app.route("/admin_view")
@require_login("admin")
def admin_view():
    reports_response = (
        supabase.table("reports")
        .select("*")
        .order("timestamp", desc=True)
        .execute()
    )
    raw_reports = reports_response.data or []
    processed_reports = [decrypt_report(report) for report in raw_reports]

    logs_response = (
        supabase.table("audit_logs")
        .select("*")
        .order("timestamp", desc=True)
        .limit(50)
        .execute()
    )
    audit_logs = [
        (log.get("timestamp"), log.get("action")) for log in (logs_response.data or [])
    ]

    agents_response = (
        supabase.table("users")
        .select("id, username, email")
        .eq("role", "agent")
        .execute()
    )
    agents = agents_response.data or []

    user_res = (
        supabase.table("users")
        .select("email")
        .eq("username", session["username"])
        .execute()
    )
    current_email = user_res.data[0].get("email") if user_res.data else None

    return render_template(
        "index.html",
        logged_in=True,
        username=session["username"],
        role=session["role"],
        reports=processed_reports,
        audit_logs=audit_logs,
        agents=agents,
        current_email=current_email,
        report_statuses=REPORT_STATUSES,
        priorities=PRIORITIES,
    )


@app.route("/create_agent", methods=["POST"])
@require_login("admin")
def create_agent():
    new_user = request.form["new_username"].strip()
    new_pass = request.form["new_password"]
    new_email = request.form.get("new_email", "").strip() or None
    hashed_pass = hashlib.sha256(new_pass.encode()).hexdigest()

    try:
        supabase.table("users").insert(
            {
                "username": new_user,
                "password_hash": hashed_pass,
                "role": "agent",
                "email": new_email,
            }
        ).execute()
        log_action(f"Admin provisioned new operative access: {new_user}")
        flash(f"Success: Operative {new_user} provisioned.")
    except Exception as exc:
        print(exc)
        flash("Error: Operative ID may already exist.")

    return redirect("/admin_view")


@app.route("/edit_agent", methods=["POST"])
@require_login("admin")
def edit_agent():
    agent_id = request.form["agent_id"]
    new_username = request.form["username"].strip()
    new_password = request.form.get("password", "")
    new_email = request.form.get("email", "").strip()

    update_data = {"username": new_username, "email": new_email or None}
    if new_password.strip():
        update_data["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()

    try:
        supabase.table("users").update(update_data).eq("id", agent_id).execute()
        log_action(f"Admin updated operative ID: {agent_id}")
        flash("Operative profile updated successfully.")
    except Exception as exc:
        print(exc)
        flash("Error: Username may already be in use.")

    return redirect("/admin_view")


@app.route("/delete_agent/<int:agent_id>", methods=["POST"])
@require_login("admin")
def delete_agent(agent_id):
    supabase.table("users").delete().eq("id", agent_id).execute()
    log_action(f"Admin revoked access and deleted operative ID: {agent_id}")
    flash("Operative access permanently revoked.")
    return redirect("/admin_view")


@app.route("/edit_report", methods=["POST"])
@require_login("admin")
def edit_report():
    report_id = request.form["report_id"]
    new_sector = request.form["sector"]
    new_threat = request.form["threat_level"]
    raw_intel = request.form["intelligence"]
    new_priority = request.form.get("priority", "MEDIUM")

    if new_priority not in PRIORITIES:
        new_priority = "MEDIUM"

    new_encrypted_payload = cipher_suite.encrypt(raw_intel.encode()).decode()
    new_integrity_hash = hashlib.sha256(new_encrypted_payload.encode()).hexdigest()

    update_data = {
        "sector": new_sector,
        "threat_level": new_threat,
        "encrypted_intel": new_encrypted_payload,
        "hash_checksum": new_integrity_hash,
        "priority": new_priority,
        "updated_at": utc_now_iso(),
    }

    try:
        supabase.table("reports").update(update_data).eq("id", report_id).execute()
    except Exception:
        update_data.pop("priority", None)
        update_data.pop("updated_at", None)
        supabase.table("reports").update(update_data).eq("id", report_id).execute()

    log_action(f"Admin updated and re-encrypted report ID: {report_id}")
    flash("Record updated successfully. New encryption keys applied.")
    return redirect("/admin_view")


@app.route("/update_report_status/<int:report_id>", methods=["POST"])
@require_login("admin")
def update_report_status(report_id):
    new_status = request.form.get("status", "OPEN")
    new_priority = request.form.get("priority", "MEDIUM")

    if new_status not in REPORT_STATUSES:
        flash("Invalid report status.")
        return redirect("/admin_view")

    if new_priority not in PRIORITIES:
        new_priority = "MEDIUM"

    update_data = {
        "status": new_status,
        "priority": new_priority,
        "reviewed_by": session["username"],
        "reviewed_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
    }

    try:
        supabase.table("reports").update(update_data).eq("id", report_id).execute()
        log_action(
            f"Admin {session['username']} updated report {report_id} to {new_status} / {new_priority}"
        )
        flash(f"Report updated to {new_status} with {new_priority} priority.")
    except Exception as exc:
        print(exc)
        flash("Status update failed. Run the reports table migration first.")

    return redirect("/admin_view")


@app.route("/delete_report/<int:report_id>", methods=["POST"])
@require_login("admin")
def delete_report(report_id):
    supabase.table("reports").delete().eq("id", report_id).execute()
    log_action(f"Admin manually deleted report ID: {report_id}")
    flash("Record successfully incinerated from database.")
    return redirect("/admin_view")


@app.route("/purge/<int:report_id>", methods=["POST"])
@require_login("admin")
def purge_report(report_id):
    supabase.table("reports").delete().eq("id", report_id).execute()
    log_action(f"SECURITY PURGE: Admin destroyed compromised report ID: {report_id}")
    flash("Compromised Data Purged from System.")
    return redirect("/admin_view")


@app.route("/protocol_zero", methods=["POST"])
@require_login("admin")
def protocol_zero():
    supabase.table("reports").delete().neq("id", 0).execute()
    supabase.table("audit_logs").delete().neq("id", 0).execute()

    log_action("CRITICAL: PROTOCOL ZERO INITIATED. ALL INTELLIGENCE INCINERATED.")
    flash("PROTOCOL ZERO EXECUTED. DATABASE WIPED.")
    return redirect("/admin_view")


@app.route("/api/dashboard_metrics")
@require_login("admin")
def dashboard_metrics():
    reports_response = supabase.table("reports").select("*").execute()
    reports = reports_response.data or []

    metrics = {
        "total_reports": len(reports),
        "open_reports": len([r for r in reports if (r.get("status") or "OPEN") == "OPEN"]),
        "reviewing_reports": len([r for r in reports if r.get("status") == "REVIEWING"]),
        "resolved_reports": len([r for r in reports if r.get("status") == "RESOLVED"]),
        "archived_reports": len([r for r in reports if r.get("status") == "ARCHIVED"]),
        "critical_reports": len([
            r for r in reports
            if r.get("priority") == "CRITICAL" or r.get("threat_level") == "Immediate Support"
        ]),
        "sector_counts": {},
        "priority_counts": {},
    }

    for report in reports:
        sector = report.get("sector") or "Unknown"
        priority = report.get("priority") or "MEDIUM"
        metrics["sector_counts"][sector] = metrics["sector_counts"].get(sector, 0) + 1
        metrics["priority_counts"][priority] = metrics["priority_counts"].get(priority, 0) + 1

    return jsonify(metrics)


@app.route("/export_reports")
@require_login("admin")
def export_reports():
    reports_response = (
        supabase.table("reports")
        .select("*")
        .order("timestamp", desc=True)
        .execute()
    )

    reports = [decrypt_report(report) for report in (reports_response.data or [])]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "ID",
            "Agent",
            "Sector",
            "Threat Level",
            "Workflow Status",
            "Priority",
            "Integrity Status",
            "Decrypted Intel",
            "Attachment",
            "Reviewed By",
            "Reviewed At",
            "Timestamp",
        ]
    )

    for report in reports:
        writer.writerow(
            [
                report.get("id"),
                report.get("agent"),
                report.get("sector"),
                report.get("threat_level"),
                report.get("status", "OPEN"),
                report.get("priority", "MEDIUM"),
                report.get("status_flag"),
                report.get("decrypted_text"),
                report.get("attachment"),
                report.get("reviewed_by"),
                report.get("reviewed_at"),
                report.get("timestamp"),
            ]
        )

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=osiris_reports.csv"
    return response


@app.route("/api/chat", methods=["POST"])
@require_login()
def api_chat():
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()

    if not GEMINI_API_KEY or ai_client is None:
        return jsonify({"reply": "SYSTEM ERROR: AI Core offline. API Key missing."}), 503

    if not user_message:
        return jsonify({"reply": "NO QUERY RECEIVED."}), 400

    try:
        tactical_prompt = (
            "You are OSIRIS, a highly advanced tactical AI assistant for a cybersecurity "
            "command center. Respond concisely, professionally, and with a slightly "
            f"militaristic/cyber tone to the following query. Query: {user_message}"
        )

        response = ai_client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=tactical_prompt,
        )
        return jsonify({"reply": response.text})

    except Exception as exc:
        error_msg = str(exc)
        print(f"❌ CRITICAL AI ERROR: {error_msg}")

        if "429" in error_msg or "quota" in error_msg.lower():
            return jsonify(
                {
                    "reply": "⚠️ SYSTEM ALERT: Comm-link cooling down to prevent tracking. Please wait 15 seconds before next transmission."
                }
            ), 429

        return jsonify({"reply": "CONNECTION FAILED: Neural link severed."}), 500


if __name__ == "__main__":
    app.run(debug=True)
