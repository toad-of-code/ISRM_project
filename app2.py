"""
app.py — Secured Student Management System (Phase 7 Implemented)

Vulnerabilities Patched:
  V1 — SQL Injection: Fixed using parameterized queries (?).
  V2 — Broken Auth: Fixed using Werkzeug password hashing and in-memory IP lockout.
  V3 — Insecure Upload: Fixed by restricting extensions and using secure_filename().
  V4 & V6 — Session/Privilege Issues: Fixed by utilizing Flask's cryptographically signed sessions.
  V5 — Command Injection: Fixed using strict Regex validation for IPs/hostnames.
  V7 — Path Traversal: Fixed using secure_filename() on the download parameter.
  V8 — Info Disclosure: debug=False applied.
  V9 — Sensitive Data: Passwords are now hashed using pbkdf2:sha256.
"""

import os
import sqlite3
import subprocess  # nosec B404 - used for a bounded admin ping utility
import logging
import re
import secrets
from datetime import datetime
from time import time

from flask import (
    Flask, flash, make_response, redirect, render_template,
    request, send_file, url_for, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from database import get_connection, init_db

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv'}
ALLOWED_MIMETYPES = {
    "text/plain",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "text/csv",
    "application/vnd.ms-excel",
}
ALLOWED_DEPARTMENTS = {
    "Computer Science",
    "Electronics",
    "Mechanical",
    "Information Technology",
    "Civil",
    "Electrical",
}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── LOGGING CONFIGURATION ─────────────────────────────────────────
logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class ClientIPFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "clientip"):
            record.clientip = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(ClientIPFilter())

# ── IN-MEMORY RATE LIMITING (Basic Lockout) ───────────────────────
failed_login_attempts = {}
LOCKOUT_TIME = 300  # 5 minutes in seconds
MAX_ATTEMPTS = 5

def check_rate_limit(ip_address):
    current_time = time()
    record = failed_login_attempts.get(ip_address, {'attempts': 0, 'lockout_until': 0})
    
    if current_time < record['lockout_until']:
        return False  # Still locked out
        
    return True

def record_failed_login(ip_address):
    current_time = time()
    record = failed_login_attempts.get(ip_address, {'attempts': 0, 'lockout_until': 0})
    
    # Reset if the lockout period has passed
    if current_time > record['lockout_until'] and record['attempts'] >= MAX_ATTEMPTS:
        record['attempts'] = 0
        
    record['attempts'] += 1
    
    if record['attempts'] >= MAX_ATTEMPTS:
        record['lockout_until'] = current_time + LOCKOUT_TIME
        logging.warning(f"IP LOCKED OUT due to multiple failed logins.", extra={'clientip': ip_address})
        
    failed_login_attempts[ip_address] = record

# ── HELPER FUNCTIONS ──────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_name(value):
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z\s.'-]{1,79}", value.strip()))


def is_valid_identifier(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{4,32}", value.strip()))


def is_valid_department(value):
    return value in ALLOWED_DEPARTMENTS


def is_valid_semester(value):
    return value.isdigit() and 1 <= int(value) <= 8


def is_valid_cgpa(value):
    if value == "":
        return True
    try:
        cgpa = float(value)
    except ValueError:
        return False
    return 0.0 <= cgpa <= 10.0


def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one digit."
    return True, "OK"


def validate_student_payload(name, roll_number, department, semester, cgpa=""):
    if not is_valid_name(name):
        return False, "Enter a valid student name."
    if not is_valid_identifier(roll_number):
        return False, "Enter a valid roll number."
    if not is_valid_department(department):
        return False, "Select a valid department."
    if not is_valid_semester(semester):
        return False, "Semester must be between 1 and 8."
    if not is_valid_cgpa(cgpa):
        return False, "CGPA must be between 0 and 10."
    return True, "OK"


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.before_request
def enforce_csrf_token():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = session.get("_csrf_token")
        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not token or not submitted_token or submitted_token != token:
            flash("Invalid or missing CSRF token.", "danger")
            return redirect(request.referrer or url_for("login"))


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net"
    )
    if request.is_secure or os.environ.get("ENABLE_HSTS", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash("File too large. Maximum upload size is 5 MB.", "danger")
    user = get_current_user()
    if user:
        return render_template("upload.html", user=user, assignments=[]), 413
    return redirect(url_for("login")), 413

def get_current_user():
    # V4 & V6 FIX: Using Flask's cryptographically signed session instead of plaintext cookies
    if "username" in session and "role" in session:
        return {"username": session["username"], "role": session["role"]}
    return None

# ──────────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip_address = request.remote_addr
    
    if request.method == "POST":
        if not check_rate_limit(ip_address):
            flash("Too many failed attempts. Try again in 5 minutes.", "danger")
            return render_template("login.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_connection()
        cursor = conn.cursor()

        # V1 FIX: Parameterized query to prevent SQL Injection
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # V2 & V9 FIX: Secure password verification
        if user and check_password_hash(user["password"], password):
            session.clear() # Prevent session fixation
            session.permanent = True
            session["username"] = user["username"]
            session["role"] = user["role"]
            
            logging.info(f"Successful login for user: {username}", extra={'clientip': ip_address})
            # Reset failed attempts on success
            if ip_address in failed_login_attempts:
                del failed_login_attempts[ip_address]
                
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            record_failed_login(ip_address)
            logging.warning(f"Failed login attempt for username: {username}", extra={'clientip': ip_address})
            flash("Invalid username or password.", "danger")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        full_name = request.form.get("full_name", "")
        roll_number = request.form.get("roll_number", "")
        department = request.form.get("department", "")

        if not all([username, password, full_name, roll_number, department]):
            flash("All fields are required.", "danger")
            return render_template("signup.html")

        if not is_valid_identifier(username):
            flash("Username must be 4-32 characters and use letters, numbers, underscores, or hyphens.", "danger")
            return render_template("signup.html")

        if not is_valid_name(full_name):
            flash("Enter a valid full name.", "danger")
            return render_template("signup.html")

        if not is_valid_identifier(roll_number):
            flash("Enter a valid roll number.", "danger")
            return render_template("signup.html")

        if not is_valid_department(department):
            flash("Select a valid department.", "danger")
            return render_template("signup.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html")

        password_ok, password_message = validate_password_strength(password)
        if not password_ok:
            flash(password_message, "danger")
            return render_template("signup.html")

        # V9 FIX: Hash the password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, "student"),
            )
            user_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO students (user_id, name, roll_number, department, semester, cgpa) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, full_name, roll_number, department, 1, 0.0),
            )
            conn.commit()
            logging.info(f"New account created for: {username}", extra={'clientip': request.remote_addr})
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or Roll Number already exists.", "danger")
        finally:
            conn.close()

    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    search_query = request.args.get("search", "")
    if len(search_query) > 100:
        search_query = search_query[:100]

    if user["role"] == "admin":
        if search_query:
            # V1 FIX: Parameterized search query
            query = (
                "SELECT * FROM students WHERE name LIKE ? OR roll_number LIKE ? OR department LIKE ?"
            )
            search_pattern = f"%{search_query}%"
            cursor.execute(query, (search_pattern, search_pattern, search_pattern))
            students = cursor.fetchall()
        else:
            cursor.execute("SELECT * FROM students")
            students = cursor.fetchall()
    else:
        cursor.execute(
            "SELECT * FROM students WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            (user["username"],),
        )
        students = cursor.fetchall()

    conn.close()
    return render_template("dashboard.html", user=user, students=students, search_query=search_query)

@app.route("/admin/students/add", methods=["GET", "POST"])
def add_student():
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_number = request.form.get("roll_number", "").strip()
        department = request.form.get("department", "").strip()
        semester = request.form.get("semester", "").strip()
        cgpa = request.form.get("cgpa", "").strip()

        valid, message = validate_student_payload(name, roll_number, department, semester, cgpa)
        if not valid:
            flash(message, "danger")
            return render_template("add_student.html", user=user)

        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO students (name, roll_number, department, semester, cgpa) VALUES (?, ?, ?, ?, ?)",
                (name, roll_number, department, int(semester), float(cgpa) if cgpa else 0.0),
            )
            conn.commit()
            flash(f"Student '{name}' added successfully!", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("A student with that roll number already exists.", "danger")
        finally:
            conn.close()

    return render_template("add_student.html", user=user)


@app.route("/admin/students/edit/<int:student_id>", methods=["GET", "POST"])
def edit_student(student_id):
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()

    if not student:
        conn.close()
        flash("Student not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_number = request.form.get("roll_number", "").strip()
        department = request.form.get("department", "").strip()
        semester = request.form.get("semester", "").strip()
        cgpa = request.form.get("cgpa", "").strip()

        valid, message = validate_student_payload(name, roll_number, department, semester, cgpa)
        if not valid:
            flash(message, "danger")
            conn.close()
            return render_template("edit_student.html", user=user, student=student)

        try:
            cursor.execute(
                "UPDATE students SET name = ?, roll_number = ?, department = ?, semester = ?, cgpa = ? WHERE id = ?",
                (name, roll_number, department, int(semester), float(cgpa) if cgpa else 0.0, student_id),
            )
            conn.commit()
            flash(f"Student '{name}' updated successfully!", "success")
            conn.close()
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("A student with that roll number already exists.", "danger")
        finally:
            conn.close()

    conn.close()
    return render_template("edit_student.html", user=user, student=student)


@app.route("/admin/students/delete/<int:student_id>", methods=["POST"])
def delete_student(student_id):
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()
    if student:
        cursor.execute("DELETE FROM students WHERE id = ?", (student_id,))
        conn.commit()
        flash(f"Student '{student['name']}' deleted successfully.", "success")
    else:
        flash("Student not found.", "danger")
    conn.close()
    return redirect(url_for("dashboard"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            # V3 FIX: Validate extension, MIME type, and sanitize filename
            if allowed_file(file.filename) and file.mimetype in ALLOWED_MIMETYPES:
                filename = secure_filename(file.filename)
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                file.save(filepath)

                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO assignments (user_id, filename, upload_date) VALUES ((SELECT id FROM users WHERE username = ?), ?, ?)",
                    (user["username"], filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
                conn.commit()
                conn.close()
                
                logging.info(f"File uploaded: {filename} by {user['username']}", extra={'clientip': request.remote_addr})
                flash("File uploaded successfully!", "success")
            else:
                logging.warning(f"Malicious upload attempt rejected by {user['username']}", extra={'clientip': request.remote_addr})
                flash("Invalid file type.", "danger")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT filename, upload_date FROM assignments WHERE user_id = (SELECT id FROM users WHERE username = ?) ORDER BY upload_date DESC",
        (user["username"],),
    )
    assignments = cursor.fetchall()
    conn.close()
    return render_template("upload.html", user=user, assignments=assignments)

@app.route("/download")
def download():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    filename = request.args.get("file")
    if filename:
        # V7 FIX: secure_filename strips out path traversal characters like '../'
        safe_filename = secure_filename(filename)
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        
        if os.path.exists(filepath) and os.path.isfile(filepath):
            logging.info(f"File downloaded: {safe_filename} by {user['username']}", extra={'clientip': request.remote_addr})
            return send_file(filepath, as_attachment=True)
        else:
            flash("File not found.", "danger")

    return render_template("download.html", user=user, files=os.listdir(UPLOAD_FOLDER) if os.path.exists(UPLOAD_FOLDER) else [])

@app.route("/admin/tools", methods=["GET", "POST"])
def admin_tools():
    user = get_current_user()
    if not user or user["role"] != "admin":
        logging.warning(f"Unauthorized admin tool access attempt", extra={'clientip': request.remote_addr})
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    ping_result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        if target:
            # V5 FIX: Strict input validation for IP addresses or basic hostnames
            # Prevents command injection like "8.8.8.8 & rm -rf /"
            if not re.match(r"^[a-zA-Z0-9.-]+$", target):
                logging.warning(f"Command injection attempt detected from {user['username']}. Payload: {target}", extra={'clientip': request.remote_addr})
                flash("Invalid target format.", "danger")
                return render_template("admin_tools.html", user=user, ping_result=None)

            try:
                # Removed shell=True and passed arguments as a list for safety
                command = ["ping", "-n", "2", target] if os.name == "nt" else ["ping", "-c", "2", target]
                result = subprocess.run(  # nosec B603 - arguments are validated and shell=False is implicit
                    command,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                ping_result = result.stdout + result.stderr
                logging.info(f"Admin pinged target: {target}", extra={'clientip': request.remote_addr})
            except Exception as e:
                ping_result = "Execution failed."

    return render_template("admin_tools.html", user=user, ping_result=ping_result)

@app.route("/logout")
def logout():
    session.clear() # Secure logout
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    # V8 FIX: Debug mode turned off for production simulation
    app.run(debug=False, host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"), port=5000)