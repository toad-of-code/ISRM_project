"""
app.py — Deliberately Vulnerable Student Management System

This application contains INTENTIONAL security vulnerabilities for academic
ISRM (Information Security Risk Management) assessment purposes.

DO NOT deploy this application on any public or production network.

Vulnerabilities embedded:
  V1 — SQL Injection (login, dashboard search)
  V2 — Broken Authentication / Brute Force (no lockout / rate-limit)
  V3 — Insecure File Upload (no validation)
  V4 — Privilege Escalation (role from cookie)
  V5 — Command Injection (admin ping tool)
  V6 — Session Hijacking (predictable session IDs in plaintext cookies)
  V7 — Path Traversal (download endpoint)
  V8 — Information Disclosure (debug=True)
  V9 — Sensitive Data Exposure (plaintext passwords, no logging)
"""

import os
import sqlite3
import subprocess
from datetime import datetime

from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from database import get_connection, init_db

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Weak secret key

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── V6: Predictable session counter ──────────────────────────────
session_counter = 0


def generate_session_id(username):
    """
    VULNERABILITY 6: Generate a predictable session ID.
    Pattern: username_<counter> — trivially guessable.
    """
    global session_counter
    session_counter += 1
    return f"{username}_{session_counter}"


def get_current_user():
    """
    VULNERABILITY 4 & 6: Read identity from plaintext cookies.
    Role is determined entirely by the 'role' cookie value.
    """
    username = request.cookies.get("session_user")
    role = request.cookies.get("role")
    if username and role:
        return {"username": username, "role": role}
    return None


# ──────────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return redirect(url_for("login"))


# ── LOGIN ─────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABILITY 1: SQL Injection — query built with f-string.
    VULNERABILITY 2: No rate-limiting, no lockout, no CAPTCHA.
    VULNERABILITY 6: Predictable session ID set in plaintext cookie.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_connection()
        cursor = conn.cursor()

        # ▼▼▼ V1: SQL INJECTION — concatenated query ▼▼▼
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except sqlite3.OperationalError:
            user = None
        conn.close()

        if user:
            session_id = generate_session_id(user["username"])
            resp = make_response(redirect(url_for("dashboard")))
            # ▼▼▼ V6: Plaintext cookies for session ▼▼▼
            resp.set_cookie("session_id", session_id)
            resp.set_cookie("session_user", user["username"])
            # ▼▼▼ V4: Role stored in plaintext cookie ▼▼▼
            resp.set_cookie("role", user["role"])
            flash("Login successful!", "success")
            return resp
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


# ── SIGNUP ────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    VULNERABILITY 9: Password stored in plaintext.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        full_name = request.form.get("full_name", "")
        roll_number = request.form.get("roll_number", "")
        department = request.form.get("department", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("signup.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html")

        if not full_name or not roll_number or not department:
            flash("Name, Roll Number, and Department are required.", "danger")
            return render_template("signup.html")

        conn = get_connection()
        cursor = conn.cursor()
        try:
            # ▼▼▼ V9: PLAINTEXT password storage ▼▼▼
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, "student"),
            )
            user_id = cursor.lastrowid

            # Create corresponding student record
            cursor.execute(
                "INSERT INTO students (user_id, name, roll_number, department, semester, cgpa) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, full_name, roll_number, department, 1, 0.0),
            )
            conn.commit()
            flash("Account created! Please log in.", "success")
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or Roll Number already exists.", "danger")
        conn.close()

    return render_template("signup.html")


# ── DASHBOARD ─────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    """
    VULNERABILITY 1: SQL Injection in search query.
    VULNERABILITY 4: Role check reads from cookie — manipulable.
    """
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    search_query = request.args.get("search", "")

    if user["role"] == "admin":
        if search_query:
            # ▼▼▼ V1: SQL INJECTION — concatenated search ▼▼▼
            query = (
                f"SELECT * FROM students WHERE name LIKE '%{search_query}%' "
                f"OR roll_number LIKE '%{search_query}%' "
                f"OR department LIKE '%{search_query}%'"
            )
            try:
                cursor.execute(query)
                students = cursor.fetchall()
            except sqlite3.OperationalError:
                students = []
                flash("Search query error.", "danger")
        else:
            cursor.execute("SELECT * FROM students")
            students = cursor.fetchall()
    else:
        # Students see only their own record
        cursor.execute(
            "SELECT * FROM students WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            (user["username"],),
        )
        students = cursor.fetchall()

    conn.close()
    return render_template(
        "dashboard.html", user=user, students=students, search_query=search_query
    )


# ── ADD STUDENT (Admin) ───────────────────────────────────────────
@app.route("/admin/students/add", methods=["GET", "POST"])
def add_student():
    """Admin only: Add a new student record."""
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "")
        roll_number = request.form.get("roll_number", "")
        department = request.form.get("department", "")
        semester = request.form.get("semester", "")
        cgpa = request.form.get("cgpa", "")

        if not all([name, roll_number, department, semester]):
            flash("All fields except CGPA are required.", "danger")
            return render_template("add_student.html", user=user)

        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO students (name, roll_number, department, semester, cgpa) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, roll_number, department, int(semester), float(cgpa) if cgpa else 0.0),
            )
            conn.commit()
            flash(f"Student '{name}' added successfully!", "success")
            conn.close()
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("A student with that roll number already exists.", "danger")
        except (ValueError, Exception) as e:
            flash(f"Error: {str(e)}", "danger")
        conn.close()

    return render_template("add_student.html", user=user)


# ── EDIT STUDENT (Admin) ──────────────────────────────────────────
@app.route("/admin/students/edit/<int:student_id>", methods=["GET", "POST"])
def edit_student(student_id):
    """Admin only: Edit an existing student record."""
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        name = request.form.get("name", "")
        roll_number = request.form.get("roll_number", "")
        department = request.form.get("department", "")
        semester = request.form.get("semester", "")
        cgpa = request.form.get("cgpa", "")

        if not all([name, roll_number, department, semester]):
            flash("All fields except CGPA are required.", "danger")
            cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
            student = cursor.fetchone()
            conn.close()
            return render_template("edit_student.html", user=user, student=student)

        try:
            cursor.execute(
                "UPDATE students SET name = ?, roll_number = ?, department = ?, "
                "semester = ?, cgpa = ? WHERE id = ?",
                (name, roll_number, department, int(semester), float(cgpa) if cgpa else 0.0, student_id),
            )
            conn.commit()
            flash(f"Student '{name}' updated successfully!", "success")
            conn.close()
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("A student with that roll number already exists.", "danger")
        except (ValueError, Exception) as e:
            flash(f"Error: {str(e)}", "danger")
        conn.close()
        return redirect(url_for("edit_student", student_id=student_id))

    cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()
    conn.close()

    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("edit_student.html", user=user, student=student)


# ── DELETE STUDENT (Admin) ────────────────────────────────────────
@app.route("/admin/students/delete/<int:student_id>", methods=["POST"])
def delete_student(student_id):
    """Admin only: Delete a student record."""
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


# ── FILE UPLOAD ───────────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    VULNERABILITY 3: No file extension or MIME type validation.
    Files saved to a publicly accessible directory with original name.
    """
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            # ▼▼▼ V3: NO validation — save with original filename ▼▼▼
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            # Record in database
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO assignments (user_id, filename, upload_date) "
                "VALUES ((SELECT id FROM users WHERE username = ?), ?, ?)",
                (user["username"], file.filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
            conn.close()

            flash(f"File '{file.filename}' uploaded successfully!", "success")
        else:
            flash("No file selected.", "danger")

    # List user's uploaded files
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM assignments WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        (user["username"],),
    )
    assignments = cursor.fetchall()
    conn.close()

    return render_template("upload.html", user=user, assignments=assignments)


# ── FILE DOWNLOAD ─────────────────────────────────────────────────
@app.route("/download")
def download():
    """
    VULNERABILITY 7: Path Traversal — '../' sequences not sanitized.
    """
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    filename = request.args.get("file")

    if filename:
        # ▼▼▼ V7: PATH TRAVERSAL — no sanitization ▼▼▼
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        try:
            return send_file(filepath, as_attachment=True)
        except FileNotFoundError:
            flash("File not found.", "danger")

    # List all files in uploads directory
    files = []
    if os.path.exists(UPLOAD_FOLDER):
        files = os.listdir(UPLOAD_FOLDER)

    return render_template("download.html", user=user, files=files)


# ── ADMIN TOOLS ───────────────────────────────────────────────────
@app.route("/admin/tools", methods=["GET", "POST"])
def admin_tools():
    """
    VULNERABILITY 5: Command Injection — user input passed to os.system().
    VULNERABILITY 4: Role check via cookie only.
    """
    user = get_current_user()
    if not user:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    # ▼▼▼ V4: Role check from cookie — easily manipulable ▼▼▼
    if user["role"] != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    ping_result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        if target:
            try:
                # ▼▼▼ V5: COMMAND INJECTION — unsanitized input ▼▼▼
                result = subprocess.run(
                    f"ping -n 2 {target}" if os.name == "nt" else f"ping -c 2 {target}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                ping_result = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                ping_result = "Command timed out."
            except Exception as e:
                ping_result = str(e)

    return render_template("admin_tools.html", user=user, ping_result=ping_result)


# ── LOGOUT ────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session_id")
    resp.delete_cookie("session_user")
    resp.delete_cookie("role")
    flash("Logged out successfully.", "info")
    return resp


# ── V8: DEBUG MODE — Information Disclosure ───────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
