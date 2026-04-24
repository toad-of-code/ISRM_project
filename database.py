"""
database.py — Initialize SQLite database and seed with dummy data.

VULNERABILITY 9: Passwords stored in PLAINTEXT (no hashing).
No logging for any database transactions.
"""

import sqlite3
import os

DB_NAME = "student_mgmt.db"


def get_db_path():
    """Return the absolute path to the database file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)


def get_connection():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed data."""
    conn = get_connection()
    cursor = conn.cursor()

    # ── Create Tables ──────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            roll_number TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL,
            semester INTEGER,
            cgpa REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            upload_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── Only seed if the database is fresh (no users exist) ─────────
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        # ── Seed Users (PLAINTEXT passwords — V9) ─────────────────────
        users = [
            ("admin", "admin123", "admin"),
            ("student1", "password1", "student"),
            ("student2", "password2", "student"),
            ("student3", "password3", "student"),
            ("student4", "password4", "student"),
            ("student5", "password5", "student"),
        ]

        for username, password, role in users:
            try:
                cursor.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, password, role),
                )
            except sqlite3.IntegrityError:
                pass  # User already exists

        # ── Seed Student Records ──────────────────────────────────────
        student_records = [
            (2, "Aarav Sharma", "CS2023001", "Computer Science", 4, 8.7),
            (3, "Priya Patel", "CS2023002", "Computer Science", 4, 9.1),
            (4, "Rohan Gupta", "EC2023001", "Electronics", 3, 7.8),
            (5, "Sneha Reddy", "ME2023001", "Mechanical", 5, 8.3),
            (6, "Vikram Singh", "IT2023001", "Information Technology", 2, 7.5),
        ]

        for user_id, name, roll, dept, sem, cgpa in student_records:
            try:
                cursor.execute(
                    "INSERT INTO students (user_id, name, roll_number, department, semester, cgpa) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, name, roll, dept, sem, cgpa),
                )
            except sqlite3.IntegrityError:
                pass  # Record already exists

        print(f"[+] Seeded {len(users)} users and {len(student_records)} student records.")
    else:
        print(f"[*] Database already has {user_count} users — skipping seed.")

    conn.commit()
    conn.close()
    print(f"[+] Database initialized: {get_db_path()}")


if __name__ == "__main__":
    init_db()
