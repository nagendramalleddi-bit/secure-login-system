"""
Secure Login System
--------------------
Features:
- User registration & login with bcrypt password hashing
- Input validation (server-side) to prevent malformed/malicious input
- Parameterized SQL queries (prevents SQL injection)
- Session-based authentication with logout
- Basic rate-limit-style lockout after repeated failed logins
"""

import sqlite3
import re
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect

def init_db():
    conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# In production behind HTTPS, also set: app.config["SESSION_COOKIE_SECURE"] = True

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def validate_password_strength(password: str):
    """Returns (is_valid, message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if "user_id" in session else redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # --- Input validation ---
        if not USERNAME_RE.match(username):
            flash("Username must be 3-30 characters: letters, numbers, underscore only.", "danger")
            return render_template("register.html")
        if not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        valid, msg = validate_password_strength(password)
        if not valid:
            flash(msg, "danger")
            return render_template("register.html")

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = get_db()
        try:
            # Parameterized query -- prevents SQL injection
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, datetime.utcnow().isoformat()),
            )
            conn.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        # Parameterized query -- prevents SQL injection
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            conn.close()
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        # Check lockout
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                conn.close()
                flash(
                    f"Account locked due to repeated failed attempts. Try again after {locked_until.strftime('%H:%M:%S')} UTC.",
                    "danger",
                )
                return render_template("login.html")

        if bcrypt.check_password_hash(user["password_hash"], password):
            # Successful login: reset failed attempts, regenerate session
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()

            session.clear()  # prevent session fixation
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.", "danger")
            else:
                flash("Invalid username or password.", "danger")

            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            conn.commit()
            conn.close()

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


with app.app_context():
    init_db()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
