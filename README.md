Secure Login System

A Flask-based secure authentication system built for the cybersecurity internship task.

Features


User registration & login with bcrypt password hashing
Server-side input validation (username format, email format, password strength)
Parameterized SQL queries throughout — prevents SQL injection
Session-based authentication with secure cookie flags and logout
Account lockout after 5 failed login attempts (10-minute lockout)
CSRF protection on all forms (Flask-WTF)
Session regenerated on login to prevent session fixation


Setup

bashpip install -r requirements.txt
python app.py

App runs at http://127.0.0.1:5000

Notes


Uses SQLite (users.db, auto-created on first run).
For production: set SESSION_COOKIE_SECURE = True and serve over HTTPS.
Optional 2FA (TOTP) was intentionally left out of this build per scope — can be added later with pyotp.


Files


app.py — Flask app (routes, auth logic, DB)
templates/ — Jinja2 templates (register, login, dashboard, base)
