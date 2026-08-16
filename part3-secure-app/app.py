"""
Flask REST API — Secure Application (Remediated)
Capstone Part 3 — Secure Application Development and Applied Cryptography

This application demonstrates security remediations for:
- SQL Injection → Parameterised queries
- Broken Access Control → Authentication middleware on /admin
- Insecure Password Storage → Bcrypt hashing with unique salts
- Hardcoded Secrets → Environment variable management with python-dotenv
"""

import os
import sqlite3
import functools
from flask import Flask, request, jsonify, g
from dotenv import load_dotenv
from hash_password import hash_password, verify_password

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# ============================================================
# SECRET MANAGEMENT — Loaded from environment variables
# ============================================================
# REMEDIATED: All secrets are loaded from environment variables
# instead of being hardcoded in source code.
DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")
SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

if not SECRET_KEY or not ADMIN_API_KEY:
    raise RuntimeError(
        "Missing required environment variables: SECRET_KEY and ADMIN_API_KEY. "
        "Copy .env.example to .env and fill in the values."
    )

app.config["SECRET_KEY"] = SECRET_KEY


# ============================================================
# DATABASE SETUP
# ============================================================
def get_db():
    """Get a database connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the database connection at the end of each request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialise the database with the users table."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()


# ============================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================
def require_admin_api_key(f):
    """
    REMEDIATED (Broken Access Control):
    Authentication middleware that verifies the API key before
    granting access to the /admin endpoint.

    The admin endpoint was previously unprotected — any user could
    access it without authentication. This decorator requires a
    valid API key in the X-API-Key header.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        if api_key != ADMIN_API_KEY:
            return jsonify({"error": "Invalid API key"}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# ROUTES
# ============================================================

@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    REMEDIATED (SQL Injection):
    Uses parameterised queries (? placeholders) instead of string
    concatenation to prevent SQL injection attacks.

    REMEDIATED (Insecure Password Storage):
    Uses Bcrypt with unique salts instead of unsalted MD5.
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"]
    password = data["password"]

    # Validate input length
    if len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be 3-50 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Hash the password using Bcrypt (with unique salt)
    password_hash = hash_password(password)

    db = get_db()
    try:
        # REMEDIATED: Parameterised query prevents SQL injection
        # The ? placeholders ensure user input is treated as data, not SQL code
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        db.commit()
        return jsonify({"message": f"User '{username}' registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409


@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user.

    REMEDIATED (SQL Injection):
    Uses parameterised queries instead of string concatenation.

    REMEDIATED (Insecure Password Storage):
    Verifies password against Bcrypt hash instead of comparing MD5.
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"]
    password = data["password"]

    db = get_db()
    # REMEDIATED: Parameterised query prevents SQL injection
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        # Use generic error message to prevent username enumeration
        return jsonify({"error": "Invalid username or password"}), 401

    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "message": "Login successful",
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }), 200


@app.route("/admin", methods=["GET"])
@require_admin_api_key  # REMEDIATED: Admin route now requires authentication
def admin_dashboard():
    """
    Admin endpoint — lists all registered users.

    REMEDIATED (Broken Access Control):
    Previously this endpoint had NO authentication — any user could
    access the admin panel. Now requires a valid X-API-Key header
    verified by the require_admin_api_key middleware.
    """
    db = get_db()
    users = db.execute("SELECT id, username, role, created_at FROM users").fetchall()
    return jsonify({
        "users": [dict(u) for u in users],
        "total_users": len(users)
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "healthy"}), 200


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Debug mode is controlled via environment variable — never hardcoded as True in production
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
