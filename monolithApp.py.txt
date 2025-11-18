"""
Monolith test app for scanners.

Intentionally includes:
- Multiple dependencies
- Insecure patterns (for SAST)
"""

import os
import sqlite3
import hashlib
import subprocess
import datetime

from typing import Optional, Any

from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import requests
import jwt  # PyJWT


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    DEBUG = True
    # Intentionally hard coded secret for scanner to flag
    SECRET_KEY = "super-insecure-hardcoded-secret"
    DATABASE_URL = "sqlite:///monolith_test.db"
    EXTERNAL_API = "https://httpbin.org/get"


# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, database_url: str):
        # sqlite:///path.db
        self.db_path = database_url.replace("sqlite:///", "")

    def init_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                created_at TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                detail TEXT,
                created_at TEXT
            )
            """
        )

        conn.commit()
        conn.close()

    def execute(self, query: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        conn.close()

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        conn.close()
        return row

    def fetch_all(self, query: str, params: tuple = ()) -> list[tuple]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return rows


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

class UserService:
    """
    User management with intentionally weak password practices for scanner tests.
    """

    def __init__(self, db: Database):
        self.db = db

    def create_user(self, username: str, password: str) -> None:
        # Intentionally weak hashing
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        now = datetime.datetime.utcnow().isoformat()
        self.db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, now),
        )

    def authenticate(self, username: str, password: str) -> bool:
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        row = self.db.fetch_one(
            "SELECT id FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash),
        )
        return row is not None


class ReportService:
    """
    Generates reports by calling the underlying OS.

    Uses subprocess with shell=True, which static analyzers should flag.
    """

    def generate_directory_listing(self, path: str) -> str:
        cmd = "ls -la " + path
        try:
            output = subprocess.check_output(cmd, shell=True)
            return output.decode("utf-8")
        except Exception as exc:
            return f"Error generating report: {exc}"


class ExternalApiService:
    """
    Uses a third party HTTP API.

    Scanners can inspect requests usage, timeouts, error handling, etc.
    """

    def get_status(self) -> dict[str, Any]:
        try:
            resp = requests.get(Config.EXTERNAL_API, timeout=3)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
            }
        except Exception as exc:
            return {"error": str(exc)}


class AuthService:
    """
    JWT based authentication.

    Uses a static secret from Config for scanners to complain about.
    """

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def issue_token(self, username: str) -> str:
        payload = {
            "sub": username,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        }
        # Explicit algorithm, but static key
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token

    def validate_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload
        except Exception:
            return None


class AuditService:
    """
    Simple audit logger stored in the database.
    """

    def __init__(self, db: Database):
        self.db = db

    def log(self, action: str, detail: str) -> None:
        now = datetime.datetime.utcnow().isoformat()
        self.db.execute(
            "INSERT INTO audit_log (action, detail, created_at) VALUES (?, ?, ?)",
            (action, detail, now),
        )


# ---------------------------------------------------------------------------
# Main monolith application
# ---------------------------------------------------------------------------

class MonolithApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config.from_object(Config)

        # Core components
        self.db = Database(Config.DATABASE_URL)
        self.user_service = UserService(self.db)
        self.report_service = ReportService()
        self.external_api = ExternalApiService()
        self.auth_service = AuthService(Config.SECRET_KEY)
        self.audit = AuditService(self.db)

        self._init_app()

    def _init_app(self):
        @self.app.before_first_request
        def init_db():
            self.db.init_schema()

        @self.app.route("/")
        def index():
            return "Monolith test app is running."

        @self.app.route("/register", methods=["GET", "POST"])
        def register():
            if request.method == "GET":
                html = """
                <h1>Register</h1>
                <form method="post">
                  <input name="username" placeholder="username" />
                  <input name="password" type="password" placeholder="password" />
                  <button type="submit">Register</button>
                </form>
                """
                return render_template_string(html)

            username = request.form.get("username")
            password = request.form.get("password")
            if not username or not password:
                return "Missing username or password", 400

            try:
                self.user_service.create_user(username, password)
                self.audit.log("register", f"User {username} registered")
                return redirect(url_for("login"))
            except Exception as exc:
                self.audit.log("register_error", str(exc))
                return f"Error creating user: {exc}", 500

        @self.app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "GET":
                html = """
                <h1>Login</h1>
                <form method="post">
                  <input name="username" placeholder="username" />
                  <input name="password" type="password" placeholder="password" />
                  <button type="submit">Login</button>
                </form>
                """
                return render_template_string(html)

            username = request.form.get("username")
            password = request.form.get("password")

            if self.user_service.authenticate(username, password):
                token = self.auth_service.issue_token(username)
                self.audit.log("login", f"User {username} logged in")
                return jsonify({"token": token})
            else:
                self.audit.log("login_failed", f"User {username} failed login")
                return "Invalid credentials", 401

        @self.app.route("/report")
        def report():
            # Example: /report?path=/tmp
            path = request.args.get("path", ".")
            self.audit.log("report_request", f"path={path}")
            listing = self.report_service.generate_directory_listing(path)
            return "<pre>{}</pre>".format(listing)

        @self.app.route("/status")
        def status():
            status_info = self.external_api.get_status()
            self.audit.log("status_check", "External API status checked")
            return jsonify(status_info)

        @self.app.route("/hello")
        def hello():
            name = request.args.get("name", "world")
            html = """
            <h1>Hello {{ name }}</h1>
            <p>This is a monolith style test endpoint.</p>
            """
            return render_template_string(html, name=name)

        @self.app.route("/audit")
        def audit_view():
            rows = self.db.fetch_all(
                "SELECT action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 20"
            )
            lines = ["{} | {} | {}".format(a, d, c) for (a, d, c) in rows]
            return "<pre>{}</pre>".format("\n".join(lines))


def create_app() -> Flask:
    monolith = MonolithApp()
    return monolith.app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
