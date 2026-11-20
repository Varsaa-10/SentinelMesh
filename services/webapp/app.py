"""
SentinelMesh — Web Application Service
Flask app with deliberately planted vulnerabilities:
  - SQL Injection in /login (CWE-89)
  - Missing Rate Limiting on /login (CWE-307)
"""

import os
import json
from datetime import datetime, timezone
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

# Database configuration via environment variables
DB_HOST = os.environ.get("DB_HOST", "database")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "sentinelmesh")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")

# Log file configuration for Detection module tailer
LOG_DIR = os.environ.get("LOG_DIR", "/var/log/sentinelmesh")
LOG_FILE = os.path.join(LOG_DIR, "webapp_events.log")


def log_security_event(event_type, result, identifier, details=None):
    """Emit a structured JSON-lines log entry per security event."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "webapp",
        "event_type": event_type,
        "result": result,
        "identifier": identifier,
        "client_ip": request.remote_addr if request else "unknown",
        "details": details or {},
    }
    line = json.dumps(event) + "\n"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        print(f"[LOG ERROR] {e}: {line.strip()}")


def get_db_connection():
    """Create a new database connection."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint — verifies the app is running and DB is reachable."""
    status = {"service": "webapp", "status": "healthy"}
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        status["database"] = "connected"
    except Exception as e:
        status["database"] = f"unreachable: {e}"
        status["status"] = "degraded"
    return jsonify(status), 200


@app.route("/", methods=["GET"])
def index():
    """Root endpoint."""
    return jsonify({
        "service": "SentinelMesh WebApp",
        "version": "0.1.0",
        "endpoints": ["/", "/health", "/login"],
    })


@app.route("/login", methods=["POST"])
def login():
    """
    Login endpoint.

    VULNERABLE — INTENTIONAL FOR LAB
    Vulnerability 1 (CWE-89): SQL Injection
      - User-supplied username and password are interpolated directly into
        a raw SQL query with no parameterization or sanitization.
      - Example payload: username = "admin' OR 1=1 --"

    Vulnerability 2 (CWE-307): Missing Rate Limiting
      - No throttle, no CAPTCHA, no account lockout.
      - Unlimited login attempts per second from any source.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # VULNERABLE — raw SQL string concatenation, no parameterized query
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        cur.execute(query)

        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            log_security_event("login_attempt", "success", username, {"authenticated_user_id": row[0], "role": row[2]})
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "user": {
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                },
            }), 200
        else:
            log_security_event("login_attempt", "failure", username)
            return jsonify({
                "status": "failure",
                "message": "Invalid credentials",
            }), 401

    except Exception as e:
        log_security_event("login_attempt", "failure", username, {"error": str(e)})
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
