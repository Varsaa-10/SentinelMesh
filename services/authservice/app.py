"""
SentinelMesh — Authentication Service
Flask app with deliberately planted vulnerabilities:
  - Default/weak credentials: admin / admin123 (CWE-798)
  - Vulnerable PyJWT dependency: PyJWT==1.7.1, CVE-2022-29217 (CWE-327)
"""

import os
import psycopg2
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# JWT secret — hardcoded intentionally for lab
JWT_SECRET = "sentinelmesh-secret-key"

# Database configuration via environment variables
DB_HOST = os.environ.get("DB_HOST", "database")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "sentinelmesh")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")


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
    """Health check endpoint — verifies the auth service is running."""
    return jsonify({
        "service": "authservice",
        "status": "healthy",
    }), 200


@app.route("/", methods=["GET"])
def index():
    """Root endpoint."""
    return jsonify({
        "service": "SentinelMesh AuthService",
        "version": "0.1.0",
        "endpoints": ["/", "/health", "/auth/login", "/auth/verify"],
    })


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """
    Authentication login endpoint.
    Returns a JWT token on valid credentials.

    VULNERABLE — INTENTIONAL FOR LAB
    Vulnerability (CWE-798): Default Credentials
      - The database is seeded with admin / admin123.
      - This endpoint happily authenticates those credentials and returns
        a JWT signed with the vulnerable PyJWT library.
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
        cur.execute(
            "SELECT id, username, role FROM users WHERE username = %s AND password = %s",
            (username, password),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            payload = {
                "user_id": row[0],
                "username": row[1],
                "role": row[2],
            }
            # Sign with the vulnerable PyJWT 1.7.1
            # Note: PyJWT 1.7.1 returns bytes, decode to str for JSON
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode("utf-8")
            return jsonify({
                "status": "success",
                "token": token,
            }), 200
        else:
            return jsonify({
                "status": "failure",
                "message": "Invalid credentials",
            }), 401

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """
    Token verification endpoint.

    VULNERABLE — INTENTIONAL FOR LAB
    Vulnerability (CWE-327 / CVE-2022-29217): Algorithm Confusion
      - PyJWT 1.7.1 does not enforce the `algorithms` parameter properly.
      - The `algorithms` kwarg is intentionally omitted, allowing an attacker
        to supply a token signed with an unexpected algorithm (e.g., 'none').
    """
    data = request.get_json(silent=True)
    if not data or "token" not in data:
        return jsonify({"error": "token required"}), 400

    token = data["token"]

    try:
        # VULNERABLE — no algorithms restriction, PyJWT 1.7.1 allows 'none'
        decoded = jwt.decode(token, JWT_SECRET)
        return jsonify({
            "status": "valid",
            "payload": decoded,
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"status": "expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({
            "status": "invalid",
            "message": str(e),
        }), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
