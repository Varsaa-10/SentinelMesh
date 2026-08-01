"""
SentinelMesh — Web Application Service
Minimal Flask app for Phase 1 scaffolding.
"""

import os
import psycopg2
from flask import Flask, jsonify

app = Flask(__name__)

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
        "endpoints": ["/", "/health"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
