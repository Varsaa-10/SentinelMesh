"""
SentinelMesh — Authentication Service
Minimal Flask app for Phase 1 scaffolding.
"""

import os
from flask import Flask, jsonify

app = Flask(__name__)

# Database configuration via environment variables
DB_HOST = os.environ.get("DB_HOST", "database")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "sentinelmesh")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "postgres")


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
        "endpoints": ["/", "/health"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
