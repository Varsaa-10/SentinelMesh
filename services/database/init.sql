-- SentinelMesh Lab Database Initialization
-- Creates the base schema for webapp and authservice

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed a test user for basic connectivity verification
INSERT INTO users (username, password, role)
VALUES ('testuser', 'testpass', 'user')
ON CONFLICT (username) DO NOTHING;
