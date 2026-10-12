#!/usr/bin/env bash
set -euo pipefail

echo "=== SentinelMesh Lab Reset ==="

# Tear down everything, including volumes and orphans
echo "Tearing down existing containers and volumes..."
docker compose down -v --remove-orphans

# Rebuild all images from scratch (no cache)
echo "Rebuilding container images (no cache)..."
docker compose build --no-cache

# Start all services
echo "Starting services..."
docker compose up -d

# Wait for health checks
echo "Waiting for services to become healthy..."
sleep 15

# Verify service health
echo "Checking service status..."
docker compose ps

echo "=== Lab reset complete ==="
