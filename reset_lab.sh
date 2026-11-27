#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
# shellcheck source=linux_run/lab_env.sh
. "$ROOT/linux_run/lab_env.sh"

echo "=== SentinelMesh Lab Reset (${ENV_ID}, project=${COMPOSE_PROJECT_NAME}) ==="

# Tear down everything, including volumes and orphans
echo "Tearing down existing containers and volumes..."
docker compose down -v --remove-orphans

# Rebuild all images from scratch (no cache)
echo "Rebuilding container images (no cache)..."
docker compose build --no-cache

# Pre-pull pinned helper images used by attack scripts (S5, S29) so no pull happens mid-window
S5_HELPER_IMAGE="postgres:15-alpine@sha256:23799e521dee9265a8b388ecf3bc0f1eaa34b95be67f5a76af4f8f6adb44c720"
S29_DEBUG_IMAGE="alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
echo "Pre-pulling attack helper images..."
for img in "$S5_HELPER_IMAGE" "$S29_DEBUG_IMAGE"; do
    docker pull "$img"
done

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
