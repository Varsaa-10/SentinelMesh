# SentinelMesh Lab Reset Script (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=== SentinelMesh Lab Reset ===" -ForegroundColor Cyan

# Tear down everything, including volumes and orphans
Write-Host "Tearing down existing containers and volumes..." -ForegroundColor Yellow
docker compose down -v --remove-orphans

# Rebuild all images from scratch (no cache)
Write-Host "Rebuilding container images (no cache)..." -ForegroundColor Yellow
docker compose build --no-cache

# Start all services
Write-Host "Starting services..." -ForegroundColor Yellow
docker compose up -d

# Wait for health checks
Write-Host "Waiting for services to become healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Verify service health
Write-Host "Checking service status..." -ForegroundColor Green
docker compose ps

Write-Host "=== Lab reset complete ===" -ForegroundColor Cyan
