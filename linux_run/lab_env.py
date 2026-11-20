"""Shared Python loader for active SentinelMesh environment profiles (.env / env/E1.env)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional, Union

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ENV: Dict[str, str] = {
    "ENV_ID": "E1",
    "COMPOSE_PROJECT_NAME": "sentinelmesh",
    "CONTAINER_PREFIX": "sentinelmesh",
    "LAB_NET_NAME": "sentinelmesh_net",
    "WEBAPP_CONTAINER": "sentinelmesh-webapp",
    "AUTHSERVICE_CONTAINER": "sentinelmesh-authservice",
    "DATABASE_CONTAINER": "sentinelmesh-database",
    "LOGCOLLECTOR_CONTAINER": "sentinelmesh-logcollector",
    "DASHBOARD_CONTAINER": "sentinelmesh-dashboard",
    "PROXY_CONTAINER": "sentinelmesh-proxy",
    "NGROK_CONTAINER": "sentinelmesh-ngrok",
    "DEBUG_CONTAINER": "sentinelmesh-debug",
    "WEBAPP_PORT": "5000",
    "AUTHSERVICE_PORT": "5001",
    "POSTGRES_PORT": "5432",
    "GRAFANA_PORT": "3000",
    "FLUENTD_PORT": "24224",
    "LOG_DIR": "/var/log/sentinelmesh",
    "DB_NAME": "sentinelmesh",
    "DB_USER": "postgres",
    "DB_PASS": "postgres",
    "JWT_SECRET": "sentinelmesh-secret-key",
    "TEST_USER": "testuser",
    "TEST_PASS": "testpass",
    "AUTH_DEFAULT_USER": "admin",
    "AUTH_DEFAULT_PASS": "admin123",
    "GRAFANA_ADMIN_USER": "admin",
    "GRAFANA_ADMIN_PASS": "admin",
}

_MANIFEST_PREFIX_RE = re.compile(
    r"^(?:container_prefix:\s*|CONTAINER_PREFIX=)(.+?)\s*$"
)


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse KEY=VALUE pairs from a .env file in order, ignoring comments/blanks."""
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key:
            values[key] = val
    return values


def resolve_active_env_file(repo_root: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Return the active env file path: root .env if present, else env/E1.env."""
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    dot_env = root / ".env"
    if dot_env.exists():
        return dot_env
    e1_env = root / "env" / "E1.env"
    if e1_env.exists():
        return e1_env
    return None


def load_lab_env(
    repo_root: Optional[Union[str, Path]] = None,
    env_file: Optional[Union[str, Path]] = None,
) -> Dict[str, str]:
    """Return active environment values merged over E1 defaults."""
    env = dict(DEFAULT_ENV)
    target = Path(env_file) if env_file is not None else resolve_active_env_file(repo_root)
    if target is not None:
        env.update(parse_env_file(target))
    prefix = env["CONTAINER_PREFIX"]
    env.setdefault("COMPOSE_PROJECT_NAME", prefix)
    env.setdefault("LAB_NET_NAME", f"{prefix}_net")
    env["WEBAPP_URL"] = f"http://127.0.0.1:{env['WEBAPP_PORT']}"
    env["AUTHSERVICE_URL"] = f"http://127.0.0.1:{env['AUTHSERVICE_PORT']}"
    env["GRAFANA_URL"] = f"http://127.0.0.1:{env['GRAFANA_PORT']}"
    return env


def read_prefix_from_manifest(
    manifest_or_run_dir: Optional[Union[str, Path]],
    default: str = "sentinelmesh",
) -> str:
    """Read CONTAINER_PREFIX / container_prefix from run_manifest.txt, else return default."""
    if manifest_or_run_dir is None:
        return default
    p = Path(manifest_or_run_dir)
    if p.is_dir():
        p = p / "run_manifest.txt"
    if not p.exists():
        return default
    for line in p.read_text(encoding="utf-8").splitlines():
        m = _MANIFEST_PREFIX_RE.match(line.strip())
        if m and m.group(1):
            return m.group(1).strip()
    return default
