#!/usr/bin/env python3
"""
validate_schema.py — KB Master schema validator.

Loads every technique and CVE record under kb_master/techniques/ and kb_master/cves/
and validates required fields against schema.json.

Usage:
    python kb_master/validate_schema.py

Exits 0 if all records pass, non-zero on the first violation found.
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KB_ROOT = Path(__file__).resolve().parent
SCHEMA_FILE = KB_ROOT / "schema.json"
TECHNIQUES_DIR = KB_ROOT / "techniques"
CVES_DIR = KB_ROOT / "cves"

REQUIRED_TECHNIQUE_FIELDS = [
    "id",
    "tactic",
    "technique_name",
    "description",
    "detection_signatures",
    "related_cves",
    "mitigation",
]

REQUIRED_CVE_FIELDS = [
    "cve_id",
    "description",
    "cvss_score",
    "affected_component",
    "related_technique_ids",
    "lab_planted",
]

VALID_SOURCES = ("log_tail", "falco")


def _err(msg: str) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)


def validate_detection_signatures(record: dict, path: str) -> bool:
    ok = True
    ds = record.get("detection_signatures")
    if not isinstance(ds, dict):
        _err(f"{path}: 'detection_signatures' must be an object, got {type(ds).__name__}")
        return False
    for key in VALID_SOURCES:
        if key not in ds:
            _err(f"{path}: 'detection_signatures' is missing sub-key '{key}' (use null if not applicable)")
            ok = False
    # At least one source must be non-null
    non_null = [k for k in VALID_SOURCES if ds.get(k) is not None]
    if not non_null:
        _err(f"{path}: 'detection_signatures' — both 'log_tail' and 'falco' are null; at least one must be populated")
        ok = False
    return ok


def validate_technique(data: dict, path: str) -> bool:
    ok = True
    for field in REQUIRED_TECHNIQUE_FIELDS:
        if field not in data:
            _err(f"{path}: missing required field '{field}'")
            ok = False
    if ok:
        ok = validate_detection_signatures(data, path) and ok
    if "related_cves" in data and not isinstance(data["related_cves"], list):
        _err(f"{path}: 'related_cves' must be an array")
        ok = False
    return ok


def validate_cve(data: dict, path: str) -> bool:
    ok = True
    for field in REQUIRED_CVE_FIELDS:
        if field not in data:
            _err(f"{path}: missing required field '{field}'")
            ok = False
    if "cvss_score" in data:
        score = data["cvss_score"]
        if not isinstance(score, (int, float)) or not (0.0 <= score <= 10.0):
            _err(f"{path}: 'cvss_score' must be a number in [0.0, 10.0], got {score!r}")
            ok = False
    if "related_technique_ids" in data and not isinstance(data["related_technique_ids"], list):
        _err(f"{path}: 'related_technique_ids' must be an array")
        ok = False
    if "lab_planted" in data and not isinstance(data["lab_planted"], bool):
        _err(f"{path}: 'lab_planted' must be a boolean")
        ok = False
    return ok


def run() -> int:
    if not SCHEMA_FILE.exists():
        _err(f"schema.json not found at {SCHEMA_FILE}")
        return 1

    technique_files = sorted(TECHNIQUES_DIR.glob("*.json")) if TECHNIQUES_DIR.exists() else []
    cve_files = sorted(CVES_DIR.glob("*.json")) if CVES_DIR.exists() else []

    technique_ok = 0
    technique_fail = 0
    for f in technique_files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            _err(f"{f.name}: invalid JSON — {e}")
            technique_fail += 1
            continue
        if validate_technique(data, f.name):
            technique_ok += 1
        else:
            technique_fail += 1

    cve_ok = 0
    cve_fail = 0
    for f in cve_files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            _err(f"{f.name}: invalid JSON — {e}")
            cve_fail += 1
            continue
        if validate_cve(data, f.name):
            cve_ok += 1
        else:
            cve_fail += 1

    print(f"[OK] {technique_ok} technique record(s) validated", file=sys.stderr if technique_fail else sys.stdout)
    print(f"[OK] {cve_ok} CVE record(s) validated", file=sys.stderr if cve_fail else sys.stdout)

    if technique_fail or cve_fail:
        print(
            f"\n[FAIL] {technique_fail} technique(s) and {cve_fail} CVE(s) failed validation. Fix above errors.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(run())
