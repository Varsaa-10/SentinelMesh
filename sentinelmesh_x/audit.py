"""Tamper-evident decision/audit log (hash chain) and decision records (M3 + M6). Redacts secrets before writing."""
from __future__ import annotations
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64
_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|jwt|authorization|api[_-]?key|credential)", re.I)
MAX_FIELD = 512


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _SECRET_KEY.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj[:50]]
    if isinstance(obj, str):
        return obj if len(obj) <= MAX_FIELD else obj[:MAX_FIELD] + f"...[truncated {len(obj) - MAX_FIELD}]"
    return obj


def _h(prev: str, body: Dict[str, Any]) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode()).hexdigest()


class AuditLog:
    """Append-only JSONL. Each line: {seq, ts, prev, body, hash}. Truncation is detectable only against an externally stored head hash/seq."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.seq, self.head = 0, GENESIS
        if self.path.exists() and self.path.stat().st_size:
            ok, info = verify_chain(self.path)
            if not ok:
                raise ValueError(f"existing audit log is corrupt: {info}")
            self.seq, self.head = info["last_seq"], info["head"]

    def append(self, body: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        body = redact(body)
        self.seq += 1
        line = {"seq": self.seq, "ts": ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "prev": self.head, "body": body}
        line["hash"] = _h(self.head, {k: line[k] for k in ("seq", "ts", "body")})
        self.head = line["hash"]
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")
        return line


def verify_chain(path: Path, expected_head: Optional[str] = None, expected_seq: Optional[int] = None):
    prev, seq = GENESIS, 0
    for i, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            line = json.loads(raw)
        except json.JSONDecodeError:
            return False, {"error": "unparseable_line", "line": i}
        if line.get("seq") != seq + 1 or line.get("prev") != prev:
            return False, {"error": "sequence_or_link_broken", "line": i}
        if _h(prev, {k: line[k] for k in ("seq", "ts", "body")}) != line.get("hash"):
            return False, {"error": "hash_mismatch", "line": i}
        prev, seq = line["hash"], line["seq"]
    if expected_head is not None and (prev != expected_head or (expected_seq is not None and seq != expected_seq)):
        return False, {"error": "truncated_or_diverged_from_anchor", "last_seq": seq}
    return True, {"last_seq": seq, "head": prev}


DECISION_SCHEMA = "smx-decision/1"


def decision_record(alert_id: str, kb_version: str, retriever_version: str, predicted: Optional[str], confidence: Optional[float], evidence: List[Dict],
                    rejected: List[Dict], integrity_status: str, route: str, reasons: List[str], action_status: str = "not_requested",
                    human_override: Optional[Dict] = None, correlation_id: Optional[str] = None) -> Dict[str, Any]:
    return {"schema": DECISION_SCHEMA, "alert_id": alert_id, "correlation_id": correlation_id or str(uuid.uuid4()), "knowledge_base_version": kb_version,
            "retriever_version": retriever_version, "predicted_technique": predicted, "confidence": confidence, "evidence": evidence, "rejected_candidates": rejected,
            "integrity_status": integrity_status, "routing_decision": route, "decision_reason": reasons, "action_execution_status": action_status,
            "human_override": human_override}
