"""M3: cryptographic knowledge-base integrity (SHA-256 record hashes + Ed25519-signed manifest + rollback protection).

SCOPE: this detects modification of the KB AFTER it was signed (records changed, removed, inserted, replaced; manifest or signature edited;
old signed KB replayed). It does NOT detect semantic poisoning introduced BEFORE signing (a poisoned source that is then signed verifies fine);
that is a different problem measured separately.
KEY MANAGEMENT: `generate_dev_keypair` writes a private key to a directory OUTSIDE the KB with mode 0600. This is a LOCAL DEVELOPMENT mode.
Production would need an HSM/KMS or offline signing ceremony, key rotation and revocation, none of which exist here.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REC_DOMAIN, MAN_DOMAIN, SCHEMA = b"SMX-REC-v1\x00", b"SMX-MAN-v1\x00", "smx-kb-manifest/1"


class IntegrityError(Exception):
    def __init__(self, failures):
        super().__init__("knowledge base verification failed: " + "; ".join(f"{k}:{v}" for k, v in failures))
        self.failures = failures


def _norm(o: Any) -> Any:
    if isinstance(o, str):
        return unicodedata.normalize("NFC", o)
    if isinstance(o, dict):
        return {unicodedata.normalize("NFC", str(k)): _norm(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_norm(x) for x in o]
    return o


def canonical(o: Any) -> bytes:
    """Deterministic UTF-8 JSON: NFC strings, sorted keys, no insignificant whitespace."""
    return json.dumps(_norm(o), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def record_hash(rec: Dict[str, Any]) -> str:
    return hashlib.sha256(REC_DOMAIN + canonical(rec)).hexdigest()


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_dev_keypair(key_dir: Path, name: str = "kb-dev") -> Tuple[Path, Path]:
    key_dir = Path(key_dir); key_dir.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    priv, pub = key_dir / f"{name}.private.pem", key_dir / f"{name}.public.pem"
    priv.write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(priv, 0o600)
    pub.write_bytes(sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def load_private(p: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(p).read_bytes(), None)


def load_public(p: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(p).read_bytes())


def build_signed_manifest(records: Sequence[Dict[str, Any]], private_key: Ed25519PrivateKey, kb_name: str, version: int, prev_manifest_sha256: str = "0" * 64,
                          created_utc: Optional[str] = None, signing_mode: str = "local-dev") -> Dict[str, Any]:
    ids = [r["id"] for r in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate record ids")
    man = {"schema": SCHEMA, "kb_name": kb_name, "version": int(version), "created_utc": created_utc or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "prev_manifest_sha256": prev_manifest_sha256, "signing_mode": signing_mode, "record_count": len(ids),
           "records": {r["id"]: record_hash(r) for r in records}, "key_id": key_id(private_key.public_key())}
    sig = private_key.sign(MAN_DOMAIN + canonical(man))
    return {"manifest": man, "signature_b64": base64.b64encode(sig).decode()}


def manifest_sha256(signed: Dict[str, Any]) -> str:
    return hashlib.sha256(MAN_DOMAIN + canonical(signed["manifest"])).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    failures: List[Tuple[str, str]] = field(default_factory=list)
    version: Optional[int] = None
    manifest_sha256: Optional[str] = None


def verify_kb(records: Sequence[Dict[str, Any]], signed: Dict[str, Any], public_key: Ed25519PublicKey, trusted_state: Optional[Dict[str, Any]] = None) -> VerifyResult:
    """trusted_state = {"max_version": int, "manifest_sha256": str} stored OUTSIDE the KB; None = first use (no rollback check possible)."""
    f: List[Tuple[str, str]] = []
    try:
        man, sig = signed["manifest"], base64.b64decode(signed["signature_b64"], validate=True)
        if man.get("schema") != SCHEMA:
            return VerifyResult(False, [("bad_schema", str(man.get("schema")))])
    except Exception as e:                                           # malformed manifest/signature encoding
        return VerifyResult(False, [("manifest_malformed", type(e).__name__)])
    try:
        public_key.verify(sig, MAN_DOMAIN + canonical(man))
    except InvalidSignature:
        return VerifyResult(False, [("signature_invalid", "manifest edited, signature edited, or signed by a different key")])
    if man.get("key_id") != key_id(public_key):
        f.append(("wrong_key_id", str(man.get("key_id"))))
    seen: Dict[str, str] = {}
    for r in records:
        rid = r.get("id")
        if rid in seen:
            f.append(("duplicate_record_id", str(rid))); continue
        seen[rid] = record_hash(r)
    exp = man["records"]
    f += [("record_missing", i) for i in sorted(set(exp) - set(seen))]
    f += [("record_unexpected", i) for i in sorted(set(seen) - set(exp))]
    f += [("record_modified", i) for i in sorted(set(seen) & set(exp)) if seen[i] != exp[i]]
    if man.get("record_count") != len(exp):
        f.append(("count_mismatch", str(man.get("record_count"))))
    msha = manifest_sha256(signed)
    if trusted_state:
        mv = man["version"]
        if mv < trusted_state["max_version"]:
            f.append(("rollback", f"version {mv} < last accepted {trusted_state['max_version']}"))
        elif mv == trusted_state["max_version"] and msha != trusted_state["manifest_sha256"]:
            f.append(("fork_same_version", f"version {mv}"))
        elif mv > trusted_state["max_version"] and man["prev_manifest_sha256"] != trusted_state["manifest_sha256"]:
            f.append(("chain_break", "prev_manifest_sha256 does not match the last accepted manifest"))
    return VerifyResult(not f, f, man["version"], msha)


def commit_state(state_path: Path, res: VerifyResult) -> None:
    """Persist the accepted version/hash (outside the KB). Only call after a successful verification."""
    if not res.ok:
        raise ValueError("refusing to commit state of a failed verification")
    Path(state_path).write_text(json.dumps({"max_version": res.version, "manifest_sha256": res.manifest_sha256}))


def load_state(state_path: Path) -> Optional[Dict[str, Any]]:
    p = Path(state_path)
    return json.loads(p.read_text()) if p.exists() else None


def load_verified_kb(kb_dir: Path, manifest_path: Path, public_key_path: Path, state_path: Path, audit=None) -> List[Dict[str, Any]]:
    """Strict loader: verification failure raises IntegrityError and nothing is returned (never silently accepted)."""
    recs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(kb_dir).glob("*.json"))]
    res = verify_kb(recs, json.loads(Path(manifest_path).read_text()), load_public(public_key_path), load_state(state_path))
    if audit is not None:
        audit.append({"event": "kb_verification", "ok": res.ok, "failures": res.failures, "version": res.version})
    if not res.ok:
        raise IntegrityError(res.failures)
    commit_state(state_path, res)
    return recs
