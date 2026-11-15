import copy, json, sys, base64
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.integrity import *
from sentinelmesh_x.audit import AuditLog, verify_chain, redact, decision_record

@pytest.fixture()
def kb(tmp_path):
    recs = [{"id": f"T{i}", "description": f"desc {i} é", "detection_signatures": {"falco": {"rule_name": f"r{i}"}}} for i in range(20)]
    priv, pub = generate_dev_keypair(tmp_path / "keys"); sk, pk = load_private(priv), load_public(pub)
    return recs, sk, pk, build_signed_manifest(recs, sk, "t", 1), tmp_path

def fails(res): return {k for k, _ in res.failures}
def test_clean_passes_and_canonicalisation_is_order_and_unicode_stable(kb):
    recs, sk, pk, m, _ = kb; assert verify_kb(recs, m, pk).ok
    shuffled = [dict(reversed(list(r.items()))) for r in reversed(recs)]; assert verify_kb(shuffled, m, pk).ok
    nfd = copy.deepcopy(recs); nfd[0]["description"] = "desc 0 e\u0301"; assert verify_kb(nfd, m, pk).ok         # equivalent unicode forms hash the same
def test_description_and_rule_modification(kb):
    recs, sk, pk, m, _ = kb
    a = copy.deepcopy(recs); a[3]["description"] += " "; assert fails(verify_kb(a, m, pk)) == {"record_modified"}
    b = copy.deepcopy(recs); b[4]["detection_signatures"]["falco"]["rule_name"] = "evil"; assert "record_modified" in fails(verify_kb(b, m, pk))
def test_replacement_deletion_insertion_duplicate(kb):
    recs, sk, pk, m, _ = kb
    r = copy.deepcopy(recs); r[1] = {**copy.deepcopy(r[2]), "id": "T1"}; assert "record_modified" in fails(verify_kb(r, m, pk))
    assert fails(verify_kb(recs[:-1], m, pk)) == {"record_missing", "count_mismatch"} or "record_missing" in fails(verify_kb(recs[:-1], m, pk))
    assert "record_unexpected" in fails(verify_kb(recs + [{"id": "TX", "description": "new"}], m, pk))
    assert "duplicate_record_id" in fails(verify_kb(recs + [recs[0]], m, pk))
def test_manifest_and_signature_modification_and_wrong_key(kb):
    recs, sk, pk, m, tmp = kb
    m2 = copy.deepcopy(m); m2["manifest"]["records"]["T0"] = "0" * 64; assert fails(verify_kb(recs, m2, pk)) == {"signature_invalid"}
    m3 = copy.deepcopy(m); s = bytearray(base64.b64decode(m3["signature_b64"])); s[0] ^= 1; m3["signature_b64"] = base64.b64encode(bytes(s)).decode(); assert fails(verify_kb(recs, m3, pk)) == {"signature_invalid"}
    m4 = copy.deepcopy(m); m4["manifest"]["version"] = 99; assert fails(verify_kb(recs, m4, pk)) == {"signature_invalid"}
    _, other_pub = generate_dev_keypair(tmp / "other"); assert fails(verify_kb(recs, m, load_public(other_pub))) == {"signature_invalid"}
    assert fails(verify_kb(recs, {"manifest": m["manifest"], "signature_b64": "!!"}, pk)) == {"manifest_malformed"}
    assert not verify_kb(recs, {"nope": 1}, pk).ok
def test_rollback_fork_and_chain(kb):
    recs, sk, pk, m1, tmp = kb
    r1 = verify_kb(recs, m1, pk); st = tmp / "state.json"; commit_state(st, r1)
    recs2 = recs + [{"id": "T99", "description": "v2"}]; m2 = build_signed_manifest(recs2, sk, "t", 2, manifest_sha256(m1))
    r2 = verify_kb(recs2, m2, pk, load_state(st)); assert r2.ok; commit_state(st, r2)
    assert fails(verify_kb(recs, m1, pk, load_state(st))) == {"rollback"}                                  # old, validly signed KB replayed
    fork = build_signed_manifest(recs2[:-1] + [{"id": "T98", "description": "x"}], sk, "t", 2, manifest_sha256(m1)); assert "fork_same_version" in fails(verify_kb(recs2[:-1] + [{"id": "T98", "description": "x"}], fork, pk, load_state(st)))
    skip = build_signed_manifest(recs2, sk, "t", 3, "f" * 64); assert "chain_break" in fails(verify_kb(recs2, skip, pk, load_state(st)))
    with pytest.raises(ValueError): commit_state(st, verify_kb(recs, m1, pk, load_state(st)))              # never commit a failed verification
def test_strict_loader_raises_and_audits(kb):
    recs, sk, pk_obj, m, tmp = kb
    d = tmp / "kb"; d.mkdir()
    for r in recs: (d / f"{r['id']}.json").write_text(json.dumps(r))
    (tmp / "m.json").write_text(json.dumps(m)); pubp = tmp / "keys" / "kb-dev.public.pem"; log = AuditLog(tmp / "a.jsonl")
    assert len(load_verified_kb(d, tmp / "m.json", pubp, tmp / "s.json", log)) == 20
    (d / "T5.json").write_text(json.dumps({**recs[5], "description": "tampered"}))
    with pytest.raises(IntegrityError): load_verified_kb(d, tmp / "m.json", pubp, tmp / "s2.json", log)
    ok, info = verify_chain(tmp / "a.jsonl"); assert ok and info["last_seq"] == 2
def test_private_key_mode_and_outside_kb(kb):
    recs, sk, pk, m, tmp = kb; p = tmp / "keys" / "kb-dev.private.pem"; assert oct(p.stat().st_mode & 0o777) == "0o600"; assert b"PRIVATE" not in json.dumps(m).encode()
def test_audit_chain_detects_edit_delete_reorder_truncate(tmp_path):
    p = tmp_path / "a.jsonl"; log = AuditLog(p)
    for i in range(5): log.append({"i": i, "password": "hunter2", "note": "x" * 2000})
    ok, info = verify_chain(p); assert ok; head, seq = info["head"], info["last_seq"]
    assert "hunter2" not in p.read_text() and "[REDACTED]" in p.read_text() and "truncated" in p.read_text()
    lines = p.read_text().splitlines()
    for mut in (lambda L: [L[0].replace('"i": 0', '"i": 9')] + L[1:], lambda L: L[:2] + L[3:], lambda L: [L[1], L[0]] + L[2:]):
        q = tmp_path / "m.jsonl"; q.write_text("\n".join(mut(lines)) + "\n"); assert not verify_chain(q)[0]
    q = tmp_path / "t.jsonl"; q.write_text("\n".join(lines[:3]) + "\n"); assert verify_chain(q)[0] and not verify_chain(q, head, seq)[0]   # truncation needs the external anchor
def test_decision_record_schema_and_redaction():
    r = decision_record("a1", "1", "DAHR-1", "T1110", .9, [{"field": "x"}], [], "verified", "analyst", ["low_calibrated_confidence"])
    assert r["schema"] == "smx-decision/1" and r["routing_decision"] == "analyst" and redact({"jwt": "eyJ", "ok": 1}) == {"jwt": "[REDACTED]", "ok": 1}
