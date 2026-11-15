import sys, json
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import importlib.util
_spec = importlib.util.spec_from_file_location("smx_experiments_common", Path(__file__).resolve().parent / "experiments" / "common.py")   # path import: avoids clashing with detection/log-tail/common.py
_c = importlib.util.module_from_spec(_spec); sys.modules["smx_experiments_common"] = _c; _spec.loader.exec_module(_c)
make_index, alert_sets, build_query, targets, ground_truth, DAHRConfig = _c.make_index, _c.alert_sets, _c.build_query, _c.targets, _c.ground_truth, _c.DAHRConfig
from sentinelmesh_x.pipeline import SafePipeline
from sentinelmesh_x.safety import PolicyEngine, PolicyConfig, SafeExecutor
from sentinelmesh_x.audit import AuditLog, verify_chain

class Cal:                                                    # stand-in calibrator
    def __init__(self, p): self.p = p
    def predict(self, X): import numpy as np; return np.array([self.p] * len(X))

@pytest.fixture(scope="module")
def ix(): return make_index("corpus_36", "auto")
def mk(ix, tmp_path, p=0.99, integrity=True, index=True):
    gt = ground_truth(); sev = {v["technique_id"]: v["severity"] for k, v in gt.items() if k != "S10"}
    return SafePipeline(ix if index else None, DAHRConfig(), Cal(p), PolicyEngine(PolicyConfig(tau=0.5)), AuditLog(tmp_path / "a.jsonl"), "kb-1.0.0", integrity, sorted(targets()), sev,
                        {"webapp": 3, "authservice": 4, "database": 5}, lambda a: build_query(a, "raw"), SafeExecutor(kill_switch=True))
def alert(): return alert_sets()["test"][0]["alert"]

def test_record_is_complete_and_chain_verifies(ix, tmp_path):
    pl = mk(ix, tmp_path); r = pl.process(alert(), "al-1")
    for k in ("alert_id", "correlation_id", "knowledge_base_version", "retriever_version", "predicted_technique", "confidence", "evidence", "rejected_candidates", "integrity_status", "routing_decision", "decision_reason", "action_execution_status", "human_override"): assert k in r
    assert r["integrity_status"] == "verified" and len(r["rejected_candidates"]) == 5 and any(e.get("tier") for e in r["evidence"]) and verify_chain(tmp_path / "a.jsonl")[0]
def test_decision_can_be_reconstructed_from_log(ix, tmp_path):
    pl = mk(ix, tmp_path); pl.process(alert(), "al-7"); line = json.loads((tmp_path / "a.jsonl").read_text().splitlines()[-1])["body"]
    assert line["alert_id"] == "al-7" and line["routing_decision"] in ("auto", "analyst", "admin") and line["knowledge_base_version"] == "kb-1.0.0" and "decision_reason" in line
def test_secrets_are_not_logged(ix, tmp_path):
    a = alert(); a["event"]["password"] = "hunter2"; a["event"]["jwt"] = "eyJabc"; pl = mk(ix, tmp_path)
    r = pl.process(a, "al-2"); assert "hunter2" not in (tmp_path / "a.jsonl").read_text() and "eyJabc" not in (tmp_path / "a.jsonl").read_text()
def test_retrieval_failure_fails_closed_and_is_logged(ix, tmp_path):
    r = mk(ix, tmp_path, index=False).process(alert(), "al-3")
    assert r["routing_decision"] != "auto" and "retrieval_unavailable_or_failed" in r["decision_reason"] and r["action_execution_status"].startswith("not_executed") and r["abstained"]
    assert "retrieval_failure" in (tmp_path / "a.jsonl").read_text()
def test_integrity_failure_blocks_automatic_action(ix, tmp_path):
    r = mk(ix, tmp_path, integrity=False).process(alert(), "al-4"); assert r["integrity_status"] == "FAILED" and "knowledge_integrity_failure" in r["decision_reason"] and r["routing_decision"] != "auto"
def test_destructive_action_never_executes_without_approval(ix, tmp_path):
    pl = mk(ix, tmp_path); r = pl.process(alert(), "al-5", "kill_container"); assert "destructive_action_needs_human_approval" in r["action_execution_status"]
    r2 = pl.process(alert(), "al-6", "kill_container", human_approval={"approver": "a", "ticket": "T1"}); assert r2["action_execution_status"].startswith("not_executed") and r2["human_override"]["approver"] == "a"
    assert all(not e.executed for e in pl.exec.log)
