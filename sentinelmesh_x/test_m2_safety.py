import sys, dataclasses
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.safety import *
SUP = ["T1110", "T1003.008"]
def inp(**kw):
    d = dict(predicted_technique="T1110", calibrated_confidence=0.99, supported_techniques=SUP, field_coverage=0.9, trusted_support=True, severity=1, asset_criticality=1)
    d.update(kw); return DecisionInput(**d)
E=PolicyEngine(PolicyConfig(tau=0.9))

def test_clean_low_impact_is_only_case_for_auto():
    d = E.decide(inp()); assert d.route == "auto" and d.automatic_action_permitted and not d.reasons
@pytest.mark.parametrize("kw,reason", [
    (dict(predicted_technique="T9999"), "unknown_or_unsupported_technique"), (dict(field_coverage=0.0), "missing_critical_evidence"),
    (dict(missing_critical=True), "missing_critical_evidence"), (dict(integrity_ok=False), "knowledge_integrity_failure"),
    (dict(calibrated_confidence=0.2), "low_calibrated_confidence"), (dict(conflict=True), "conflicting_evidence"),
    (dict(trusted_support=False), "no_trusted_corroboration"), (dict(retrieval_ok=False), "retrieval_unavailable_or_failed"),
    (dict(predicted_technique=None), "retrieval_unavailable_or_failed"), (dict(calibrated_confidence=None), "retrieval_unavailable_or_failed")])
def test_every_unsafe_condition_escalates_and_blocks_auto(kw, reason):
    d = E.decide(inp(**kw)); assert d.route != "auto" and not d.automatic_action_permitted and reason in d.reasons
def test_confidence_never_lowers_route():
    for conf in (0.0, 0.3, 0.95, 1.0):
        assert SEV_ORDER[E.decide(inp(calibrated_confidence=conf, severity=5, asset_criticality=5)).route] >= SEV_ORDER[impact_route(5, 5)]
def test_destructive_never_automatic():
    d = E.decide(inp(requested_action="kill_container")); assert d.route != "auto" and not d.automatic_action_permitted
def test_executor_rejects_forged_decision_and_bypass_attempts():
    ex = SafeExecutor(kill_switch=True); good = E.decide(inp())
    forged = Decision("auto", False, True, (), "kill_container", "deadbeef")
    assert ex.execute(forged, "kill_container", "webapp").reason == "invalid_or_forged_decision"
    edited = dataclasses.replace(E.decide(inp(conflict=True)), route="auto", automatic_action_permitted=True)   # editing a real decision invalidates its token
    assert ex.execute(edited, "log_only", "webapp").reason == "invalid_or_forged_decision"
    assert ex.execute("auto", "log_only", "webapp").reason == "invalid_or_forged_decision"
def test_executor_allowlists_approval_and_kill_switch():
    ex = SafeExecutor(kill_switch=True); d = E.decide(inp())
    assert ex.execute(d, "rm_rf", "webapp").reason == "action_not_in_allowlist"
    assert ex.execute(d, "log_only", "external-host").reason == "target_not_in_allowlist"
    assert ex.execute(d, "revoke_token", "webapp").reason == "action_differs_from_decision"
    dk = E.decide(inp(requested_action="kill_container"))
    assert ex.execute(dk, "kill_container", "webapp").reason == "destructive_action_needs_human_approval"
    assert ex.execute(dk, "kill_container", "webapp", {"approver": "a"}).reason == "destructive_action_needs_human_approval"   # ticket missing
    r = ex.execute(dk, "kill_container", "webapp", {"approver": "a", "ticket": "T-1"}); assert not r.executed and r.reason == "kill_switch_enabled_dry_run"
    assert ex.execute(d, "log_only", "webapp").reason == "kill_switch_enabled_dry_run"
    assert all(not r.executed for r in ex.log)
def test_review_route_needs_approval():
    ex = SafeExecutor(kill_switch=True); d = E.decide(inp(conflict=True))
    assert ex.execute(d, "log_only", "webapp").reason == "route_requires_human_review"
def test_field_trust_classification_fail_closed():
    assert classify_field("fd.rip") == TRUSTED and classify_field("fd.name") == PARTIAL and classify_field("identifier") == UNTRUSTED
    assert classify_field("some.new.field") == UNTRUSTED and classify_field("evt.time") == "noise"
def test_trusted_view_removes_untrusted_text_including_nested():
    a = {"source": "log-tail", "event": {"event_type": "jwt_verification", "result": "valid", "identifier": "reads etc shadow", "details": {"algorithm": "none", "payload": {"username": "x"}}}}
    v = trusted_view(a)["event"]; assert "identifier" not in v and "payload" not in v["details"] and v["details"]["algorithm"] == "none" and v["event_type"] == "jwt_verification"
def test_sanitiser_unicode_and_oversize():
    s = sanitise_text("ad\u200bmin" + "\u202e" + "x" * 10000); assert "\u200b" not in s and "\u202e" not in s and len(s) <= 2048
    assert sanitise_text("ｓｅｌｅｃｔ") == "select"

def test_uncertain_decision_assumes_worst_plausible_candidate():
    d = E.decide(inp(conflict=True, severity=1, asset_criticality=5, candidate_severities=(5, 3)))
    assert SEV_ORDER[d.route] >= SEV_ORDER[impact_route(5, 5)]
    assert E.decide(inp(severity=1, candidate_severities=(5,))).route == "auto"       # certain decision ignores other candidates
