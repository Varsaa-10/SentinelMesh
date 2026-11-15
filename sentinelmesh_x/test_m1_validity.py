import random, sys
from pathlib import Path
import numpy as np, pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.track_b import *
from sentinelmesh_x.retrieval import Components, DAHRConfig
from sentinelmesh_x import tuning, calib_eval
from sentinelmesh_x.calibration import brier

ALERT = {"title": "Sensitive credential file read", "scenario": "S9", "source": "falco", "event": {"fd.name": "/etc/shadow", "proc.name": "cat", "evt.time": 1, "container.id": "x"}}
PH = forbidden_phrases(["Sensitive credential file read"], ["Unauthorized DB connection (source=%fd.rip)"])

# ---------------- leakage ----------------
def test_clean_query_passes():
    q = build_independent_query(ALERT); assert_query_clean(q, PH); assert "title" not in q and "S9" not in q

@pytest.mark.parametrize("bad", ["Sensitive credential file read. fd.name=/etc/shadow", "fd.name=/etc/shadow T1003.008", "scenario S9 fd.name=x", "failure_count=5", "Unauthorized DB connection fd.rip=1"])
def test_track_b_rejects_leaked_queries(bad):
    with pytest.raises(LeakageError): assert_query_clean(bad, PH)

def test_track_b_rejects_identity_keys():
    with pytest.raises(LeakageError): assert_alert_clean(ALERT)                      # raw alert carries title/scenario
    assert_alert_clean(independent_alert(ALERT))
    a = independent_alert(ALERT); a["event"]["failure_count"] = 5
    with pytest.raises(LeakageError): assert_alert_clean(a)

def test_sanitiser_drops_identity_and_noise():
    a = independent_alert({**ALERT, "event": {**ALERT["event"], "failure_count": 5, "window_seconds": 30}})
    assert set(a) == {"source", "event"} and set(a["event"]) == {"fd.name", "proc.name"}

def test_kb_leak_detected():
    base = [{"id": "T1", "description": "d", "detection_signatures": {"falco": {"rule_name": "x"}}}]
    assert_kb_clean(base, base)
    inj = [{"id": "T1", "description": "d", "detection_signatures": {"falco": {"rule_name": "x", "generated": True}}}]
    with pytest.raises(LeakageError): assert_kb_clean(inj, base)
    inj2 = [{"id": "T1", "description": "d + lab words", "detection_signatures": {"falco": {"rule_name": "x"}}}]
    with pytest.raises(LeakageError): assert_kb_clean(inj2, base)

# ---------------- nested tuning ----------------
def _fake(run, truth, n=6, seed=0):
    r = np.random.default_rng(seed)
    ids = [f"T{i}" for i in range(n)]
    return (run, truth, Components(r.random(n), r.random(n), np.zeros(n), {2: r.random(n), 3: r.random(n), 5: r.random(n)}, 0.0, 0.5, 0.2, 1.0, ids))

def _examples():
    return [_fake(f"c{c}", f"T{(c + k) % 6}", seed=100 * c + k) for c in range(4) for k in range(8)]

def test_held_out_capture_never_reaches_selector():
    seen = []
    def spy(train, grid=None):
        seen.append({e[0] for e in train}); return DAHRConfig(use_field=False), {}
    res = tuning.nested_loco(_examples(), selector=spy)
    for r, s in zip(res, seen): assert r["held_out_capture"] not in s and len(s) == 3

def test_selection_is_invariant_to_heldout_data():
    ex = _examples(); grid = tuning.candidate_grid(False)[:40]
    train = [e for e in ex if e[0] != "c0"]
    a, _ = tuning.select_config(train, grid)
    altered = train + [_fake("c0", "T0", seed=999)]                       # what must NOT be used: anything from c0
    b, _ = tuning.select_config([e for e in altered if e[0] != "c0"], grid)
    assert a == b

def test_selector_only_sees_given_examples():
    ex = _examples(); grid = tuning.candidate_grid(False)[:40]
    tr = [e for e in ex if e[0] in ("c1", "c2")]
    _, info = tuning.select_config(tr, grid); assert info["train_captures"] == ["c1", "c2"]

# ---------------- calibration evaluation ----------------
def _rows(n_alerts=10, per=4):
    return [{"original_alert_id": f"r{a // 5}|a{a}", "run": f"r{a // 5}", "pert": "p", "form": f"f{k}", "cond": "c"} for a in range(n_alerts) for k in range(per)]

def test_split_integrity_ok_and_failures():
    calib_eval.check_split_integrity(_rows(), ["r0"], ["r1"])
    with pytest.raises(AssertionError): calib_eval.check_split_integrity(_rows(), ["r0"], ["r0"])                 # contamination
    with pytest.raises(AssertionError): calib_eval.check_split_integrity(_rows() + _rows()[:1], ["r0"], ["r1"])      # duplicate observation
    bad = _rows(); bad[0]["run"] = "r1"
    with pytest.raises(AssertionError): calib_eval.check_split_integrity(bad, ["x"], ["y"])                        # id spans captures

def test_bootstrap_resamples_whole_clusters():
    rows = _rows(); idx = calib_eval.clusters_index([r["original_alert_id"] for r in rows])
    rng = np.random.default_rng(1)
    for _ in range(50):
        s = calib_eval.draw_cluster_sample(idx, rng)
        counts = {k: int(np.isin(v, s).all()) for k, v in idx.items()}
        for k, v in idx.items():                                    # a drawn cluster is present with ALL of its rows, or not at all
            present = np.isin(v, s)
            assert present.all() or not present.any()

def test_cluster_ci_wider_than_row_ci_for_correlated_rows():
    rng = np.random.default_rng(0); n = 60
    base = rng.random(n); p = np.repeat(base, 20); y = np.repeat((rng.random(n) < base).astype(int), 20)    # rows within a cluster identical -> strongly dependent
    ids = np.repeat(np.arange(n), 20)
    c = calib_eval.cluster_bootstrap(p, y, ids, brier, b=400)
    r = calib_eval.cluster_bootstrap(p, y, np.arange(len(p)), brier, b=400)
    assert (c["ci95"][1] - c["ci95"][0]) > (r["ci95"][1] - r["ci95"][0])
