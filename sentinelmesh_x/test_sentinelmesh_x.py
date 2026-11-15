import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.falco_cond import parse_condition, score, leaves
from sentinelmesh_x.knowledge_gen import generate_all
from sentinelmesh_x.calibration import brier, ece
ROOT = Path(__file__).resolve().parents[1]

def test_falco_condition_three_valued():
    n = parse_condition('evt.type = connect and not fd.sip in (lst)', {"lst": ["1.1.1.1"]})
    assert score(n, {"fd.sip": "9.9.9.9"})[0] == 1.0       # evt.type unknown, negated list matches
    assert score(n, {"fd.sip": "1.1.1.1"})[0] == 0.0       # contradicts

def test_generator_covers_all_detectors():
    dks = generate_all(ROOT)
    assert len(dks) == 9 and {d.kind for d in dks} == {"falco", "log_tail"}
    assert all(d.technique and d.text_plain for d in dks)
    s2 = next(d for d in dks if d.detector_id.startswith("scenario2"))
    assert s2.thresholds["count"] == 5 and s2.thresholds["window_seconds"] == 30

def test_calibration_metrics():
    assert brier([1, 0], [1, 0]) == 0.0 and ece([1.0, 0.0], [1, 0]) == 0.0
