import sys, yaml
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.external import SigmaRule, Unsupported
def R(det, tags=("attack.t1547.001",)): return SigmaRule({"title": "t", "tags": list(tags), "detection": det})
REG = {"selection": {"Image|endswith": "\\reg.exe", "CommandLine|contains|all": ["reg", " add "], "CommandLine|contains": ["CurrentVersion\\Run"]}, "condition": "selection"}
def test_fires_and_not_fires_and_unknown_is_not_a_match():
    r = R(REG); assert r.fires({"Image": "C:\\x\\REG.exe", "CommandLine": "reg add HKCU\\...\\CurrentVersion\\Run /v a"})
    assert not r.fires({"Image": "C:\\x\\reg.exe", "CommandLine": "reg query foo"})
    assert r.evaluate({"CommandLine": "reg add x\\CurrentVersion\\Run"}) is None and not r.fires({"CommandLine": "reg add x\\CurrentVersion\\Run"})   # Image unknown -> unknown, never fires
def test_boolean_conditions_and_filters():
    r = R({"a": {"CommandLine|contains": "x"}, "f": {"Image|endswith": "\\ok.exe"}, "condition": "a and not f"})
    assert r.fires({"CommandLine": "x", "Image": "c:\\bad.exe"}) and not r.fires({"CommandLine": "x", "Image": "c:\\ok.exe"})
    assert R({"s1": {"CommandLine|contains": "x"}, "s2": {"CommandLine|contains": "y"}, "condition": "1 of s*"}).fires({"CommandLine": "y"})
    assert not R({"s1": {"CommandLine|contains": "x"}, "s2": {"CommandLine|contains": "y"}, "condition": "all of s*"}).fires({"CommandLine": "y"})
    assert R({"s": [{"CommandLine|startswith": "a"}, {"CommandLine|startswith": "b"}], "condition": "s"}).fires({"CommandLine": "bz"})
    assert R({"s": {"CommandLine|re": "^p[a-z]+$"}, "condition": "s"}).fires({"CommandLine": "pow"})
def test_unsupported_constructs_are_reported_not_silently_accepted():
    for det in ({"s": {"CommandLine|base64offset|contains": "x"}, "condition": "s"}, {"s": ["keyword"], "condition": "s"}, {"s": {"A": 1}, "condition": "s | count() > 3"}, {"s": {"A": 1}, "condition": "t"}):
        with pytest.raises(Unsupported): R(det)
