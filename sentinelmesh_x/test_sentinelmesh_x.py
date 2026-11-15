import logging
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.falco_cond import parse_condition, score, leaves, eval_leaf
from sentinelmesh_x.knowledge_gen import generate_all, load_falco_rules, load_stock_falco_rules
ROOT = Path(__file__).resolve().parents[1]
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


EXPECTED_STOCK_19 = {
    "Terminal shell in container": "T1059",
    "Search Private Keys or Passwords": "T1552.001",
    "Fileless execution via memfd_create": "T1620",
    "PTRACE attached to process": "T1055.008",
    "Packet socket created in container": "T1557.002",
    "Remove Bulk Data from Disk": "T1485",
    "Execution from /dev/shm": "T1059.004",
    "Schedule Cron Jobs": "T1053.003",
    "Modify Shell Configuration File": "T1546.004",
    "User mgmt binaries": "T1098",
    "Set Setuid or Setgid bit": "T1548.001",
    "Launch Remote File Copy Tools in Container": "T1020",
    "Adding ssh keys to authorized_keys": "T1098.004",
    "Read environment variable from /proc files": "T1083",
    "Launch Suspicious Network Tool in Container": "T1059",
    "Create Hidden Files or Directories": "T1564.001",
    "Decoding Payload in Container": "T1132",
    "Delete or rename shell history": "T1070",
    "Mount Launched in Privileged Container": "T1611",
}


def test_stock_19_falco_rules_parse():
    unknown = []
    dks = load_stock_falco_rules(ROOT / "detection/falco-stock", unknown_leaves=unknown)
    by_name = {d.rule_name: d for d in dks}
    assert unknown == []
    for rname, expected_tech in EXPECTED_STOCK_19.items():
        assert rname in by_name
        dk = by_name[rname]
        assert dk.technique == expected_tech
        assert len(leaves(dk.cond_ast)) > 0
        assert dk.text_plain and dk.text_lexicon


def test_falco_macros_lists_indexed_fields_and_operators():
    lists = {
        "base_procs": ["runc:[0:PARENT]", "sh"],
        "all_procs": ["base_procs", "bash"],
    }
    macros = {
        "spawned_process": "evt.type in (execve, execveat)",
        "container": "container.id != host",
        "good_env": "spawned_process and container",
    }
    cond = (
        "good_env and proc.aname[2] in (all_procs) and proc.apid[3] = 100 "
        'and fd.name pmatch (/etc, /var/log) and proc.args intersects ("-l", "-V") '
        'and evt.buffer bcontains cafebabe and proc.cmdline regex "^/usr/bin/[a-z]+$"'
    )
    ast_ = parse_condition(cond, lists, macros)
    ls = leaves(ast_)
    assert len(ls) == 8
    ev = {
        "evt.type": "execve",
        "container.id": "c1",
        "proc.aname[2]": "runc:[0:PARENT]",
        "proc.apid[3]": "100",
        "fd.name": "/var/log/syslog",
        "proc.args": "-a -l",
        "evt.buffer": b"\xca\xfe\xba\xbe\x00",
        "proc.cmdline": "/usr/bin/python",
    }
    matched, checkable, total = score(ast_, ev)
    assert matched == checkable == total == 8.0
    assert score(ast_, {**ev, "fd.name": "/var/log2/syslog"})[0] == 7.0


def test_falco_cycles_val_unknown_and_registry_precedence(tmp_path, caplog):
    with pytest.raises(ValueError, match="cyclic Falco macro"):
        parse_condition("a and evt.type = execve", macros={"a": "b", "b": "a"})
    with pytest.raises(ValueError, match="cyclic Falco list"):
        parse_condition("proc.name in (l1)", lists={"l1": ["l2"], "l2": ["l1"]})

    unknown = []
    with caplog.at_level(logging.WARNING):
        ast_ = parse_condition(
            "evt.type = execve and proc.ppid = val(proc.pid)",
            rule_name="CheckVal",
            unknown_leaves=unknown,
        )
    ls = leaves(ast_)
    assert len(ls) == 2 and ls[1][2] == "unknown"
    assert eval_leaf(ls[1], {"proc.ppid": 1}) is None
    assert score(ast_, {"evt.type": "execve", "proc.ppid": 1}) == (1.0, 1.0, 2.0)
    assert unknown and unknown[0][0] == "CheckVal" and "val" in unknown[0][1]
    assert any("CheckVal" in r.message and "val" in r.message for r in caplog.records)

    rule_file = tmp_path / "custom.yaml"
    rule_file.write_text(
        "- rule: Custom Rule\n"
        "  desc: test\n"
        "  condition: evt.type = execve\n"
        "  output: out\n"
        "  priority: WARNING\n"
        "  tags: [T1059]\n",
        encoding="utf-8",
    )
    assert load_falco_rules(rule_file)[0].technique == "T1059"
    assert load_falco_rules(rule_file, registry={"Custom Rule": "T1190"})[0].technique == "T1190"
