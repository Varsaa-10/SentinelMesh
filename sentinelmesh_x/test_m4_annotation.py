import sys, csv
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelmesh_x.annotation import *
def test_cohen_known_values():
    assert cohens_kappa(list("aabb"), list("aabb")) == 1.0
    assert abs(cohens_kappa(["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15, ["y"] * 25 + ["n"] * 25) - 0.4) < 1e-9     # textbook example (po=.7, pe=.5)
    assert cohens_kappa(list("abab"), list("baba")) < 0
def test_fleiss_known_and_extremes():
    assert fleiss_kappa([["a", "a", "a"], ["b", "b", "b"]]) == 1.0
    r = [[1, 1, 1], [1, 1, 2], [3, 3, 3], [2, 2, 2], [1, 2, 3]]; assert -1 <= fleiss_kappa(r) <= 1
    assert percent_agreement([["a", "a"], ["a", "b"]]) == 0.5
def test_blinded_packet_has_no_labels(tmp_path):
    items = [{"alert_id": f"id{i}", "source": "falco", "event_text": f"fd.name=/x{i}", "label": f"T{i}"} for i in range(10)]
    h = build_blinded_packet(items, 1, tmp_path / "p.csv", tmp_path / "k.csv"); text = (tmp_path / "p.csv").read_text()
    assert "T1" not in text and "id1" not in text and len(h) == 64
    rows = list(csv.DictReader((tmp_path / "p.csv").read_text().splitlines())); assert len(rows) == 10 and all(r["attack_technique_id"] == "" for r in rows)
