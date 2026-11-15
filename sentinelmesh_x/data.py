"""Alert sets, knowledge-base conditions and environment metadata for the SentinelMesh-X experiments.

Splits follow the pre-registered protocol of the original paper (docs/analysis_plan_v3.md):
  dev      5 development captures (faulty S8 slots removed)  -> used for tuning / training only
  test     10 fresh captures on 5 Docker subnets (140 alerts) -> never used for tuning
  heldout  5 alerts from the held-out variant capture
"""
from __future__ import annotations
import copy
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rag_engine" / "src"))
from eval.alert_query import QUERY_FORMS, build_query, load_alerts, select_alerts  # noqa: E402
from eval.kb_curation_ablation import (DEV_RUNS, FRESH_RUNS, HELDOUT_RUNS, RUNS_WITH_FAULTY_S8, CORPORA, strip_citations)  # noqa: E402

SUBNET = {"20261014T104641Z": "172.30", "20261014T111618Z": "172.30", "20261014T113310Z": "172.18",
          "20261014T122816Z": "172.18", "20261014T130955Z": "10.20", "20261014T132438Z": "10.20",
          "20261014T134019Z": "10.40", "20261014T135319Z": "10.40", "20261014T140601Z": "172.25",
          "20261014T141640Z": "172.25"}


@lru_cache(maxsize=1)
def ground_truth() -> Dict[str, Any]:
    return json.loads((ROOT / "eval/ground_truth.json").read_text(encoding="utf-8"))["scenarios"]


def run_environment(run_dir: Path) -> Dict[str, str]:
    """Host kernel / Docker / Falco version from run_manifest.txt (environment descriptor)."""
    m = run_dir / "run_manifest.txt"
    env = {"host": "", "docker": "", "falco": ""}
    if m.exists():
        for line in m.read_text(errors="replace").splitlines():
            if line.startswith("host:"):
                env["host"] = line[5:].strip()
            elif line.startswith("docker:"):
                env["docker"] = line[7:].strip()
            elif line.startswith("falco:") and "version" in line:
                env["falco"] = line.split("version:")[-1].strip()
    return env


@lru_cache(maxsize=1)
def alert_sets() -> Dict[str, List[Dict[str, Any]]]:
    gt = ground_truth()
    sets = {"dev": [], "test": [], "heldout": []}
    plan = [(r, "runs", "dev") for r in DEV_RUNS] + [(r, "runs", "test") for r in FRESH_RUNS] + [(r, "runs_heldout", "heldout") for r in HELDOUT_RUNS]
    for run, folder, name in plan:
        d = ROOT / "eval" / folder / run
        env = run_environment(d)
        sel, _ = select_alerts(load_alerts(d / "alerts.jsonl"), gt)
        for it in sel:
            if name == "dev" and run in RUNS_WITH_FAULTY_S8 and it["slot"] in ("S8", "S10:S8"):
                continue
            sets[name].append({"set": name, "run": run, "slot": it["slot"], "scenario": it["scenario_id"], "truth": it["ground_truth_technique"],
                               "alert": it["alert"], "subnet": SUBNET.get(run, "172.30"), "env": env,
                               "queries": {f: build_query(it["alert"], f) for f in QUERY_FORMS}})
    return sets


def load_corpus(name: str) -> List[Dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "rag_engine/kb/corpora" / name).glob("*.json"))]


def clean_record(r: Dict[str, Any]) -> Dict[str, Any]:
    r = copy.deepcopy(r)
    r["description"] = strip_citations(r.get("description", ""))
    r["mitigation"] = strip_citations(r.get("mitigation", ""))
    return r


def correct(pred: str, truth: str, corpus: str) -> bool:
    """Exact technique id; corpus_200 has no sub-techniques so the parent id also counts (as in the paper)."""
    return pred == truth or (corpus == "corpus_200" and "." in truth and pred == truth.split(".")[0])
