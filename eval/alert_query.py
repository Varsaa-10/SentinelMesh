"""
eval/alert_query.py -- build retrieval queries from captured alerts (alerts.jsonl).

Capture records carry structured `event` fields, not an `output` string, so the
query text has to be rebuilt from those fields:

  raw        Falco alerts: the rule's own `output:` template from
             detection/falco-rules/*.yaml, with %field placeholders filled from
             the event (missing fields render as <NA>, as Falco does).
             Log-tail alerts: "<event_type> event_type, k=v, k=v, ..." over the
             event fields (nested dicts flattened with dots; timestamp and
             service dropped). Grafana alerts already are a key=value log line,
             so `raw_log_line` is used as-is.
  title_raw  the detector's own title from the capture, then the raw query.
  rewrite    rag_engine/src/alert_normalizer.py (frozen at tag v2-rules-frozen).

Also holds the pre-registered alert selection rule (docs/analysis_plan_v3.md):
one alert per single scenario S1-S9 (first in file order, chain alerts
excluded) plus one alert per S10 chain stage (S1,S3,S4,S9,S8). No backfill: a
scenario with no alert is reported as missing, never relabelled.
"""
from __future__ import annotations

import glob
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "rag_engine" / "src"))
from alert_normalizer import normalize_alert_text  # noqa: E402

FALCO_RULES_DIR = REPO_ROOT / "detection" / "falco-rules"
SINGLE_SCENARIOS = [f"S{i}" for i in range(1, 10)]
CHAIN_STAGES = ["S1", "S3", "S4", "S9", "S8"]
QUERY_FORMS = ("raw", "title_raw", "rewrite")
_FIELD_RE = re.compile(r"%([A-Za-z0-9_.]+[A-Za-z0-9_])")


@lru_cache(maxsize=1)
def falco_output_templates() -> Dict[str, str]:
    """rule name -> single-line output template."""
    templates: Dict[str, str] = {}
    for path in sorted(glob.glob(str(FALCO_RULES_DIR / "*.yaml"))):
        with open(path, encoding="utf-8", errors="replace") as f:
            for item in yaml.safe_load(f) or []:
                if isinstance(item, dict) and "rule" in item and "output" in item:
                    templates[item["rule"]] = " ".join(str(item["output"]).split())
    return templates


def _render_falco(alert: Dict[str, Any]) -> str:
    event = alert.get("event") or {}
    template = falco_output_templates().get(alert.get("title", ""))
    if template is None:
        raise KeyError(f"no Falco rule named {alert.get('title')!r} in {FALCO_RULES_DIR}")

    def sub(m: re.Match) -> str:
        val = event.get(m.group(1))
        return "<NA>" if val is None else str(val)

    return _FIELD_RE.sub(sub, template)


def _flatten(prefix: str, value: Any, out: List[Tuple[str, Any]]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else k, v, out)
    else:
        out.append((prefix, value))


def _fmt(v: Any) -> str:
    s = str(v)
    return f'"{s}"' if (" " in s or "'" in s) else s


def _render_log_tail(alert: Dict[str, Any]) -> str:
    event = alert.get("event") or {}
    if "raw_log_line" in event:
        return str(event["raw_log_line"])
    pairs: List[Tuple[str, Any]] = []
    for k, v in event.items():
        if k in ("timestamp", "service", "event_type"):
            continue
        _flatten(k, v, pairs)
    body = ", ".join(f"{k}={_fmt(v)}" for k, v in pairs)
    et = event.get("event_type")
    return f"{et} event_type, {body}" if et else body


def build_raw_query(alert: Dict[str, Any]) -> str:
    text = _render_falco(alert) if alert.get("source") == "falco" else _render_log_tail(alert)
    if not text.strip():
        raise ValueError(f"empty raw query for alert: {json.dumps(alert)[:200]}")
    return text


def build_query(alert: Dict[str, Any], form: str) -> str:
    raw = build_raw_query(alert)
    if form == "raw":
        return raw
    if form == "title_raw":
        title = (alert.get("title") or "").strip()
        return f"{title}. {raw}" if title else raw
    if form == "rewrite":
        return normalize_alert_text({**alert, "output": raw})
    raise ValueError(f"unknown query form {form!r}")


def select_alerts(alerts: List[Dict[str, Any]], ground_truth: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Pre-registered selection. Returns (selected, missing) where each selected
    item carries the capture alert plus its label; `missing` lists slots with no alert."""
    selected: List[Dict[str, Any]] = []
    missing: List[str] = []
    for sid in SINGLE_SCENARIOS:
        a = next((x for x in alerts if x.get("scenario") == sid and x.get("chain_id") != "S10"), None)
        if a is None:
            missing.append(sid)
            continue
        selected.append({"slot": sid, "scenario_id": sid, "alert": a,
                         "ground_truth_technique": ground_truth[sid]["technique_id"]})
    for stage in CHAIN_STAGES:
        a = next((x for x in alerts if x.get("chain_id") == "S10"
                  and (x.get("component_scenario") or x.get("scenario")) == stage), None)
        if a is None:
            missing.append(f"S10:{stage}")
            continue
        selected.append({"slot": f"S10:{stage}", "scenario_id": stage, "alert": a,
                         "ground_truth_technique": ground_truth[stage]["technique_id"]})
    return selected, missing


def load_alerts(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


if __name__ == "__main__":
    gt = json.loads((REPO_ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "eval" / "runs" / "20261012T140201Z" / "alerts.jsonl"
    sel, miss = select_alerts(load_alerts(run), gt)
    print(f"{run}: {len(sel)} selected, missing={miss}")
    for s in sel:
        print(f"[{s['slot']:<7}] {build_query(s['alert'], 'title_raw')}")
