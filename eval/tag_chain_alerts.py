"""
eval/tag_chain_alerts.py -- retro-tag S10 chain alerts in an existing alerts.jsonl.

New harness runs tag chain alerts at capture time (see eval/harness.py,
tag_chain_alerts). This script exists for run folders captured BEFORE that
change. It does NOT modify the source run: it writes a new folder
eval/runs/<source>_chaintagged/ containing the tagged alerts.jsonl and a
provenance.json (source path, sha256, method, tagged count).

Method (heuristic, recorded in provenance.json): the chain script runs LAST,
so take the final alert for the first chain stage (S1) and tag every alert
from there on whose scenario is a chain stage. The result is accepted only if
those alerts contain the stages S1,S3,S4,S9,S8 in order; otherwise nothing is
written and the script exits non-zero. Prefer a fresh harness run when
possible: it uses the real script start/end times instead of this heuristic.

Usage:  python3 eval/tag_chain_alerts.py eval/runs/20261012T031032Z
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

STAGES = ["S1", "S3", "S4", "S9", "S8"]


def is_ordered_subsequence(seq, stages):
    it = iter(seq)
    return all(any(x == s for x in it) for s in stages)


def main(run_dir: str) -> int:
    run = Path(run_dir)
    src = run / "alerts.jsonl"
    alerts = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]

    starts = [i for i, a in enumerate(alerts) if a.get("scenario") == STAGES[0]]
    if not starts:
        print("no S1 alert found; cannot locate chain", file=sys.stderr)
        return 1
    first = starts[-1]
    idxs = [i for i in range(first, len(alerts)) if alerts[i].get("scenario") in STAGES]
    if not is_ordered_subsequence([alerts[i]["scenario"] for i in idxs], STAGES):
        print("tail of alert file does not contain S1,S3,S4,S9,S8 in order; refusing to tag", file=sys.stderr)
        return 1

    for i in idxs:
        alerts[i]["chain_id"] = "S10"
        alerts[i]["component_scenario"] = alerts[i]["scenario"]

    out = run.parent / f"{run.name}_chaintagged"
    out.mkdir(exist_ok=True)
    (out / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    (out / "provenance.json").write_text(json.dumps({
        "source": str(src),
        "source_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
        "method": "heuristic: last S1 onward, chain-stage scenarios, ordered-subsequence check",
        "tagged_alerts": len(idxs),
        "total_alerts": len(alerts),
    }, indent=2))
    print(f"tagged {len(idxs)}/{len(alerts)} alerts -> {out / 'alerts.jsonl'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
