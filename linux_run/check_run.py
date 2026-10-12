#!/usr/bin/env python3
"""Post-run sanity report: python3 linux_run/check_run.py eval/runs/<run_id>"""
import argparse, ipaddress, json, sys
from collections import Counter
from pathlib import Path

LAB_STATIC = {"172.30.0.2": "database", "172.30.0.3": "logcollector", "172.30.0.4": "webapp",
              "172.30.0.5": "authservice", "172.30.0.6": "dashboard"}
EXPECT = {"S1": 2, "S2": None, "S3": 2, "S4": 2, "S5": 1, "S6": 1, "S7": 2, "S8": 6, "S9": 2}

def load(p):
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]
def ev(a, k):
    return (a.get("event") or {}).get(k)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--lab-cidr", default="172.30.0.0/16")
    args = ap.parse_args()
    run = Path(args.run_dir)
    lab = ipaddress.ip_network(args.lab_cidr)
    alerts = load(run / "alerts.jsonl")
    res = json.loads((run / "baseline1_results.json").read_text())
    by = {}
    for a in alerts:
        by.setdefault(a.get("scenario", "?"), []).append(a)
    review = []

    print(f"RUN {run.name}: {len(alerts)} alerts, harness score "
          f"{res['single_scenario_pass_count']}/{res['single_scenario_total']}, "
          f"S10 stages all fired: {res.get('s10_chain_all_stages_fired')}")
    print("\nPer scenario")
    for sid in sorted(set(EXPECT) | set(by), key=lambda s: (len(s), s)):
        r = res["results"].get(sid, {})
        n = len(by.get(sid, []))
        exp = EXPECT.get(sid)
        flag = ""
        if sid in res["results"] and not r.get("fired"):
            flag = "  <-- DID NOT FIRE"; review.append(f"{sid} did not fire")
        elif exp is not None and n > exp * 2:
            flag = f"  <-- {n} alerts vs ~{exp} expected: noise"; review.append(f"{sid} noisy ({n} vs ~{exp})")
        print(f"  {sid:<4} fired={str(r.get('fired','-')):<5} alerts={n:<3} (expect ~{exp if exp else 'n/a'}){flag}")
    if "UNKNOWN" in by:
        review.append("alerts with scenario=UNKNOWN")

    print("\nS8 alerts by (container, process, dest):")
    c8 = Counter((ev(a, "container.name"), ev(a, "proc.name"), ev(a, "fd.sip") or ev(a, "fd.rip")) for a in by.get("S8", []))
    ext = 0
    for (cont, proc, rip), n in c8.most_common():
        kind = "EXTERNAL (real S8)"
        try:
            ip = ipaddress.ip_address(rip)
            if ip in lab: kind = "IN-LAB -> FALSE POSITIVE"
            elif ip.is_unspecified: kind = "0.0.0.0 -> connect noise"
            elif ip.is_loopback: kind = "loopback -> should have been excluded"
        except (ValueError, TypeError):
            kind = "no destination recorded -> cannot confirm this is the example.com connect"
        if kind.startswith("EXTERNAL"): ext += n
        else: review.append(f"S8 noise: {cont}/{proc}->{rip} x{n}")
        print(f"  {n:>3}x  {cont} / {proc} -> {rip}   [{kind}]")
    print(f"  => {ext} S8 alert(s) with a real external destination (expect 2: attack + chain)")
    if ext == 0 and by.get("S8"):
        review.append("S8 'fired' but NO alert records an external destination — check raw output_fields in falco_alerts_raw.jsonl")

    print("\nS5 alerts by source IP:")
    for rip, n in Counter(ev(a, "fd.rip") for a in by.get("S5", [])).most_common():
        who = LAB_STATIC.get(rip)
        if who: review.append(f"S5 fired for lab service {who} ({rip})")
        print(f"  {n:>3}x  {rip}  [{'LAB SERVICE: false positive' if who else 'ephemeral client (attacker)'}]")

    print("\nS6 writes:")
    for (p, f), n in Counter((ev(a, "proc.name"), ev(a, "fd.name")) for a in by.get("S6", [])).most_common():
        if p and ("fluent" in str(p) or p == "ruby"):
            review.append("S6 fires on Fluentd's own writes")
        print(f"  {n:>3}x  {p} -> {f}")
    print("\nS9 reads:")
    for k, n in Counter((ev(a, "fd.name"), ev(a, "proc.name"), ev(a, "container.name")) for a in by.get("S9", [])).most_common():
        print(f"  {n:>3}x  {k}")
    print("\nS7 titles:")
    for t, n in Counter(a.get("title", "")[:60] for a in by.get("S7", [])).most_common():
        print(f"  {n:>3}x  {t}")

    stages = ["S1", "S3", "S4", "S9", "S8"]
    ts = [max((a["timestamp"] for a in by.get(s, [])), default=None) for s in stages]
    print("\nS10 chain: latest alert per stage (should increase S1<S3<S4<S9<S8):")
    for s, t in zip(stages, ts): print(f"  {s}: {t}")
    if None in ts or ts != sorted(ts):
        review.append("S10 chain stages missing or out of order")

    print("\n" + "=" * 60)
    if review:
        print("REVIEW BEFORE FREEZING:")
        for r in dict.fromkeys(review): print("  -", r)
        sys.exit(2)
    print("CLEAN: every scenario fired, no noise flagged. Safe to freeze.")

if __name__ == "__main__":
    main()
