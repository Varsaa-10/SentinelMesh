"""Find which Sigma commit reproduces the saved per-event Sigma predictions (m4_external_events.json)."""
import sys, json, subprocess, tarfile, io, collections, os
sys.path.insert(0, os.environ.get("SENTINELMESH_ROOT", ".")); sys.path.insert(0, os.path.join(os.environ.get("SENTINELMESH_ROOT", "."), "rag_engine/src"))
from sentinelmesh_x.external import load_sigma_process_creation, load_atomic_events
from sentinelmesh_x.data import load_corpus, clean_record
saved = {e["event_id"]: e for e in json.load(open(os.path.join(os.environ.get("SENTINELMESH_ROOT", "."), "results_x_v3/m4_external_events.json")))}
events, _ = load_atomic_events(__import__("pathlib").Path("/tmp/ext/atomic_index.yaml"))
cid = {r["id"] for r in (clean_record(x) for x in load_corpus("corpus_full"))}
events = [e for e in events if e["technique"] in cid]
print("events", len(events), "saved", len(saved), "ids match", {e["event_id"] for e in events} == set(saved))
repo = os.environ.get("SIGMA_GIT", "sigma")
for c in sys.argv[1:]:
    tgz = f"/tmp/ext/sigma_{c}.tgz"
    if not os.path.exists(tgz):
        subprocess.run(f"git -C {repo} archive --format=tar.gz --prefix=sigma-master/ -o {tgz} {c} rules/windows/process_creation", shell=True, check=True)
    rules, st = load_sigma_process_creation(__import__("pathlib").Path(tgz))
    diff = 0
    for e in events:
        ev = {"Image": e["Image"], "CommandLine": e["CommandLine"]}; sc = collections.Counter()
        for r in rules:
            if r.fires(ev):
                for t in r.techniques: sc[t] += 1.0 / len(r.techniques)
        pred = sorted(sc, key=lambda t: (-sc[t], t))[0] if sc else None
        s = saved[e["event_id"]]
        diff += (bool(sc) != s["fired"]) or (pred != s["pred"])
    print(c, "parsed rules", len(rules), st, "events differing", diff, flush=True)
