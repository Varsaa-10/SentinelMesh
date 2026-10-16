"""eval/summarise_scores.py -- tables from the per-alert scores: test-set and held-out counts per knowledge base,
per-subnet results on the lab-written corpus, held-out predictions, and a leave-one-run-out fallback check.
Usage: python3 eval/summarise_scores.py eval/results/scores_<embedder>.json"""
import json, sys, math
from collections import defaultdict, Counter
d = json.load(open(sys.argv[1]))
A = d["alerts"]
SUB = {"20261014T104641Z": "172.30", "20261014T111618Z": "172.30", "20261014T113310Z": "172.18",
       "20261014T122816Z": "172.18", "20261014T130955Z": "10.20", "20261014T132438Z": "10.20",
       "20261014T134019Z": "10.40", "20261014T135319Z": "10.40", "20261014T140601Z": "172.25",
       "20261014T141640Z": "172.25"}

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k / n; den = 1 + z*z/n; c = (p + z*z/(2*n)) / den; h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / den
    return (round(100*(c-h)), round(100*(c+h)))

def ok(pred, truth, corpus):
    return pred == truth or (corpus == "corpus_200" and "." in truth and pred == truth.split(".")[0])

def get(corpus, variant, form):
    return next(r for r in d["results"] if r["corpus"] == corpus and r["variant"] == variant and r["form"] == form)

def score(res, sel, eng):
    return sum(ok(p[eng], A[i]["truth"], res["corpus"]) for i, p in enumerate(res["preds"]) if sel(A[i]))

fresh = lambda a: a["set"] == "fresh"
held = lambda a: a["set"] == "heldout"
FORMS = ("raw", "title_raw", "rewrite")
CORP = ("corpus_36", "corpus_200", "corpus_full")
VARS = ("mitre_with_citations", "mitre", "+detection", "+description", "+detection+description", "+all_lab_fields")

for setname, sel in (("FRESH 140", fresh), ("HELD-OUT 5", held)):
    print(f"\n==== {setname}  (tactic-first / flat)")
    print(f"{'lab':<12}{'':<24}" + "  ".join(f"{score(get('lab','lab',f),sel,'tl')}/{score(get('lab','lab',f),sel,'fl')}" for f in FORMS))
    for c in CORP:
        for v in VARS:
            print(f"{c:<12}{v:<24}" + "  ".join(f"{score(get(c,v,f),sel,'tl')}/{score(get(c,v,f),sel,'fl')}" for f in FORMS))

print("\n==== lab corpus, raw, per run (tactic-first, flat), failing slots of tactic-first")
for f in FORMS:
    res = get("lab", "lab", f)
    bysub = defaultdict(lambda: [0, 0, 0])
    fails = Counter()
    for i, p in enumerate(res["preds"]):
        a = A[i]
        if a["set"] != "fresh": continue
        s = SUB[a["run"]]; bysub[s][2] += 1
        bysub[s][0] += p["tl"] == a["truth"]; bysub[s][1] += p["fl"] == a["truth"]
        if p["tl"] != a["truth"]: fails[(s, a["slot"].replace("S10:", ""), p["tl"], p["tl_tactic"])] += 1
    tot = [sum(v[j] for v in bysub.values()) for j in range(3)]
    print(f, dict(bysub), "total", tot, "wilson tl", wilson(tot[0], tot[2]))
    for k, v in sorted(fails.items()): print("   ", k, v)

print("\n==== held-out predictions (lab corpus)")
for f in FORMS:
    res = get("lab", "lab", f)
    print(f, [(A[i]["slot"], A[i]["truth"], p["tl"], p["fl"]) for i, p in enumerate(res["preds"]) if A[i]["set"] == "heldout"])
for c in CORP:
    for v in ("mitre", "+detection", "+all_lab_fields"):
        for f in FORMS:
            res = get(c, v, f)
            print(c, v, f, [(A[i]["slot"], p["tl"], p["fl"]) for i, p in enumerate(res["preds"]) if A[i]["set"] == "heldout"])

# leave-one-run-out fallback threshold on fresh, lab corpus
GRID = [round(x*0.01, 2) for x in range(31)]
runs = sorted(SUB)
def acc(items, th):
    k = fb = 0
    for p, a in items:
        use = p["sim"] < th; fb += use
        k += (p["fl"] if use else p["tl"]) == a["truth"]
    return k, fb
print("\n==== LORO fallback, lab corpus, fresh")
chosen_by_form = {}
for f in FORMS:
    res = get("lab", "lab", f)
    items = [(p, A[i]) for i, p in enumerate(res["preds"]) if A[i]["set"] == "fresh"]
    tot_ok = tot_fb = 0; chosen = []
    for r in runs:
        train = [x for x in items if x[1]["run"] != r]; test = [x for x in items if x[1]["run"] == r]
        best = max(GRID, key=lambda t: (acc(train, t)[0], -acc(train, t)[1], -t))
        k, fb = acc(test, best); tot_ok += k; tot_fb += fb; chosen.append(best)
    chosen_by_form[f] = Counter(chosen).most_common(1)[0][0]
    print(f, "chosen", Counter(chosen), "held-out acc", tot_ok, "/", len(items), "fallback rate", round(100*tot_fb/len(items)))
    th = chosen_by_form[f]
    for c in CORP:
        for v in ("mitre", "+detection", "+all_lab_fields"):
            res2 = get(c, v, f)
            sims = [p["sim"] for i, p in enumerate(res2["preds"]) if A[i]["set"] == "fresh"]
            print(f"    at {th}: {c} {v} fires on {round(100*sum(s < th for s in sims)/len(sims))}%")
