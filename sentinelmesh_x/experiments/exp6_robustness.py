"""Adaptive poisoning / manipulation robustness (item 8). corpus_full auto KB, tuned DAHR vs BM25 / TF-IDF, 140 test alerts."""
import copy, random, hashlib, time
from bench import *
from sentinelmesh_x.knowledge_gen import to_kb_signature
S = alert_sets(); cfg = tuned_cfg(); CORPUS = "corpus_full"; test = S["test"]
tg = sorted(targets()); rng0 = random.Random(SEED)
base_raw = build_raw_condition(CORPUS, "auto")
base_ix = make_index(CORPUS, "auto")
FORMS = ("raw", "rewrite")

def flag(c):   # retrieval-level anomaly flag: field channel and text channels disagree on the top-1
    f = int(np.argmax(c.fld)) if c.fld.max() > 0 else None
    t = int(np.argmax(c.sem_n + c.bm_n))
    return f is not None and f != t

def run(ix, rows, form, mutate=None, rng=None):
    out = []
    for row in rows:
        a = row["alert"] if mutate is None else mutate(row, rng)
        r = requery(row, a)
        q = r["queries"][form]
        c = dahr_components(ix, q, a)
        out.append({"truth": row["truth"], "dahr": dahr_combine(c, cfg).ids[0], "bm25": rank_bm25(ix, q).ids[0], "tfidf": rank_tfidf(ix, q).ids[0], "flag": flag(c)})
    return out

def summarise(clean, att):
    res = {}
    for m in ("dahr", "bm25", "tfidf"):
        ok0 = [c[m] == c["truth"] for c in clean]
        ok1 = [a[m] == a["truth"] for a in att]
        flips = [o and not n for o, n in zip(ok0, ok1)]
        res[m] = {"acc_clean": float(np.mean(ok0)), "acc_attack": float(np.mean(ok1)), "ASR": float(sum(flips) / max(1, sum(ok0)))}
    res["flag_rate_attack"] = float(np.mean([a["flag"] for a in att])); res["flag_rate_clean"] = float(np.mean([c["flag"] for c in clean]))
    # detection rate among alerts whose DAHR prediction was flipped
    fl = [a["flag"] for a, c in zip(att, clean) if c["dahr"] == c["truth"] and a["dahr"] != a["truth"]]
    res["detection_rate_of_successful_attacks"] = float(np.mean(fl)) if fl else None
    return res

results = {}
clean = {f: run(base_ix, test, f) for f in FORMS}
# ---- A: knowledge-base poisoning of covered technique records ----
desc_of = {r["id"]: r["description"] for r in base_raw}
def poison_ix(k, mode, seed):
    rng = random.Random(seed); victims = rng.sample(tg, k)
    raw = copy.deepcopy(base_raw)
    for r in raw:
        if r["id"] in victims:
            donor = rng.choice([t for t in tg if t != r["id"]])
            if mode == "swap_description":
                r["description"] = desc_of[donor]
            elif mode == "stuff":
                r["description"] += " " + desc_of[donor] * 3
            elif mode == "swap_signature":
                r["detection_signatures"] = to_kb_signature(detectors(), donor)
    recs = make_records(raw, use_mitre_sigs=True)
    ix = KBIndex(recs, detectors())
    return ix, victims, raw
A = {}
for mode in ("swap_description", "stuff", "swap_signature"):
    for k in (1, 2, 4, 8):
        accs = {f: [] for f in FORMS}
        det = []
        for seed in range(5):
            ix, victims, raw = poison_ix(k, mode, seed)
            # integrity detector: regenerated detector knowledge vs KB signature text (hash) -- catches signature tampering
            tampered = [r["id"] for r in raw if r["id"] in tg and r["detection_signatures"] != next(b["detection_signatures"] for b in base_raw if b["id"] == r["id"])]
            det.append(len(set(tampered) & set(victims)) / k if mode == "swap_signature" else 0.0)
            for f in FORMS:
                accs[f].append(summarise(clean[f], run(ix, test, f)))
        A[f"{mode}|k={k}"] = {f: {m: {kk: float(np.mean([s[m][kk] for s in accs[f]])) for kk in ("acc_attack", "ASR")} for m in ("dahr", "bm25", "tfidf")} for f in FORMS}
        A[f"{mode}|k={k}"]["integrity_check_detection_rate"] = float(np.mean(det))
results["A_kb_poisoning"] = A
# ---- B: attacker-controlled field injection (identifier / path text carrying another technique's vocabulary) ----
DECOY = {"T1003.008": "reads etc shadow password hash file credential dumping", "T1041": "exfiltration over command and control channel outbound connection",
         "T1021": "remote service postgresql database lateral movement", "T1070": "indicator removal clear logs tampering", "T1110": "brute force password guessing"}
def inject(level):
    def f(row, rng):
        a = copy.deepcopy(row["alert"]); ev = a["event"]
        donors = [t for t in DECOY if t != row["truth"]]
        txt = " ".join(DECOY[rng.choice(donors)] for _ in range(level))
        for key in ("identifier", "username", "fd.name", "raw_log_line"):
            if isinstance(ev.get(key), str):
                ev[key] = ev[key] + " " + txt
                break
        else:
            if "details" in ev and isinstance(ev["details"], dict):
                ev["details"]["note"] = txt
        return a
    return f
results["B_field_injection"] = {f"level={l}": {f: summarise(clean[f], run(base_ix, test, f, inject(l), random.Random(SEED + l))) for f in FORMS} for l in (1, 3, 6)}
# ---- C/D: detector output manipulation and unseen corruption ----
def pert(mode, p):
    return lambda row, rng: perturb_alert(row["alert"], mode, p, rng)
def shuffle_fields(row, rng):
    a = copy.deepcopy(row["alert"]); ev = a["event"]; ks = [k for k, v in ev.items() if isinstance(v, str) and k not in ("timestamp", "service")]
    vs = [ev[k] for k in ks]; rng.shuffle(vs)
    for k, v in zip(ks, vs): ev[k] = v
    return a
C = {}
for name, fn in [("drop_0.5", pert("drop", .5)), ("drop_0.8", pert("drop", .8)), ("rename_1.0", pert("rename", 1.0)), ("noise_0.1", pert("noise", .1)),
                 ("noise_0.3", pert("noise", .3)), ("shuffle_values", shuffle_fields)]:
    C[name] = {f: summarise(clean[f], run(base_ix, test, f, fn, random.Random(SEED))) for f in FORMS}
results["C_D_detector_output_and_unseen_corruption"] = C
save("robustness.json", results)
print({k: v["raw"]["dahr"] for k, v in C.items()}); print({k: v["raw"]["dahr"]["ASR"] for k, v in results["B_field_injection"].items()})
print({k: round(v["raw"]["dahr"]["ASR"], 3) for k, v in A.items()})
