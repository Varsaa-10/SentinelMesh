"""Cross-environment / zero-shot generalisation (item 7) and ablation + sensitivity (item 10). corpus_full, tuned DAHR."""
import itertools, random, time
from bench import *
S = alert_sets(); cfg = tuned_cfg(); CORPUS = "corpus_full"
t0 = time.time()
ix_auto = make_index(CORPUS, "auto"); ix_lex = make_index(CORPUS, "auto_lex"); ix_mitre = make_index(CORPUS, "mitre")
test, held = S["test"], S["heldout"]
out = {}

def acc(method, rows, form, ix, disabled=(), sup=None):
    sc = score_rows(method, rows, form, ix, CORPUS, cfg, sup=sup, disabled=disabled)
    return sc["metrics"]["P@1"], sc["metrics"]["MRR"]

# ---------- leave-one-subnet-out (environment = Docker subnet; two captures each; all on one lab design) ----------
loso = []
for sub in sorted({r["subnet"] for r in test}):
    te = [r for r in test if r["subnet"] == sub]
    for form in QUERY_FORMS:
        tr = S["dev"] + [r for r in test if r["subnet"] != sub]
        sup = Supervised(tr, form)
        for m in ("tfidf", "bm25", "dahr", "supervised"):
            a, mrr = acc(m, te, form, ix_auto, sup=sup)
            loso.append({"held_out_subnet": sub, "form": form, "method": m, "P@1": a, "MRR": mrr, "n": len(te)})
out["leave_one_subnet_out"] = loso
# held-out variant attacks (written after freeze) -- seen vs unseen attack variants
out["heldout_variants"] = [{"form": f, "method": m, **dict(zip(("P@1", "MRR"), acc(m, held, f, ix_auto, sup=Supervised(S["dev"], f))))}
                           for f in QUERY_FORMS for m in ("tfidf", "bm25", "dahr", "supervised")]
# ---------- leave-one-technique-out: knowledge for the technique is withheld (zero-shot) ----------
loto = []
for tech in sorted(targets()):
    ixd = make_index(CORPUS, "auto", drop_knowledge_for=[tech])
    te = [r for r in test if r["truth"] == tech]
    for form in QUERY_FORMS:
        sup = Supervised([r for r in S["dev"] if r["truth"] != tech], form)
        for m in ("tfidf", "bm25", "dahr", "supervised"):
            a, mrr = acc(m, te, form, ixd, sup=sup)
            loto.append({"held_out_technique": tech, "form": form, "method": m, "P@1": a, "MRR": mrr, "n": len(te)})
out["leave_one_technique_out"] = loto
print("generalisation", round(time.time() - t0), "s", flush=True)

# ---------- ablation under perturbation ----------
rng = random.Random(SEED)
PERT = [("none", 0.0), ("drop", 0.3), ("noise", 0.15), ("rename", 0.5)]
comps = {}
for row in test:
    for mode, p in PERT:
        a = row["alert"] if mode == "none" else perturb_alert(row["alert"], mode, p, rng)
        r = requery(row, a)
        for form in QUERY_FORMS:
            comps[(row["run"], row["slot"], mode, form)] = (row["truth"], dahr_components(ix_auto, r["queries"][form], a, top_ms=(2, 3, 5)))
            if mode == "none":     # lexicon variant for -lexicon ablation
                comps[(row["run"], row["slot"], "lex", form)] = (row["truth"], dahr_components(ix_lex, r["queries"][form], a, top_ms=(2, 3, 5)))
            comps[(row["run"], row["slot"], mode, form, "mitre")] = (row["truth"], dahr_components(ix_mitre, r["queries"][form], a, top_ms=(2, 3, 5)))

def ev(cfg_, mode, key_extra=()):
    ranks = []
    for k, (truth, c) in comps.items():
        if k[2] != mode or len(k) != 4 + len(key_extra):
            continue
        if key_extra and k[4:] != key_extra:
            continue
        ranks.append(dahr_combine(c, cfg_).ids.index(truth) + 1)
    r = np.array(ranks, float)
    return {"P@1": float((r == 1).mean()), "MRR": float((1 / r).mean()), "n": len(r)}

def variant(**kw):
    d = dict(cfg.__dict__); d.update(kw); return DAHRConfig(**d)

abl = {}
for mode, _ in PERT:
    rows = {"full (tuned)": ev(cfg, mode), "default weights": ev(DAHRConfig(), mode),
            "- field matching": ev(variant(use_field=False), mode), "- semantic TF-IDF": ev(variant(use_sem=False), mode),
            "- BM25": ev(variant(use_bm25=False), mode), "- hierarchy": ev(variant(use_hier=False), mode),
            "- adaptive weights": ev(variant(adaptive=False), mode),
            "- generated knowledge (MITRE text only)": ev(variant(use_field=False), mode, ("mitre",)) if mode != "lex" else None,
            "default weights, hierarchy on (w_h=.15)": ev(DAHRConfig(), mode)}
    abl[f"{mode}"] = rows
abl["none"]["+ lexicon in generated text"] = ev(cfg, "lex")
out["ablation"] = abl
# full 2^4 channel factorial (interactions)
fact = []
for f, s, b, h in itertools.product([0, 1], repeat=4):
    if not (f or s or b or h):
        continue
    for mode in ("none", "rename"):
        fact.append({"field": f, "sem": s, "bm25": b, "hier": h, "perturbation": mode,
                     **ev(variant(use_field=bool(f), use_sem=bool(s), use_bm25=bool(b), use_hier=bool(h), w_h=max(cfg.w_h, 0.15)), mode)})
out["factorial_channels"] = fact
# one-at-a-time sensitivity (perturbed: rename 0.5)
sens = []
for name, vals in [("w_f", [0.05, 0.1, 0.25, 0.4, 0.55, 0.7]), ("w_s", [0.0, 0.1, 0.2, 0.3, 0.45]), ("w_b", [0.0, 0.1, 0.2, 0.4]),
                   ("w_h", [0.0, 0.1, 0.2, 0.3, 0.5]), ("top_m", [1, 2, 3, 5])]:
    for v in vals:
        for mode in ("none", "rename"):
            sens.append({"param": name, "value": v, "perturbation": mode, **ev(variant(**{name: v}), mode)})
out["sensitivity"] = sens
save("generalisation_ablation.json", out)
print("done", round(time.time() - t0), "s")
