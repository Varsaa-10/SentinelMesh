"""eval/plot_paper_figures.py -- the paper's figures from the per-alert scores and clustered statistics.
Usage: python3 eval/plot_paper_figures.py eval/results/scores_tfidf-word.json OUTDIR eval/results/stats_tfidf-word.json [--paper]
--paper drops titles and footnotes (the LaTeX captions carry them) and enlarges fonts."""
import json, math, sys
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

d = json.load(open(sys.argv[1])); out = Path(sys.argv[2]); out.mkdir(exist_ok=True)
PAPER = "--paper" in sys.argv  # no titles or footnotes; the LaTeX caption carries them
A = d["alerts"]
SUB = {"20261014T104641Z": "172.30", "20261014T111618Z": "172.30", "20261014T113310Z": "172.18",
       "20261014T122816Z": "172.18", "20261014T130955Z": "10.20", "20261014T132438Z": "10.20",
       "20261014T134019Z": "10.40", "20261014T135319Z": "10.40", "20261014T140601Z": "172.25",
       "20261014T141640Z": "172.25"}
FORMS = [("raw", "raw"), ("title_raw", "title + raw"), ("rewrite", "rewrite")]
CORP = [("corpus_36", "36 records"), ("corpus_200", "227 parents"), ("corpus_full", "706 records")]
VARS = [("mitre", "MITRE text"), ("+description", "+ lab description"), ("+detection", "+ lab detection text"),
        ("+detection+description", "+ detection + description"), ("+all_lab_fields", "+ all lab fields")]
ENG = [("tl", "Tactic-first"), ("fl", "Flat")]
C_TL, C_FL = "#d9714e", "#3a7fc4"
plt.rcParams.update({"font.size": 14 if PAPER else 10, "axes.spines.top": False, "axes.spines.right": False})

def get(c, v, f):
    return next(r for r in d["results"] if r["corpus"] == c and r["variant"] == v and r["form"] == f)
def ok(p, t, c):
    return p == t or (c == "corpus_200" and "." in t and p == t.split(".")[0])
def count(c, v, f, e, setname="fresh"):
    r = get(c, v, f)
    idx = [i for i, a in enumerate(A) if a["set"] == setname]
    return sum(ok(r["preds"][i][e], A[i]["truth"], c) for i in idx), len(idx)
STATS = json.load(open(sys.argv[3])) if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None


def cluster_ci(c, v, f, e):
    """Two-way cluster bootstrap interval (captures x scenarios) from clustered_stats.py."""
    r = next(x for x in STATS["configs"] if x["corpus"] == c and x["variant"] == v and x["form"] == f)
    return tuple(r[e]["ci2way"])


def wilson(k, n, z=1.96):
    p = k / n; den = 1 + z*z/n; c = (p + z*z/(2*n)) / den; h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / den
    return 100*(c-h), 100*(c+h)

# ---- 1. heatmap
rows, labels = [], []
for f, fl in FORMS:
    for v, vl in VARS:
        rows.append([100*count(c, v, f, e)[0]/140 for c, _ in CORP for e, _ in ENG])
        labels.append(f"{fl}  |  {vl}")
M = np.array(rows)
fig, ax = plt.subplots(figsize=(12, 10) if PAPER else (10, 8.6))
im = ax.imshow(M, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
for i in range(M.shape[0]):
    for j in range(M.shape[1]):
        k = round(M[i, j]*140/100)
        ax.text(j, i, f"{k}", ha="center", va="center", fontsize=12 if PAPER else 9, fontweight="bold",
                color="white" if M[i, j] < 15 or M[i, j] > 90 else "black")
ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels)
ax.set_xticks(range(6))
if PAPER:
    ax.set_xticklabels(["Tactic-\nfirst", "Flat"] * 3)
    for g, (_, cl) in enumerate(CORP):
        ax.text(2*g + 0.5, -0.75, cl, ha="center", va="bottom", fontweight="bold")
else:
    ax.set_xticklabels([f"{cl}\n{el}" for _, cl in CORP for _, el in ENG])
for y in (4.5, 9.5): ax.axhline(y, color="white", lw=3)
for x in (1.5, 3.5): ax.axvline(x, color="white", lw=3)
for s in ax.spines.values(): s.set_visible(False)
cb = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02); cb.set_label("Top-1 accuracy (%)")
if not PAPER: ax.set_title("Lab text added to MITRE records: correct out of 140 test alerts (TF-IDF)", fontweight="bold", pad=12)
if not PAPER: fig.text(0.01, 0.005, "Ten captures on five subnets, 14 alerts each. Lab text added only to the 8 answer techniques. "
             "227-record corpus has no T1003.008, so T1003 is accepted.", fontsize=8, color="#444")
fig.tight_layout(rect=(0, 0.02, 1, 1)); fig.savefig(out / "fig_ablation_heatmap_140.png", dpi=200); plt.close(fig)

# ---- 2. MITRE text vs lab text, with Wilson intervals
show = [("mitre", "MITRE text"), ("+detection", "+ detection\ntext"), ("+all_lab_fields", "+ all lab\nfields")]
fig, axes = plt.subplots(3, 3, figsize=(11, 9), sharey=True)
for r, (f, fl) in enumerate(FORMS):
    for c_i, (c, cl) in enumerate(CORP):
        ax = axes[r, c_i]; x = np.arange(len(show)); w = 0.36
        for k, (e, el) in enumerate(ENG):
            vals, lo, hi = [], [], []
            for v, _ in show:
                n_ok, n = count(c, v, f, e); p = 100*n_ok/n; a, b = cluster_ci(c, v, f, e) if STATS else wilson(n_ok, n)
                vals.append(p); lo.append(p-a); hi.append(b-p)
            ax.bar(x + (k-0.5)*w, vals, w, yerr=[lo, hi], capsize=3, color=C_TL if e == "tl" else C_FL,
                   edgecolor="#333", lw=0.5, error_kw={"lw": 0.8}, label=el)
        ax.set_xticks(x); ax.set_xticklabels([s[1] for s in show], fontsize=12 if PAPER else 9); ax.set_ylim(0, 105)
        ax.grid(axis="y", alpha=0.3)
        if r == 0: ax.set_title(cl, fontweight="bold")
        if c_i == 0: ax.set_ylabel(f"{fl}\naccuracy (%)")
if PAPER:
    h, l = axes[0, 0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.0))
else:
    axes[0, 0].legend(loc="upper left", frameon=False, fontsize=9)
if not PAPER: fig.suptitle("MITRE text against MITRE text plus lab text: 140 test alerts, TF-IDF", fontweight="bold")
if not PAPER: fig.text(0.01, 0.005, ("Error bars: 95% two-way cluster bootstrap intervals (captures and scenarios resampled)."
                                     if STATS else "Error bars: 95% Wilson intervals; they treat the 140 alerts as independent."),
                      fontsize=8, color="#444")
fig.tight_layout(rect=(0, 0.02, 1, 0.95 if PAPER else 0.97)); fig.savefig(out / "fig_mitre_vs_lab_140.png", dpi=200); plt.close(fig)

# ---- 3. scaling with corpus size (detection text added, and all lab fields)
sizes = [36, 227, 706]
fig, axes = plt.subplots(1, 3, figsize=(13, 4.2), sharey=True)
for a_i, (f, fl) in enumerate(FORMS):
    ax = axes[a_i]
    for v, vl, ls in (("+detection", "detection text", "-"), ("+all_lab_fields", "all lab fields", ":")):
        for e, el in ENG:
            ks = [count(c, v, f, e)[0] for c, _ in CORP]
            ys = [100*k/140 for k in ks]
            col = C_TL if e == "tl" else C_FL
            ax.plot(sizes, ys, ls, marker="o", color=col, lw=2, label=f"{el}, {vl}")
            if v == "+detection":
                band = [cluster_ci(c, v, f, e) for c, _ in CORP] if STATS else [wilson(k, 140) for k in ks]
                ax.fill_between(sizes, [b[0] for b in band], [b[1] for b in band], color=col, alpha=0.12)
    ax.set_xscale("log"); ax.set_xticks(sizes); ax.set_xticklabels(["36", "227\n(parents)", "706"])
    ax.minorticks_off(); ax.set_ylim(0, 105); ax.grid(alpha=0.3); ax.set_title(f"Query form: {fl}", fontweight="bold")
    ax.set_xlabel("Records in the knowledge base (log scale)")
axes[0].set_ylabel("Top-1 accuracy (%)")
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=4, frameon=False, fontsize=13 if PAPER else 9)
if not PAPER: fig.suptitle("Accuracy as the catalogue grows: MITRE records with lab text for the 8 answer techniques, 140 test alerts",
             fontweight="bold")
fig.tight_layout(rect=(0, 0.1, 1, 0.94)); fig.savefig(out / "fig_scaling_140.png", dpi=200); plt.close(fig)

# ---- 4. subnet effect, lab-written corpus, raw
subs = ["172.30", "172.18", "10.20", "10.40", "172.25"]
res = get("lab", "lab", "raw")
tl = {s: 0 for s in subs}; fl = {s: 0 for s in subs}
for i, a in enumerate(A):
    if a["set"] != "fresh": continue
    s = SUB[a["run"]]; tl[s] += res["preds"][i]["tl"] == a["truth"]; fl[s] += res["preds"][i]["fl"] == a["truth"]
fig, ax = plt.subplots(figsize=(7, 3.8)); x = np.arange(len(subs)); w = 0.36
b1 = ax.bar(x - w/2, [tl[s] for s in subs], w, color=C_TL, edgecolor="#333", lw=0.5, label="Tactic-first")
b2 = ax.bar(x + w/2, [fl[s] for s in subs], w, color=C_FL, edgecolor="#333", lw=0.5, label="Flat")
ax.bar_label(b1, padding=2, fontsize=12 if PAPER else 9); ax.bar_label(b2, padding=2, fontsize=12 if PAPER else 9)
ax.set_xticks(x); ax.set_xticklabels([f"{s}.0.0/16" for s in subs] if not PAPER else subs); ax.set_ylim(0, 37); ax.set_yticks([0, 10, 20, 28]); ax.set_ylabel("Correct out of 28")
if PAPER: ax.set_xlabel("Docker subnet (/16)")
ax.legend(frameon=False, ncol=2, loc="upper center"); ax.grid(axis="y", alpha=0.3)
if not PAPER: ax.set_title("Raw alerts by Docker subnet, lab-written knowledge base", fontweight="bold")
if not PAPER: fig.text(0.01, 0.01, "Two captures per subnet. Tactic-first misses brute force everywhere and token forgery everywhere "
             "except 172.30.", fontsize=8, color="#444")
fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(out / "fig_subnet_140.png", dpi=200); plt.close(fig)
print("tl", tl, "fl", fl)
