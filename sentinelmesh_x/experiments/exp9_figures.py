import json, collections, csv
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np
from common import *
R = OUT; F = ROOT / "figures_x"
L = lambda n: json.loads((R / n).read_text())
bm, ga, cal, rob, e2e, eff = L("benchmark.json"), L("generalisation_ablation.json"), L("calibration.json"), L("robustness.json"), L("end_to_end.json"), L("efficiency.json")
def sv(n): plt.tight_layout(); plt.savefig(F / n, dpi=150); plt.close()
# 1 architecture
fig, ax = plt.subplots(figsize=(11, 3.2)); ax.axis("off")
boxes = ["Detectors\n(Falco + log-tail)", "Knowledge generator\n(AST + Falco parser)", "Alert\n(7-key)", "DAHR retrieval\nfield | TF-IDF | BM25 | hierarchy", "Calibrator\n(learned LR)", "Attack graph", "Risk + routing\n(auto/analyst/admin)"]
for i, b in enumerate(boxes):
    y = 0.62 if i == 1 else 0.3; x = 0.02 + i * 0.14
    ax.text(x + .06, y, b, ha="center", va="center", fontsize=7.5, bbox=dict(boxstyle="round", fc="#dfe9f5", ec="k"))
for i in range(len(boxes) - 1):
    ax.annotate("", xy=(0.02 + (i + 1) * .14 + .005, .3 if i + 1 != 1 else .62), xytext=(0.02 + i * .14 + .115, .3 if i != 1 else .62), arrowprops=dict(arrowstyle="->"))
ax.annotate("", xy=(0.02 + 3 * .14 + .03, .36), xytext=(0.02 + 1 * .14 + .1, .57), arrowprops=dict(arrowstyle="->"))
ax.set_title("SentinelMesh-X architecture (new components: generator, DAHR, calibrator)"); sv("fig1_architecture.png")
# 2 dataset table
S = alert_sets(); rows = []
for sname in ("dev", "test", "heldout"):
    cnt = collections.Counter(r["run"] for r in S[sname])
    for run, n in sorted(cnt.items()):
        r0 = next(r for r in S[sname] if r["run"] == run)
        rows.append([sname, run, r0["subnet"], r0["env"].get("host", "")[:28], r0["env"].get("docker", "")[:22], r0["env"].get("falco", ""), n])
with open(F / "table2_dataset.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["split", "capture", "subnet", "host", "docker", "falco", "labelled_alerts"]); w.writerows(rows)
fig, ax = plt.subplots(figsize=(11, 0.3 * len(rows) + 1)); ax.axis("off")
t = ax.table(cellText=rows, colLabels=["split", "capture", "subnet", "host", "docker", "falco", "alerts"], loc="center"); t.auto_set_font_size(False); t.set_fontsize(7); t.scale(1, 1.2)
ax.set_title("Dataset (all alerts are lab-generated attacks; no benign capture yet)"); sv("fig2_dataset_table.png")
# 3 coverage heatmap: tactic x technique, counts of test alerts per subnet
tactics = ["Initial Access", "Credential Access", "Lateral Movement", "Defense Evasion", "Exfiltration"]
techs = sorted(targets()); subs = sorted({r["subnet"] for r in S["test"]})
M = np.array([[sum(r["truth"] == t and r["subnet"] == s for r in S["test"]) for s in subs] for t in techs])
fig, ax = plt.subplots(figsize=(6, 4)); im = ax.imshow(M, cmap="Blues"); ax.set_xticks(range(len(subs)), subs); ax.set_yticks(range(len(techs)), techs)
for i in range(M.shape[0]):
    for j in range(M.shape[1]): ax.text(j, i, M[i, j], ha="center", va="center", fontsize=8)
ax.set_title("Attack coverage: 8 techniques (5 tactics of 14) x 5 subnets"); sv("fig3_attack_coverage.png")
# 4 retrieval comparison
fig, axs = plt.subplots(1, 3, figsize=(13, 3.6), sharey=True)
meths = ["repo_flat", "repo_two_layer", "tfidf", "bm25", "rrf", "supervised", "dahr", "registry"]
for ax, form in zip(axs, QUERY_FORMS):
    vals = [next(r for r in bm["rows"] if r["corpus"] == "corpus_full" and r["kb"] == "auto" and r["form"] == form and r["set"] == "test" and r["method"] == m)["P@1"] for m in meths]
    ax.bar(range(len(meths)), vals); ax.set_xticks(range(len(meths)), meths, rotation=60, ha="right", fontsize=7); ax.set_title(f"{form} (706 records, generated knowledge)")
axs[0].set_ylabel("P@1 (140 test alerts)"); sv("fig4_retrieval_comparison.png")
with open(F / "table4_retrieval_metrics.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["corpus", "kb", "form", "set", "method", "P@1", "R@3", "R@5", "MRR", "nDCG@5", "macroF1", "n"])
    for r in bm["rows"]: w.writerow([r[k] for k in ("corpus", "kb", "form", "set", "method", "P@1", "R@3", "R@5", "MRR", "nDCG@5", "macroF1", "n")])
# 5 ablation
fig, ax = plt.subplots(figsize=(9, 4)); ab = ga["ablation"]; names = [k for k in ab["none"] if ab["none"][k]]
for i, mode in enumerate(["none", "drop", "noise", "rename"]):
    ax.bar(np.arange(len(names)) + i * .2, [ab[mode].get(n, {"MRR": 0})["MRR"] if ab[mode].get(n) else 0 for n in names], .2, label=mode)
ax.set_xticks(np.arange(len(names)) + .3, names, rotation=45, ha="right", fontsize=7); ax.set_ylabel("MRR"); ax.legend(title="perturbation"); ax.set_title("Ablation (test alerts)"); sv("fig5_ablation.png")
# 6 generalisation
def mean(rows, m, key): v = [r["P@1"] for r in rows if r["method"] == m and (key is None or True)]; return float(np.mean(v))
ms = ["tfidf", "bm25", "dahr", "supervised"]
groups = {"test (seen)": [next(r for r in bm["rows"] if r["corpus"] == "corpus_full" and r["kb"] == "auto" and r["form"] == "raw" and r["set"] == "test" and r["method"] == m)["P@1"] for m in ms],
          "leave-one-subnet-out": [mean(ga["leave_one_subnet_out"], m, None) for m in ms], "held-out variants": [mean(ga["heldout_variants"], m, None) for m in ms],
          "leave-one-technique-out": [mean(ga["leave_one_technique_out"], m, None) for m in ms]}
fig, ax = plt.subplots(figsize=(9, 3.8))
for i, (g, v) in enumerate(groups.items()): ax.bar(np.arange(4) + i * .2, v, .2, label=g)
ax.set_xticks(np.arange(4) + .3, ms); ax.set_ylabel("P@1 (mean over query forms)"); ax.legend(fontsize=7); ax.set_title("Seen vs unseen environments / variants / techniques"); sv("fig6_generalisation.png")
# 7 calibration
fig, axs = plt.subplots(1, 3, figsize=(11, 3.6))
for ax, k in zip(axs, ["manual_weights (original)", "raw_fused_score", "learned_LR"]):
    rel = cal[k]["reliability"]; ax.plot([0, 1], [0, 1], "k--"); ax.plot([b["conf"] for b in rel], [b["acc"] for b in rel], "o-")
    ax.set_title(f"{k}\nBrier {cal[k]['brier']:.3f}  ECE {cal[k]['ECE10']:.3f}", fontsize=8); ax.set_xlabel("confidence"); ax.set_ylabel("accuracy")
sv("fig7_calibration.png")
# 8 robustness
fig, axs = plt.subplots(1, 2, figsize=(11, 3.6))
A = rob["A_kb_poisoning"]; ks = [1, 2, 4, 8]
for mode in ("swap_description", "stuff", "swap_signature"):
    axs[0].plot(ks, [A[f"{mode}|k={k}"]["raw"]["dahr"]["ASR"] for k in ks], "o-", label=f"DAHR {mode}")
axs[0].plot(ks, [A[f"swap_description|k={k}"]["raw"]["bm25"]["ASR"] for k in ks], "x--", label="BM25 swap_description"); axs[0].set_xlabel("poisoned records"); axs[0].set_ylabel("attack success rate"); axs[0].legend(fontsize=6); axs[0].set_title("KB poisoning (raw)")
C = rob["C_D_detector_output_and_unseen_corruption"]; nm = list(C); axs[1].bar(np.arange(len(nm)) - .2, [C[n]["raw"]["dahr"]["acc_attack"] for n in nm], .4, label="DAHR"); axs[1].bar(np.arange(len(nm)) + .2, [C[n]["raw"]["bm25"]["acc_attack"] for n in nm], .4, label="BM25")
axs[1].set_xticks(range(len(nm)), nm, rotation=45, ha="right", fontsize=7); axs[1].set_ylabel("accuracy under attack"); axs[1].legend(); axs[1].set_title("Alert manipulation / corruption (raw)"); sv("fig8_robustness.png")
# 9 end to end table
cols = ["retrieval_acc", "chain_stage_acc", "routing_matches_oracle", "under_escalated", "latency_ms_per_alert_retrieval", "missed_slots", "auto_on_wrong_prediction", "chain_path_exact_captures"]
tbl = [[c, f"{e2e['mean_P0'][c]:.3f}", f"{e2e['mean_PX'][c]:.3f}"] for c in cols]
with open(F / "table9_end_to_end.csv", "w", newline="") as f: w = csv.writer(f); w.writerow(["metric", "P0 original", "PX SentinelMesh-X"]); w.writerows(tbl)
fig, ax = plt.subplots(figsize=(7, 3)); ax.axis("off"); t = ax.table(cellText=tbl, colLabels=["metric (mean over 10 captures)", "P0 original", "PX SentinelMesh-X"], loc="center"); t.auto_set_font_size(False); t.set_fontsize(8); sv("fig9_end_to_end.png")
# 10 efficiency
fig, axs = plt.subplots(1, 2, figsize=(10, 3.6))
for m in ("tfidf", "bm25", "dahr"):
    d = [r for r in eff["kb"] if r["method"] == m]; axs[0].plot([r["records"] for r in d], [r["mean_ms"] for r in d], "o-", label=m)
axs[0].set_xscale("log"); axs[0].set_xlabel("KB records (>706 synthetic)"); axs[0].set_ylabel("mean latency ms"); axs[0].legend()
axs[1].plot([v["alerts"] for v in eff["volume"]], [v["alerts_per_s"] for v in eff["volume"]], "o-"); axs[1].set_xlabel("alert volume"); axs[1].set_ylabel("alerts/s (DAHR, 706 records)"); sv("fig10_efficiency.png")
print("figures ok")
