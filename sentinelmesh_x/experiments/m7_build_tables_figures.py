"""M7: manuscript-ready tables (CSV + Markdown + LaTeX) and figures 12-18 from the versioned result files. Nothing is recomputed here."""
import csv, json
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np
from pathlib import Path
R = Path(__file__).resolve().parents[2]; V2, V3, F, T = R / "results_x_v2", R / "results_x_v3", R / "figures_x", R / "tables_x"; T.mkdir(exist_ok=True)
L = lambda p: json.loads(p.read_text())
m1b, m1t, m1c = L(V2 / "detector_independent_benchmark.json"), L(V2 / "tuning_nested.json"), L(V2 / "calibration_v2.json"); m1a = L(V2 / "detector_aware_benchmark.json"); aud = L(V2 / "leakage_audit.json")
m2, m3, m4, m5z, m5a, m5e, m6a, m6e = (L(V3 / n) for n in ("m2_safety_eval.json", "m3_integrity_eval.json", "m4_external_eval.json", "m5_zero_shot.json", "m5_ablation_stats.json", "m5_external_stats.json", "m6_adaptive_attacks.json", "m6_efficiency.json"))
f3 = lambda x: "" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))
def table(name, header, rows, caption):
    with open(T / f"{name}.csv", "w", newline="") as f: w = csv.writer(f); w.writerow(header); w.writerows(rows)
    md = f"**{caption}**\n\n| " + " | ".join(header) + " |\n|" + "---|" * len(header) + "\n" + "\n".join("| " + " | ".join(f3(c) for c in r) + " |" for r in rows) + "\n"
    (T / f"{name}.md").write_text(md)
    tex = "\\begin{table}[t]\\centering\\caption{" + caption.replace("_", "\\_").replace("%", "\\%") + "}\n\\begin{tabular}{" + "l" * len(header) + "}\\hline\n" + " & ".join(h.replace("_", "\\_") for h in header) + " \\\\\\hline\n" + \
        "\n".join(" & ".join(f3(c).replace("_", "\\_").replace("%", "\\%") for c in r) + " \\\\" for r in rows) + "\n\\hline\\end{tabular}\\end{table}\n"
    (T / f"{name}.tex").write_text(tex)
# ---- tables
fam = {(c["corpus"], c["B"]): c for c in m1b["paired_stats"]["comparisons"]}
rows = []
for m in ("tfidf", "bm25", "rrf", "dahr", "repo_flat", "repo_two_layer", "supervised"):
    r = next(x for x in m1b["rows"] if x["corpus"] == "corpus_full" and x["set"] == "test" and x["method"] == m)
    a = next(x for x in m1a["rows"] if x["corpus"] == "corpus_full" and x["kb"] == "auto" and x["form"] == "raw" and x["method"] == m)
    rows.append([m, a["P@1"], r["P@1"], f"[{r['P@1_ci95_cluster'][0]:.2f},{r['P@1_ci95_cluster'][1]:.2f}]", r["R@5"], r["MRR"]])
table("T1_track_a_vs_b", ["method", "TrackA_P@1_raw", "TrackB_P@1", "TrackB_CI95_cluster", "TrackB_R@5", "TrackB_MRR"], rows, "Detector-aware (A) vs detector-independent (B) retrieval, 706 records, 140 test alerts")
table("T2_leakage_audit", ["query_form", "queries_with_detector_wording", "of"], [[k, v["queries_with_leakage"], v["of"]] for k, v in aud["existing_query_forms_test_set"].items()] + [["track_b_independent", aud["track_b_queries_with_leakage"], aud["track_b_queries_total"]]], "Leakage audit of query construction")
table("T3_calibration", ["track", "predictor", "Brier", "Brier_CI95", "ECE10", "slope", "intercept"], [[t, k, m1c[t]["overall"][k]["brier"]["value"], str([round(x, 3) for x in m1c[t]["overall"][k]["brier"]["ci95"]]), m1c[t]["overall"][k]["ece10"]["value"], (m1c[t]["overall"][k]["slope_intercept"] or {}).get("slope"), (m1c[t]["overall"][k]["slope_intercept"] or {}).get("intercept")] for t in "AB" for k in ("manual_confidence_original", "raw_fused_score", "learned_LR")], "Calibration with original-alert cluster bootstrap (140 original alerts)")
o = m2["overall"]; table("T4_safety_gate", ["policy", "under_escalation", "over_escalation", "auto_rate", "auto_on_wrong_prediction", "route_matches_oracle"], [[p, o[p]["under_escalation"], o[p]["over_escalation"], o[p]["auto_rate"], o[p]["auto_on_wrong_prediction"], o[p]["route_matches_oracle"]] for p in ("P0_legacy_manual", "P1_learned_conf_legacy_formula", "P2_safety_gate")], "Routing under degraded and attacked inputs (6,160 observations of 140 alerts; oracle never selects auto)")
table("T5_integrity", ["attack", "detection_rate", "expected_failure_code_rate"], [[k, v["detection_rate"], v["expected_failure_code_rate"]] for k, v in m3["attacks"].items()] + [["false_positive_benign_reserialisation", m3["false_positive_rate_benign_reserialisation"]["rate"], ""]], "Cryptographic KB integrity (300 trials per attack; local-dev Ed25519 signing)")
d = m4["detector_aware_sigma"]; table("T6_external", ["measure", "value"], [["Sigma rules usable", m4["sigma_rules"]["usable_after_parsing"]], ["Atomic events", m4["atomic"]["events"]], ["techniques with executable detector knowledge and independent events", m4["coverage"]["executable_detector_knowledge_AND_independent_test_events"]["techniques"]],
    ["rule fire rate", d["fire_rate"]], ["precision top-1 when fired", d["precision_top1_given_fired"]], ["CI95 (cluster by atomic test)", str([round(x, 3) for x in d["precision_top1_given_fired_ci95_test_cluster"]])], ["abstained on unsupported-technique events", d["abstained_on_unsupported"]],
    ["TF-IDF P@1 all events", m4["text_only_baselines"]["tfidf"]["P@1"]], ["BM25 P@1", m4["text_only_baselines"]["bm25"]["P@1"]], ["LSA (non-pretrained dense) P@1", m4["text_only_baselines"]["lsa_dense_nonpretrained"]["P@1"]]], "Independent validation: Sigma rules x Atomic Red Team (not real telemetry; no benign data)")
table("T7_zero_shot", ["regime", "top1", "R@5", "no_abstention_false_confident", "abstain_rate", "false_confident_after_abstention", "selective_accuracy"], [[k, m5z[k]["top1"], m5z[k]["R@5"], m5z[k]["no_abstention_false_confident_rate"], m5z[k]["abstain_rate"], m5z[k]["false_confident_after_abstention"], m5z[k]["selective_accuracy_on_answered"]] for k in ("known", "unseen")], "Known vs unseen techniques with confidence-based abstention")
table("T8_ablation", ["variant", "MRR", "CI95_cluster", "diff_vs_full", "diff_CI95_cluster"], [[n, v["MRR"], str([round(x, 3) for x in v["MRR_ci95"]]), *( [next((p["mean_diff_MRR"] for p in m5a["paired_vs_full"] if p["variant"] == n), 0.0), str([round(x, 3) for x in next((p["diff_ci95_cluster"] for p in m5a["paired_vs_full"] if p["variant"] == n), [0, 0])])])] for n, v in m5a["variants"].items()], "Channel ablation with two-way cluster bootstrap")
table("T9_adaptive", ["attack", "legacy_wrong_pred", "safe_wrong_pred", "safe_under_escalation", "safe_auto_route", "conflict_flag_rate"], [[k, v["legacy_wrong_prediction_rate"], v["safe_pipeline_wrong_prediction_rate"], v["safe_under_escalation"], v["safe_auto_route_rate"], v["conflict_flag_rate"]] for k, v in m6a.items() if k != "note"], "Adaptive attacks (140 test alerts)")
table("T10_efficiency", ["records", "method", "p50_ms", "p95_ms", "p99_ms", "alerts_per_s", "cpu_util", "index_build_s", "peak_index_MB"], [[x["records"], x["method"], x["p50"]["mean"], x["p95"]["mean"], x["p99"]["mean"], x["throughput"]["mean"], x["cpu_util"]["mean"], x["index_build_s"], x["peak_index_MB_tracemalloc"]] for x in m6e["kb"]], "CPU-only efficiency (>706 records are synthetic replicas)")
# ---- figures
fig, ax = plt.subplots(figsize=(12, 3.6)); ats = list(m2["by_attack"]); w = .27
for i, (p, lab) in enumerate((("P0_legacy_manual", "legacy"), ("P1_learned_conf_legacy_formula", "learned conf, legacy formula"), ("P2_safety_gate", "safety gate"))):
    ax.bar(np.arange(len(ats)) + (i - 1) * w, [m2["by_attack"][a][p]["under_escalation"] for a in ats], w, label=lab)
ax.set_xticks(range(len(ats)), ats, rotation=40, ha="right", fontsize=7); ax.set_ylabel("under-escalation rate"); ax.legend(); ax.set_title("M2: routing under missing / corrupted / attacker-controlled fields"); plt.tight_layout(); plt.savefig(F / "fig12_safety_gate.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(9, 3.6)); k = list(m3["attacks"]); ax.barh(k, [m3["attacks"][x]["detection_rate"] for x in k]); ax.set_xlim(0, 1.05); ax.set_xlabel("detection rate (300 trials each)"); ax.set_title(f"M3: integrity detection; false positives {m3['false_positive_rate_benign_reserialisation']['rate']:.3f}"); plt.tight_layout(); plt.savefig(F / "fig13_integrity.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(8, 3.6)); labs = ["Sigma\n(all events)", "TF-IDF\n(all events)", "Sigma\n(fired only)", "TF-IDF\n(fired only)"]; c = m5e["comparisons"]
ax.bar(labs, [c[0]["sigma_top1"], c[0]["tfidf_top1"], c[2]["sigma_top1"], c[2]["tfidf_top1"]]); ax.set_ylabel("top-1"); ax.set_title("M4/M5: independent Sigma x Atomic events (5,935 events, 1,320 tests)"); plt.tight_layout(); plt.savefig(F / "fig14_external_validation.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(7, 3.6)); kk = ["top1", "no_abstention_false_confident_rate", "abstain_rate", "false_confident_after_abstention"]
for i, reg in enumerate(("known", "unseen")): ax.bar(np.arange(4) + i * .4, [m5z[reg][x] for x in kk], .4, label=reg)
ax.set_xticks(np.arange(4) + .2, ["top-1", "false confident\n(no abstain)", "abstain rate", "false confident\n(after abstain)"], fontsize=8); ax.legend(); ax.set_title("M5: unseen techniques and abstention"); plt.tight_layout(); plt.savefig(F / "fig15_zero_shot_abstention.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(12, 3.4)); ax.axis("off")
bx = ["Detectors\n(Falco, log-tail)", "Signed KB\n(SHA-256 + Ed25519)", "Alert", "Field trust\n+ sanitiser", "DAHR\n(full + trusted view)", "Calibrator", "Policy engine\n(fail-closed)", "Executor\n(simulator, kill switch)", "Audit log\n(hash chain)"]
for i, b in enumerate(bx): ax.text(.055 + i * .11, .5, b, ha="center", va="center", fontsize=7, bbox=dict(boxstyle="round", fc="#e6efe0" if i in (1, 3, 6, 7, 8) else "#dfe9f5", ec="k"))
for i in range(len(bx) - 1): ax.annotate("", xy=(.055 + (i + 1) * .11 - .042, .5), xytext=(.055 + i * .11 + .042, .5), arrowprops=dict(arrowstyle="->"))
ax.set_title("SentinelMesh-X v2 (green = added in M2/M3/M6)"); plt.tight_layout(); plt.savefig(F / "fig16_architecture_v2.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(7, 3.6))
for m in ("tfidf", "bm25", "dahr"): d_ = [x for x in m6e["kb"] if x["method"] == m]; ax.errorbar([x["records"] for x in d_], [x["p50"]["mean"] for x in d_], [x["p50"]["std"] for x in d_], marker="o", label=m)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("records (>706 synthetic)"); ax.set_ylabel("p50 latency ms"); ax.legend(); ax.set_title("M6: scaling"); plt.tight_layout(); plt.savefig(F / "fig17_efficiency_v2.png", dpi=150); plt.close()
fig, ax = plt.subplots(figsize=(8, 3.6)); an = [k for k in m6a if k != "note"]; ax.bar(np.arange(len(an)) - .2, [m6a[a]["legacy_wrong_prediction_rate"] for a in an], .4, label="wrong prediction (legacy)"); ax.bar(np.arange(len(an)) + .2, [m6a[a]["safe_under_escalation"] for a in an], .4, label="under-escalation (safe pipeline)")
ax.set_xticks(range(len(an)), [a.replace("_", "\n", 2) for a in an], fontsize=6); ax.legend(fontsize=7); ax.set_title("M6: adaptive attacks"); plt.tight_layout(); plt.savefig(F / "fig18_adaptive_attacks.png", dpi=150); plt.close()
print("tables", len(list(T.glob("*.csv"))), "figures ok")
