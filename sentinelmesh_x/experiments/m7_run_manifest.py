"""M7: machine-readable run manifest + verification that the frozen M1 results are byte-identical."""
import hashlib, json, os, platform, subprocess, sys
from importlib import metadata
from pathlib import Path
R = Path(__file__).resolve().parents[2]; sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
frozen = {}; 
for l in (R / "results_x_v3/M1_FROZEN_RESULT_HASHES.txt").read_text().splitlines():
    h, f = l.split(None, 1); frozen[f.strip()] = h
changed = [f for f, h in frozen.items() if not (R / f).exists() or sha(R / f) != h]
alerts = hashlib.sha256(b"".join(sha(p).encode() for p in sorted((R / "eval").glob("runs*/*/alerts.jsonl")))).hexdigest()
pk = ["numpy", "scipy", "scikit-learn", "pandas", "matplotlib", "cryptography", "PyYAML", "fastapi", "starlette", "pytest", "onnxruntime"]
man = {"schema": "smx-run-manifest/1", "python": platform.python_version(), "platform": platform.platform(), "cpu": subprocess.run("lscpu | grep 'Model name' | head -1 | cut -d: -f2", shell=True, capture_output=True, text=True).stdout.strip(),
       "cores": os.cpu_count(), "packages": {p: metadata.version(p) for p in pk}, "seeds": {"SEED": 20261105, "calibration_bootstrap": 20261106, "annotation_packet": 20261105},
       "inputs": {"ground_truth_sha256": sha(R / "eval/ground_truth.json"), "held_out_ground_truth_sha256": sha(R / "eval/held_out_ground_truth.json"), "all_alerts_jsonl_combined_sha256": alerts},
       "m1_frozen_files_checked": len(frozen), "m1_frozen_files_changed": changed, "results_v3_sha256": {p.name: sha(p) for p in sorted((R / "results_x_v3").glob("*.json"))},
       "external_data": json.loads((R / "results_x_v3/m4_external_eval.json").read_text())["provenance"], "git_commit": "NOT AVAILABLE (project was delivered as a zip without .git)"}
(R / "results_x_v3/RUN_MANIFEST.json").write_text(json.dumps(man, indent=1)); print("frozen M1 files changed:", changed, "| checked", len(frozen))
