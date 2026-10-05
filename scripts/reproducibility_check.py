"""
SentinelMesh Reproducibility Verification Check Script.

Runs clean-state verification across:
  1. Attack Graph unit tests (graph/tests/)
  2. Log Tail Scenario Detector checks (detection/log-tail/)
  3. FastAPI Backend unit tests (backend/test_backend.py)
  4. RAG Engine Evaluation (rag_engine/src/evaluate.py)
  5. Knowledge Base Poisoning Detection (rag_engine/poisoning/poison_detection.py)
  6. Frontend Asset Verification (frontend/index.html)

Outputs a comprehensive reproducibility report to evaluation/results/reproducibility_report.json
and evaluation/results/reproducibility_report.md.
"""

from __future__ import annotations

import os
import sys
import json
import time
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT_DIR, "evaluation", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def run_step(name: str, cmd: list, env: dict = None) -> dict:
    t0 = time.time()
    current_env = os.environ.copy()
    if env:
        current_env.update(env)

    print(f"[{time.strftime('%H:%M:%S')}] Running {name}...")
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            env=current_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        duration = round(time.time() - t0, 3)
        passed = proc.returncode == 0
        output_snippet = (proc.stdout + "\n" + proc.stderr).strip()[-500:]
        print(f"    -> {'PASSED' if passed else 'FAILED'} ({duration}s)")
        return {
            "name": name,
            "passed": passed,
            "duration_seconds": duration,
            "exit_code": proc.returncode,
            "snippet": output_snippet,
        }
    except Exception as e:
        duration = round(time.time() - t0, 3)
        print(f"    -> ERROR: {e}")
        return {
            "name": name,
            "passed": False,
            "duration_seconds": duration,
            "exit_code": -1,
            "snippet": str(e),
        }


def main():
    print("=========================================================")
    print("  SentinelMesh Automated Reproducibility Verification  ")
    print("=========================================================\n")

    steps = []

    # 1. Graph Module Tests
    steps.append(run_step(
        "Attack Graph Unit Tests (69 tests)",
        [sys.executable, "-m", "unittest", "discover", "-s", "graph/tests", "-p", "test_*.py"]
    ))

    # 2. Log Tail Scenario Detector Checks
    log_tail_env = {"PYTHONPATH": os.path.join(ROOT_DIR, "detection", "log-tail")}
    steps.append(run_step(
        "Log-Tail Scenario Detector Checks (12 checks)",
        [sys.executable, "detection/log-tail/test_detectors.py"],
        env=log_tail_env
    ))

    # 3. FastAPI Backend Unit Tests
    steps.append(run_step(
        "FastAPI Backend Unit Tests (5 tests)",
        [sys.executable, "-m", "unittest", "backend/test_backend.py"]
    ))

    # 4. RAG Engine Evaluation Run
    steps.append(run_step(
        "RAG Engine Evaluation Benchmark",
        [sys.executable, "-m", "rag_engine.src.evaluate"]
    ))

    # 5. Poisoning Detection Check
    steps.append(run_step(
        "Knowledge Base Poisoning Scan",
        [sys.executable, "-m", "rag_engine.poisoning.poison_detection"]
    ))

    # 6. Frontend Asset Check
    frontend_path = os.path.join(ROOT_DIR, "frontend", "index.html")
    frontend_exists = os.path.exists(frontend_path)
    steps.append({
        "name": "Analyst Dashboard Frontend Asset Check",
        "passed": frontend_exists,
        "duration_seconds": 0.001,
        "exit_code": 0 if frontend_exists else 1,
        "snippet": f"Frontend asset exists at {frontend_path}" if frontend_exists else "Frontend index.html missing",
    })

    # Summary
    total_steps = len(steps)
    passed_steps = sum(1 for s in steps if s["passed"])
    all_passed = passed_steps == total_steps

    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_status": "REPRODUCIBLE_PASSED" if all_passed else "FAILED",
        "total_checks": total_steps,
        "passed_checks": passed_steps,
        "failed_checks": total_steps - passed_steps,
        "steps": steps,
    }

    # Save JSON Report
    json_path = os.path.join(RESULTS_DIR, "reproducibility_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Save Markdown Report
    md_path = os.path.join(RESULTS_DIR, "reproducibility_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# SentinelMesh Reproducibility Report\n\n")
        f.write(f"**Timestamp**: `{report_data['timestamp']}`  \n")
        f.write(f"**Status**: `{report_data['overall_status']}` ({passed_steps}/{total_steps} Passed)\n\n")
        f.write("## Test & Benchmark Execution Summary\n\n")
        f.write("| Step Name | Status | Duration | Exit Code |\n")
        f.write("|---|---|---|---|\n")
        for s in steps:
            f.write(f"| {s['name']} | {'✅ PASSED' if s['passed'] else '❌ FAILED'} | {s['duration_seconds']}s | {s['exit_code']} |\n")

    print("\n=========================================================")
    print(f"  Reproducibility Check Result: {'PASSED' if all_passed else 'FAILED'} ({passed_steps}/{total_steps})")
    print(f"  Report saved to: {json_path}")
    print("=========================================================")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
