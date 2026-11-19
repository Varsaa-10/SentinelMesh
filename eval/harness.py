
#!/usr/bin/env python3
"""
harness.py — SentinelMesh Module A3 logging harness + Baseline 1 runner.

Runs:
    1. Falco via falco_shim.py
    2. log-tail tailer.py
    3. S7 Grafana detector (optional)
    4. attack scripts (optional)

The harness captures all detector output into a timestamped run folder,
merges alerts into alerts.jsonl, scores them against ground_truth.json,
and writes baseline1_results.json.

S7 Grafana detector:
    scenario7_grafana_detector.py

The S7 detector watches:
    docker logs -f <grafana-container>

and emits JSON alerts for:
    - Successful Grafana login
    - Anonymous dashboard/API access
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.attribute import attribute_alerts, summarize_attribution  # noqa: E402


# ---------------------------------------------------------------------------
# Attack order
# ---------------------------------------------------------------------------

STOCK_FALCO_FILES = (
    "falco_rules.yaml",
    "falco-incubating_rules.yaml",
    "falco-sandbox_rules.yaml",
)

# All single-technique scenarios (S1-S9 + ENV2 S11-S28).
# S10 (chain) is appended when --chain-script is supplied.
# S29 (privileged debug container) is appended ONLY when --privileged-debug is passed.
DEFAULT_ATTACK_ORDER = [
    ("S1", "scenario1_sqli.sh", "bash"),
    ("S2", "scenario2_bruteforce.sh", "bash"),
    ("S3", "scenario3_default_credentials.sh", "bash"),
    ("S4", "scenario4_jwt_confusion.py", "python3"),
    ("S5", "scenario5_db_connection.sh", "bash"),
    ("S6", "scenario6_log_tampering.sh", "bash"),
    ("S7", "scenario7_grafana_default_creds.sh", "bash"),
    ("S9", "scenario9_credential_access.sh", "bash"),
    ("S8", "scenario8_exfiltration.sh", "bash"),
    ("S11", "scenario11_terminal_shell.sh", "bash"),
    ("S12", "scenario12_search_private_keys.sh", "bash"),
    ("S13", "scenario13_memfd_exec.sh", "bash"),
    ("S14", "scenario14_ptrace_attach.sh", "bash"),
    ("S15", "scenario15_packet_socket.sh", "bash"),
    ("S16", "scenario16_remove_bulk_data.sh", "bash"),
    ("S17", "scenario17_exec_dev_shm.sh", "bash"),
    ("S18", "scenario18_cron_persistence.sh", "bash"),
    ("S19", "scenario19_shell_config.sh", "bash"),
    ("S20", "scenario20_useradd.sh", "bash"),
    ("S21", "scenario21_setuid.sh", "bash"),
    ("S22", "scenario22_remote_file_copy.sh", "bash"),
    ("S23", "scenario23_authorized_keys.sh", "bash"),
    ("S24", "scenario24_read_proc_environ.sh", "bash"),
    ("S25", "scenario25_network_tool.sh", "bash"),
    ("S26", "scenario26_hidden_files.sh", "bash"),
    ("S27", "scenario27_decode_payload.sh", "bash"),
    ("S28", "scenario28_delete_shell_history.sh", "bash"),
]

PRIVILEGED_DEBUG_SCENARIO = ("S29", "scenario29_privileged_mount.sh", "bash")


SECONDS_BETWEEN_ATTACKS = 15
QUIET_MARGIN_SECONDS = 3  # benign-free margin before window start and after window end


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def now_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def log(msg):
    print(f"[harness] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Falco
# ---------------------------------------------------------------------------

def resolve_rule_files(rules_dir, include_stock_falco=False, stock_falco_dir=None):
    """Collect custom s0*.yaml rule files and optionally stock Falco rules."""
    rules_dir = Path(rules_dir)
    rule_files = sorted(rules_dir.glob("s0*.yaml"))

    if not rule_files:
        log(f"WARNING: no s0*.yaml rule files found in {rules_dir}")

    if include_stock_falco:
        if stock_falco_dir is not None:
            stock_dir = Path(stock_falco_dir)
        else:
            candidate = rules_dir.parent / "falco-stock"
            stock_dir = candidate if candidate.exists() else REPO_ROOT / "detection" / "falco-stock"
        for fname in STOCK_FALCO_FILES:
            sf = stock_dir / fname
            if not sf.exists():
                raise FileNotFoundError(f"Stock Falco rule file not found: {sf}")
            rule_files.append(sf)

    return rule_files


def build_falco_command(rules_dir, include_stock_falco=False, stock_falco_dir=None):
    """Build the stdbuf/falco command line with ordered -r rule arguments."""
    rule_files = resolve_rule_files(
        rules_dir,
        include_stock_falco=include_stock_falco,
        stock_falco_dir=stock_falco_dir,
    )
    cmd = ["stdbuf", "-oL", "falco", "-o", "json_output=true"]
    for rf in rule_files:
        cmd += ["-r", str(rf)]
    return cmd


def start_falco(
    rules_dir,
    shim_path,
    out_path,
    stderr_dir,
    include_stock_falco=False,
    stock_falco_dir=None,
):
    falco_cmd = build_falco_command(
        rules_dir,
        include_stock_falco=include_stock_falco,
        stock_falco_dir=stock_falco_dir,
    )

    log(
        f"starting falco: {' '.join(falco_cmd)} | {shim_path}"
    )

    out_f = open(out_path, "w")
    falco_err_f = open(
        stderr_dir / "falco_stderr.log",
        "w",
    )
    shim_err_f = open(
        stderr_dir / "shim_stderr.log",
        "w",
    )

    falco_proc = subprocess.Popen(
        falco_cmd,
        stdout=subprocess.PIPE,
        stderr=falco_err_f,
    )

    shim_proc = subprocess.Popen(
        [sys.executable, str(shim_path)],
        stdin=falco_proc.stdout,
        stdout=out_f,
        stderr=shim_err_f,
    )

    falco_proc.stdout.close()

    return (
        falco_proc,
        shim_proc,
        out_f,
        falco_err_f,
        shim_err_f,
    )


# ---------------------------------------------------------------------------
# Log tailer
# ---------------------------------------------------------------------------

def start_tailer(
    tailer_path,
    webapp_log,
    auth_log,
    out_path,
    stderr_dir,
):
    cmd = [
        sys.executable,
        str(tailer_path),
        "--files",
        f"webapp={webapp_log}",
        f"authservice={auth_log}",
    ]

    log(f"starting tailer: {' '.join(cmd)}")

    out_f = open(out_path, "w")
    err_f = open(
        stderr_dir / "tailer_stderr.log",
        "w",
    )

    proc = subprocess.Popen(
        cmd,
        stdout=out_f,
        stderr=err_f,
    )

    return proc, out_f, err_f


# ---------------------------------------------------------------------------
# S7 Grafana detector
# ---------------------------------------------------------------------------

def start_grafana_detector(
    detector_path,
    container_name,
    out_path,
    stderr_dir,
):
    """
    Start the S7 Grafana detector.

    The detector itself follows:
        docker logs -f <container>

    Its stdout is expected to contain JSON alert lines generated by
    emit_alert().
    """

    cmd = [
        sys.executable,
        str(detector_path),
        "--container",
        container_name,
    ]

    log(
        f"starting Grafana detector: {' '.join(cmd)}"
    )

    out_f = open(out_path, "w")

    err_f = open(
        stderr_dir / "grafana_detector_stderr.log",
        "w",
    )

    proc = subprocess.Popen(
        cmd,
        stdout=out_f,
        stderr=err_f,
    )

    return proc, out_f, err_f


# ---------------------------------------------------------------------------
# Attack scripts
# ---------------------------------------------------------------------------

def build_attack_order(chain_script=None, privileged_debug=False):
    """Return ordered (scenario, filename, interpreter, extra_args) tuples."""
    order = [(sid, fname, interp, []) for sid, fname, interp in DEFAULT_ATTACK_ORDER]
    if privileged_debug:
        sid, fname, interp = PRIVILEGED_DEBUG_SCENARIO
        order.append((sid, fname, interp, ["--privileged-debug"]))
    if chain_script:
        order.append(("S10", chain_script, "bash", []))
    return order


def start_benign_workload(script_path, duration_minutes, log_path, out_dir=None, attack_lock_path=None):
    """Launch linux_run/benign_workload.sh asynchronously and return (proc, log_f)."""
    cmd = ["bash", str(script_path), "--duration", str(duration_minutes)]
    env = os.environ.copy()
    if out_dir is not None:
        env["OUT"] = str(out_dir)
    if attack_lock_path is not None:
        env["SM_ATTACK_LOCK"] = str(attack_lock_path)
    elif out_dir is not None:
        env["SM_ATTACK_LOCK"] = str(Path(out_dir) / "attack.lock")
    log(f"starting benign workload: {' '.join(cmd)}")
    log_f = open(log_path, "w")
    proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT, env=env)
    return proc, log_f


def load_benign_actions(actions_path):
    """Load benign action records from a JSONL file, if present."""
    path = Path(actions_path)
    if not path.exists():
        return []
    actions = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                actions.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                log(f"WARNING: skipping invalid benign action at {path}:{line_no}: {exc}")
    return actions


def collect_container_image_digests():
    """Return running containers paired with their image tags, IDs, and repo digests."""
    try:
        ps_proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return []
    if ps_proc.returncode != 0:
        return []

    names = sorted(line.strip() for line in ps_proc.stdout.splitlines() if line.strip())
    entries = []
    for name in names:
        config_image = ""
        image_id = ""
        repo_digest = ""
        try:
            c_proc = subprocess.run(
                ["docker", "inspect", "-f", "{{.Config.Image}}\t{{.Image}}", name],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if c_proc.returncode == 0 and c_proc.stdout.strip():
                parts = c_proc.stdout.strip().split("\t", 1)
                config_image = parts[0]
                image_id = parts[1] if len(parts) > 1 else ""
        except Exception:
            pass

        lookup_ref = image_id or config_image
        if lookup_ref:
            try:
                i_proc = subprocess.run(
                    ["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", lookup_ref],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if i_proc.returncode == 0 and i_proc.stdout.strip():
                    digests = json.loads(i_proc.stdout.strip())
                    if isinstance(digests, list) and digests:
                        repo_digest = str(digests[0])
            except Exception:
                pass

        entries.append(
            {
                "container": name,
                "config_image": config_image,
                "image_id": image_id,
                "repo_digest": repo_digest,
            }
        )
    return entries


def write_run_manifest(run_path):
    """Write run metadata and running container image digests to run_manifest.txt."""
    run_path = Path(run_path)
    manifest_path = run_path / "run_manifest.txt"
    containers = collect_container_image_digests()

    lines = [
        f"date_utc: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"running_containers: {len(containers)}",
    ]
    for entry in containers:
        digest = entry["repo_digest"] or entry["image_id"] or "unknown"
        lines.append(
            f"{entry['container']} image={entry['config_image'] or 'unknown'} "
            f"digest={digest} image_id={entry['image_id'] or 'unknown'}"
        )

    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest_path


def run_attack_scripts(
    attack_scripts_dir,
    chain_script=None,
    privileged_debug=False,
    lock_path=None,
    busy_timeout=60.0,
):
    attack_scripts_dir = Path(attack_scripts_dir)
    order = build_attack_order(
        chain_script=chain_script,
        privileged_debug=privileged_debug,
    )

    lock_file = Path(lock_path) if lock_path is not None else None
    busy_file = Path(f"{lock_file}.busy") if lock_file is not None else None
    if lock_file is not None:
        lock_file.parent.mkdir(parents=True, exist_ok=True)

    scenario_windows = {}
    quiet_margin = QUIET_MARGIN_SECONDS if lock_file is not None else 0
    post_wait = min(3, max(1, SECONDS_BETWEEN_ATTACKS - 1)) if SECONDS_BETWEEN_ATTACKS > 1 else 0
    lock_tail_wait = quiet_margin if SECONDS_BETWEEN_ATTACKS > 0 else 0
    inter_gap = (
        max(1, SECONDS_BETWEEN_ATTACKS - quiet_margin - post_wait - lock_tail_wait)
        if SECONDS_BETWEEN_ATTACKS > 0
        else 0
    )

    for scenario, filename, interpreter, extra_args in order:
        script_path = (attack_scripts_dir / filename).resolve()

        if not script_path.exists():
            log(
                f"SKIPPING {scenario}: "
                f"{script_path} not found"
            )
            continue

        lock_start_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            if lock_file is not None:
                lock_file.write_text(f"{scenario}\n", encoding="utf-8")
                deadline = time.monotonic() + busy_timeout
                while busy_file.exists():
                    if time.monotonic() >= deadline:
                        log(
                            f"WARNING: benign busy file {busy_file} still present after "
                            f"{busy_timeout:.0f}s before {scenario}, continuing"
                        )
                        break
                    time.sleep(0.1)
                # Quiet margin: benign tolerance is +/-2 s on whole-second timestamps.
                time.sleep(quiet_margin)

            start_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            log(f"firing {scenario}: {filename}")

            try:
                result = subprocess.run(
                    [interpreter, str(script_path), *extra_args],
                    timeout=30,
                    capture_output=True,
                    text=True,
                )

                if result.stdout:
                    log(f"{scenario} stdout:\n{result.stdout.strip()}")

                if result.stderr:
                    log(f"{scenario} stderr:\n{result.stderr.strip()}")

            except subprocess.TimeoutExpired:
                log(f"WARNING: {filename} timed out after 30s, continuing")

            except Exception as exc:
                log(f"WARNING: {filename} raised {exc}, continuing")

            time.sleep(post_wait)
            end_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if lock_file is not None and lock_tail_wait:
                time.sleep(lock_tail_wait)
        finally:
            if lock_file is not None:
                lock_file.unlink(missing_ok=True)
            lock_end_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if lock_file is not None:
            scenario_windows[scenario] = {
                "start": start_ts,
                "end": end_ts,
                "lock_start": lock_start_ts,
                "lock_end": lock_end_ts,
            }
        else:
            scenario_windows[scenario] = {"start": start_ts, "end": end_ts}
        if inter_gap:
            time.sleep(inter_gap)

    return scenario_windows, scenario_windows.get("S10")


# ---------------------------------------------------------------------------
# Chain tagging
# ---------------------------------------------------------------------------

CHAIN_STAGES = ["S1", "S3", "S4", "S9", "S8"]  # eval/ground_truth.json S10.expected_alerts_in_order


def tag_chain_alerts(alerts, chain_window, stages=CHAIN_STAGES, chain_id="S10"):
    """Mark alerts produced by the chain script.

    Alerts keep their component `scenario` (S1, S3, ...) so per-scenario
    scoring is unchanged. Alerts whose timestamp falls inside the window in
    which the chain script ran, and whose scenario is a chain stage, also get
    chain_id="S10" and component_scenario=<scenario>. That is what lets the
    graph reconstruct a path for S10 itself.
    """
    if not chain_window or not chain_window.get("start"):
        return 0
    start = chain_window["start"]
    end = chain_window.get("end") or "9999-12-31T23:59:59Z"
    n = 0
    for a in alerts:
        ts = a.get("timestamp", "")
        if start <= ts <= end and a.get("scenario") in stages:
            a["chain_id"] = chain_id
            a["component_scenario"] = a["scenario"]
            n += 1
    return n


# ---------------------------------------------------------------------------
# Merge alerts
# ---------------------------------------------------------------------------

def merge_alerts(
    falco_out_path,
    tailer_out_path,
    merged_path,
    grafana_out_path=None,
    chain_window=None,
):
    """
    Merge all detector JSONL output into one timestamp-sorted file.

    Falco/shim:
        falco_alerts_raw.jsonl

    Log tailer:
        logtail_alerts_raw.jsonl

    S7 Grafana detector:
        grafana_alerts_raw.jsonl
    """

    alerts = []

    paths = [
        falco_out_path,
        tailer_out_path,
    ]

    if grafana_out_path is not None:
        paths.append(grafana_out_path)

    for path in paths:
        if not os.path.exists(path):
            continue

        with open(path) as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    alerts.append(
                        json.loads(line)
                    )
                except json.JSONDecodeError:
                    continue

    alerts.sort(
        key=lambda a: a.get(
            "timestamp",
            "",
        )
    )

    tagged = tag_chain_alerts(alerts, chain_window)
    if chain_window:
        log(f"tagged {tagged} alerts as S10 chain stages (window {chain_window})")

    with open(merged_path, "w") as f:
        for alert in alerts:
            f.write(
                json.dumps(alert) + "\n"
            )

    return alerts


# ---------------------------------------------------------------------------
# Ground-truth scoring
# ---------------------------------------------------------------------------

def score_against_ground_truth(
    alerts,
    ground_truth,
    include_stock_falco=False,
    privileged_debug=False,
    benign_only=False,
    exclude_ambiguous=False,
):
    """
    Score captured alerts against ground_truth.json scenarios.

    - In benign-only mode, returns {} (every alert is scored as a false positive).
    - When exclude_ambiguous=True, alerts with attribution="ambiguous" are excluded.
    - Lab scenarios (detection.source != 'falco-stock') match expected_scenario,
      expected_title prefix, and expected_severity.
    - Stock Falco scenarios (S11-S29) are scored only when include_stock_falco=True
      (and S29 only when privileged_debug=True), using attributed_scenario.
    - S10 is scored separately because it is a multi-alert chain.
    """
    if benign_only:
        return {}

    alerts = [
        a
        for a in alerts
        if a.get("attribution") not in ("setup", "attack_collateral", "benign", "unattributed")
    ]
    if exclude_ambiguous:
        alerts = [a for a in alerts if a.get("attribution") != "ambiguous"]

    results = {}
    scenarios = ground_truth["scenarios"]

    for sid, spec in scenarios.items():
        if sid == "S10":
            continue

        detection = spec.get("detection", {})
        is_stock = detection.get("source") == "falco-stock"
        if is_stock and not include_stock_falco:
            continue
        if sid == "S29" and not privileged_debug:
            continue

        expected_scenario = detection.get("expected_scenario")
        expected_title = detection.get("expected_title")
        expected_severity = detection.get("expected_severity")

        if is_stock:
            matches = [
                alert
                for alert in alerts
                if (
                    alert.get("attributed_scenario") == sid
                    and alert.get("designated_rule", True) is True
                    and str(alert.get("title", "")).startswith(expected_title or "")
                    and (not expected_severity or alert.get("severity") == expected_severity)
                )
            ]
            expected_alert = spec.get("expected_alert")
            fired = len(matches) > 0
            results[sid] = {
                "name": spec.get("name"),
                "expected_scenario": expected_scenario,
                "expected_title": expected_title,
                "expected_severity": expected_severity,
                "expected_alert": expected_alert,
                "fired": fired,
                "matches_expectation": (fired == expected_alert) if expected_alert is not None else fired,
                "match_count": len(matches),
                "matched_alerts": matches,
            }
        else:
            matches = [
                alert
                for alert in alerts
                if (
                    alert.get("scenario") == expected_scenario
                    and alert.get("designated_rule", True) is True
                    and str(alert.get("title", "")).startswith(expected_title or "")
                    and alert.get("severity") == expected_severity
                )
            ]
            results[sid] = {
                "name": spec.get("name"),
                "expected_scenario": expected_scenario,
                "expected_title": expected_title,
                "expected_severity": expected_severity,
                "fired": len(matches) > 0,
                "match_count": len(matches),
                "matched_alerts": matches,
            }

    # -----------------------------------------------------------------------
    # S10 chain scoring
    # -----------------------------------------------------------------------

    if "S10" in scenarios:

        s10 = scenarios["S10"]

        expected_stages = (
            s10
            .get("detection", {})
            .get(
                "expected_alerts_in_order",
                [],
            )
        )

        stage_results = {}

        for stage in expected_stages:

            stage_spec = (
                scenarios
                .get(stage, {})
                .get("detection", {})
            )

            matches = [
                alert
                for alert in alerts
                if (
                    alert.get("designated_rule", True) is True
                    and alert.get("scenario")
                    == stage_spec.get(
                        "expected_scenario"
                    )
                    and str(
                        alert.get("title", "")
                    ).startswith(
                        stage_spec.get(
                            "expected_title"
                        ) or ""
                    )
                )
            ]

            stage_results[stage] = (
                len(matches) > 0
            )

        results["S10"] = {
            "name": s10.get("name"),
            "expected_stages": expected_stages,
            "stage_fired": stage_results,
            "all_stages_fired": (
                all(stage_results.values())
                if stage_results
                else False
            ),
        }

    return results


def _count_score_summary(results, benign_only=False):
    passed = sum(
        1
        for sid, result in results.items()
        if sid != "S10"
        and result.get("matches_expectation", result.get("fired"))
    )
    total_single = sum(1 for sid in results if sid != "S10")
    s10_pass = None if benign_only else results.get("S10", {}).get("all_stages_fired", None)
    return passed, total_single, s10_pass


def build_dual_reports(
    attributed_alerts,
    ground_truth,
    attribution_summary,
    include_stock_falco=False,
    privileged_debug=False,
    benign_only=False,
):
    """Compute scenario scoring with ambiguous alerts excluded and counted as attack."""
    reports = {}
    for key, exclude_flag in (("ambiguous_excluded", True), ("ambiguous_as_attack", False)):
        scored = score_against_ground_truth(
            attributed_alerts,
            ground_truth,
            include_stock_falco=include_stock_falco,
            privileged_debug=privileged_debug,
            benign_only=benign_only,
            exclude_ambiguous=exclude_flag,
        )
        passed, total_single, s10_pass = _count_score_summary(scored, benign_only=benign_only)
        reports[key] = {
            "single_scenario_pass_count": passed,
            "single_scenario_total": total_single,
            "s10_chain_all_stages_fired": s10_pass,
            "attribution": attribution_summary.get(key, {}),
            "results": scored,
        }
    return reports


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    ap = argparse.ArgumentParser(
        description=(
            "SentinelMesh Module A3 logging harness / "
            "Baseline 1 runner"
        )
    )

    # Required core arguments
    ap.add_argument(
        "--ground-truth",
        required=True,
    )

    ap.add_argument(
        "--falco-rules-dir",
        required=True,
    )

    ap.add_argument(
        "--falco-shim",
        required=True,
    )

    ap.add_argument(
        "--tailer",
        required=True,
    )

    ap.add_argument(
        "--webapp-log",
        required=True,
    )

    ap.add_argument(
        "--auth-log",
        required=True,
    )

    # Attack configuration
    ap.add_argument(
        "--attack-scripts-dir",
        default=None,
    )

    ap.add_argument(
        "--auto-run-attacks",
        action="store_true",
        help=(
            "Automatically fire all single-technique "
            "attack scripts in order"
        ),
    )

    ap.add_argument(
        "--chain-script",
        default=None,
        help=(
            "Filename of the S10 chain script "
            "(e.g. scenario9_chain.sh)"
        ),
    )

    # S7 Grafana detector
    ap.add_argument(
        "--grafana-detector",
        default=None,
        help=(
            "Path to the S7 Grafana detector script "
            "(e.g. scenario7_grafana_detector.py)"
        ),
    )

    ap.add_argument(
        "--grafana-container",
        default="sentinelmesh-dashboard",
        help=(
            "Grafana Docker container name used by "
            "the S7 detector"
        ),
    )

    # Manual mode
    ap.add_argument(
        "--listen-seconds",
        type=int,
        default=120,
        help=(
            "If not --auto-run-attacks, how long to "
            "listen for manually-fired attacks"
        ),
    )

    ap.add_argument(
        "--include-stock-falco",
        action="store_true",
        help=(
            "Also load stock Falco rules from detection/falco-stock/ "
            "(falco_rules.yaml, falco-incubating_rules.yaml, falco-sandbox_rules.yaml)"
        ),
    )

    ap.add_argument(
        "--stock-falco-dir",
        default=None,
        help="Override path to detection/falco-stock directory",
    )

    ap.add_argument(
        "--privileged-debug",
        action="store_true",
        help="Include S29 (privileged debug mount; disposable VM ONLY)",
    )

    ap.add_argument(
        "--benign-minutes",
        type=float,
        default=0,
        help="Run linux_run/benign_workload.sh for N minutes alongside attacks",
    )

    ap.add_argument(
        "--benign-only",
        action="store_true",
        help="Run benign_workload.sh with no attack scripts (requires --benign-minutes > 0)",
    )

    ap.add_argument(
        "--benign-workload-script",
        default=None,
        help="Override path to linux_run/benign_workload.sh",
    )

    # Output
    ap.add_argument(
        "--run-dir",
        default="runs",
        help=(
            "Base directory for timestamped run folders"
        ),
    )

    args = ap.parse_args()

    if args.benign_only and args.benign_minutes <= 0:
        ap.error("--benign-only requires --benign-minutes > 0")
    if args.auto_run_attacks and not args.benign_only and not args.attack_scripts_dir:
        ap.error("--auto-run-attacks requires --attack-scripts-dir")

    # -----------------------------------------------------------------------
    # Ground truth
    # -----------------------------------------------------------------------

    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    # -----------------------------------------------------------------------
    # Run directory
    # -----------------------------------------------------------------------

    run_id = now_ts()

    run_path = (
        Path(args.run_dir)
        / run_id
    )

    run_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    log(
        f"run folder: "
        f"{run_path.resolve()}"
    )

    # -----------------------------------------------------------------------
    # Output files
    # -----------------------------------------------------------------------

    falco_out = (
        run_path
        / "falco_alerts_raw.jsonl"
    )

    tailer_out = (
        run_path
        / "logtail_alerts_raw.jsonl"
    )

    grafana_out = (
        run_path
        / "grafana_alerts_raw.jsonl"
    )

    # -----------------------------------------------------------------------
    # Process handles
    # -----------------------------------------------------------------------

    falco_proc = None
    shim_proc = None
    falco_f = None
    falco_err_f = None
    shim_err_f = None

    tailer_proc = None
    tailer_f = None
    tailer_err_f = None

    grafana_proc = None
    grafana_f = None
    grafana_err_f = None

    benign_proc = None
    benign_f = None

    # -----------------------------------------------------------------------
    # Start Falco
    # -----------------------------------------------------------------------

    (
        falco_proc,
        shim_proc,
        falco_f,
        falco_err_f,
        shim_err_f,
    ) = start_falco(
        args.falco_rules_dir,
        args.falco_shim,
        falco_out,
        run_path,
        include_stock_falco=args.include_stock_falco,
        stock_falco_dir=args.stock_falco_dir,
    )

    # -----------------------------------------------------------------------
    # Start log tailer
    # -----------------------------------------------------------------------

    (
        tailer_proc,
        tailer_f,
        tailer_err_f,
    ) = start_tailer(
        args.tailer,
        args.webapp_log,
        args.auth_log,
        tailer_out,
        run_path,
    )

    # -----------------------------------------------------------------------
    # Start S7 Grafana detector
    # -----------------------------------------------------------------------

    if args.grafana_detector:

        detector_path = Path(
            args.grafana_detector
        )

        if not detector_path.exists():
            log(
                "WARNING: Grafana detector does not "
                f"exist: {detector_path}"
            )
        else:
            (
                grafana_proc,
                grafana_f,
                grafana_err_f,
            ) = start_grafana_detector(
                detector_path,
                args.grafana_container,
                grafana_out,
                run_path,
            )

    # -----------------------------------------------------------------------
    # Wait for Falco readiness
    # -----------------------------------------------------------------------

    # Give both processes a moment to finish loading
    # rules / opening files.

    falco_err_path = (
        run_path
        / "falco_stderr.log"
    )

    max_wait = 120
    poll_interval = 2

    ready_markers = (
        "Loaded event sources",
        "Enabled event sources",
        "Starting internal webserver",
    )

    log(
        "waiting up to "
        f"{max_wait}s for falco to finish "
        "attaching its probe..."
    )

    waited = 0
    falco_ready = False

    while waited < max_wait:

        time.sleep(poll_interval)
        waited += poll_interval

        try:
            content = (
                falco_err_path
                .read_text()
            )

        except FileNotFoundError:
            continue

        if any(
            marker in content
            for marker in ready_markers
        ):

            falco_ready = True

            # Give it a few extra seconds after
            # the marker to ensure the probe is live.

            time.sleep(5)

            break

    if falco_ready:

        log(
            f"falco appears ready after "
            f"~{waited}s"
        )

    else:

        log(
            "WARNING: no readiness marker seen in "
            f"falco_stderr.log after {max_wait}s — "
            "proceeding anyway, but S5-S8 alerts "
            "may be missed. Check the stderr log manually."
        )

    log(
        "waiting 3s for tailer startup..."
    )

    time.sleep(3)

    # -----------------------------------------------------------------------
    # Run attacks / listen
    # -----------------------------------------------------------------------

    attack_lock_path = run_path / "attack.lock"

    try:

        scenario_windows = {}
        chain_window = None

        benign_script = (
            Path(args.benign_workload_script)
            if args.benign_workload_script
            else REPO_ROOT / "linux_run" / "benign_workload.sh"
        )
        if args.benign_only or args.benign_minutes > 0:
            if not benign_script.exists():
                log(f"ERROR: benign workload script not found: {benign_script}")
                sys.exit(1)
            benign_proc, benign_f = start_benign_workload(
                benign_script,
                args.benign_minutes,
                run_path / "benign_workload.log",
                out_dir=run_path,
                attack_lock_path=None if args.benign_only else attack_lock_path,
            )

        if args.benign_only:

            log(
                f"benign-only capture: running workload for "
                f"{args.benign_minutes} minute(s) with no attacks"
            )
            benign_proc.wait()
            log("benign workload completed. waiting 5s for final alerts to land...")
            time.sleep(5)

        elif args.auto_run_attacks:

            if not args.attack_scripts_dir:

                log(
                    "ERROR: --auto-run-attacks "
                    "requires --attack-scripts-dir"
                )

                sys.exit(1)

            scenario_windows, chain_window = run_attack_scripts(
                args.attack_scripts_dir,
                chain_script=args.chain_script,
                privileged_debug=args.privileged_debug,
                lock_path=attack_lock_path,
            )

            log(
                "all attack scripts fired. "
                "waiting 5s for final alerts to land..."
            )

            time.sleep(5)

        else:

            log(
                f"listening for "
                f"{args.listen_seconds}s — "
                "fire attack scripts manually "
                "in another terminal now"
            )

            time.sleep(
                args.listen_seconds
            )

    except KeyboardInterrupt:

        log(
            "interrupted, stopping early"
        )

    finally:

        attack_lock_path.unlink(missing_ok=True)

        # ---------------------------------------------------------------
        # Stop all detector processes
        # ---------------------------------------------------------------

        processes = [
            (
                "benign workload",
                benign_proc,
            ),
            (
                "grafana detector",
                grafana_proc,
            ),
            (
                "tailer",
                tailer_proc,
            ),
            (
                "falco shim",
                shim_proc,
            ),
            (
                "falco",
                falco_proc,
            ),
        ]

        for name, proc in processes:

            if proc is None:
                continue

            try:

                log(
                    f"stopping {name}"
                )

                proc.send_signal(
                    signal.SIGTERM
                )

            except Exception:
                pass

        time.sleep(1)

        # ---------------------------------------------------------------
        # Force-kill anything still running
        # ---------------------------------------------------------------

        for name, proc in processes:

            if proc is None:
                continue

            try:

                if proc.poll() is None:
                    proc.kill()

            except Exception:
                pass

        # ---------------------------------------------------------------
        # Close output files
        # ---------------------------------------------------------------

        for f in (
            benign_f,
            falco_f,
            tailer_f,
            grafana_f,
            falco_err_f,
            shim_err_f,
            tailer_err_f,
            grafana_err_f,
        ):

            if f is None:
                continue

            try:
                f.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Merge alerts
    # -----------------------------------------------------------------------

    merged_path = (
        run_path
        / "alerts.jsonl"
    )

    alerts = merge_alerts(
        falco_out,
        tailer_out,
        merged_path,
        grafana_out_path=(
            grafana_out
            if args.grafana_detector
            else None
        ),
        chain_window=chain_window,
    )

    log(
        f"merged {len(alerts)} alerts -> "
        f"{merged_path}"
    )

    if scenario_windows:
        with open(run_path / "scenario_windows.json", "w") as f:
            json.dump(scenario_windows, f, indent=2)

    benign_actions = load_benign_actions(run_path / "benign_actions.jsonl")
    attributed = attribute_alerts(
        alerts,
        scenario_windows,
        ground_truth,
        benign_only=args.benign_only,
        benign_actions=benign_actions,
    )
    attribution_summary = summarize_attribution(attributed)
    with open(run_path / "alerts_attributed.jsonl", "w") as f:
        for alert in attributed:
            f.write(json.dumps(alert) + "\n")

    # -----------------------------------------------------------------------
    # Score
    # -----------------------------------------------------------------------

    dual_reports = build_dual_reports(
        attributed,
        ground_truth,
        attribution_summary,
        include_stock_falco=args.include_stock_falco,
        privileged_debug=args.privileged_debug,
        benign_only=args.benign_only,
    )
    as_attack = dual_reports["ambiguous_as_attack"]
    excluded = dual_reports["ambiguous_excluded"]
    results = as_attack["results"]
    passed = as_attack["single_scenario_pass_count"]
    total_single = as_attack["single_scenario_total"]
    s10_pass = as_attack["s10_chain_all_stages_fired"]

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    summary = {
        "run_id": run_id,
        "run_timestamp_utc": run_id,
        "baseline": (
            "Baseline 1 "
            "(Falco-only + log-tail + S7 Grafana detector, "
            "no RAG/graph/response)"
        ),
        "include_stock_falco": args.include_stock_falco,
        "privileged_debug": args.privileged_debug,
        "benign_only": args.benign_only,
        "benign_minutes": args.benign_minutes,
        "benign_actions_count": sum(
            1 for a in benign_actions if a.get("action") not in ("pause", "resume")
        ),
        "scenario_windows": scenario_windows,
        "attribution_summary": attribution_summary,
        "ground_truth_file": str(
            Path(
                args.ground_truth
            ).resolve()
        ),
        "grafana_detector": (
            str(
                Path(
                    args.grafana_detector
                ).resolve()
            )
            if args.grafana_detector
            else None
        ),
        "grafana_container": (
            args.grafana_container
            if args.grafana_detector
            else None
        ),
        "total_alerts_captured": len(
            alerts
        ),
        "single_scenario_pass_count": passed,
        "single_scenario_total": total_single,
        "s10_chain_all_stages_fired": s10_pass,
        "results": results,
        "reports": dual_reports,
    }

    # -----------------------------------------------------------------------
    # Write results and run manifest
    # -----------------------------------------------------------------------

    results_path = (
        run_path
        / "baseline1_results.json"
    )

    with open(results_path, "w") as f:

        json.dump(
            summary,
            f,
            indent=2,
            default=str,
        )

    manifest_path = write_run_manifest(run_path)

    log(
        "Baseline 1 results written to: "
        f"{results_path.resolve()}"
    )
    log(
        "Run manifest written to: "
        f"{manifest_path.resolve()}"
    )

    log(
        f"Score (ambiguous as attack): {passed}/{total_single} "
        "single-technique scenarios fired correctly"
    )
    log(
        f"Score (ambiguous excluded): "
        f"{excluded['single_scenario_pass_count']}/{excluded['single_scenario_total']} "
        "single-technique scenarios fired correctly"
    )

    if s10_pass is not None:

        log(
            "S10 chain: "
            + (
                "ALL STAGES FIRED"
                if s10_pass
                else "INCOMPLETE"
            )
        )

    if passed < total_single:

        log(
            "Some scenarios did not fire — "
            "check stderr logs for clues:"
        )

        log(
            f"  {run_path / 'falco_stderr.log'}"
        )

        log(
            f"  {run_path / 'shim_stderr.log'}"
        )

        log(
            f"  {run_path / 'tailer_stderr.log'}"
        )

        if args.grafana_detector:

            log(
                f"  {run_path / 'grafana_detector_stderr.log'}"
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()


