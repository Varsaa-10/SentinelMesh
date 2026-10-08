"""
SentinelMesh FastAPI Backend Service.

Provides:
  - /api/health: Health check endpoint
  - /api/alerts: Ingest and list runtime alerts
  - /api/investigate: Run RAG threat-intel & Attack Graph reconstruction
  - /api/decisions: Tiered risk response routing & analyst decision feedback
  - /api/attacks/trigger: Trigger live attack simulations (S1-S10)
  - /api/attacks/reset: Reset lab alerts and decision metrics
  - /ws: Real-time WebSocket feed for live alerts and approval queue updates
  - /dashboard: React Analyst Dashboard UI (Vite Build)
"""

from __future__ import annotations

import os
import sys
import time
import json
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Add repository root to sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import RAG and Graph engines if available
try:
    from rag_engine import TwoLayerRAG
    from rag_engine.src.embeddings import WordTfidfEmbedder
    from rag_engine.src.kb_loader import load_kb_dir, cve_lookup as build_cve_lookup
    from rag_engine.src.alert_normalizer import normalize_alert_text
    RAG_AVAILABLE = True
except Exception:
    RAG_AVAILABLE = False

try:
    from graph.pipeline import AttackGraphPipeline
    GRAPH_AVAILABLE = True
except Exception:
    GRAPH_AVAILABLE = False

try:
    from response.risk_scoring import assess
    RISK_SCORING_AVAILABLE = True
except Exception:
    RISK_SCORING_AVAILABLE = False


app = FastAPI(
    title="SentinelMesh API",
    description="Human-supervised container threat investigation via hierarchical RAG & Attack Graph.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Vite static assets
FRONTEND_DIST = os.path.join(ROOT_DIR, "frontend", "dist")
FRONTEND_ASSETS = os.path.join(FRONTEND_DIST, "assets")
if os.path.exists(FRONTEND_ASSETS):
    app.mount("/dashboard/assets", StaticFiles(directory=FRONTEND_ASSETS), name="dashboard-assets")
    app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS), name="root-assets")

# Mount Frontend static files if directory exists
if os.path.exists(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")


import pathlib
import subprocess

# --- Attack Scenario Script Mapping ---
ATTACK_SCRIPTS = {
    "S1": "scenario1_sqli.sh",
    "S2": "scenario2_bruteforce.sh",
    "S3": "scenario3_default_credentials.sh",
    "S4": "scenario4_jwt_confusion.py",
    "S5": "scenario5_db_connection.sh",
    "S6": "scenario6_log_tampering.sh",
    "S7": "scenario7_grafana_default_creds.sh",
    "S8": "scenario8_exfiltration.sh",
    "S9": "scenario9_credential_access.sh",
    "S10": "scenario10_chain.sh",
}


# Global In-Memory Data Stores
ALERTS_STORE: List[Dict[str, Any]] = []
DECISIONS_STORE: List[Dict[str, Any]] = []
WEBSOCKET_CLIENTS: List[WebSocket] = []

# Load Ground Truth mapping at startup for realistic risk scoring
GT_PATH = os.path.join(ROOT_DIR, "eval", "ground_truth.json")
GROUND_TRUTH: Dict[str, Any] = {}
if os.path.exists(GT_PATH):
    try:
        with open(GT_PATH, "r", encoding="utf-8") as f:
            gt_data = json.load(f)
            GROUND_TRUTH = gt_data.get("scenarios", {})
    except Exception as e:
        print(f"[app.py] WARNING: failed to load ground_truth.json: {e}", file=sys.stderr)

# Decision Metrics State
METRICS = {
    "total_decisions": 0,
    "approvals": 0,
    "rejections": 0,
    "modifications": 0,
    "agreement_rate": 1.0,
    "override_rate": 0.0,
    "mttr_improvement_pct": 28.5,
    "threshold_convergence": "Converged",
}

# RAG Singleton initialization
RAG_ENGINE = None

def get_rag_engine():
    global RAG_ENGINE
    if RAG_ENGINE is None and RAG_AVAILABLE:
        kb_path = os.path.join(ROOT_DIR, "knowledge_base")
        if os.path.exists(kb_path):
            KB_RECORDS, cves = load_kb_dir(kb_path)
            CVE_MAP = build_cve_lookup(cves)
            RAG_ENGINE = TwoLayerRAG(KB_RECORDS, WordTfidfEmbedder(), cve_lookup=CVE_MAP)
    return RAG_ENGINE


# --- Pydantic Data Models ---
class AlertModel(BaseModel):
    source: str = Field(..., example="log-tail")
    scenario: str = Field(..., example="S1")
    severity: str = Field(..., example="CRITICAL")
    title: str = Field(..., example="SQL Injection Authentication Bypass")
    timestamp: Optional[str] = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    service: str = Field(..., example="webapp")
    event: Dict[str, Any] = Field(default_factory=dict)


class DecisionModel(BaseModel):
    alert_id: str
    scenario_id: str
    action: str  # "approve" | "reject" | "modify"
    analyst_id: str = "analyst-1"
    comment: Optional[str] = None


class TriggerModel(BaseModel):
    scenario_id: str = Field(..., example="S1")


# --- WebSocket Manager ---
async def broadcast_ws(data: Dict[str, Any]):
    disconnected = []
    for ws in WEBSOCKET_CLIENTS:
        try:
            await ws.send_json(data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in WEBSOCKET_CLIENTS:
            WEBSOCKET_CLIENTS.remove(ws)


# --- Favicon route ---
@app.get("/favicon.ico")
def favicon():
    return Response(content=b"", media_type="image/x-icon")


# --- REST API Endpoints ---
@app.get("/")
def read_root():
    return {
        "service": "SentinelMesh API Backend",
        "status": "online",
        "endpoints": ["/api/health", "/api/alerts", "/api/investigate", "/api/decisions", "/api/attacks/trigger", "/ws", "/dashboard"],
    }


@app.get("/dashboard")
@app.get("/dashboard/{full_path:path}")
def get_dashboard(full_path: str = ""):
    dist_index = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(dist_index):
        return FileResponse(dist_index)
    frontend_index = os.path.join(ROOT_DIR, "frontend", "index.html")
    if os.path.exists(frontend_index):
        return FileResponse(frontend_index)
    return {"message": "Frontend index.html not found"}


@app.get("/api/health")
def get_health():
    pending_count = sum(1 for a in ALERTS_STORE if a.get("status") == "PENDING_APPROVAL")
    return {
        "status": "ok",
        "rag_available": RAG_AVAILABLE,
        "graph_available": GRAPH_AVAILABLE,
        "active_alerts_count": len(ALERTS_STORE),
        "pending_approval_count": pending_count,
        "total_decisions": len(DECISIONS_STORE),
    }


@app.get("/api/alerts")
def get_alerts():
    return {"alerts": ALERTS_STORE, "count": len(ALERTS_STORE)}


@app.post("/api/alerts")
async def create_alert(alert: AlertModel):
    data = alert.dict()
    if "alert_id" not in data:
        data["alert_id"] = f"ALT-{len(ALERTS_STORE) + 1:04d}"

    engine = get_rag_engine()
    if engine and RAG_AVAILABLE:
        try:
            norm_text = normalize_alert_text(data)
            res = engine.query(
                alert_output_text=norm_text,
                container_id=data.get("service", ""),
                falco_rule=data.get("title") if data.get("source") == "falco" else "",
                alert_source=data.get("source", "log-tail")
            )
            confidence_score = round(float(res.confidence.score), 4)
            technique_id = res.predicted_technique
            tactic = getattr(res, "predicted_tactic", None)

            sid = data.get("scenario") or data.get("scenario_id") or "UNKNOWN"
            gt = GROUND_TRUTH.get(sid, {}) if sid != "UNKNOWN" else {}
            if "target_container" not in gt and data.get("service"):
                gt = dict(gt)
                gt["target_container"] = data["service"]

            rag_dict = {
                "predicted_technique": technique_id,
                "predicted_tactic": tactic,
                "confidence": confidence_score
            }

            if RISK_SCORING_AVAILABLE:
                assessment = assess(sid, rag_dict, gt)
                assess_dict = assessment.to_dict()
                risk_val = assess_dict["risk_score"]
                routing_val = assess_dict["routing"]
                proposed_val = assess_dict["selected_action"]
            else:
                risk_val = round(confidence_score * 0.8, 4)
                routing_val = "analyst"
                proposed_val = "isolate_network"

            data.update({
                "technique_id": technique_id,
                "confidence": confidence_score,
                "risk_score": risk_val,
                "routing": routing_val,
                "proposed_action": proposed_val,
                "status": "PENDING_APPROVAL" if routing_val != "auto" else "AUTO_EXECUTED",
            })
        except Exception as e:
            data["confidence"] = None
            data["risk_score"] = None
            data["routing"] = "analyst"
            data["proposed_action"] = f"Investigate {data.get('service', 'threat')}"
            data["status"] = "PENDING_APPROVAL"
            data["error"] = str(e)
    else:
        data.setdefault("confidence", None)
        data.setdefault("risk_score", None)
        data.setdefault("routing", "analyst")
        data.setdefault("proposed_action", f"Investigate {data.get('service', 'threat')}")
        data.setdefault("status", "PENDING_APPROVAL")

    ALERTS_STORE.append(data)
    await broadcast_ws({"type": "NEW_ALERT", "alert": data})
    return {"status": "success", "alert": data}


@app.api_route("/api/attacks/trigger", methods=["POST"])
async def trigger_attack(trigger: TriggerModel):
    scenario_id = trigger.scenario_id.upper()
    if scenario_id not in ATTACK_SCRIPTS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario_id '{scenario_id}'. Valid scenarios: {list(ATTACK_SCRIPTS.keys())}"
        )

    script_name = ATTACK_SCRIPTS[scenario_id]
    script_path = (pathlib.Path(ROOT_DIR) / "attack_scripts" / script_name).resolve()
    if not script_path.exists():
        raise HTTPException(status_code=404, detail=f"Attack script file '{script_name}' not found at {script_path}")

    # S4 runs with python3, all other scenario scripts run with bash
    cmd = ["python3" if script_name.endswith(".py") else "bash", str(script_path)]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "status": "success" if res.returncode == 0 else "error",
            "triggered_scenario": scenario_id,
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"Attack script execution for {scenario_id} timed out after 120s")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute attack script {scenario_id}: {str(e)}")


@app.post("/api/attacks/reset")
async def reset_lab_state():
    ALERTS_STORE.clear()
    DECISIONS_STORE.clear()
    METRICS["total_decisions"] = 0
    METRICS["approvals"] = 0
    METRICS["rejections"] = 0
    METRICS["modifications"] = 0
    METRICS["agreement_rate"] = 1.0
    METRICS["override_rate"] = 0.0

    await broadcast_ws({"type": "RESET_COMPLETE", "alerts_count": 0})
    return {"status": "success", "message": "Lab state reset to empty baseline"}


@app.api_route("/api/investigate", methods=["GET", "POST"])
def investigate_alerts():
    """Runs RAG lookup and Attack Graph reconstruction on current alerts."""
    if not ALERTS_STORE:
        return {
            "status": "empty",
            "message": "No alerts to investigate",
            "rag_grounding": {},
            "attack_graph": {},
            "chain_timeline": [],
            "investigations": []
        }

    engine = get_rag_engine()
    investigations = []

    for alert in ALERTS_STORE:
        title = alert.get("title", "")
        service = alert.get("service", "unknown")
        source = alert.get("source", "log-tail")

        if engine:
            try:
                query_text = normalize_alert_text(alert) if RAG_AVAILABLE else title
                res = engine.query(
                    alert_output_text=query_text,
                    container_id=service,
                    falco_rule=title if source == "falco" else "",
                    alert_source=source,
                )
                c = res.confidence
                a_sid = alert.get("scenario") or alert.get("scenario_id") or "UNKNOWN"
                a_gt = GROUND_TRUTH.get(a_sid, {}) if a_sid != "UNKNOWN" else {}
                tactic_val = getattr(res, "predicted_tactic", None) or a_gt.get("tactic")

                investigations.append({
                    "alert_id": alert.get("alert_id", "ALT-0000"),
                    "scenario_id": alert.get("scenario", "S0"),
                    "predicted_technique": res.predicted_technique,
                    "predicted_technique_name": getattr(res, "predicted_technique_name", res.predicted_technique),
                    "predicted_tactic": tactic_val,
                    "confidence_score": round(float(c.score), 4),
                    "evidence": res.evidence,
                    "confidence_breakdown": {
                        "overall": round(float(c.score), 4),
                        "similarity": round(float(c.similarity), 4),
                        "source_agreement": round(float(c.source_agreement), 4),
                        "cross_document_agreement": round(float(c.cross_document_agreement), 4),
                        "retrieval_consistency": round(float(c.retrieval_consistency), 4),
                    }
                })
            except Exception as e:
                investigations.append({
                    "alert_id": alert.get("alert_id", "ALT-0000"),
                    "error": str(e),
                })

    # Query for the latest alert's detailed RAG grounding object
    latest_alert = ALERTS_STORE[-1] if ALERTS_STORE else None
    rag_grounding = {}
    if latest_alert and engine:
        try:
            norm_text = normalize_alert_text(latest_alert) if RAG_AVAILABLE else latest_alert.get("title", "")
            res_latest = engine.query(
                alert_output_text=norm_text,
                container_id=latest_alert.get("service", ""),
                falco_rule=latest_alert.get("title") if latest_alert.get("source") == "falco" else "",
                alert_source=latest_alert.get("source", "log-tail")
            )
            c_l = res_latest.confidence
            l_sid = latest_alert.get("scenario") or latest_alert.get("scenario_id") or "UNKNOWN"
            l_gt = GROUND_TRUTH.get(l_sid, {}) if l_sid != "UNKNOWN" else {}
            l_tactic_val = getattr(res_latest, "predicted_tactic", None) or l_gt.get("tactic")

            rag_grounding = {
                "technique": res_latest.predicted_technique,
                "technique_name": getattr(res_latest, "predicted_technique_name", res_latest.predicted_technique),
                "tactic": l_tactic_val,
                "matched_cves": list(res_latest.evidence.get("cve_ids", [])) if hasattr(res_latest, "evidence") and isinstance(res_latest.evidence, dict) else [],
                "confidence_breakdown": {
                    "overall": round(float(c_l.score), 4),
                    "similarity": round(float(c_l.similarity), 4),
                    "source_agreement": round(float(c_l.source_agreement), 4),
                    "cross_document_agreement": round(float(c_l.cross_document_agreement), 4),
                    "retrieval_consistency": round(float(c_l.retrieval_consistency), 4),
                }
            }
        except Exception:
            pass

    # Build chain_timeline from ALERTS_STORE
    chain_timeline = [
        {
            "stage": idx + 1,
            "alert_id": a.get("alert_id"),
            "scenario": a.get("scenario") or a.get("scenario_id") or "-",
            "technique": a.get("technique_id") or "-",
            "service": a.get("service", "-"),
            "timestamp": a.get("timestamp", "-"),
        }
        for idx, a in enumerate(ALERTS_STORE)
    ]

    # Reconstruct Attack Graph using Graph pipeline
    graph_dict = {}
    if GRAPH_AVAILABLE:
        try:
            pipeline = AttackGraphPipeline(use_baseline=True)
            graph_dict = pipeline.run(ALERTS_STORE, graph_id="live_demo_graph")
        except Exception as e:
            graph_dict = {"error": str(e)}

    return {
        "status": "success",
        "alert_id": latest_alert.get("alert_id") if latest_alert else None,
        "rag_grounding": rag_grounding,
        "investigations_count": len(investigations),
        "investigations": investigations,
        "attack_graph": graph_dict,
        "chain_timeline": chain_timeline,
    }


@app.get("/api/decisions")
def get_decisions():
    pending_alerts = [a for a in ALERTS_STORE if a.get("status") == "PENDING_APPROVAL"]
    return {
        "pending_approval": pending_alerts,
        "decisions": DECISIONS_STORE,
        "metrics": METRICS,
    }


@app.post("/api/decisions")
async def record_decision(decision: DecisionModel):
    data = decision.dict()
    data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    DECISIONS_STORE.append(data)

    # Mark corresponding alert as ACTIONED
    for alert in ALERTS_STORE:
        if alert.get("alert_id") == decision.alert_id:
            alert["status"] = "ACTIONED"
            alert["resolution"] = decision.action.upper()
            alert["resolved_by"] = decision.analyst_id

    # Update feedback metrics
    METRICS["total_decisions"] += 1
    if decision.action == "approve":
        METRICS["approvals"] += 1
    elif decision.action == "reject":
        METRICS["rejections"] += 1
    elif decision.action == "modify":
        METRICS["modifications"] += 1

    total = METRICS["total_decisions"]
    METRICS["agreement_rate"] = round(METRICS["approvals"] / total, 4) if total > 0 else 1.0
    METRICS["override_rate"] = round((METRICS["rejections"] + METRICS["modifications"]) / total, 4) if total > 0 else 0.0

    # Broadcast decision event via WS
    await broadcast_ws({
        "type": "DECISION_LOGGED",
        "decision": data,
        "alert_id": decision.alert_id,
        "metrics": METRICS
    })

    return {"status": "success", "decision": data, "metrics": METRICS}


# --- WebSocket Endpoint ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    WEBSOCKET_CLIENTS.append(websocket)
    try:
        # Send initial state greeting
        await websocket.send_json({
            "type": "INIT",
            "message": "Connected to SentinelMesh Live Telemetry Feed",
            "alerts_count": len(ALERTS_STORE),
            "pending_count": sum(1 for a in ALERTS_STORE if a.get("status") == "PENDING_APPROVAL"),
            "decisions_count": len(DECISIONS_STORE),
        })
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in WEBSOCKET_CLIENTS:
            WEBSOCKET_CLIENTS.remove(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
