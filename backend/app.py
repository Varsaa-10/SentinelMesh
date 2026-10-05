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
  - /dashboard: React Analyst Dashboard UI
"""

from __future__ import annotations

import os
import sys
import time
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
    RAG_AVAILABLE = True
except Exception:
    RAG_AVAILABLE = False

try:
    from graph.pipeline import AttackGraphPipeline
    GRAPH_AVAILABLE = True
except Exception:
    GRAPH_AVAILABLE = False


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


# --- Attack Scenario Catalog ---
ATTACK_CATALOG = {
    "S1": {
        "title": "SQL Injection Authentication Bypass",
        "service": "webapp",
        "severity": "CRITICAL",
        "proposed_action": "Isolate Webapp Container",
        "confidence": 0.9412,
        "evidence": "SQLi Pattern Match (' OR '1'='1)",
        "event": {"payload": "' OR '1'='1 --", "endpoint": "/api/v1/login"}
    },
    "S2": {
        "title": "Brute Force Credential Spray",
        "service": "auth-service",
        "severity": "HIGH",
        "proposed_action": "Rate Limit & Lock Auth IP",
        "confidence": 0.8950,
        "evidence": "50 Failed Logins in 10 Seconds",
        "event": {"attempts": 50, "target_user": "admin", "src_ip": "192.168.1.105"}
    },
    "S3": {
        "title": "Remote Code Execution (Command Injection)",
        "service": "api-gateway",
        "severity": "CRITICAL",
        "proposed_action": "Terminate Process & Quarantine Container",
        "confidence": 0.9650,
        "evidence": "Shell Spawn via Subprocess",
        "event": {"payload": "; cat /etc/passwd", "command": "sh -c"}
    },
    "S4": {
        "title": "JWT Algorithm Confusion Attack",
        "service": "auth-service",
        "severity": "HIGH",
        "proposed_action": "Revoke Signing Key & Force Re-Auth",
        "confidence": 0.9120,
        "evidence": "Header alg='none' Mismatch",
        "event": {"alg": "none", "claimed_user": "admin"}
    },
    "S5": {
        "title": "Server-Side Request Forgery (SSRF)",
        "service": "internal-proxy",
        "severity": "HIGH",
        "proposed_action": "Block Metadata Endpoint Access",
        "confidence": 0.8870,
        "evidence": "Cloud Metadata Fetch (169.254.169.254)",
        "event": {"target_url": "http://169.254.169.254/latest/meta-data/"}
    },
    "S6": {
        "title": "Path Traversal Arbitrary File Read",
        "service": "file-server",
        "severity": "MEDIUM",
        "proposed_action": "Sanitize Path Parameter & Block IP",
        "confidence": 0.8540,
        "evidence": "Traversal Sequence ../../etc/passwd",
        "event": {"filepath": "../../../etc/shadow"}
    },
    "S7": {
        "title": "Container Escape & Privilege Escalation",
        "service": "k8s-node-01",
        "severity": "CRITICAL",
        "proposed_action": "Cordon & Drain Node",
        "confidence": 0.9850,
        "evidence": "Host Namespace Mount & CAP_SYS_ADMIN",
        "event": {"syscall": "nsenter", "target": "host_pid"}
    },
    "S8": {
        "title": "Defense Evasion Log Manipulation",
        "service": "syslog-daemon",
        "severity": "MEDIUM",
        "proposed_action": "Restore Immutable Audit Pipeline",
        "confidence": 0.8320,
        "evidence": "Auditd Daemon Termination",
        "event": {"action": "kill", "process": "auditd"}
    },
    "S9": {
        "title": "Credential Access /etc/shadow Dump",
        "service": "db-container",
        "severity": "CRITICAL",
        "proposed_action": "Rotate DB Passwords & Encrypt Volume",
        "confidence": 0.9710,
        "evidence": "Sensitive File Access /etc/shadow",
        "event": {"file": "/etc/shadow", "mode": "read"}
    },
    "S10": {
        "title": "Multi-Stage APT Attack Chain",
        "service": "cluster-ingress",
        "severity": "CRITICAL",
        "proposed_action": "Execute Emergency Cluster Containment Plan",
        "confidence": 0.9920,
        "evidence": "Correlated Attack Chain (T1190 -> T1068 -> T1041)",
        "event": {"chain_steps": ["SQLi", "PrivEsc", "Data Exfiltration"]}
    }
}


# --- In-memory Stores ---
ALERTS_STORE: List[Dict[str, Any]] = [
    {
        "alert_id": "ALT-0001",
        "source": "log-tail",
        "scenario": "S1",
        "severity": "CRITICAL",
        "title": "SQL Injection Authentication Bypass",
        "service": "webapp",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PENDING_APPROVAL",
        "proposed_action": "Isolate Webapp Container",
        "confidence": 0.9412,
        "evidence": "SQLi Pattern Match",
        "event": {"payload": "' OR '1'='1"}
    }
]
DECISIONS_STORE: List[Dict[str, Any]] = []
WEBSOCKET_CLIENTS: List[WebSocket] = []

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

# Lazy-loaded RAG engine instance
RAG_ENGINE = None
CVE_MAP = {}
KB_RECORDS = []

def get_rag_engine():
    global RAG_ENGINE, CVE_MAP, KB_RECORDS
    if RAG_ENGINE is None and RAG_AVAILABLE:
        tech_dir = os.path.join(ROOT_DIR, "rag_engine", "kb", "kb_master_real", "techniques")
        cve_dir = os.path.join(ROOT_DIR, "rag_engine", "kb", "kb_master_real", "cves")
        if os.path.exists(tech_dir) and os.path.exists(cve_dir):
            KB_RECORDS, cves = load_kb_dir(tech_dir, cve_dir)
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
def get_dashboard():
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
    data["status"] = "PENDING_APPROVAL"
    data["proposed_action"] = f"Remediate {data.get('title', 'threat')}"
    data["confidence"] = 0.9200
    ALERTS_STORE.append(data)
    
    # Broadcast to websocket clients
    await broadcast_ws({"type": "NEW_ALERT", "alert": data})
    return {"status": "success", "alert": data}


@app.api_route("/api/attacks/trigger", methods=["POST"])
async def trigger_attack(trigger: TriggerModel):
    scenario_id = trigger.scenario_id.upper()
    if scenario_id not in ATTACK_CATALOG:
        raise HTTPException(status_code=400, detail=f"Unknown scenario_id '{scenario_id}'. Valid scenarios: {list(ATTACK_CATALOG.keys())}")

    spec = ATTACK_CATALOG[scenario_id]
    alert_data = {
        "alert_id": f"ALT-{len(ALERTS_STORE) + 1:04d}",
        "source": "attack-simulator",
        "scenario": scenario_id,
        "severity": spec["severity"],
        "title": spec["title"],
        "service": spec["service"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PENDING_APPROVAL",
        "proposed_action": spec["proposed_action"],
        "confidence": spec["confidence"],
        "evidence": spec["evidence"],
        "event": spec["event"]
    }
    ALERTS_STORE.append(alert_data)

    # Broadcast new alert immediately over WebSockets
    await broadcast_ws({"type": "NEW_ALERT", "alert": alert_data})
    return {"status": "success", "triggered_scenario": scenario_id, "alert": alert_data}


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

    # Re-insert initial S1 alert for demo readiness
    initial_alert = {
        "alert_id": "ALT-0001",
        "source": "log-tail",
        "scenario": "S1",
        "severity": "CRITICAL",
        "title": "SQL Injection Authentication Bypass",
        "service": "webapp",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PENDING_APPROVAL",
        "proposed_action": "Isolate Webapp Container",
        "confidence": 0.9412,
        "evidence": "SQLi Pattern Match",
        "event": {"payload": "' OR '1'='1"}
    }
    ALERTS_STORE.append(initial_alert)
    await broadcast_ws({"type": "RESET_COMPLETE", "alert": initial_alert})
    return {"status": "success", "message": "Lab state reset to initial baseline"}


@app.api_route("/api/investigate", methods=["GET", "POST"])
def investigate_alerts():
    """Runs RAG lookup and Attack Graph reconstruction on current alerts."""
    if not ALERTS_STORE:
        return {"status": "empty", "message": "No alerts to investigate", "graph": {}, "investigations": []}

    engine = get_rag_engine()
    investigations = []

    for alert in ALERTS_STORE:
        title = alert.get("title", "")
        service = alert.get("service", "unknown")
        source = alert.get("source", "log-tail")

        if engine:
            try:
                res = engine.query(
                    alert_output_text=title,
                    container_id=service,
                    falco_rule=title if source == "falco" else "",
                    alert_source=source,
                )
                investigations.append({
                    "alert_id": alert.get("alert_id", "ALT-0000"),
                    "scenario_id": alert.get("scenario", "S0"),
                    "predicted_technique": res.predicted_technique,
                    "predicted_technique_name": res.predicted_technique_name,
                    "predicted_tactic": res.predicted_tactic,
                    "confidence_score": round(res.confidence.score, 4),
                    "evidence": res.evidence,
                })
            except Exception as e:
                investigations.append({
                    "alert_id": alert.get("alert_id", "ALT-0000"),
                    "error": str(e),
                })

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
        "investigations_count": len(investigations),
        "investigations": investigations,
        "attack_graph": graph_dict,
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
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
