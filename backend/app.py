"""
SentinelMesh FastAPI Backend Service.

Provides:
  - /api/health: Health check endpoint
  - /api/alerts: Ingest and list runtime alerts
  - /api/investigate: Run RAG threat-intel & Attack Graph reconstruction
  - /api/decisions: Tiered risk response routing & analyst decision feedback
  - /ws: Real-time WebSocket feed for live alerts and approval queue updates
  - /dashboard: Analyst Dashboard UI
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
        "endpoints": ["/api/health", "/api/alerts", "/api/investigate", "/api/decisions", "/ws", "/dashboard"],
    }


@app.get("/dashboard")
def get_dashboard():
    frontend_index = os.path.join(ROOT_DIR, "frontend", "index.html")
    if os.path.exists(frontend_index):
        return FileResponse(frontend_index)
    return {"message": "Frontend index.html not found"}


@app.get("/api/health")
def get_health():
    return {
        "status": "ok",
        "rag_available": RAG_AVAILABLE,
        "graph_available": GRAPH_AVAILABLE,
        "active_alerts_count": len(ALERTS_STORE),
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
    ALERTS_STORE.append(data)
    
    # Broadcast to websocket clients
    await broadcast_ws({"type": "NEW_ALERT", "alert": data})
    return {"status": "success", "alert": data}


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
    return {
        "decisions": DECISIONS_STORE,
        "metrics": METRICS,
    }


@app.post("/api/decisions")
async def record_decision(decision: DecisionModel):
    data = decision.dict()
    data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    DECISIONS_STORE.append(data)

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
    await broadcast_ws({"type": "DECISION_LOGGED", "decision": data, "metrics": METRICS})

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
