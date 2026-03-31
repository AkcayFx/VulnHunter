"""FastAPI server with WebSocket for live scan updates."""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from vulnhunter.agents.orchestrator import OrchestratorAgent
from vulnhunter.config import AppConfig, load_config
from vulnhunter.db.engine import close_db, init_db
from vulnhunter.db.repository import Repository
from vulnhunter.db import get_session
from vulnhunter.models import AgentAction, ScanPhase, ScanReport, ScanTarget
from vulnhunter.reporting import save_html_report, save_json_report

logger = logging.getLogger("vulnhunter.ui")

STATIC_DIR = Path(__file__).parent / "static"

active_connections: list[WebSocket] = []
current_scan: dict[str, Any] = {"running": False, "report": None}


@asynccontextmanager
async def lifespan(application: FastAPI):
    cfg = load_config()
    try:
        await init_db(cfg.database.effective_url)
        logger.info("Database connected")
    except Exception as e:
        logger.warning(f"Database unavailable ({e}), running without persistence")
    yield
    await close_db()


app = FastAPI(title="VulnHunter", version="2.0.0", lifespan=lifespan)

from vulnhunter.api.routes import router as api_router
app.include_router(api_router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_file = STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    logger.info("WebSocket client connected")

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "start_scan":
                target_host = msg.get("target", "").strip()
                custom_task = msg.get("task", "").strip()
                if not target_host:
                    await websocket.send_json({"type": "error", "message": "No target specified"})
                    continue
                if len(target_host) > 253 or not all(c.isalnum() or c in '.-:/' for c in target_host):
                    await websocket.send_json({"type": "error", "message": "Invalid target format"})
                    continue
                if len(custom_task) > 500:
                    custom_task = custom_task[:500]
                if current_scan["running"]:
                    await websocket.send_json({"type": "error", "message": "Scan already running"})
                    continue
                asyncio.create_task(_run_scan(target_host, custom_task))

            elif msg.get("type") == "cancel_scan":
                if current_scan.get("cancel_event"):
                    current_scan["cancel_event"].set()

    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in active_connections:
            active_connections.remove(websocket)


async def _broadcast(message: dict[str, Any]) -> None:
    disconnected = []
    for ws in active_connections:
        try:
            await ws.send_json(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        active_connections.remove(ws)


async def _persist_report(report: ScanReport, target_host: str) -> None:
    """Save scan results to the database."""
    try:
        async with get_session() as session:
            repo = Repository(session)
            flow = await repo.create_flow(target_host=target_host)
            await repo.update_flow(
                flow.id,
                status="completed",
                risk_score=report.risk_score,
                threat_level=report.threat_level,
                ai_summary=report.ai_summary,
                remediation_steps=report.remediation_steps,
                duration_seconds=report.total_duration_seconds,
            )
            for tr in report.tool_results:
                await repo.create_tool_result(
                    flow_id=flow.id,
                    tool_name=tr.tool_name,
                    success=tr.success,
                    raw_output=tr.raw_output[:5000],
                    data=tr.data,
                    duration_seconds=tr.duration_seconds,
                    error=tr.error,
                )
            for v in report.vulnerabilities:
                await repo.create_vulnerability(
                    flow_id=flow.id,
                    title=v.title,
                    severity=v.severity.value,
                    tool=v.tool,
                    description=v.description,
                    evidence=v.evidence,
                    cwe_id=v.cwe_id,
                    cvss_score=v.cvss_score,
                    remediation=v.remediation,
                )
    except Exception as e:
        logger.warning(f"Failed to persist scan: {e}")


async def _run_scan(target_host: str, custom_task: str = "") -> None:
    current_scan["running"] = True
    current_scan["report"] = None
    cancel_event = asyncio.Event()
    current_scan["cancel_event"] = cancel_event

    config = load_config()
    target = ScanTarget(host=target_host, custom_task=custom_task)

    await _broadcast({"type": "scan_started", "target": target_host})

    def on_action(action: AgentAction):
        asyncio.create_task(_broadcast({
            "type": "agent_action",
            "agent": action.agent.value,
            "action_type": action.action_type,
            "tool_name": action.tool_name,
            "tool_input": action.tool_input,
            "tool_output": action.tool_output[:500] if action.tool_output else "",
            "thought": action.thought[:500] if action.thought else "",
            "timestamp": action.timestamp.isoformat(),
        }))
        if action.action_type == "tool_call" and action.tool_name:
            asyncio.create_task(_broadcast({
                "type": "search_log",
                "tool": action.tool_name,
                "query": str(action.tool_input or "")[:200],
                "timestamp": action.timestamp.isoformat(),
            }))

    def on_phase(phase: ScanPhase):
        asyncio.create_task(_broadcast({
            "type": "phase_change",
            "phase": phase.value,
        }))

    try:
        orchestrator = OrchestratorAgent(
            config=config,
            on_action=on_action,
            on_phase=on_phase,
        )
        report = await orchestrator.run(target)
        current_scan["report"] = report

        json_path = save_json_report(report, config.reporting.output_dir)
        html_path = save_html_report(report, config.reporting.output_dir)

        await _persist_report(report, target_host)

        vulns = [
            {
                "title": v.title,
                "severity": v.severity.value,
                "tool": v.tool,
                "description": v.description,
                "cwe_id": v.cwe_id,
                "cvss_score": v.cvss_score,
                "remediation": v.remediation,
            }
            for v in report.vulnerabilities
        ]

        tool_results = [
            {
                "tool": tr.tool_name,
                "success": tr.success,
                "findings": len(tr.vulnerabilities),
                "duration": round(tr.duration_seconds, 2),
                "error": tr.error,
            }
            for tr in report.tool_results
        ]

        attack_chains = [
            {
                "name": c.name,
                "combined_cvss": c.combined_cvss,
                "impact": c.impact,
                "mitre_techniques": c.mitre_techniques,
                "steps": [{"title": s.title, "severity": s.severity.value} for s in c.steps],
            }
            for c in report.attack_chains
        ]

        await _broadcast({
            "type": "scan_complete",
            "target": target_host,
            "risk_score": report.risk_score,
            "threat_level": report.threat_level,
            "summary": report.ai_summary,
            "total_vulns": report.total_vulns,
            "vuln_counts": report.vuln_counts,
            "vulnerabilities": vulns,
            "tool_results": tool_results,
            "attack_chains": attack_chains,
            "mitre_tactics": report.mitre_tactics,
            "remediation_steps": report.remediation_steps,
            "duration": round(report.total_duration_seconds, 2),
            "json_report": json_path,
            "html_report": html_path,
        })

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        await _broadcast({"type": "scan_error", "message": str(e)})
    finally:
        current_scan["running"] = False
        current_scan["cancel_event"] = None


def run_server(host: str = "127.0.0.1", port: int = 8477):
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
