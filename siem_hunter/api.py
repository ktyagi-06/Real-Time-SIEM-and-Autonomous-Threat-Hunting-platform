"""FastAPI application: REST API + the dashboard."""
from __future__ import annotations

import hmac
import os
import time
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import simulator
from .config import Config
from .pipeline import Platform

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "dashboard")
MAX_LINES = 100_000

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


class IngestBody(BaseModel):
    lines: List[str] = Field(..., description="Raw log lines (syslog, nginx, Windows JSON, flow JSON ...)")
    host: Optional[str] = Field(None, description="Default host name for formats that carry none")


class StatusBody(BaseModel):
    status: str


class DemoBody(BaseModel):
    reset: bool = True
    seed: int = 7
    attack: bool = True


def create_app(platform: Optional[Platform] = None) -> FastAPI:
    platform = platform or Platform()
    cfg: Config = platform.cfg
    app = FastAPI(title="SIEM + Autonomous Threat Hunting Platform", version="1.0.0")
    app.state.platform = platform

    def require_key(x_api_key: Optional[str] = Header(default=None)) -> str:
        """Authenticate; returns the actor name recorded in the audit log."""
        if cfg.api_key:
            if not x_api_key or not hmac.compare_digest(x_api_key, cfg.api_key):
                raise HTTPException(status_code=401, detail="missing or invalid API key")
            return "analyst"
        return "analyst"

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------------------------------------------------------- dashboard
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))

    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    # ---------------------------------------------------------------- basics
    @app.get("/api/health")
    def health():
        return {"status": "ok", "events": platform.store.count_events(), "auth_required": bool(cfg.api_key),
                "demo_enabled": cfg.enable_demo, "llm": "enabled" if cfg.llm_enabled else "disabled",
                "auto_response": cfg.auto_response, "time": time.time()}

    @app.get("/api/stats", dependencies=[Depends(require_key)])
    def stats():
        return platform.store.stats()

    # ---------------------------------------------------------------- ingestion
    @app.post("/api/ingest", dependencies=[Depends(require_key)])
    def ingest(body: IngestBody):
        if len(body.lines) > MAX_LINES:
            raise HTTPException(413, f"too many lines (max {MAX_LINES} per request)")
        return platform.ingest_lines(body.lines, default_host=body.host)

    @app.post("/api/ingest/text", dependencies=[Depends(require_key)])
    async def ingest_text(request: Request, host: Optional[str] = None):
        raw = await request.body()
        if len(raw) > 50_000_000:
            raise HTTPException(413, "body too large")
        lines = raw.decode("utf-8", "replace").splitlines()
        if len(lines) > MAX_LINES * 5:
            raise HTTPException(413, "too many lines")
        return platform.ingest_lines(lines, default_host=host)

    @app.post("/api/demo/load")
    def demo_load(body: DemoBody = DemoBody(), _: str = Depends(require_key)):
        if not cfg.enable_demo:
            raise HTTPException(403, "demo mode is disabled")
        if body.reset:
            platform.store.reset()
        end = time.time()
        totals = {"stored": 0, "alerts_created": 0}
        for name, lines in simulator.generate(end_ts=end, seed=body.seed, attack=body.attack).items():
            r = platform.ingest_lines(lines, default_host=simulator.DEFAULT_HOSTS.get(name), ref_time=end)
            totals["stored"] += r["stored"]
            totals["alerts_created"] += r["alerts_created"]
        platform.store.audit("analyst", "demo_loaded", totals)
        return totals

    # ---------------------------------------------------------------- alerts
    @app.get("/api/alerts", dependencies=[Depends(require_key)])
    def alerts(severity: Optional[str] = None, status: Optional[str] = None, limit: int = Query(200, ge=1, le=1000)):
        return platform.store.list_alerts(severity=severity, status=status, limit=limit)

    @app.get("/api/alerts/{alert_id}", dependencies=[Depends(require_key)])
    def alert_detail(alert_id: int):
        d = platform.alert_detail(alert_id)
        if d is None:
            raise HTTPException(404, "alert not found")
        return d

    @app.post("/api/alerts/{alert_id}/investigate")
    def investigate(alert_id: int, actor: str = Depends(require_key)):
        inv = platform.investigate(alert_id)
        if inv is None:
            raise HTTPException(404, "alert not found or already closed")
        platform.store.audit(actor, "investigation_run", {"alert_id": alert_id})
        return platform.alert_detail(alert_id)

    @app.post("/api/alerts/{alert_id}/status")
    def set_status(alert_id: int, body: StatusBody, actor: str = Depends(require_key)):
        try:
            return platform.set_alert_status(alert_id, body.status, actor)
        except KeyError:
            raise HTTPException(404, "alert not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    # ---------------------------------------------------------------- events
    @app.get("/api/events/search", dependencies=[Depends(require_key)])
    def search(q: str = "", limit: int = Query(100, ge=1, le=1000)):
        return [e.to_dict() for e in platform.store.search(q, limit)]

    # ---------------------------------------------------------------- response
    @app.get("/api/actions", dependencies=[Depends(require_key)])
    def actions(status: Optional[str] = None, alert_id: Optional[int] = None, limit: int = Query(200, ge=1, le=1000)):
        return platform.store.list_actions(alert_id=alert_id, status=status, limit=limit)

    def _act(fn, action_id: int, actor: str):
        try:
            return fn(action_id, actor=actor)
        except KeyError:
            raise HTTPException(404, "action not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/actions/{action_id}/approve")
    def approve(action_id: int, actor: str = Depends(require_key)):
        return _act(platform.responder.approve, action_id, actor)

    @app.post("/api/actions/{action_id}/reject")
    def reject(action_id: int, actor: str = Depends(require_key)):
        return _act(platform.responder.reject, action_id, actor)

    @app.post("/api/actions/{action_id}/revert")
    def revert(action_id: int, actor: str = Depends(require_key)):
        return _act(platform.responder.revert, action_id, actor)

    @app.get("/api/enforcement", dependencies=[Depends(require_key)])
    def enforcement():
        return platform.store.list_enforcement()

    @app.get("/api/audit", dependencies=[Depends(require_key)])
    def audit(limit: int = Query(200, ge=1, le=1000)):
        return platform.store.list_audit(limit)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    return app


def app_factory() -> FastAPI:  # for `uvicorn siem_hunter.api:app_factory --factory`
    return create_app()
