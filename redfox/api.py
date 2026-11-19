"""FastAPI surface: engagements, live events, findings, reports, approvals.

Binds loopback by default. There is deliberately no anonymous remote control:
the CLI and this API act on the same local state directory.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
import hmac

from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .audit import AuditLog
from .config import Settings
from .db import Store
from .engine import Campaign
from .models import Authorization, Scope, ScopeError
from .policy import PolicyEnforcementPoint

WEB_DIR = Path(__file__).resolve().parent / "web"


class ScopeDocument(BaseModel):
    name: str = "engagement"
    autonomy: int = Field(default=2, ge=0, le=3)
    scope: dict[str, Any]
    authorization: dict[str, Any]
    config: dict[str, Any] = Field(default_factory=dict)


class RunRequest(BaseModel):
    max_steps: int | None = None


class ApprovalRequest(BaseModel):
    approved: bool
    note: str = ""


def create_app(home: str | None = None) -> FastAPI:
    settings = Settings.load(home)
    store = Store(settings.db_path)
    audit = AuditLog(settings.audit_path)
    policy = PolicyEnforcementPoint(settings)
    running: dict[str, asyncio.Task] = {}

    app = FastAPI(title="RedFox AI", version="0.1.0",
                  description="Autonomous, scope-bound penetration testing platform.")

    def campaign() -> Campaign:
        return Campaign(settings, store, audit, policy)

    def require(eid: str) -> dict:
        eng = store.get_engagement(eid)
        if not eng:
            raise HTTPException(status_code=404, detail="engagement not found")
        return eng

    @app.middleware("http")
    async def authenticate(request, call_next):
        """Bearer token on every data route when REDFOX_API_TOKEN is set.

        Off by default: the server binds loopback and the shell is the trust
        boundary. Set the token before putting anything in front of it.
        """
        if settings.api_token and request.url.path.startswith("/api"):
            supplied = request.headers.get("x-redfox-token") or ""
            header = request.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                supplied = header[7:]
            if not hmac.compare_digest(supplied, settings.api_token):
                return JSONResponse({"detail": "invalid or missing API token"},
                                    status_code=401)
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        c = campaign()
        return {"status": "ok", "tools": c.toolbox.available(),
                "kill_switch": policy.killed(),
                "llm": {"provider": c.llm.provider, "model": c.llm.model,
                        "configured": c.llm.configured}}

    @app.post("/api/engagements")
    def create_engagement(doc: ScopeDocument) -> dict[str, Any]:
        try:
            scope = Scope.from_dict(doc.scope)
            auth = Authorization.from_dict(doc.authorization)
        except ScopeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        eid = store.create_engagement(doc.name, scope.as_dict(), auth.as_dict(),
                                      doc.autonomy, doc.config)
        return {"engagement": eid, "scope": scope.as_dict()}

    @app.get("/api/engagements")
    def list_engagements() -> list[dict[str, Any]]:
        return store.list_engagements()

    @app.get("/api/engagements/{eid}")
    def get_engagement(eid: str) -> dict[str, Any]:
        eng = require(eid)
        return {"engagement": eng, "assets": store.assets_for(eid),
                "findings": store.findings_for(eid),
                "actions": store.actions_for(eid)[-50:],
                "summary": campaign().summary(eid)}

    @app.post("/api/engagements/{eid}/run")
    async def run(eid: str, body: RunRequest) -> dict[str, Any]:
        require(eid)
        if eid in running and not running[eid].done():
            return {"status": "already running"}
        task = asyncio.create_task(campaign().run(eid, body.max_steps))
        running[eid] = task
        return {"status": "started"}

    @app.post("/api/engagements/{eid}/halt")
    def halt(eid: str) -> dict[str, Any]:
        require(eid)
        store.set_status(eid, "paused")
        return {"status": "paused"}

    @app.post("/api/kill")
    def kill(undo: bool = False) -> dict[str, Any]:
        if undo:
            policy.clear_kill()
        else:
            policy.engage_kill()
            Campaign(settings, store, audit, policy).runtime.kill_all()
        audit.append({"event": "killswitch.undo" if undo else "killswitch.engaged"})
        return {"kill_switch": policy.killed()}

    @app.get("/api/engagements/{eid}/findings")
    def findings(eid: str) -> list[dict[str, Any]]:
        require(eid)
        return store.findings_for(eid)

    @app.get("/api/engagements/{eid}/events")
    def events(eid: str, after: int = 0) -> list[dict[str, Any]]:
        require(eid)
        return store.events_since(eid, after)

    @app.get("/api/engagements/{eid}/report")
    def report_file(eid: str, fmt: str = "html") -> FileResponse:
        require(eid)
        ext = {"html": "report.html", "md": "report.md", "sarif": "report.sarif"}.get(fmt)
        if not ext:
            raise HTTPException(status_code=422, detail="fmt must be html, md or sarif")
        path = settings.home / "reports" / eid / ext
        if not path.exists():
            raise HTTPException(status_code=404, detail="report not generated yet")
        return FileResponse(path)

    @app.get("/api/engagements/{eid}/approvals")
    def approvals(eid: str) -> list[dict[str, Any]]:
        require(eid)
        pending = store.pending_approval(eid)
        return [pending] if pending else []

    @app.post("/api/approvals/{approval_id}")
    def decide(approval_id: str, body: ApprovalRequest) -> dict[str, Any]:
        result = store.decide_approval(approval_id, body.approved, body.note)
        if not result:
            raise HTTPException(status_code=404, detail="approval not found")
        return result

    @app.get("/api/audit/verify")
    def verify_audit() -> dict[str, Any]:
        ok, message = audit.verify()
        return {"ok": ok, "message": message}

    @app.websocket("/ws/{eid}")
    async def stream(websocket: WebSocket, eid: str) -> None:
        if settings.api_token:
            supplied = websocket.query_params.get("token") or ""
            if not hmac.compare_digest(supplied, settings.api_token):
                await websocket.close(code=4401)
                return
        await websocket.accept()
        last = 0
        try:
            while True:
                for event in store.events_since(eid, last):
                    last = event["id"]
                    await websocket.send_text(json.dumps(event, default=str))
                eng = store.get_engagement(eid)
                if eng:
                    await websocket.send_text(json.dumps({"type": "status",
                                                          "status": eng["status"]}))
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        path = WEB_DIR / "index.html"
        if not path.exists():
            return HTMLResponse("<h1>RedFox AI</h1><p>web assets missing</p>", status_code=500)
        return HTMLResponse(path.read_text(encoding="utf-8"))

    @app.get("/app.js")
    def app_js() -> FileResponse:
        return FileResponse(WEB_DIR / "app.js", media_type="application/javascript")

    return app