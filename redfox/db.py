"""SQLite persistence: engagement state, findings, evidence, approvals, memory.

One file, WAL journal, foreign keys on. Every mutation is a short transaction so
a crash mid-campaign leaves a consistent state that the engine can resume from.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS engagements (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  authorization_json TEXT NOT NULL,
  autonomy INTEGER NOT NULL,
  status TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  agent TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  result_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_engagement ON tasks(engagement_id, state);

CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  task_id TEXT,
  agent TEXT NOT NULL,
  tool TEXT NOT NULL,
  target TEXT NOT NULL,
  argv_json TEXT NOT NULL,
  risk TEXT NOT NULL,
  decision TEXT NOT NULL,
  deny_reason TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exit_code INTEGER,
  evidence_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_engagement ON actions(engagement_id, started_at);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  action_id TEXT,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  summary TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER,
  service TEXT,
  product TEXT,
  version TEXT,
  status TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, host, port, service)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  cvss REAL,
  cve TEXT,
  asset TEXT NOT NULL,
  location TEXT,
  description TEXT NOT NULL,
  reproduction_json TEXT NOT NULL DEFAULT '[]',
  remediation TEXT,
  status TEXT NOT NULL,
  evidence_ids_json TEXT NOT NULL DEFAULT '[]',
  source_tool TEXT,
  template_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(engagement_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  action_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_at TEXT NOT NULL,
  decided_at TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id TEXT,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_key ON memory(kind, key);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id TEXT,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}'
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- engagements -------------------------------------------------
    def create_engagement(self, name: str, scope_json: dict, auth_json: dict, autonomy: int,
                          config: dict | None = None) -> str:
        eid = new_id("eng")
        ts = now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO engagements(id,name,scope_json,authorization_json,autonomy,status,"
                "config_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (eid, name, json.dumps(scope_json), json.dumps(auth_json), autonomy,
                 "created", json.dumps(config or {}), ts, ts),
            )
        self.event(eid, "engagement.created", {"name": name, "autonomy": autonomy})
        return eid

    def get_engagement(self, eid: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
        return _engagement_row(row) if row else None

    def list_engagements(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM engagements ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_engagement_row(r) for r in rows]

    def set_status(self, eid: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE engagements SET status=?, updated_at=? WHERE id=?", (status, now(), eid)
            )
        self.event(eid, "engagement.status", {"status": status})

    # ---- tasks -------------------------------------------------------
    def add_task(self, eid: str, phase: str, agent: str, kind: str, payload: dict) -> str:
        tid = new_id("task")
        ts = now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tasks(id,engagement_id,phase,agent,kind,payload_json,state,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (tid, eid, phase, agent, kind, json.dumps(payload), "pending", ts, ts),
            )
        return tid

    def next_task(self, eid: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE engagement_id=? AND state='pending' "
                "ORDER BY created_at LIMIT 1", (eid,)
            ).fetchone()
        return _task_row(row) if row else None

    def claim_task(self, tid: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE tasks SET state='running', attempts=attempts+1, updated_at=? "
                "WHERE id=? AND state='pending'", (now(), tid)
            )
            return cur.rowcount == 1

    def finish_task(self, tid: str, state: str, result: dict | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE tasks SET state=?, result_json=?, updated_at=? WHERE id=?",
                (state, json.dumps(result or {}), now(), tid),
            )

    def tasks_for(self, eid: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE engagement_id=? ORDER BY created_at", (eid,)
            ).fetchall()
        return [_task_row(r) for r in rows]

    def reset_running_tasks(self, eid: str) -> int:
        """Crash recovery: a task stuck in 'running' is requeued, not lost."""
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE tasks SET state='pending', updated_at=? "
                "WHERE engagement_id=? AND state='running'", (now(), eid)
            )
            return cur.rowcount

    # ---- actions / evidence -----------------------------------------
    def record_action(self, **kw: Any) -> str:
        aid = kw.pop("id", None) or new_id("act")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO actions(id,engagement_id,task_id,agent,tool,target,argv_json,risk,"
                "decision,deny_reason,started_at,finished_at,exit_code,evidence_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, kw["engagement_id"], kw.get("task_id"), kw["agent"], kw["tool"],
                 kw["target"], json.dumps(kw.get("argv", [])), kw["risk"],
                 kw["decision"], kw.get("deny_reason"), kw.get("started_at") or now(),
                 kw.get("finished_at"), kw.get("exit_code"), kw.get("evidence_id")),
            )
        return aid

    def add_evidence(self, eid: str, action_id: str | None, kind: str, path: str,
                     sha256: str, summary: str = "") -> str:
        vid = new_id("ev")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO evidence(id,engagement_id,action_id,kind,path,sha256,summary,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (vid, eid, action_id, kind, path, sha256, summary, now()),
            )
        return vid

    def get_evidence(self, vid: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM evidence WHERE id=?", (vid,)).fetchone()
        return dict(row) if row else None

    def evidence_for(self, eid: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE engagement_id=? ORDER BY created_at", (eid,)
            ).fetchall()
        return [dict(r) for r in rows]

    def actions_for(self, eid: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE engagement_id=? ORDER BY started_at", (eid,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- assets ------------------------------------------------------
    def upsert_asset(self, eid: str, target: str, host: str, port: int | None = None,
                     service: str = "", product: str = "", version: str = "",
                     status: str = "") -> None:
        ts = now()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM assets WHERE engagement_id=? AND host=? AND port IS ? AND service=?",
                (eid, host, port, service),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE assets SET product=?,version=?,status=?,last_seen=? WHERE id=?",
                    (product, version, status, ts, row["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO assets(engagement_id,target,host,port,service,product,version,"
                    "status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (eid, target, host, port, service, product, version, status, ts, ts),
                )

    def assets_for(self, eid: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM assets WHERE engagement_id=? ORDER BY host,port", (eid,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- findings ----------------------------------------------------
    def upsert_finding(self, eid: str, fingerprint: str, title: str, severity: str,
                       asset: str, description: str, status: str = "candidate",
                       cvss: float | None = None, cve: str = "", location: str = "",
                       reproduction: list[str] | None = None, remediation: str = "",
                       evidence_ids: list[str] | None = None, source_tool: str = "",
                       template_id: str = "") -> str:
        ts = now()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id,status FROM findings WHERE engagement_id=? AND fingerprint=?",
                (eid, fingerprint),
            ).fetchone()
            if row:
                # Validated beats candidate; never silently downgrade evidence.
                final_status = row["status"] if row["status"] == "validated" else status
                conn.execute(
                    "UPDATE findings SET title=?,severity=?,cvss=?,cve=?,asset=?,location=?,"
                    "description=?,reproduction_json=?,remediation=?,status=?,evidence_ids_json=?,"
                    "source_tool=?,template_id=?,updated_at=? WHERE id=?",
                    (title, severity, cvss, cve, asset, location, description,
                     json.dumps(reproduction or []), remediation, final_status,
                     json.dumps(sorted(set(evidence_ids or []))), source_tool,
                     template_id or "", ts, row["id"]),
                )
                return str(row["id"])
            fid = new_id("find")
            conn.execute(
                "INSERT INTO findings(id,engagement_id,fingerprint,title,severity,cvss,cve,asset,"
                "location,description,reproduction_json,remediation,status,evidence_ids_json,"
                "source_tool,template_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, eid, fingerprint, title, severity, cvss, cve, asset, location, description,
                 json.dumps(reproduction or []), remediation, status,
                 json.dumps(sorted(set(evidence_ids or []))), source_tool, template_id, ts, ts),
            )
        return fid

    def finding_by_fingerprint(self, eid: str, fingerprint: str) -> dict | None:
        for finding in self.findings_for(eid):
            if finding["fingerprint"] == fingerprint:
                return finding
        return None

    def update_finding(self, eid: str, fingerprint: str, **fields: Any) -> None:
        """Update triage/validation fields. Unknown keys are ignored on purpose."""
        allowed = {"title", "severity", "cvss", "status", "description", "remediation",
                   "location", "asset", "cve"}
        sets, values = [], []
        for key, value in fields.items():
            if key not in allowed or value is None:
                continue
            sets.append(f"{key}=?")
            values.append(value)
        add_evidence = fields.get("evidence_ids")
        if add_evidence:
            current = self.finding_by_fingerprint(eid, fingerprint)
            merged = sorted(set((current or {}).get("evidence_ids", [])) | set(add_evidence))
            sets.append("evidence_ids_json=?")
            values.append(json.dumps(merged))
        if fields.get("reproduction"):
            sets.append("reproduction_json=?")
            values.append(json.dumps(fields["reproduction"]))
        if not sets:
            return
        sets.append("updated_at=?")
        values.append(now())
        values.extend([eid, fingerprint])
        with self.connect() as conn:
            conn.execute(
                f"UPDATE findings SET {', '.join(sets)} WHERE engagement_id=? AND fingerprint=?",
                values,
            )

    def findings_for(self, eid: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE engagement_id=? ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, title", (eid,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reproduction"] = json.loads(d.pop("reproduction_json") or "[]")
            d["evidence_ids"] = json.loads(d.pop("evidence_ids_json") or "[]")
            out.append(d)
        return out

    # ---- approvals ---------------------------------------------------
    def request_approval(self, eid: str, action_json: dict, reason: str) -> str:
        pid = new_id("apr")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO approvals(id,engagement_id,action_json,reason,status,requested_at)"
                " VALUES(?,?,?,?,?,?)",
                (pid, eid, json.dumps(action_json), reason, "pending", now()),
            )
        self.event(eid, "approval.requested", {"approval_id": pid, "reason": reason})
        return pid

    def decide_approval(self, pid: str, approved: bool, note: str = "") -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (pid,)).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE approvals SET status=?, decided_at=?, note=? WHERE id=?",
                ("approved" if approved else "denied", now(), note, pid),
            )
        out = dict(row)
        out["status"] = "approved" if approved else "denied"
        self.event(out["engagement_id"], "approval.decided",
                   {"approval_id": pid, "approved": approved, "note": note})
        return out

    def pending_approval(self, eid: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE engagement_id=? AND status='pending' "
                "ORDER BY requested_at LIMIT 1", (eid,)
            ).fetchone()
        return dict(row) if row else None

    # ---- memory ------------------------------------------------------
    def add_memory(self, kind: str, key: str, value: str, eid: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO memory(engagement_id,kind,key,value,created_at) VALUES(?,?,?,?,?)",
                (eid, kind, key, value, now()),
            )

    def recall(self, kind: str, key: str, limit: int = 5) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT value FROM memory WHERE kind=? AND key=? ORDER BY id DESC LIMIT ?",
                (kind, key, limit),
            ).fetchall()
        return [r["value"] for r in rows]

    # ---- events ------------------------------------------------------
    def event(self, eid: str | None, etype: str, payload: dict | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events(engagement_id,ts,type,payload_json) VALUES(?,?,?,?)",
                (eid, now(), etype, json.dumps(payload or {})),
            )

    def events_since(self, eid: str, last_id: int = 0, limit: int = 200) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE engagement_id=? AND id>? ORDER BY id LIMIT ?",
                (eid, last_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]


def _engagement_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["scope"] = json.loads(d.pop("scope_json"))
    d["authorization"] = json.loads(d.pop("authorization_json"))
    d["config"] = json.loads(d.pop("config_json") or "{}")
    return d


def _task_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["payload"] = json.loads(d.pop("payload_json") or "{}")
    d["result"] = json.loads(d.pop("result_json") or "{}")
    return d