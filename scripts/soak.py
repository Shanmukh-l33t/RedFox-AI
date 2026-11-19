"""Soak/load check: repeat fresh init + campaign rounds against the lab target.

    python scripts/soak.py --rounds 3 --steps 12 [--home DIR] [--no-lab]

The scope used is examples/scope-lab.json, which authorizes ports 8080/8081 only:
passing different --port/--admin-port values will be refused by the policy gate,
which is the correct behaviour, not a bug in this script. Peak memory is
tracemalloc (Python allocations), not process RSS.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
import tracemalloc
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redfox.audit import AuditLog  # noqa: E402
from redfox.config import Settings  # noqa: E402
from redfox.db import Store  # noqa: E402
from redfox.engine import Campaign  # noqa: E402
from redfox.models import Authorization, Scope  # noqa: E402
from redfox.policy import PolicyEnforcementPoint  # noqa: E402

SCOPE_FILE = ROOT / "examples" / "scope-lab.json"


def http_ok(port: int, timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def wait_http(port: int, deadline_s: float = 15.0) -> bool:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if http_ok(port, timeout=0.5):
            return True
        time.sleep(0.1)
    return False


def start_lab(port: int, admin_port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "lab" / "vulnapp.py"),
         "--port", str(port), "--admin-port", str(admin_port)],
        cwd=str(ROOT),
    )
    if not wait_http(port):
        stop_lab(proc)
        raise RuntimeError(f"lab target did not answer on :{port} within 15s")
    return proc


def stop_lab(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def llm_ready() -> bool:
    if os.environ.get("REDFOX_LLM_PROVIDER", "openai").lower() == "ollama":
        return True
    return bool(os.environ.get("REDFOX_LLM_MODEL")) and bool(os.environ.get("REDFOX_LLM_API_KEY"))


def run_round(index: int, args: argparse.Namespace) -> dict:
    home = Path(args.home).expanduser() / f"round-{index:02d}"
    tracemalloc.start()
    started = time.perf_counter()
    try:
        settings = Settings.load(home)
        store = Store(settings.db_path)
        audit = AuditLog(settings.audit_path)
        policy = PolicyEnforcementPoint(settings)
        raw = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
        eid = store.create_engagement(
            raw.get("name") or f"soak-{index}",
            Scope.from_dict(raw["scope"]).as_dict(),
            Authorization.from_dict(raw["authorization"]).as_dict(),
            int(raw.get("autonomy", 2)),
            raw.get("config") or {},
        )
        policy.clear_kill()
        campaign = Campaign(settings, store, audit, policy)
        summary = asyncio.run(campaign.run(eid, args.steps))
        wall = time.perf_counter() - started
        peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        ok, message = audit.verify()
        return {
            "round": index,
            "wall_s": wall,
            "steps": summary.get("steps", 0),
            "tasks": dict(Counter(t["state"] for t in store.tasks_for(eid))),
            "allowed": summary.get("actions", {}).get("allowed", 0),
            "denied": summary.get("actions", {}).get("denied", 0),
            "evidence": summary.get("evidence", 0),
            "findings": dict(Counter(f["status"] for f in store.findings_for(eid))),
            "audit_ok": ok,
            "audit_msg": message,
            "peak_mib": peak,
        }
    except Exception as exc:  # a bad round must not kill the soak report
        return {
            "round": index,
            "wall_s": time.perf_counter() - started,
            "steps": 0,
            "tasks": {},
            "allowed": 0,
            "denied": 0,
            "evidence": 0,
            "findings": {},
            "audit_ok": False,
            "audit_msg": f"{type(exc).__name__}: {exc}",
            "peak_mib": tracemalloc.get_traced_memory()[1] / (1024 * 1024),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        tracemalloc.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Soak test RedFox campaigns")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--steps", type=int, default=8)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--admin-port", type=int, default=8081)
    parser.add_argument("--home", default=str(Path.home() / ".redfox-soak"))
    parser.add_argument("--no-lab", action="store_true", help="do not start the lab, just probe it")
    args = parser.parse_args(argv)

    lab = None
    try:
        if args.no_lab:
            print(f"lab: {'up' if http_ok(args.port, 2.0) else 'not running'} on :{args.port}")
        else:
            lab = start_lab(args.port, args.admin_port)
            print(f"lab: started on :{args.port} (admin :{args.admin_port})")

        if not llm_ready():
            print("no LLM configured (set REDFOX_LLM_MODEL + REDFOX_LLM_API_KEY, or "
                  "REDFOX_LLM_PROVIDER=ollama): skipping campaign rounds")
            return 0

        rounds = []
        for i in range(1, max(args.rounds, 1) + 1):
            r = run_round(i, args)
            rounds.append(r)
            verdict = "ERROR " + r["error"] if "error" in r else f"audit {'ok' if r['audit_ok'] else 'FAIL'}"
            print(f"round {i:02d}: {r['wall_s']:.2f}s {r['steps']} steps "
                  f"tasks={r['tasks']} actions={r['allowed']}/{r['denied']} "
                  f"evidence={r['evidence']} findings={r['findings']} {verdict} "
                  f"peak={r['peak_mib']:.1f}MiB")
            if "error" in r:
                break
    finally:
        stop_lab(lab)

    walls = [r["wall_s"] for r in rounds]
    total = sum(walls)
    actions = sum(r["allowed"] for r in rounds)
    denied = sum(r["denied"] for r in rounds)
    audit_failures = sum(1 for r in rounds if not r["audit_ok"])
    errors = sum(1 for r in rounds if "error" in r)
    print()
    print(f"{'rounds':<18}{len(rounds)}")
    print(f"{'total wall':<18}{total:.2f} s")
    print(f"{'median round':<18}{statistics.median(walls):.2f} s")
    print(f"{'actions/min':<18}{actions / (total / 60) if total else 0:.1f}")
    print(f"{'denied':<18}{denied} (must be 0)")
    print(f"{'audit failures':<18}{audit_failures} (must be 0)")
    print(f"{'tracemalloc peak':<18}{max(r['peak_mib'] for r in rounds):.1f} MiB")
    return 1 if (denied or audit_failures or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())