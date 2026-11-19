"""Command line interface.

    redfox init scope.json      # create an engagement from an attested scope file
    redfox run <id>             # run (or resume) the campaign
    redfox status <id>          # state, findings counts, audit chain
    redfox findings <id>        # list findings with evidence ids
    redfox report <id>          # write report bundle
    redfox scope-check <id> T   # prove a target is in/out of scope
    redfox kill | unkill        # global kill switch
    redfox verify-audit         # verify the hash chain
    redfox tools                # adapter availability
    redfox serve                # API + web UI on 127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .config import AUTONOMY_LEVELS, Settings
from .db import Store
from .engine import Campaign
from .models import Authorization, Scope, ScopeError, ToolCall, parse_target
from .policy import PolicyEnforcementPoint


def _context(home: str | None = None):
    settings = Settings.load(home)
    store = Store(settings.db_path)
    audit = AuditLog(settings.audit_path)
    policy = PolicyEnforcementPoint(settings)
    return settings, store, audit, policy


def cmd_init(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    raw = json.loads(Path(args.scope_file).read_text(encoding="utf-8"))
    try:
        scope = Scope.from_dict(raw.get("scope") or raw)
        auth = Authorization.from_dict(raw.get("authorization") or {})
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    autonomy = int(raw.get("autonomy", args.autonomy))
    if autonomy not in AUTONOMY_LEVELS:
        print(f"refused: autonomy must be one of {sorted(AUTONOMY_LEVELS)}", file=sys.stderr)
        return 2
    eid = store.create_engagement(
        raw.get("name") or Path(args.scope_file).stem,
        scope.as_dict(), auth.as_dict(), autonomy, raw.get("config") or {},
    )
    policy.clear_kill()
    print(json.dumps({"engagement": eid, "autonomy": autonomy,
                      "scope": scope.as_dict(), "operator": auth.operator}, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    campaign = Campaign(settings, store, audit, policy)
    try:
        summary = asyncio.run(campaign.run(args.engagement, args.max_steps))
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # surface the reason, never a fake success
        print(f"campaign stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0 if summary["status"] in {"completed", "halted"} else 1


def cmd_status(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    eng = store.get_engagement(args.engagement)
    if not eng:
        print("no such engagement", file=sys.stderr)
        return 2
    campaign = Campaign(settings, store, audit, policy)
    print(json.dumps(campaign.summary(args.engagement), indent=2))
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    settings, store, _, _ = _context(args.home)
    findings = store.findings_for(args.engagement)
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0
    if not findings:
        print("no findings recorded")
        return 0
    for f in findings:
        print(f"[{f['severity']:8}] {f['status']:12} {f['title'][:60]:60} "
              f"{f.get('location') or f['asset']}")
        if f["evidence_ids"]:
            print(f"           evidence: {', '.join(f['evidence_ids'])}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    eng = store.get_engagement(args.engagement)
    if not eng:
        print("no such engagement", file=sys.stderr)
        return 2
    campaign = Campaign(settings, store, audit, policy)
    result = asyncio.run(campaign.write_report(args.engagement))
    print(json.dumps(result, indent=2))
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    eng = store.get_engagement(args.engagement)
    if not eng:
        print("no such engagement", file=sys.stderr)
        return 2
    call = ToolCall(tool="nmap", target=args.target, argv=("-sT", args.target),
                    risk=args.risk)
    decision = policy.check(call, eng, "cli")
    audit.append({"engagement_id": args.engagement, "event": "scope.check",
                  "target": args.target, "allowed": decision.allowed,
                  "reason": decision.reason})
    print(json.dumps(decision.as_dict(), indent=2))
    return 0 if decision.allowed else 3


def cmd_kill(args: argparse.Namespace) -> int:
    settings, _, audit, policy = _context(args.home)
    if args.undo:
        policy.clear_kill()
        print("kill switch cleared")
    else:
        policy.engage_kill()
        audit.append({"event": "killswitch.engaged"})
        print(f"kill switch engaged ({settings.kill_switch_path}); "
              "all agents halt and in-flight tools are terminated")
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    settings, _, audit, _ = _context(args.home)
    ok, message = audit.verify()
    print(("OK: " if ok else "FAILED: ") + message)
    return 0 if ok else 1


def cmd_approvals(args: argparse.Namespace) -> int:
    settings, store, _, _ = _context(args.home)
    if not store.get_engagement(args.engagement):
        print("no such engagement", file=sys.stderr)
        return 2
    pending = store.pending_approval(args.engagement)
    if not pending:
        print("no pending approvals")
        return 0
    print(json.dumps(pending, indent=2))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    settings, store, audit, _ = _context(args.home)
    result = store.decide_approval(args.approval_id, not args.deny, args.note)
    if not result:
        print("no such approval", file=sys.stderr)
        return 2
    audit.append({"engagement_id": result["engagement_id"], "event": "approval.decided",
                  "approval_id": args.approval_id, "approved": not args.deny,
                  "note": args.note})
    print(json.dumps({"approval_id": args.approval_id,
                      "status": "denied" if args.deny else "approved"}, indent=2))
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    settings, store, audit, policy = _context(args.home)
    campaign = Campaign(settings, store, audit, policy)
    rows = campaign.toolbox.catalog()
    width = max(len(r["name"]) for r in rows)
    for row in rows:
        state = "available" if row["available"] else "NOT INSTALLED"
        print(f"{row['name']:{width}}  {row['risk']:10} {state}")
    return 0


def cmd_impact(args: argparse.Namespace) -> int:
    """Queue the gated impact demonstration. It still needs an approval to run."""
    settings, store, audit, policy = _context(args.home)
    eng = store.get_engagement(args.engagement)
    if not eng:
        print("no such engagement", file=sys.stderr)
        return 2
    if not (eng.get("config") or {}).get("impact"):
        print("refused: this engagement has no 'impact' spec in its config",
              file=sys.stderr)
        return 2
    store.add_task(args.engagement, "postexploit", "postexploit", "impact",
                   {"reason": "operator requested an impact demonstration"})
    campaign = Campaign(settings, store, audit, policy)
    summary = asyncio.run(campaign.run(args.engagement, args.max_steps))
    print(json.dumps(summary, indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .api import create_app

    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.i_know:
        print("refusing to bind a non-loopback address without --i-know", file=sys.stderr)
        return 2
    uvicorn.run(create_app(args.home), host=args.host, port=args.port, log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redfox", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", default=None, help="state directory (default ~/.redfox)")
    parser.add_argument("--version", action="version", version="redfox 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create an engagement from a scope file")
    p.add_argument("scope_file")
    p.add_argument("--autonomy", type=int, default=2, choices=sorted(AUTONOMY_LEVELS))
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("run", help="run or resume a campaign")
    p.add_argument("engagement")
    p.add_argument("--max-steps", type=int, default=None)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("status", help="campaign status")
    p.add_argument("engagement")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("findings", help="list findings")
    p.add_argument("engagement")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("report", help="write the report bundle")
    p.add_argument("engagement")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("scope-check", help="check one target against the scope")
    p.add_argument("engagement")
    p.add_argument("target")
    p.add_argument("--risk", default="active")
    p.set_defaults(func=cmd_scope_check)

    p = sub.add_parser("kill", help="engage or clear the kill switch")
    p.add_argument("--undo", action="store_true")
    p.set_defaults(func=cmd_kill)

    p = sub.add_parser("verify-audit", help="verify the audit hash chain")
    p.set_defaults(func=cmd_verify_audit)

    p = sub.add_parser("approvals", help="show a pending gated action")
    p.add_argument("engagement")
    p.set_defaults(func=cmd_approvals)

    p = sub.add_parser("approve", help="approve or deny a gated action")
    p.add_argument("approval_id")
    p.add_argument("--deny", action="store_true")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("tools", help="adapter availability")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("impact", help="queue the gated impact demonstration (L3 + approval)")
    p.add_argument("engagement")
    p.add_argument("--max-steps", type=int, default=3)
    p.set_defaults(func=cmd_impact)

    p = sub.add_parser("serve", help="API and web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--i-know", action="store_true")
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())