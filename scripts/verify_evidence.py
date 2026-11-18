#!/usr/bin/env python3
"""Verify that every finding in an engagement is backed by intact evidence.

    python scripts/verify_evidence.py <engagement_id> [--home DIR]

Checks, in order:
  1. the audit hash chain is intact,
  2. every evidence row's file exists and its SHA-256 matches the stored digest,
  3. every finding references at least one existing evidence id,
  4. every reported finding's location was actually touched by a recorded action.

Exit code 0 only if all four pass. This is the check run before a report is
trusted; a report whose evidence fails here should not be delivered.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redfox.audit import AuditLog          # noqa: E402
from redfox.config import Settings         # noqa: E402
from redfox.db import Store                # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engagement")
    parser.add_argument("--home", default=None)
    args = parser.parse_args(argv)

    settings = Settings.load(args.home)
    store = Store(settings.db_path)
    audit = AuditLog(settings.audit_path)
    eid = args.engagement

    failures: list[str] = []

    ok, message = audit.verify()
    print(f"audit chain      : {'OK' if ok else 'FAILED'} — {message}")
    if not ok:
        failures.append(f"audit chain broken: {message}")

    evidence = {e["id"]: e for e in store.evidence_for(eid)}
    checked = 0
    for ev in evidence.values():
        path = Path(ev["path"])
        if not path.exists():
            failures.append(f"evidence {ev['id']} missing: {path}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != ev["sha256"]:
            failures.append(f"evidence {ev['id']} hash mismatch: {path}")
        checked += 1
    print(f"evidence files   : {checked}/{len(evidence)} intact")

    findings = store.findings_for(eid)
    for finding in findings:
        if not finding["evidence_ids"]:
            failures.append(f"finding without evidence: {finding['fingerprint']}")
            continue
        for ev_id in finding["evidence_ids"]:
            if ev_id not in evidence:
                failures.append(
                    f"finding {finding['fingerprint']} references unknown evidence {ev_id}")

    touched = {a["target"] for a in store.actions_for(eid) if a["decision"] == "allowed"}
    for finding in findings:
        location = (finding.get("location") or finding.get("asset") or "")
        if finding["status"] in {"validated", "candidate"} and location:
            if not any(location.startswith(t) or t.startswith(location) for t in touched):
                failures.append(
                    f"finding {finding['fingerprint']} location never fetched: {location}")

    print(f"findings         : {len(findings)} "
          f"({sum(1 for f in findings if f['status'] == 'validated')} validated)")

    if failures:
        print("\nFAILED:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\nAll findings are backed by intact, recorded evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())