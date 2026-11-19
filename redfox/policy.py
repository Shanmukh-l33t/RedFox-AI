"""The single choke point between an agent's decision and a running tool.

`PolicyEnforcementPoint.check()` is called by the runtime for *every* proposed
tool call, immediately before the process is spawned. Adapters cannot spawn
processes (see runtime.py), so there is no code path to a tool that skips this.

Checks, in order:
  1. kill switch
  2. quiet hours
  3. risk class against the engagement's autonomy ceiling
  4. intrusive actions require explicit approval unless the engagement is
     lab-attested, at L3, and configured to auto-approve
  5. target inside the signed scope (deny-by-default)
  6. requested ports inside the authorized port spec
  7. rate limits (per engagement and per target)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import RISK_RANK, Settings
from .models import Decision, Scope, ScopeError, ToolCall, parse_target


class RateLimiter:
    """Sliding-window limiter. In-process is enough: one campaign node."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def take(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > window_s:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


@dataclass
class CampaignBudget:
    actions: int = 0
    denied: int = 0
    failures: int = 0
    started: float = 0.0


MAX_RISK_BY_LEVEL = {0: "passive", 1: "active", 2: "validation", 3: "intrusive"}


class PolicyEnforcementPoint:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.limiter = RateLimiter()
        # Set by the campaign: (tool, target) -> approval row or None.
        self.approval_lookup = None

    def bind_approvals(self, lookup) -> None:
        self.approval_lookup = lookup

    # ---- kill switch -------------------------------------------------
    def killed(self) -> bool:
        return Path(self.settings.kill_switch_path).exists()

    def engage_kill(self) -> None:
        Path(self.settings.kill_switch_path).write_text(
            f"engaged at {datetime.now().isoformat(timespec='seconds')}\n", encoding="utf-8"
        )

    def clear_kill(self) -> None:
        Path(self.settings.kill_switch_path).unlink(missing_ok=True)

    # ---- quiet hours -------------------------------------------------
    def _in_quiet_hours(self) -> bool:
        spec = (self.settings.quiet_hours or "").strip()
        if not spec or "-" not in spec:
            return False
        try:
            start_s, end_s = spec.split("-", 1)
            start = datetime.strptime(start_s.strip(), "%H:%M").time()
            end = datetime.strptime(end_s.strip(), "%H:%M").time()
        except ValueError:
            return False
        current = datetime.now().time()
        if start <= end:
            return start <= current <= end
        return current >= start or current <= end

    # ---- the decision ------------------------------------------------
    def check(self, call: ToolCall, engagement: dict, agent: str = "unknown") -> Decision:
        risk = call.risk if call.risk in RISK_RANK else "intrusive"

        if self.killed():
            return Decision(False, "kill switch is engaged; all agent actions are halted", risk)

        if self._in_quiet_hours():
            return Decision(False, "within configured quiet hours", risk)

        autonomy = int(engagement.get("autonomy", 0))
        ceiling = MAX_RISK_BY_LEVEL.get(autonomy, "passive")
        if RISK_RANK[risk] > RISK_RANK[ceiling]:
            return Decision(
                False,
                f"risk class '{risk}' exceeds autonomy level L{autonomy} ({ceiling})",
                risk,
            )

        if risk == "intrusive":
            auth = engagement.get("authorization") or {}
            cfg = engagement.get("config") or {}
            lab_ok = bool(auth.get("lab_isolated")) and autonomy >= 3
            auto_ok = lab_ok and bool(cfg.get("auto_intrusive", False))
            approved = False
            if not auto_ok:
                approval = None
                if self.approval_lookup is not None:
                    approval = self.approval_lookup(call.tool, call.target)
                if not approval:
                    return Decision(
                        False,
                        "intrusive action requires explicit human approval",
                        risk,
                        needs_approval=True,
                    )
                approved = True

        # Scope: deny-by-default.
        try:
            target = parse_target(call.target)
        except ScopeError as exc:
            return Decision(False, f"unresolvable target: {exc}", risk)

        if target.kind == "cidr":
            return Decision(
                False,
                "a network range is not an executable target; expand it to hosts first",
                risk,
            )

        scope = Scope.from_dict(engagement["scope"])
        ok, why = scope.check(target)
        if not ok:
            return Decision(False, why, risk)

        if call.ports:
            ok, why = scope.check_ports(list(call.ports))
            if not ok:
                return Decision(False, why, risk)

        eid = engagement["id"]
        if not self.limiter.take(f"eng:{eid}", self.settings.rate_per_min):
            return Decision(False, "engagement rate limit reached", risk)
        if not self.limiter.take(f"tgt:{eid}:{target.key}",
                                 self.settings.rate_per_target_per_min):
            return Decision(False, f"per-target rate limit reached for {target.key}", risk)

        if risk == "intrusive" and approved:
            return Decision(True, f"authorized by operator approval: {why}", risk,
                            via_approval=True)
        return Decision(True, f"authorized: {why}", risk)