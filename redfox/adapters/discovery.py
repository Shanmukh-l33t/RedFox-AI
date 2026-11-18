"""Passive discovery: subfinder.

Passive means it asks third-party data sources (certificate transparency, search
engines), not the target. Classified `passive`, so it is the one adapter usable
at autonomy L0.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from ..models import ExecutionResult, Target, ToolCall
from .base import Observation, ToolAdapter


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    binary = "subfinder"
    risk = "passive"
    summary = "Passive subdomain enumeration from public data sources."
    phases = ("recon",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        if target.kind not in {"domain", "url"}:
            return []
        yield ToolCall(
            tool=self.name, target=target.host,
            argv=("-d", target.host, "-silent", "-json", "-no-color",
                  "-timeout", "10", "-max-time", "5"),
            risk=self.risk, timeout_s=300,
            reason="passive subdomain discovery from public sources",
        )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            host = ""
            source = ""
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                    host = row.get("host", "")
                    source = row.get("source", "")
                except json.JSONDecodeError:
                    continue
            else:
                host = line
            if host:
                out.append(Observation("host", {"host": host, "source": source or "subfinder"}))
        return out