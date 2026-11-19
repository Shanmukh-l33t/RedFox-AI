"""Passive discovery: amass.

`amass enum` asks certificate transparency, DNS and search-engine sources, so it
is classified `passive` like subfinder. `-json` writes one object per line to the
path the runtime substitutes for `{out}`.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from ..models import ExecutionResult, Target, ToolCall
from .base import Observation, ToolAdapter


class AmassAdapter(ToolAdapter):
    name = "amass"
    binary = "amass"
    risk = "passive"
    summary = "Passive subdomain enumeration from public data sources."
    phases = ("recon",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        if target.kind not in {"domain", "url"}:
            return []
        yield ToolCall(
            tool=self.name, target=target.host,
            argv=("enum", "-d", target.host, "-json", "{out}", "-silent", "-timeout", "10"),
            risk=self.risk, timeout_s=600,
            reason="passive subdomain discovery from public sources",
        )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Skip the runtime's own "[output-file]" marker and amass progress chatter.
            if not line or line.startswith("["):
                continue
            host = ""
            if line.startswith("{"):
                try:
                    host = json.loads(line).get("name", "")
                except json.JSONDecodeError:
                    continue
            elif " " not in line:
                host = line
            if host:
                out.append(Observation("host", {"host": host, "source": "amass"}))
        return out