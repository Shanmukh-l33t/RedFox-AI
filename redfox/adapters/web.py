"""Web-layer adapters: httpx, nuclei (discovery and validation), ffuf, whatweb.

Each parse() consumes only what the real tool printed. A missing binary, a
crash, or an empty result produces no observations — never a synthesised one.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from ..models import ExecutionResult, Target, ToolCall
from .base import Observation, ToolAdapter, base_urls


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binary = "httpx"
    risk = "active"
    summary = "HTTP probing: status, title, server, detected technologies for a URL."
    phases = ("recon", "enumeration")

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        for url in base_urls(target, ctx)[:4]:
            yield ToolCall(
                tool=self.name, target=url,
                argv=("-u", url, "-silent", "-json", "-no-color", "-title",
                      "-tech-detect", "-status-code", "-web-server", "-timeout", "10"),
                risk=self.risk, timeout_s=120, reason="HTTP fingerprint",
            )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(Observation("url", {
                "url": row.get("url") or row.get("input", ""),
                "status": row.get("status_code"),
                "title": (row.get("title") or "").strip(),
                "server": row.get("webserver") or row.get("web_server") or "",
                "tech": row.get("tech") or [],
                "content_length": row.get("content_length"),
                "final_url": row.get("final_url") or row.get("url", ""),
            }))
        return out


class NucleiAdapter(ToolAdapter):
    """Template-driven detection. `validate` mode targets specific template ids."""

    name = "nuclei"
    binary = "nuclei"
    risk = "active"
    summary = "Template-based vulnerability and exposure detection (ProjectDiscovery nuclei)."
    phases = ("enumeration", "analysis")

    DISCOVERY_TAGS = "exposure,misconfig,tech,default-login,headers"

    def __init__(self, validate: bool = False) -> None:
        self.validate = validate
        if validate:
            self.name = "nuclei_validate"
            self.risk = "validation"
            self.summary = "Re-runs specific nuclei templates to confirm a candidate finding."
            self.phases = ("validation",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        template_ids = ctx.get("template_ids") or []
        if self.validate and not template_ids:
            return []
        for url in base_urls(target, ctx)[:2]:
            argv = ["-u", url, "-jsonl", "-silent", "-no-color",
                    "-disable-update-check", "-stats=false", "-timeout", "15",
                    "-retries", "1", "-severity", "critical,high,medium,low"]
            if self.validate:
                argv += ["-id", ",".join(str(t) for t in template_ids)]
            else:
                argv += ["-tags", self.DISCOVERY_TAGS]
            yield ToolCall(
                tool=self.binary, target=url, argv=tuple(argv), risk=self.risk,
                timeout_s=900,
                reason=("confirm candidate with templates " + ",".join(template_ids)
                        if self.validate else "template sweep over discovery/misconfig classes"),
                meta={"adapter": self.name},
            )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            severity = str(info.get("severity", "unknown")).lower()
            classification = info.get("classification") or {}
            cves = classification.get("cve-id") or info.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            out.append(Observation("finding", {
                "title": info.get("name") or row.get("template-id", "unnamed template"),
                "severity": severity,
                "description": (info.get("description") or "").strip(),
                "location": row.get("matched-at") or row.get("host") or result.evidence_path,
                "template_id": row.get("template-id", ""),
                "cve": ",".join(cves) if cves else "",
                "cvss": classification.get("cvss-score"),
                "evidence_id": "",
                "extracted": row.get("extracted-results") or [],
                "curl_command": row.get("curl-command", ""),
                "confirmed": self.validate,
                "source_tool": self.name,
            }))
        return out


class FfufAdapter(ToolAdapter):
    name = "ffuf"
    binary = "ffuf"
    risk = "active"
    summary = "Content discovery with a bundled wordlist; reports non-404 responses."
    phases = ("enumeration",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        wordlist = ctx.get("wordlist")
        if not wordlist:
            return []
        for url in base_urls(target, ctx)[:2]:
            yield ToolCall(
                tool=self.name, target=url,
                argv=("-u", f"{url.rstrip('/')}/FUZZ", "-w", str(wordlist),
                      "-mc", "200,204,301,302,307,401,403,405,500",
                      "-t", "20", "-timeout", "10", "-noninteractive",
                      "-of", "json", "-o", "{out}"),
                risk=self.risk, timeout_s=600, reason="content discovery",
            )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        text = result.stdout.strip()
        if "{" not in text:
            return out
        try:
            payload = json.loads(text[text.find("{"):])
        except json.JSONDecodeError:
            return out
        for row in payload.get("results") or []:
            out.append(Observation("path", {
                "url": row.get("url", ""),
                "status": row.get("status"),
                "length": row.get("length"),
                "words": row.get("words"),
                "input": (row.get("input") or {}).get("FUZZ", ""),
            }))
        return out


_CONSOLE = re.compile(r"^(https?://\S+)\s+\[(\d{3})[^\]]*\]\s*(.*)$")


def _from_console(stdout: str) -> list[Observation]:
    """whatweb's default line: `URL [200 OK] Plugin[value], Other[value]`.

    Some builds do not create the --log-json file, so the human-readable line is
    the only thing to parse. Numbers and bare flags are noise, not technologies.
    """
    out: list[Observation] = []
    for line in stdout.splitlines():
        match = _CONSOLE.match(line.strip())
        if not match:
            continue
        url, status, rest = match.groups()
        tech = [part.split("[")[0].strip()
                for part in rest.split(", ")
                if "[" in part and not part.split("[")[0].strip().isdigit()]
        out.append(Observation("url", {
            "url": url, "status": int(status), "title": "", "server": "",
            "tech": tech, "content_length": None, "final_url": url,
        }))
    return out


class WhatwebAdapter(ToolAdapter):
    name = "whatweb"
    binary = "whatweb"
    risk = "active"
    summary = "Aggressive-safe technology fingerprinting via whatweb."
    phases = ("enumeration",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        for url in base_urls(target, ctx)[:2]:
            yield ToolCall(
                tool=self.name, target=url,
                argv=("--log-json={out}", "--color=never", "-a", "1", url),
                risk=self.risk, timeout_s=180, reason="technology fingerprint",
            )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        text = result.stdout.strip()
        # The runtime appends the tool's log file after an "[output-file]" marker;
        # that marker contains a bracket, so the JSON must be searched for after it.
        marker = text.rfind("[output-file]")
        if marker >= 0:
            text = text[marker + len("[output-file]"):]
        start = text.find("[")
        if start < 0:
            return _from_console(result.stdout)
        try:
            payload = json.loads(text[start:])
        except json.JSONDecodeError:
            return _from_console(result.stdout)
        for row in payload if isinstance(payload, list) else [payload]:
            tech = []
            for name, details in (row.get("plugins") or {}).items():
                version = ""
                if isinstance(details, dict):
                    versions = details.get("version") or []
                    if versions:
                        version = str(versions[0])
                tech.append(f"{name}{('/' + version) if version else ''}")
            out.append(Observation("url", {
                "url": row.get("target", ""),
                "status": row.get("http_status"),
                "title": "",
                "server": "",
                "tech": tech,
                "content_length": None,
                "final_url": row.get("target", ""),
            }))
        return out