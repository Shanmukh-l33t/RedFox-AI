"""Report generation: SARIF 2.1.0, Markdown, HTML.

Findings only appear here if they exist in the database with evidence attached.
The prose comes from the reporting agent; the facts never do.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
NOTICE = (
    "Authorized testing only. RedFox AI refuses targets that are not present in an "
    "operator-attested authorization scope. Unauthorized use is illegal."
)

LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def sarif(findings: list[dict[str, Any]], engagement: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = finding.get("template_id") or finding["fingerprint"][:32]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding["title"][:120],
            "shortDescription": {"text": finding["title"][:200]},
            "fullDescription": {"text": (finding.get("description") or "")[:1000]},
            "help": {"text": (finding.get("remediation") or "")[:1000]},
            "properties": {"severity": finding["severity"],
                           "security-severity": str(finding.get("cvss") or _cvss_for(finding["severity"]))},
        })
        results.append({
            "ruleId": rule_id,
            "level": LEVEL.get(finding["severity"], "note"),
            "message": {"text": f"{finding['title']} — {finding.get('location') or finding.get('asset')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("location") or finding.get("asset") or ""},
                }
            }],
            "properties": {
                "severity": finding["severity"],
                "cvss": finding.get("cvss"),
                "status": finding["status"],
                "evidenceIds": finding.get("evidence_ids", []),
                "sourceTool": finding.get("source_tool", ""),
                "reproduction": finding.get("reproduction", []),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RedFox AI",
                "version": VERSION,
                "informationUri": "https://github.com/Shanmukh-l33t/RedFox-AI",
                "rules": list(rules.values()),
            }},
            "invocations": [{"executionSuccessful": True,
                             "startTimeUtc": engagement.get("created_at", "")}],
            "results": results,
            "properties": {
                "engagement": engagement.get("name", ""),
                "autonomy": engagement.get("autonomy", 0),
                "authorization": engagement.get("authorization", {}).get("authorization_ref", ""),
            },
        }],
    }


def _cvss_for(severity: str) -> float:
    return {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.0}.get(
        severity, 0.0)


def markdown(findings: list[dict[str, Any]], engagement: dict[str, Any],
             summary: dict[str, Any], meta: dict[str, Any]) -> str:
    counts = _counts(findings)
    lines = [
        f"# Penetration test report — {engagement.get('name', 'engagement')}",
        "",
        f"> **{NOTICE}**",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Engagement | `{engagement.get('id', '')}` |",
        f"| Operator | {engagement.get('authorization', {}).get('operator', '')} |",
        f"| Authorization ref | `{engagement.get('authorization', {}).get('authorization_ref', '')}` |",
        f"| Attested | {engagement.get('authorization', {}).get('attested_at', '')} |",
        f"| Autonomy | L{engagement.get('autonomy', 0)} |",
        f"| Scope | `{json.dumps(engagement.get('scope', {}))}` |",
        f"| Generated | {datetime.now(timezone.utc).isoformat(timespec='seconds')} |",
        f"| Model | {meta.get('model', 'n/a')} |",
        "",
        "## Executive summary",
        "",
        summary.get("executive_summary") or "_No summary was produced._",
        "",
        "## Findings",
        "",
        f"Critical {counts['critical']} · High {counts['high']} · Medium {counts['medium']} "
        f"· Low {counts['low']} · Info {counts['info']} — total {len(findings)}",
        "",
        "| # | Severity | Finding | Asset | Status |",
        "|---|---|---|---|---|",
    ]
    for i, finding in enumerate(findings, 1):
        lines.append(
            f"| {i} | {finding['severity']} | {finding['title']} | "
            f"`{finding.get('asset', '')}` | {finding['status']} |"
        )
    lines.append("")
    for i, finding in enumerate(findings, 1):
        lines += [
            f"### {i}. {finding['title']}",
            "",
            f"- **Severity:** {finding['severity']}"
            + (f" (CVSS {finding['cvss']})" if finding.get("cvss") else ""),
            f"- **Asset:** `{finding.get('asset', '')}`",
            f"- **Location:** `{finding.get('location', '')}`",
            f"- **Status:** {finding['status']}",
            f"- **Detected by:** {finding.get('source_tool') or 'n/a'}",
            "",
            finding.get("description") or "_No description._",
            "",
        ]
        if finding.get("reproduction"):
            lines += ["**Reproduction**", ""]
            lines += [f"{n}. {step}" for n, step in enumerate(finding["reproduction"], 1)]
            lines.append("")
        if finding.get("evidence_ids"):
            lines += ["**Evidence**", ""]
            for ev in finding["evidence_ids"]:
                lines.append(f"- `{ev}` — {meta.get('evidence_paths', {}).get(ev, '')}")
            lines.append("")
        remediation = summary.get("remediation", {}).get(finding["fingerprint"]) or finding.get(
            "remediation")
        if remediation:
            lines += ["**Remediation**", "", remediation, ""]
    lines += [
        "## Tooling and actions",
        "",
        f"- Actions executed: {meta.get('actions_allowed', 0)}",
        f"- Actions refused by policy: {meta.get('actions_denied', 0)}",
        f"- Tools used: {', '.join(meta.get('tools_used', [])) or 'none'}",
        f"- Audit chain: {meta.get('audit_status', 'unknown')}",
        "",
        "## Limitations",
        "",
        "- Only findings with recorded evidence are listed.",
        "- Inconclusive checks are labelled as such and are not counted as findings.",
        "- Validation proves the minimum needed; absence of a finding is not proof of safety.",
        "",
    ]
    return "\n".join(lines)


def html(findings: list[dict[str, Any]], engagement: dict[str, Any],
         summary: dict[str, Any], meta: dict[str, Any]) -> str:
    counts = _counts(findings)
    rows = []
    cards = []
    for i, finding in enumerate(findings, 1):
        rows.append(
            f"<tr><td>{i}</td><td><span class='sev {finding['severity']}'>"
            f"{finding['severity']}</span></td><td>{_esc(finding['title'])}</td>"
            f"<td><code>{_esc(finding.get('asset', ''))}</code></td>"
            f"<td>{finding['status']}</td></tr>"
        )
        evidence = "".join(
            f"<li><code>{_esc(ev)}</code> {_esc(meta.get('evidence_paths', {}).get(ev, ''))}</li>"
            for ev in finding.get("evidence_ids", [])
        )
        repro = "".join(f"<li>{_esc(step)}</li>" for step in finding.get("reproduction", []))
        remediation = summary.get("remediation", {}).get(finding["fingerprint"]) or finding.get(
            "remediation") or ""
        cards.append(f"""
        <section class="finding">
          <h3><span class="sev {finding['severity']}">{finding['severity']}</span>
              {_esc(finding['title'])}</h3>
          <p class="meta"><code>{_esc(finding.get('location') or finding.get('asset', ''))}</code>
             · {finding['status']} · {_esc(finding.get('source_tool') or '')}</p>
          <p>{_esc(finding.get('description') or '')}</p>
          {f'<h4>Reproduction</h4><ol>{repro}</ol>' if repro else ''}
          {f'<h4>Evidence</h4><ul class="evidence">{evidence}</ul>' if evidence else ''}
          {f'<h4>Remediation</h4><p>{_esc(remediation)}</p>' if remediation else ''}
        </section>""")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>RedFox AI report — {_esc(engagement.get('name', ''))}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; padding:48px 6vw; background:#0d1117; color:#e6edf3;
         font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }}
  h1 {{ font-size:34px; letter-spacing:-.02em; margin:0 0 8px; }}
  h2 {{ margin-top:44px; font-size:22px; border-bottom:1px solid #21262d; padding-bottom:8px; }}
  h3 {{ font-size:18px; margin:0 0 6px; }}
  h4 {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:#8b949e; margin:16px 0 6px; }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px;
          background:#161b22; padding:2px 6px; border-radius:4px; word-break:break-all; }}
  .notice {{ border-left:3px solid #d29922; background:#1c1610; padding:12px 16px;
             border-radius:6px; color:#e3b341; font-size:14px; }}
  .grid {{ display:flex; gap:16px; flex-wrap:wrap; margin:28px 0; }}
  .stat {{ flex:1 1 120px; background:#161b22; border:1px solid #21262d; border-radius:10px;
           padding:14px 16px; }}
  .stat b {{ display:block; font-size:26px; }}
  .stat span {{ color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
  .tablewrap {{ overflow-x:auto; -webkit-overflow-scrolling:touch; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:14px; }}
  td code, td a {{ white-space:nowrap; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #21262d; }}
  th {{ color:#8b949e; font-weight:600; font-size:12px; text-transform:uppercase; }}
  .finding {{ background:#161b22; border:1px solid #21262d; border-radius:12px;
              padding:20px 22px; margin:16px 0; }}
  .sev {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; padding:3px 8px;
          border-radius:999px; font-weight:700; }}
  .sev.critical {{ background:#3d1114; color:#ff7b72; }}
  .sev.high {{ background:#3d1d11; color:#ffa657; }}
  .sev.medium {{ background:#3d3211; color:#e3b341; }}
  .sev.low {{ background:#12261e; color:#7ee787; }}
  .sev.info {{ background:#1c2128; color:#8b949e; }}
  .meta {{ color:#8b949e; font-size:13px; }}
  .evidence li {{ font-size:13px; color:#8b949e; }}
  footer {{ margin-top:48px; color:#6e7681; font-size:12px; }}
</style></head><body>
<h1>Penetration test report — {_esc(engagement.get('name', ''))}</h1>
<p class="meta">{_esc(engagement.get('authorization', {}).get('operator', ''))} ·
 authorization <code>{_esc(engagement.get('authorization', {}).get('authorization_ref', ''))}</code> ·
 autonomy L{engagement.get('autonomy', 0)} · generated {meta.get('generated', '')}</p>
<p class="notice">{_esc(NOTICE)}</p>
<div class="grid">
  <div class="stat"><b>{len(findings)}</b><span>findings</span></div>
  <div class="stat"><b>{counts['critical']}</b><span>critical</span></div>
  <div class="stat"><b>{counts['high']}</b><span>high</span></div>
  <div class="stat"><b>{counts['medium']}</b><span>medium</span></div>
  <div class="stat"><b>{meta.get('actions_allowed', 0)}</b><span>actions</span></div>
  <div class="stat"><b>{meta.get('actions_denied', 0)}</b><span>refused</span></div>
</div>
<h2>Executive summary</h2>
<p>{_esc(summary.get('executive_summary') or 'No summary was produced.')}</p>
<h2>Findings</h2>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Severity</th><th>Finding</th>
<th>Asset</th><th>Status</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
{''.join(cards)}
<h2>Tooling and trace</h2>
<p class="meta">Tools used: {_esc(', '.join(meta.get('tools_used', [])) or 'none')} ·
 audit chain {_esc(meta.get('audit_status', 'unknown'))} ·
 scope <code>{_esc(json.dumps(engagement.get('scope', {})))}</code></p>
<footer>Generated by RedFox AI {VERSION}. Findings are listed only where recorded evidence exists.</footer>
</body></html>"""


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    out = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        out[finding["severity"]] = out.get(finding["severity"], 0) + 1
    return out


def _esc(text: Any) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def write_bundle(directory: Path, findings: list[dict[str, Any]], engagement: dict[str, Any],
                 summary: dict[str, Any], meta: dict[str, Any]) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "sarif": directory / "report.sarif",
        "markdown": directory / "report.md",
        "html": directory / "report.html",
    }
    paths["sarif"].write_text(json.dumps(sarif(findings, engagement), indent=2), encoding="utf-8")
    paths["markdown"].write_text(markdown(findings, engagement, summary, meta), encoding="utf-8")
    paths["html"].write_text(html(findings, engagement, summary, meta), encoding="utf-8")
    return paths