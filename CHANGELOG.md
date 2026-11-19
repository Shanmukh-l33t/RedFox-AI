# Changelog

## v0.1.0

First release. An autonomous, scope-bound penetration-testing platform that runs
real tooling behind an enforced policy gate and reports only what it can prove.

### Safety

- Engagement record with operator attestation (operator, authorization reference,
  attestation time, optional lab flag) required before a campaign can start.
- Deny-by-default scope engine: allow/deny rules, explicit port spec, no
  wildcards, no `0.0.0.0/0`, CIDR not executable, exclusions always win.
- Policy enforcement point between every agent decision and every tool execution:
  kill switch, quiet hours, autonomy ceiling, approval requirement, scope, port
  spec, per-engagement and per-target rate limits.
- Structural guarantee: adapters cannot spawn processes or open sockets. Only
  `redfox/runtime.py` executes, and a test fails the build if any other module
  imports `subprocess` or uses a shell.
- Hash-chained, append-only audit log with `redfox verify-audit`.
- Automatic halt after three consecutive policy denials.

### Capabilities

- Adapters with real parsers: nmap (XML), nuclei (JSONL, discovery and
  template-specific validation), httpx (JSON), subfinder (JSON), ffuf (JSON),
  whatweb (JSON), sslscan (XML), and an HTTP credential check.
- Agents: orchestrator (plans from a closed task vocabulary), triage, validator,
  reporter — over shared, durable state. No agent calls another.
- Validation proves candidates with a template re-run, a safe SQL-injection or
  reflection PoC, or a credential check. Reachability alone is never proof.
- Reports: SARIF 2.1.0, Markdown, and print-ready HTML, all from one findings
  table joined to evidence ids.
- Interfaces: CLI, REST + WebSocket API, static web UI with live events, kill
  switch and report download.
- Resumable campaigns: durable task table, requeue on start, retry of transient
  failures; `plan.floor` coverage fallback when the planner returns nothing.
- Provider-agnostic LLM: any OpenAI-compatible endpoint, Anthropic, or local
  Ollama. JSON mode enforced, replies schema-checked, hallucinated tools and
  out-of-scope targets dropped before they can be queued.

### Deliberately not shipped

- Post-exploitation modules. The gated path (intrusive risk class, approvals,
  L3 + lab attestation) exists; no intrusive adapter ships.
- Per-tool container isolation. Tools run as the invoking user behind the policy
  gate. Use a container or VM for anything beyond a lab.
- Multi-node execution. The task table is SQLite.
- PDF rendering. HTML is print-ready.

### Notes

- Three of the six reference projects studied in `docs/DESIGN_SYNTHESIS.md` are
  AGPL-3.0; no code was copied from any of them.