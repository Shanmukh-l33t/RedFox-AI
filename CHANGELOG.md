# Changelog

## v0.4.0

Two gaps from the previous release's own "what it does not do" list are closed, and
one of them is proven in CI rather than described.

### Added

- **Per-tool container isolation.** `REDFOX_ISOLATE=docker` runs an invocation as
  `docker run` of an image that holds only that tool: no capabilities, no new
  privileges, a pid limit, and the engagement's evidence directory as the only
  mount. The policy gate is unchanged and runs before the container starts. A tool
  with no image is refused (`isolation.no_image`) instead of silently running on
  the host. A CI job runs nmap inside a container against the lab and asserts the
  port is still found and the evidence still written through the mount.
- **API authentication.** `REDFOX_API_TOKEN` requires `Authorization: Bearer …` on
  every `/api` route (constant-time compare) and `?token=` on the WebSocket. The UI
  asks for the token inline and remembers it; a modal dialog was rejected because
  it blocked the event stream the UI exists to show.

### Changed

- `docs/ARCHITECTURE.md#isolation`, the runbook and the README describe what
  isolation contains and does not, instead of listing it as missing.

### Known limits

- No images yet for `ffuf`, `amass`, `whatweb`, `sslscan`; they are refused while
  isolation is on. Adding an entry to `redfox/isolation.py` is the whole change.

## v0.3.2

`redfox --version` and the package metadata still said 0.1.0. The version now has a
single source, `redfox/__init__.py`.

## v0.3.1

Planner memory is one line per tool (observations found, denials, or why a tool was
unavailable) instead of one tool's raw observation dump inside the prompt.

## v0.3.0

Hardening: a security review of the platform itself, with the fixes it found, plus
proof that the tool adapters run real binaries in CI.

### Security

The full review, with what was checked and what was accepted, is in
[docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md).

- **Credentials no longer reach a model.** The validator was handed the whole
  `auth_check` block, password included, and sent it to whichever provider was
  configured. It now receives a redacted spec.
- **Argument injection fixed.** A target string beginning with `-` reached a
  tool's argv as an option rather than a host. Hosts are now validated before
  they can become a target, and scope rules reject a leading dash.
- **Tool output is capped** at 8 MB before it is decoded, stored as evidence and
  hashed, so a flooding tool or target cannot exhaust memory.
- **`parse_target` no longer raises `ValueError`** on `host:port/path` — a normal
  shape for a model to emit — which used to stop a campaign.
- **Evidence filenames are slugged**, so no tool name can traverse out of the
  evidence directory.

### Added

- **Credential references.** A password may be written `${ENV_VAR}`; only the
  reference is stored and the value is read at request time. A missing variable
  is a hard error, never a blank password sent to a live login.
- **Real-tool test suite and CI job.** `tests/test_toolchain.py` runs nmap,
  httpx, ffuf, nuclei and whatweb against the lab through the policy gate; the new
  `toolchain` CI job installs the binaries and runs it, so adapter regressions
  fail the build instead of being skipped.

- **Verification record** (`docs/VERIFICATION.md`): a clean-clone campaign — 26
  findings, 9 validated, 19/19 evidence intact, audit chain verified — run as a
  stranger would, which is what found the broken Windows installer.
- **Planner memory is a summary, not a dump.** One line per tool (observations
  found, denials, or why it was unavailable) instead of raw tool output.

### Changed

- Longer soak (5 rounds, 10 steps each): 0 denials, 0 audit failures, 5 MB peak.

## v0.2.0

Completes the platform surface the v0.1.0 release left open.

### Added

- **Working approval loop.** An `intrusive` action files an approval record, the
  campaign stops at `awaiting_approval`, and `redfox approve` releases it for the
  next run. One approval authorizes one operation and is consumed when it ends;
  the exact `(tool, target)` pair is matched, so an approval for one target cannot
  unlock another. Previously the request was filed and dropped.
- **Gated post-exploitation step** (`redfox impact`): authenticates with
  operator-supplied credentials and reads one protected page to demonstrate
  impact. Read-only by construction; declared `intrusive`, so it needs L3 plus an
  approval.
- **PDF reports.** A dependency-free PDF renderer (`redfox/pdf.py`) writes a
  paginated report with the same findings and evidence ids as the other formats.
- **amass adapter** for passive subdomain enumeration, alongside subfinder.
- **Cost and timing accounting.** Every model call records model and token counts;
  reports state wall clock, total tool time and input/output tokens.

### Fixed

- The HTTP execution path did not file approval requests, and a budget-exhausted
  run could report `paused` while an approval was outstanding.
- Approvals were keyed on the request URL rather than the operation target, which
  made a two-request impact check need two approvals.

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