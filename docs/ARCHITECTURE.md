# Architecture

## Layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ Interfaces        CLI (argparse)   REST + WebSocket (FastAPI)   SPA   │
├──────────────────────────────────────────────────────────────────────┤
│ Orchestration     Campaign engine (resumable state machine)          │
│                   Orchestrator · Triage · Validator · Reporter (LLM)  │
├──────────────────────────────────────────────────────────────────────┤
│ Policy            PolicyEnforcementPoint(scope, autonomy, rate, kill) │
├──────────────────────────────────────────────────────────────────────┤
│ Execution         ToolRuntime — the only process/HTTP executor        │
│                   Adapters (inert): plan() -> ToolCall, parse()       │
├──────────────────────────────────────────────────────────────────────┤
│ Persistence       SQLite (WAL): engagements, tasks, actions, evidence,│
│                   assets, findings, approvals, memory, events         │
│                   AuditLog: append-only hash-chained JSONL            │
└──────────────────────────────────────────────────────────────────────┘
```

## Why the boundary is structural, not a convention

A policy that lives in a prompt is a suggestion. In RedFox:

1. An adapter's only output is a `ToolCall(tool, target, argv, risk)`. Adapter
   modules import `models` and nothing else that can act; they have no handle to
   a process, a socket, or the runtime.
2. `ToolRuntime.execute()` and `.execute_http()` are the only methods in the
   package that spawn a process or open a request. Both call
   `PolicyEnforcementPoint.check()` first and return without acting if the
   decision is not `allowed`.
3. The binary name is checked against a fixed allowlist (`ALLOWED_BINARIES`)
   before policy runs, and `asyncio.create_subprocess_exec` is used — never a
   shell — so argv is not re-parsed.
4. `tests/test_structural_guarantees.py` walks the AST of every module outside
   `runtime.py` and fails if one imports `subprocess`/`multiprocessing` or calls
   `os.system`/`popen`. It also fails on any `shell=True` in the tree.

The result: adding a tool cannot create a bypass, because there is nothing in
the adapter layer that can bypass anything.

## Policy decision order

For every proposed action:

1. **Kill switch** — a `KILL` file in the state directory, or the API endpoint.
2. **Quiet hours** — optional window (`REDFOX_QUIET_HOURS=22:00-06:00`).
3. **Autonomy ceiling** — `passive < active < validation < intrusive`; the
   engagement's level caps the highest class that may run.
4. **Approval** — `intrusive` requires an approval record unless the engagement is
   lab-attested at L3 *and* `auto_intrusive` is set.
5. **Scope** — deny-by-default allowlist match, exclude if any deny rule matches.
   A CIDR is not executable; it must be expanded to hosts.
6. **Ports** — every port the adapter asks for must be inside the engagement's
   port spec.
7. **Rate limit** — per engagement and per target, sliding window.

A denial is recorded twice: as an `actions` row with `decision='denied'` and in
the audit log with the reason. Three consecutive denials halt the campaign
(`campaign.halted`), which is the "stop on an out-of-scope spike" control.

## State machine

```
created ──run──► running ──task──► running … ──report──► completed
                    │  ▲                    │
        kill switch │  │ resume()           │ intrusive action
                    ▼  │                    ▼
              halted / paused        awaiting_approval ──approve──► running
```

Tasks are rows: `pending → running → done|failed`. `Campaign.run()` requeues any
`running` task at startup, so a crash costs at most one task's work. Each task's
result is written before the next task is claimed.

## Agents

| Agent | Input | Output | Can it act? |
|---|---|---|---|
| Orchestrator | engagement state (assets, findings, actions, tool catalogue) | 1–4 tasks from a closed vocabulary | No |
| Recon / Enum | a task from the orchestrator | adapter runs, parsed observations | Only via the runtime |
| Triage | candidates with evidence ids | severity, status, description, remediation | No |
| Validator | candidates + configured login | validation plan (`nuclei_validate`, `http_probe`, `authcheck`) | Only via the runtime |
| Post-exploitation | engagement `impact` spec + operator approval | one authenticated read of a protected page | Only via the runtime, `intrusive` risk class |
| Reporter | findings + engagement meta | executive summary, remediation prose | No |

Specialists do not call each other. They read and write shared state, and the
engine routes. The planner can only name tools that exist, and every target it
names is re-checked against the scope before a task is even queued
(`agents.validate_plan`), then again by policy at execution time.

**Coverage floor.** If the planner returns no tasks while nothing has been done,
the engine falls back to a deterministic coverage ladder (recon → nuclei → ffuf →
triage → validation → report) and records `plan.floor` in the event stream. This
exists so a weak local model cannot end a campaign having done nothing and let
that read as a clean result. It is visible in the event log, never silent.

## Data model

| Table | Purpose |
|---|---|
| `engagements` | scope, authorization, autonomy, status |
| `tasks` | durable pending work with state and attempts |
| `actions` | every proposed action: tool, target, argv, risk, decision, exit code, evidence id |
| `evidence` | file path + SHA-256 for each captured output |
| `assets` | hosts, ports, services, HTTP endpoints |
| `findings` | fingerprint, severity, CVSS, status, location, reproduction, evidence ids, template id |
| `approvals` | gated actions awaiting a human decision |
| `memory` | tool outcomes and technology notes for later campaigns |
| `events` | UI/audit stream (also mirrored into the hash-chained log) |

## Evidence

The runtime writes one file per action:

```
# tool: nuclei
# target: http://127.0.0.1:8080
# argv: [...]
# duration_s: 41.2
# sha256: <digest of stdout+stderr>
==========
[stdout] ...
[stderr] ...
```

The SHA-256 of the captured output is stored with the evidence row. Credentials
found in output (password/token/authorization/cookie lines) are redacted before
anything is written.

## Isolation

**Not shipped: per-tool containers.** Tool processes run as the invoking user.
The policy gate decides *whether* a tool runs and against what; it does not
sandbox *what the tool does to the host*. A malicious or compromised tool binary
would run with your privileges.

Mitigations present: fixed binary allowlist resolved from a project directory or
`PATH`, argv-only execution (no shell), timeouts with hard kill, per-scope port
restriction, and full audit of every invocation.

If you need stronger isolation, run the whole platform in a container or VM whose
egress is limited to the engagement scope. That is the recommended deployment for
anything beyond a lab.

## Approvals

An `intrusive` action is refused by policy below L3. At L3 (with `lab_isolated`)
it is refused with `needs_approval`, and the runtime files an approval record
carrying the tool, target, argv and rationale. The campaign sets
`awaiting_approval` and stops. `redfox approve` flips the record to `approved`;
the next run re-queues the operation, policy consults the approval for that exact
`(tool, target)` pair, and the engine consumes it when the operation ends — so
one approval authorizes one operation, never a standing permission.

## Observability

- `events` table: every plan, action, denial, approval, triage and validation.
- `actions` table: per-tool timing, exit code, decision.
- `redfox status <id>`: steps, findings by status, actions allowed/denied, evidence
  count, audit chain status.
- Cost accounting: every model call writes an `llm.usage` event with model and
  token counts; the report summarises calls, input/output tokens, wall clock and
  total tool time, and the SARIF marks the model in the run properties.

## Scale path

Single process is the shipped design. To scale out: replace the task table claim
with a lease-based queue (the claim is already `UPDATE … WHERE state='pending'`,
which is the shape a queue needs), move SQLite to Postgres, and put the tool
runtime behind a worker service. Nothing in the policy or adapter layers assumes
one process.