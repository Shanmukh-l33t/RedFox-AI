# usestrix/strix

Vendored snapshot analyzed read-only at `C:/Users/ImMandatory/RedFox-AI-refs/strix`. Nothing in the repo was
executed, installed, or built. All statements below are OBSERVED unless marked INFERENCE or UNKNOWN.

## Identity

| Field | Value | Evidence |
|---|---|---|
| URL | https://github.com/usestrix/strix (`strix-agent` on PyPI) | `pyproject.toml` |
| Version | 1.7.1 | `pyproject.toml` |
| License | Apache-2.0 (full Apache text, no NOTICE file present) | `LICENSE`, `pyproject.toml:6` |
| Last commit | `1152d53579d5b3af37ada8c798f197ab093b99c6`, 2026-11-16 22:57 UTC — "feat(threat-model): give boundaries, stories and severity a consistent shape" | `git log -1` |
| History depth | 1 commit in this mirror (squashed snapshot); contributor history UNKNOWN | `git log --oneline` |
| Primary languages | Python ≥3.12 (~45.5k src LOC / 83.4k incl. tests), Go ~13.2k (TUI), TypeScript/TSX ~8.8k (web viewer) | `find`+`wc -l`; `strix/interface/tui/`, `strix/interface/viewer/frontend/` |
| Declared status | "Development Status :: 3 - Alpha" despite 1.7.x version | `pyproject.toml` |
| Runtime deps | `openai-agents[litellm]`, `openai`, `litellm`, `docker`, `pydantic(-settings)`, `cvss`, `caido-sdk-client`, `reportlab`, `pypdf`, `cryptography<49`, `boto3`, `google-auth`, `rich`, `pyyaml` | `pyproject.toml` |

Key sub-tree sizes (Python, `wc -l`): `strix/interface` 18,247 · `strix/tools` 11,054 · `strix/report` 4,254 ·
`strix/core` 3,739 · `strix/config` 2,284 · `strix/llm` 2,007 · `strix/runtime` 1,432 · `strix/agents` 1,041 ·
`strix/telemetry` 673 · `strix/utils` 373.

## Architecture

Layered, engine/interface split with a hard seam at `run_strix_scan()`.

```
interface/   cli_args → scan_setup → main → (tui.runtime | headless) → viewer
                    │
core/        runner.run_strix_scan  ── owns: settings, MCP roster, sandbox session,
             │                        root agent build, loop start, resume, teardown
             ├── execution.py   run_agent_loop / _run_cycle / spawn_child_agent / respawn_subagents
             ├── agents.py      AgentCoordinator: statuses, parent_of, mailboxes, budget state, snapshot
             ├── hooks.py       ReportUsageHooks: per-LLM-call budget + turn enforcement
             ├── inputs.py      pure prompt/task builders (root task, scope context, model settings)
             ├── sessions.py    SQLiteSession pooling + image scrubbing
             └── paths.py       strix_runs/<run>/.state layout
agents/      factory.build_strix_agent + prompt.render_system_prompt (Jinja) + skills/*.md corpus
tools/       ~40 function tools: agents_graph, reporting, coverage, threat_model, notes, todo,
             proxy (Caido), mcp, finish, web_search, load_skill, thinking, wait_for_user
report/      state (artifacts, dedupe, usage ledger) + writer + sarif + coverage + runs + pricing
runtime/     docker_client (SDK subclass) + session_manager + caido_bootstrap + backends
llm/         compaction, context_budget, request_log, warmup
telemetry/   posthog + scarf + scan logging
```

- The engine is a library, not a CLI: `run_strix_scan()` takes a `scan_config` dict, sinks
  (`event_sink`, `status_sink`, `mcp_status_sink`), a tool override pair and returns `RunResultBase | None`
  (`strix/core/runner.py:run_strix_scan`). The CLI/TUI/viewer are consumers, and `strix-pro`/SaaS can
  substitute `root_finish_tool` / `report_tool` (`replace_root_scan_prompt`, `extra_system_prompt_context`).
- LLM transport is exclusively `openai-agents` `SandboxAgent` + `Runner.run_streamed`; Strix supplies a
  custom `StrixProvider` and model-routing logic (`strix/config/models.py`), not its own agent loop.
- Tool execution is delegated to the SDK's `Filesystem`/`Shell` sandbox capabilities
  (`strix/agents/factory.py:build_strix_agent`, `capabilities=[Filesystem(...), Shell(...)]`) — Strix
  wraps those tools rather than writing executors.
- Single entry point to the engine: `strix = strix.interface.main:main` (`pyproject.toml`).

## Agent topology

- Two roles only, distinguished at build time by `is_root` (`strix/agents/factory.py:build_strix_agent`):
  **root** gets `finish_scan`, **child** gets `agent_finish`. Both get the same ~50-tool base set.
- Roles are *not* code-defined (no `ReconAgent`/`SQLiAgent` classes). Specialization is emergent: the root
  names a child and passes `skills=[...]`; `create_agent(name, task, skills, inherit_context)`
  (`strix/tools/agents_graph/tools.py:494`). Children are identical objects with different prompts/skills.
- Root is instructed to be a pure orchestrator: "YOU ARE THE ROOT AGENT. Your job is ORCHESTRATION, not
  hands-on testing… even a single quick test on a discovered endpoint is out of role"
  (`strix/agents/prompts/system_prompt.jinja:5-9`), reinforced by `strix/skills/coordination/root_agent.md`.
- Prescribed chains: black-box `Discovery → Validation → Reporting` (3 agents per vulnerability);
  white-box `Discovery → Validation → Reporting-with-fix` (fix derived inline at report time, explicitly
  **no** separate fixing agent) — `system_prompt.jinja` `<multi_agent_system>`.
- Handoff mechanics: parent creates child with `child_initial_input()` (task + `parent_history` when
  `inherit_context=True`) (`strix/core/execution.py:spawn_child_agent`, `strix/core/inputs.py`). Child's
  terminal message is rendered by `_render_completion_report` and pushed to the parent mailbox
  (`strix/tools/agents_graph/tools.py:63`, `strix/core/execution.py:notify_parent_on_terminal`).
  `wait_for_agents` blocks the parent; `send_message_to_agent` steers; `stop_agent` cancels.
- Coordination is via shared state, not messages: notes, coverage ledger, threat model, proxy history and
  `/workspace` are global to the run (`system_prompt.jinja` "STATE & COORDINATION TOOLS"; agents run in
  one container, `system_prompt.jinja` `<multi_agent_system>` "All agents run in the same shared Docker
  container").
- Graph is arbitrary-depth and re-parented on resume: `respawn_subagents()` rebuilds every non-terminal
  agent from `agents.json` metadata (`strix/core/execution.py:454`).
- Skill corpus: 76 packaged markdown skills (77 files incl. `README.md`) across `strix/skills/{vulnerabilities,protocols,technologies,
  frameworks,cloud,tooling,reconnaissance,analysis,coordination,scan_modes,custom}` (~13.8k lines) plus 9
  user-facing workflow skills in `skills/*/SKILL.md`. Skills are Jinja-rendered only when frontmatter says
  `template: jinja` (`strix/skills/__init__.py`).

## Orchestration and LLM usage

- Loop: `run_agent_loop` → `_run_until_lifecycle` → `_run_cycle`, which calls
  `Runner.run_streamed(agent, input, run_config, context, max_turns, session, hooks)` and iterates
  `stream.stream_events()` (`strix/core/execution.py:761-936`). Action selection is entirely the model's
  tool-call choice; Strix never injects a plan.
- **Termination is tool-gated.** `_finish_tool_use_behavior` returns `is_final_output=True` only when
  `finish_scan`/`agent_finish` output parses to `{"success": true, "scan_completed"|"agent_completed": true}`
  (`strix/agents/factory.py:_lifecycle_tool_completed`). Plain text never ends a turn; the prompt says so
  explicitly and the runner logs an error if a headless scan ends without `finish_scan`
  (`strix/core/runner.py`, "ended without calling finish_scan").
- Validation of LLM output, four distinct layers:
  1. **Malformed JSON arguments** → detected before invocation and returned as a model-facing "re-issue the
     call" message (`strix/config/tool_call_arguments.py:describe_malformed_arguments`, wired in
     `strix/agents/factory.py:_with_coerced_arguments`).
  2. **Schema coercion**: string→array/object decoding, `"null"`→None for read-only `list_/search_/view_/get_`
     tools (`_coerce_arguments`, `_QUERY_TOOL_PREFIXES`).
  3. **Strict-schema downgrade** per provider route (`supports_strict_tool_schemas`,
     `_with_strictness`), plus a `CustomTool`→`FunctionTool` adapter for chat-completions routes.
  4. **Tool-level validation** with structured `{success:false, errors:[...]}` returns — most developed in
     `strix/tools/reporting/tool.py` (10 required text fields, CVSS breakdown re-derived via `cvss.CVSS3`,
     CWE/CVE normalisation, `confidence` gating that requires a rationale unless `high`, mandatory
     `counterevidence` and `severity_change_conditions`, mandatory `fix_verification` when any
     `code_location.fix_after` exists).
- Unknown tool name is recoverable: `RunConfig(tool_not_found_behavior="return_error_to_model")`
  (`strix/core/runner.py`).
- Loop hygiene: `TurnToolCallLimiter` caps queued tool calls per assistant response to stop
  pre-written poll loops (`strix/config/tool_call_limits.py`); `_MAX_TRANSIENT_MODEL_RETRIES=5` with
  exponential backoff; image-rejection recovery strips images (≤3×); context-overflow recovery forces
  compaction (≤2×) (`strix/core/execution.py:_run_cycle`).
- Context management: proactive compaction before each run and forced compaction on overflow
  (`strix/llm/compaction.py`), token budgeting per model (`strix/llm/context_budget.py`), tool output
  bounded by lines/bytes with spill-to-`/workspace` (`strix/tools/output_store.py`,
  `strix/agents/factory.py:_bound_result`).
- Budget/turn enforcement is hook-level, not prompt-level: `ReportUsageHooks` tracks cost per LLM call,
  emits graduated wrap-up directives, and raises `BudgetExceededError` / `BudgetPausedError` /
  `SubagentBudgetReservedError` at 100% and at a 90% sub-agent reserve (`strix/core/hooks.py:60,104,443`).
  Two policies: `stop` (default, ends scan) and `pause` (parks agents before their next LLM call until
  `coordinator.resume_budget()`; `strix/core/agents.py:park_for_budget`).
- `DEFAULT_MAX_TURNS = 500` per agent; soft per-skill sub-agent turn limits warn but never stop
  (`strix/config/settings.py:14`, `subagent_turn_limits` in `strix/core/runner.py`).
- Model routing: LiteLLM-style provider prefixes, Bedrock/Vertex/Codex-subscription handling,
  prompt-cache points, per-route header/body injection, non-strict-schema fallbacks
  (`strix/config/models.py`, `strix/core/inputs.py:make_model_settings`).
- Two auxiliary LLM calls exist outside the agent loop: **dedupe** (`strix/report/dedupe.py`, own
  model/key/endpoint via `DEDUPE_LLM_*`) and **compaction summarisation** (`strix/llm/compaction.py`).

## State and persistence

Two stores, deliberately separated:

| Store | Path | Owner | Contents |
|---|---|---|---|
| SDK conversation state | `strix_runs/<run>/.state/agents.db` (SQLite, one session per agent) | `openai-agents` `SQLiteSession` | full message history incl. tool calls/results, used for resume replay (`strix/core/runner.py:open_agent_session`) |
| Graph topology | `strix_runs/<run>/.state/agents.json` | `AgentCoordinator._maybe_snapshot` | statuses, parent_of, names, per-agent `{task, skills}`, pending counts — written atomically via temp-file rename on every state change (`strix/core/agents.py:684`) |
| Coverage ledger | `.state/coverage.json` → export `coverage.json` | `strix/tools/coverage/tools.py` | surface×risk entries with outcome/evidence/source |
| Notes | `.state/notes.json` | `strix/tools/notes/tools.py` | shared cross-agent scratchpad |
| Threat model | `.state/threat_models.json` | `strix/tools/threat_model/tools.py` | per-target model + attributed amendments |
| Todos | `.state/todos.json` | `strix/tools/todo/tools.py` | per-agent checklists |
| Findings | `<run>/vulnerabilities.json`, `<run>/vulnerabilities/<id>.md`, `<run>/vulnerabilities.csv` | `strix/report/state.py`, `strix/report/writer.py` | the finding of record |
| Run record | `<run>/run.json` | same | status, timings, targets, LLM usage, exit reason, MCP roster |
| Other artifacts | `findings.sarif`, `penetration_test_report.md`, `coverage.json` | `strix/report/{sarif,writer,coverage}.py` | CI/consumer outputs |

- `ReportState.hydrate_from_run_dir()` reloads `run.json` + `vulnerabilities.json` on resume and **raises**
  on a corrupt `vulnerabilities.json` rather than starting fresh, to avoid overwriting prior MDs
  (`strix/report/state.py:262-330`). All writes go through `atomic_write_text` (temp + replace).
- Resumability is real and tested: `run_strix_scan` detects `agents.json`, restores the coordinator,
  validates `agents.db` exists, recomputes budget flags, respawns sub-agents, and injects a
  `resume_instruction` as a new user message (`strix/core/runner.py:is_resume` branches;
  `tests/test_runner_interrupt.py`, `tests/test_tui_resume_history.py`).
- Agent counting/status is authoritative in `AgentCoordinator` (a single asyncio-locked owner) with
  `TERMINAL_STATUSES`/`ACTIVE_STATUSES` and `WaitKind` in `{user, agents, stalled}`
  (`strix/core/agents.py:31-44`).
- Everything is filesystem- and CWD-relative: `strix_runs/` under the process CWD (`strix/core/paths.py`).
  No database server, no cloud dependency for the OSS path.
- Evidence is bound by ID, not by prose: `http_exchange_ids` are validated as numeric and then **verified to
  exist in the live Caido project**, rejected if unknown, and stored with a warning if the proxy is
  unreachable (`strix/tools/reporting/tool.py:_verify_http_exchange_ids`).

## Tool integration and execution

- **No first-class scanner tools.** `grep -rn "nuclei|nmap" strix/*.py` returns only a comment about
  `NET_ADMIN`. nmap, nuclei, sqlmap, ffuf, katana, httpx, subfinder, naabu, wapiti, arjun, dirsearch,
  wafw00f, gospider, jwt_tool, JS-Snooper, gitleaks, trufflehog, trivy, opengrep, ast-grep (`sg`),
  tree-sitter, bandit, retire, eslint are installed as binaries and invoked by the model through the
  generic shell tool (`containers/Dockerfile`; `docs/tools/sandbox.mdx`).
- Consequently there are **no parsers**: no JSON/CSV adapters for scanner output, no normalisation layer.
  Output handling is generic head/tail truncation with spill-to-file (`strix/tools/output_store.py`) and
  shell-output token caps (`_apply_shell_output_cap`).
- Execution path: model → `exec_command` / `write_stdin` (SDK `Shell` capability, wrapped in
  `strix/agents/factory.py`) → PTY/non-PTY session inside the container. Strix annotates the tool
  description with the non-TTY output-loss caveat and rewrites `shell` to `bash` by default
  (`_wrap_exec_command`, `_annotate_running_non_tty`).
- Prompt-level tool doctrine is heavy: mandatory `opengrep` + `sg`/Tree-sitter AST pass + secrets pass +
  `trivy fs` per repo for white-box, `vulnx` for CVE lookup, explicit "spray payloads via Python scripts,
  not the browser" rule (`system_prompt.jinja`, `strix/skills/scan_modes/deep.md`).
- **Proxy**: Caido runs in-container on port 48080, started by `containers/docker-entrypoint.sh` with
  `--allow-guests`, `--no-logging` and an imported CA; the container exports
  `http_proxy/https_proxy/ALL_PROXY=http://127.0.0.1:48080` at session bring-up
  (`strix/runtime/session_manager.py:317-327`). Strix talks to it over `caido-sdk-client` GraphQL
  (`strix/tools/proxy/caido_api.py`, 767 lines) and exposes `list_requests`, `view_request`,
  `repeat_request`, `list_sitemap`, `view_sitemap_entry`, `scope_rules` as tools, plus an importable
  `caido_api` module inside the sandbox (`system_prompt.jinja` "For Caido proxy automation").
- **Browser**: `agent-browser@0.26.0` with Chromium, session-per-agent guidance, 3-minute idle reclaim
  (`containers/Dockerfile`, `system_prompt.jinja` "Browsers are NOT per-agent by default").
- **MCP**: two transports (`http`, `stdio`), per-connection tool allowlist, warmup with a 30 s prompt
  budget, fail-open registry, dead-session reconnect (`strix/tools/mcp/{config,client,registry,session}.py`).
  MCP tools are deliberately **not** injected into the tool list; agents reach them through
  `list_mcps → search_mcp_tools → get_mcp_tool_schema → call_mcp` (`strix/core/runner.py` comment;
  `scope.jinja` MCP section).
- **Sandbox/container**: Kali rolling image, non-root `pentester` user with `NOPASSWD` sudo
  (`containers/Dockerfile`), `setcap cap_net_raw,cap_net_admin` on nmap, and Docker `cap_add`
  `NET_ADMIN`,`NET_RAW` plus `host.docker.internal:host-gateway` injected by a subclassed Docker client
  (`strix/runtime/docker_client.py:1-20,251-260`). Optional: `STRIX_DOCKER_SANDBOX_NETWORK` (removes port
  publishing), `STRIX_DOCKER_SANDBOX_DEVICES` (e.g. `/dev/net/tun`), cgroup caps
  (`STRIX_SANDBOX_{MEM_LIMIT,SHM_SIZE,CPUS,PIDS_LIMIT}`), and a **default-on** container log cap (50 MB × 3)
  to protect the host disk (`_apply_log_limits`).
- No egress allowlist/firewall exists in the OSS path: isolation is "container + proxy", not network-level
  scope. INFERENCE: a model-chosen `curl` to any host succeeds unless the operator supplies a custom
  Docker network.
- Tool output is bounded before it enters history (`bound_and_store`), and oversized results are spilled to
  `<workspace>/.strix-output/…` via `session.write` (`strix/core/runner.py:_spill_to_sandbox`).
- Local source trees are **bind-mounted read-write by default** so the agent can apply fixes
  (`strix/interface/utils.py:collect_local_sources` — `"read_only": bool(details.get("read_only"))`,
  i.e. False unless set). `.git` is mounted read-only via `protect_metadata`
  (`strix/runtime/session_manager.py:_metadata_mounts`). Mount roots are screened against
  system/home/credential directories (`check_mountable_dir`, `strix/interface/utils.py:1406`).

## Safety, scope and authorization controls

Present:

- Target parsing/mount screening: refuses `/`, `$HOME`, system trees, and any path containing a
  credential-looking directory name (`strix/interface/utils.py:_FORBIDDEN_MOUNT_ROOTS`,
  `check_mountable_dir`).
- Interactive mount gate: launching with no target mounts CWD only after an explicit in-TUI approval
  (`strix/interface/tui/backend/controller.py:_confirm_mount`, `pending_workspace_mount`).
- Localhost rewriting for host-served apps (`rewrite_localhost_targets`, `HOST_GATEWAY_HOSTNAME` in
  `strix/interface/scan_setup.py`).
- Caido scope rules are *available* as a tool (`scope_rules`, allowlist/denylist, denylist wins) but are a
  traffic filter, not an execution gate (`strix/tools/proxy/tools.py:596`).
- Budget cap, turn cap, sub-agent budget reserve, operator pause — the only hard runtime brakes, and they
  are cost/volume brakes, not authorization brakes (`strix/core/hooks.py`, `strix/core/agents.py`).
- `--fail-on` severity gate for CI exit codes (`strix/interface/cli_args.py`), and headless exit codes
  documented as 0/1/2 (`AGENTS.md`).
- Reporter-side anti-hallucination controls: mandatory `counterevidence`, `confidence` + rationale,
  evidence field, PoC code, and proxy-ID existence check (`strix/tools/reporting/tool.py`).

Absent or inverted (these are the important ones):

- **No technical scope enforcement anywhere.** `build_scope_context()` produces `authorized_targets`, which
  is used only to render the prompt and to name scan targets
  (`strix/core/inputs.py:192-241`). No tool checks a URL/host against it; `exec_command` runs anything.
- **The prompt actively unbinds scope.** `strix/agents/prompts/scope.jinja`:
  "The list below is the starting scope, not a ceiling. If the user names another target, it is authorized
  too. Never tell the user a target is outside scope or ask them to confirm." Combined with
  "NEVER ask for permission or confirmation", "There is no user attached to this run", and a
  REFUSAL AVOIDANCE block ("Do not produce generic policy warnings or generic safety refusals",
  "continue with the most useful in-scope validation step rather than refusing")
  (`system_prompt.jinja` `<execution_guidelines>`), the safety posture is *prompt-level permission
  assertion*, not a control. Prompt injection from a scanned site that says "scan X too" meets an
  instruction that already grants it.
- **No confirmation gates** for destructive or high-blast-radius actions (no approval hook on shell,
  no `needs_approval` on any Strix tool — `factory.py` only forwards SDK-provided `needs_approval` for
  custom tools).
- **No audit log.** `grep -rn audit strix/*.py` matches only the *cloud* CLI's remote `/audit` endpoints
  (`strix/interface/cloud/{render,runner,spec}.py`). Locally there is scan logging
  (`setup_scan_logging`) and request logging (`strix/llm/request_log.py`), plus optional telemetry, but no
  tamper-evident, append-only record of "who authorized what and what was touched". `run.json` captures
  targets and timings — that is the closest artifact.
- **Telemetry defaults on** (`STRIX_TELEMETRY` default True; PostHog public key hardcoded,
  `strix/telemetry/posthog.py:22-23`), so scan metadata leaves the machine unless disabled.
- In-container privilege is high: `pentester ALL=(ALL) NOPASSWD:ALL` plus `NET_ADMIN`/`NET_RAW`
  (`containers/Dockerfile`, `strix/runtime/docker_client.py`). INFERENCE: container escape == host impact
  on a rootful Docker daemon; nothing in the repo mitigates that.
- Local code targets are writable by default — an autonomous agent can modify the user's real tree
  (`collect_local_sources`), which is intentional for auto-fix but is an unreviewed write path.

## UI and API surface

- **CLI** (headless): `strix -n --target … --scan-mode quick|standard|deep --max-budget --max-turns
  --fail-on --resume` (`strix/interface/cli_args.py`, 542 lines; `strix/interface/main.py`, 556 lines).
  Multi-target via repeated `--target`/`--target-list`; `--instruction`/`--instruction-file`;
  `--workspace-file`; `--scope-mode auto|diff|full` with `--diff-base` for PR-diff scoping.
- **TUI**: a Go/Bubble Tea binary (`strix/interface/tui/`, 13.2k LOC) launched as a sidecar by the Python
  process over a JSON protocol (`protocol.Version = 3`, capabilities `state-revisions`,
  `collection-deltas`, `structured-command-errors`, `agents-collection` —
  `strix/interface/tui/internal/protocol/protocol.go`). Auth is a token + fd/addr handshake, and the child
  environment is filtered of `*_API_KEY`/secret/credential vars (`strix/interface/tui/sidecar.py`).
  Python-side backend (`strix/interface/tui/backend/{server,controller,projection,live_view}.py`) owns
  setup, start, mount confirmation, steering, and event projection.
- **Web viewer**: stdlib `http.server` + a React 19/Vite bundle served from `strix/interface/viewer/`
  (8.8k LOC frontend, committed build in `static/`). Auth model: a per-process `secrets.token_urlsafe(32)`
  exchanged for a cookie via constant-time compare; no network exposure by default; run history listing is
  gated behind an email-OTP "verified" flag against the Strix relay, and PDF delivery is relay-proxied with
  the password kept local (`strix/interface/viewer/{server,auth}.py`).
- **Programmatic API**: `run_strix_scan(...)` as an importable coroutine with pluggable tools/sinks — this
  is the real integration point for a platform (`strix/core/runner.py`). No HTTP/REST server for local
  scans; the REST surface in the repo is the *cloud* client (`strix/interface/cloud/`, ~2.7k LOC of
  `strix cloud <resource> <verb>` commands + OpenAPI spec mirror).
- `strix completions {bash,zsh,fish}`, `strix auth`, `strix update` subcommands exist
  (`strix/interface/main.py` dispatch, `completions.py`, `auth_cli.py`, `update_check.py`).

## Reporting and evidence

- Primary deliverable is written by the agent, not templated by code: `finish_scan(executive_summary,
  methodology, technical_analysis, recommendations)` validates for non-empty sections then writes
  `penetration_test_report.md` (`strix/tools/finish/tool.py`, `strix/report/writer.py:write_executive_report`).
- Findings are structured records, not prose: `add_vulnerability_report` stores ~25 fields including
  `cvss`, `cvss_breakdown`, `cve`, `cwe`, `code_locations[{path,start_line,end_line,fix_before,fix_after}]`,
  `http_exchange_ids`, `counterevidence`, `confidence`, `fix_verification`, `fix_pr_body`, `finding_class`,
  `dependency_metadata`, and `agent_id`/`agent_name` provenance (`strix/report/state.py:add_vulnerability_report`).
- Per-finding artifacts: `vulnerabilities/<vuln-NNNN>.md` rendered by `render_vulnerability_md` (223+ lines
  of layout, incl. update history) + `vulnerabilities.csv` (CSV-injection-safe via `csv_safe`) +
  `vulnerabilities.json` (`strix/report/writer.py`).
- SARIF 2.1.0 with real engineering behind it: CWE-keyed rules, severity→level collapse with raw label kept
  in `properties.strix`, `security-severity` from CVSS, `fixes` from `fix_before/fix_after`,
  `logicalLocations` for DAST-only findings, `versionControlProvenance`/`automationDetails` from repo
  context, coverage carried as `pass`/`notApplicable`/`open` results, and synthetic anchoring instead of
  dropping unsafe paths (`strix/report/sarif.py`, 1,185 lines; schema-validated in
  `tests/test_sarif.py`).
- Deduplication: LLM-judge on (root cause, component, exploit vector, fix-equivalence) with configurable
  model; duplicate returns `duplicate_of` and the agent is told to revise rather than re-file
  (`strix/report/dedupe.py`, `strix/tools/reporting/tool.py:_do_create`).
- Revision lifecycle modelled explicitly: `update_vulnerability_report` diffs fields and rejects
  cross-class revisions; `delete_vulnerability_report` exists with a required `delete_reason`, and the
  prompt forbids leaving retracted findings on file (`tool.py:_do_update`, `_do_delete`;
  `system_prompt.jinja` "WITHDRAWING A FINDING").
- `coverage.json` is a genuinely differentiated artifact: it separates `agent_reported` from
  `machine_observed` provenance so a hallucinated "tested and clean" is not laundered into an attestation
  (`strix/report/coverage.py` docstring).
- PDF: generated fully locally with reportlab, no browser (`strix/interface/viewer/report_pdf.py`).
- LLM cost attribution per finding/run: `LLMUsageLedger`, `litellm_cost_callback`, pricing table, per-agent
  token/cost breakdown surfaced in `run.json` (`strix/report/{usage,pricing}.py`, `strix/report/state.py`).

## Tests and CI

- 110 test modules, 1,726 test functions, 37,874 lines under `tests/` — a test:src ratio near 0.8:1 by
  line count. No Docker-dependent integration suite; tests are unit-level with 4 platform skips
  (`mkdir`/FIFO/POSIX-keyreader only): `tests/conftest.py`, `grep -c "def test_"`.
- Coverage is unusually good on exactly the risky seams: `test_execution.py`, `test_agent_graph_coordination.py`,
  `test_budget_pause_policy.py`, `test_e2e_budget_lifecycle.py`, `test_runner_teardown.py`,
  `test_runner_interrupt.py`, `test_unknown_tool_recovery.py`, `test_tool_call_arguments.py`,
  `test_reporting_tool.py`, `test_reporting_fields.py`, `test_sarif.py`, `test_sarif_stride.py`,
  `test_dedupe_decisions.py`, `test_docker_client_{devices,delete}.py`, `test_mcp_resilience.py`,
  `test_viewer_auth.py`, `test_tui_protocol_conformance.py`, `test_packaging.py`.
- CI (`/.github/workflows/ci.yml`): `uv lock --check`, `ruff check`, `ruff format --check`, `mypy strix/`,
  `bandit -r strix/`, pytest on 3.12 **and** 3.14, a Go job (`gofmt`, `go vet`, build, `go test -race`), a
  viewer job (`npm ci`, build, and a *bundle-matches-build* diff gate), and a wheel job that asserts the
  wheel contains the TUI sidecar + viewer bundle and that the installed CLI runs. All actions pinned to
  commit SHAs, `permissions: contents: read`, `persist-credentials: false`.
- Additional workflows: `binary.yml` (PyInstaller build + smoke), `build-release.yml`, `workflows.yml`
  (actionlint). Dependabot configured (`.github/dependabot.yml`).
- Supply-chain hygiene is above par: `uv` `exclude-newer = "5 days"` cooldown with a cited poisoned-release
  incident, SHA256-pinned trivy/opengrep downloads, pinned gitleaks build, and a documented CVE-2026-111497
  brotli backport in the image (`pyproject.toml [tool.uv]`, `containers/Dockerfile`).
- Pre-commit runs ruff/mypy/bandit (`.pre-commit-config.yaml`). No coverage threshold, no mutation testing,
  no `tox`/multi-OS test matrix (Linux only).
- UNKNOWN: no test exercises a real scan end-to-end against a live target; correctness of the *agent
  behaviour* (as opposed to the harness) is unverified by CI.

## Capability marks

Mark legend: **P** present/strong · **W** weak/partial · **M** missing. "Reference tool" is Strix itself;
capability rows are the axes the synthesis matrix needs.

| Capability | Mark | Note | Evidence |
|---|---|---|---|
| Recon (subdomain/port/crawl) | P | binaries + mandatory recon phase, but no structured output | `containers/Dockerfile`, `system_prompt.jinja` PHASE 1 |
| DAST scanning | P | nuclei/sqlmap/ffuf/wapiti available; orchestration is prompt-level | `docs/tools/sandbox.mdx` |
| SAST / code review | P | opengrep + sg + tree-sitter + gitleaks/trufflehog/trivy workflow encoded in prompt and skills | `system_prompt.jinja`, `strix/skills/scan_modes/deep.md`, `containers/opengrep-rules/` |
| Exploit validation with PoC | P | required `poc_script_code`/`evidence`; validation-agent chain mandated | `strix/tools/reporting/tool.py:_REQUIRED_FIELDS` |
| Multi-agent orchestration | P | root/child graph, mailboxes, wait/steer/stop, reactively spawned | `strix/core/{agents,execution}.py`, `strix/tools/agents_graph/tools.py` |
| Structured tool adapters/parsers | M | zero scanner parsers; everything is shell + head/tail truncation | `grep -rn nuclei strix/*.py` |
| Scope enforcement (technical) | M | prompt-only; scope explicitly "not a ceiling" | `strix/agents/prompts/scope.jinja`, `strix/core/inputs.py:192` |
| Authorization/confirmation gates | M | no approval hooks; only a CWD-mount prompt in TUI | `strix/agents/factory.py`, `tui/backend/controller.py:_confirm_mount` |
| Audit logging | M | local scan logs only; `/audit` exists solely in the cloud client | `strix/interface/cloud/*`, `strix/telemetry/logging.py` |
| Sandbox isolation | W | container + non-root user, but NOPASSWD sudo, NET_ADMIN/NET_RAW, no egress filter | `containers/Dockerfile`, `strix/runtime/docker_client.py` |
| Proxy / traffic capture | P | Caido in-container, GraphQL client, 6 tools, `caido_api` importable in sandbox | `strix/tools/proxy/caido_api.py`, `containers/docker-entrypoint.sh` |
| Evidence binding | P | proxy exchange IDs verified against the live project | `strix/tools/reporting/tool.py:_verify_http_exchange_ids` |
| State persistence / resume | P | per-agent SQLite + JSON topology + artifact hydration, tested | `strix/core/{runner,sessions,agents}.py`, `strix/report/state.py` |
| Cost/turn governance | P | 90% reserve, pause policy, graduated warnings, per-agent ledger | `strix/core/hooks.py`, `strix/report/usage.py` |
| Provider abstraction | P | LiteLLM + Bedrock/Vertex/Codex, per-route schema & cache handling | `strix/config/models.py` |
| MCP integration | P | http+stdio, allowlist, search-first discovery, fail-open | `strix/tools/mcp/` |
| Skill/knowledge system | P | 77 packaged skills, Jinja-templated, user-overridable dirs | `strix/skills/`, `strix/tools/load_skill/tool.py` |
| Reporting artifacts | P | MD + per-finding MD + CSV + JSON + SARIF + coverage + PDF | `strix/report/{writer,sarif,coverage}.py` |
| Deduplication | P | LLM judge with dedicated model support | `strix/report/dedupe.py` |
| UI – CLI | P | rich flag surface, CI-oriented exit codes | `strix/interface/cli_args.py` |
| UI – TUI | P | Go sidecar, versioned protocol, steering, live graph | `strix/interface/tui/` |
| UI – Web | P | React viewer, token/cookie auth, PDF export | `strix/interface/viewer/` |
| Local HTTP API for scans | M | viewer serves only artifacts; no scan-control REST endpoint | `strix/interface/viewer/server.py` |
| Tests / CI | P | 1,726 tests, 3 languages, pinned actions, lock check | `.github/workflows/ci.yml`, `tests/` |
| Supply-chain hardening | P | 5-day cooldown, SHA256 pins, non-root image user… with sudo | `pyproject.toml [tool.uv]`, `containers/Dockerfile` |

## Strengths worth adopting

1. **Lifecycle-tool-gated termination.** `is_final_output` only after a validated success payload
   (`finish_scan`/`agent_finish`); text-only turns are structurally incapable of ending a run, and the
   runner logs when a scan "completes" without the tool. Kills the classic "model says Done!" failure.
   `strix/agents/factory.py:_finish_tool_use_behavior`
2. **Evidence bound to retrievable IDs.** HTTP evidence is numeric-only and verified against the proxy
   project; unknown IDs are rejected rather than stored. `_verify_http_exchange_ids`
3. **Adversarial metadata required at write time.** `counterevidence`, `confidence`+rationale (unless
   high), `severity_change_conditions`, `fix_verification` when a patch is proposed. Cheap, and it stops
   the "scanner label as severity" pattern. `_validate_analysis_fields`, `_validate_fix_verification`
4. **Two-store state split** (SDK SQLite conversation vs Strix-owned JSON artifacts) with atomic writes,
   corruption-fatal hydration, and true multi-agent resume. `strix/core/agents.py:_maybe_snapshot`,
   `strix/report/state.py:hydrate_from_run_dir`
5. **Coordinator as single lock-owning authority** for statuses, mailboxes, budget epochs, and snapshotting
   — every mutation is one locked method that also snapshots. `strix/core/agents.py`
6. **Budget semantics as first-class policy** (`stop` vs `pause`) with a 90% sub-agent reserve, operator
   pause/resume via `resume_epoch`, and per-agent cost accounting. `strix/core/hooks.py`,
   `AgentCoordinator.pause_budget/resume_budget`
7. **Coverage as provenance-separated negative space** (`agent_reported` vs `machine_observed`) — the
   honest way to report "what was checked" without laundering agent claims. `strix/report/coverage.py`
8. **Malformed-arguments recovery that also repairs history**, so strict OpenAI-compatible servers don't
   wedge the run permanently. `strix/config/tool_call_arguments.py`
9. **Shell/tool result bounding with spill-to-workspace** instead of blind truncation. `output_store.py`
10. **Search-first MCP discovery** (no 200-tool prompt bloat) with a non-secret status roster for UIs.
11. **SARIF emitter with coverage results and synthetic anchoring** — CI-ready without dropping findings.
12. **CI rigour**: 3-language jobs, pinned SHAs, wheel-content assertions, viewer-bundle drift gate,
    `uv lock --check`, `exclude-newer` cooldown.

## Weaknesses and gaps

1. **Scope is a suggestion, not a control.** `scope.jinja` states the target list is "not a ceiling" and
   forbids refusing; nothing in `exec_command`, the proxy tools, or the shell layer consults
   `authorized_targets`. There is no allowlist enforcement, no per-host rate/egress policy, and no way for
   an operator to make scope binding. This is the single largest gap for a platform that must prove
   authorization.
2. **No audit trail.** No append-only record of target set, commands executed, or approvals. `run.json` +
   rotating log files are forensic-adjacent at best, and telemetry is on by default.
3. **No structured scanner layer.** No parsers, no normalised findings from nuclei/nmap/sqlmap, no
   idempotent tool wrappers, no per-tool capability/version checks. The model must read raw text, so
   determinism and dedup quality depend on the LLM.
4. **Sandbox hardening is nominal.** `NOPASSWD:ALL` sudo, `NET_ADMIN`/`NET_RAW`, writable host bind mounts
   by default, no egress filtering, and a Docker-socket-trusting design. "Isolated" here means
   "containerised", not "constrained".
5. **Refusal-avoidance prompting is a liability.** The prompt instructs the model to treat authorization as
   settled, avoid policy language, and never ask for confirmation; any prompt injection from target
   content lands inside an environment already primed to comply.
6. **Documentation/claim drift.** `docs/tools/sandbox.mdx` lists ZAP, which is not installed anywhere in
   `containers/Dockerfile`; `docs` also implies `--fail-on` semantics that only apply headless. Cheap to
   fix, but it undermines trust in the capability list.
7. **No end-to-end behavioural tests.** 1,726 unit tests, zero live-target scans in CI; agent-level
   regressions (prompt changes) are untested by construction.
8. **Prompt size and duplication.** `system_prompt.jinja` is a ~400-line document that restates rules in
   several places (root directive, multi-agent section, coordination tools, skill files). High token cost
   per turn and a maintenance hazard — the repo's own last commit is a prompt-shape refactor.
9. **Single-vendor coupling** to `openai-agents` internals: `StrixDockerSandboxClient` is a *verbatim copy*
   of SDK code "Pinned to openai-agents==0.14.6" (`strix/runtime/docker_client.py:1-20`) — an upgrade
   requires re-merging upstream by hand.
10. **Telemetry default-on** with a hardcoded PostHog key and a second (Scarf) beacon; opt-out only.

## License and attribution requirements

- Project: **Apache-2.0** (`LICENSE`, `pyproject.toml:6`). Redistribution requires retaining the license and
  NOTICE-style attribution for modified files, and the patent grant/termination terms apply. No `NOTICE`
  file ships in the repo, so downstream must add its own attribution file when vendoring.
- Bundled runtime image (`containers/Dockerfile`) redistributes third-party offensive tooling whose licenses
  are **not** Apache-2.0. Observed installs include `nmap` (GPLv2), `sqlmap` (GPLv2), `wapiti` (GPLv2),
  `nuclei`/`subfinder`/`naabu`/`httpx`/`katana` (MIT), `ffuf` (Apache/MIT), `gitleaks` (MIT),
  `trufflehog` (AGPL-3.0 — verify at the pinned 3.99.2 tag), `trivy` (Apache-2.0), `opengrep` (LGPL-2.1 —
  verify), `agent-browser` (check npm metadata), Kali base image. If the sandbox image is redistributed or
  offered as a service, GPL/AGPL obligations attach to *the image contents*, not to Strix's own code.
  INFERENCE from tool provenance; each must be verified against the pinned version before shipping.
- Python dependency licenses are **not recorded in `uv.lock`** (uv omits them), so a per-package audit is
  required. Highest-risk item to check: `cvss 3.6` (Red Hat) is commonly published under **LGPL-3.0**;
  `caido-sdk-client 0.2.0` license is not stated in the repo at all (`uv.lock:322`, `570`). Both are
  imported, not statically linked, so the practical obligation is likely notice-level — but this is
  UNKNOWN until verified from package metadata.
- Caido is a separate commercial product invoked in-container (`caido-cli`); its license/terms, not
  Apache-2.0, govern that component (`containers/docker-entrypoint.sh`).
- Go deps: Bubble Tea/Lipgloss/Chroma etc. are MIT (typical) — verify `strix/interface/tui/go.mod`; npm
  deps in `strix/interface/viewer/frontend/package.json` are MIT/Apache/ISC except `diff` (BSD-3) — verify.
- Trademark: "Strix", logos and the `strix.ai`/`app.strix.ai` service are not granted by the Apache license;
  a derivative platform must not imply endorsement.

## Evidence ledger

| Claim | File path |
|---|---|
| Apache-2.0, version 1.7.1, Python ≥3.12, entry point `strix.interface.main:main` | `LICENSE`, `pyproject.toml` |
| 5-day dependency cooldown with cited poisoned-release incident | `pyproject.toml` (`[tool.uv] exclude-newer`) |
| Engine-as-library entry point with injectable report/finish tools and sinks | `strix/core/runner.py` |
| Root/child role split, tool sets, lifecycle-tool termination gate | `strix/agents/factory.py` |
| Root "orchestration only" directive; refusal-avoidance block; no-confirmation rule | `strix/agents/prompts/system_prompt.jinja` |
| Scope "not a ceiling", never refuse a user-named target | `strix/agents/prompts/scope.jinja` |
| Scope context built but never enforced | `strix/core/inputs.py:192-241` |
| Agent graph tools (create/wait/steer/stop/finish, open_items) | `strix/tools/agents_graph/tools.py` |
| Coordinator: statuses, mailboxes, budget epochs, atomic snapshot | `strix/core/agents.py` |
| Streaming run loop, retries, image/overflow recovery, salvage | `strix/core/execution.py` |
| Budget/turn hooks, 90% sub-agent reserve | `strix/core/hooks.py` |
| Default 500 turns; telemetry default on; default image tag | `strix/config/settings.py` |
| Malformed tool-argument repair + strict-JSON history rewrite | `strix/config/tool_call_arguments.py` |
| Per-response tool-call cap | `strix/config/tool_call_limits.py` |
| Compaction and context budgeting | `strix/llm/{compaction,context_budget}.py` |
| Tool output bounding + spill writer | `strix/tools/output_store.py`, `strix/core/runner.py` |
| Report validation rules (10 required fields, CVSS, confidence, counterevidence, fix verification) | `strix/tools/reporting/tool.py` |
| Proxy exchange-ID existence verification | `strix/tools/reporting/tool.py:_verify_http_exchange_ids` |
| Finding/run artifact persistence + corruption-fatal hydration | `strix/report/state.py` |
| MD/CSV/JSON writers, CSV injection safety, atomic writes | `strix/report/writer.py` |
| SARIF 2.1.0 emitter with coverage + fixes + VCS provenance | `strix/report/sarif.py` |
| Provenance-separated coverage document | `strix/report/coverage.py` |
| LLM-judge dedupe with dedicated model/endpoint | `strix/report/dedupe.py` |
| `finish_scan` validation + coverage reconciliation summary | `strix/tools/finish/tool.py` |
| Run dir / `.state` layout, `agents.json` resume detection | `strix/core/paths.py`, `strix/core/runner.py` |
| SQLite session per agent (resume replay) | `strix/core/sessions.py` |
| Docker caps, host-gateway, resource/log limits, SDK-copy warning | `strix/runtime/docker_client.py` |
| Sandbox backend registry (`STRIX_RUNTIME_BACKEND`, docker only) | `strix/runtime/backends.py` |
| Caido proxy env vars, exposed port, bind mounts, metadata protection | `strix/runtime/session_manager.py` |
| Kali image, non-root user with NOPASSWD sudo, NET_RAW setcap, tool inventory, `agent-browser`, opengrep pins, brotli CVE backport | `containers/Dockerfile` |
| Caido `--allow-guests`, `--no-logging`, CA import, host-uid remap | `containers/docker-entrypoint.sh` |
| Caido GraphQL client + proxy tools incl. scope rules | `strix/tools/proxy/{caido_api,tools}.py` |
| MCP config/transports/allowlist/search-first discovery | `strix/tools/mcp/*.py`, `strix/core/runner.py` |
| Skill corpus, Jinja templating, user-overridable dirs | `strix/skills/__init__.py`, `strix/skills/**/*.md`, `strix/tools/load_skill/tool.py` |
| Scan-mode skill content (deep/quick/standard/diff) | `strix/skills/scan_modes/*.md` |
| Local code mounted writable by default | `strix/interface/utils.py:collect_local_sources` |
| Mount-root/credential-path screening | `strix/interface/utils.py:check_mountable_dir` |
| TUI mount confirmation gate | `strix/interface/tui/backend/controller.py:_confirm_mount` |
| Go TUI protocol v3 + capability list | `strix/interface/tui/internal/protocol/protocol.go` |
| TUI sidecar env scrubbing, token handshake | `strix/interface/tui/sidecar.py` |
| Viewer token/cookie auth, OTP-gated history, relay PDF delivery | `strix/interface/viewer/{server,auth}.py` |
| Local reportlab PDF generation | `strix/interface/viewer/report_pdf.py` |
| CLI flags (`--fail-on`, `--scan-mode`, `--scope-mode`, `--max-budget`, `--resume`) | `strix/interface/cli_args.py` |
| Headless exit codes 0/1/2 and artifact list | `AGENTS.md` |
| No `audit` references outside the cloud client | `strix/interface/cloud/{render,runner,spec}.py` |
| PostHog key + default-on telemetry | `strix/telemetry/posthog.py`, `strix/config/settings.py:178` |
| CI matrix: ruff/mypy/bandit, pytest 3.12+3.14, Go race, viewer bundle gate, wheel assertions | `.github/workflows/ci.yml` |
| Binary build + PyInstaller smoke | `.github/workflows/binary.yml` |
| Test count/scope (1,726 functions, 110 modules) | `tests/` |
| ZAP documented but not installed | `docs/tools/sandbox.mdx` vs `containers/Dockerfile` |
| Dependency licenses unrecorded; `cvss 3.6`, `caido-sdk-client 0.2.0` | `uv.lock:322,570` |
| Git identity of snapshot (single commit, 2026-11-16) | `git log` |

### UNKNOWNS

- Real-world effectiveness/FP rate on live targets (no benchmark results beyond `benchmarks/README.md`,
  which points at an external harness).
- Whether `trufflehog` 3.99.2 / `opengrep` / `agent-browser` / `caido-cli` licenses match the INFERENCE
  above (no vendored license texts in the repo).
- Behaviour of `strix-pro`/SaaS extensions referenced in code (`finish_pr_review` hook,
  `register_agent_tools`, `register_backend`, `register_skill_dir`) — not in this repo.
- Contributor/maintenance history (single squashed commit in the mirror).
- Actual cost per scan at default `deep` mode; only the budgeting machinery is observable.