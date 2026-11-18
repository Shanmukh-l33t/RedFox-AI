# vxcontrol/pentagi

Reference analysis for RedFox-AI (Phase 1). Read-only: no repo code, installer, container or package manager was executed. All facts below are from reading files; `INFERENCE:` marks reasoning that is not directly in a file, and `UNKNOWN:` marks what was not read or could not be determined.

## Identity

| Field | Value |
|---|---|
| URL | https://github.com/vxcontrol/pentagi |
| License | MIT (`LICENSE:1-3`) plus a separate `EULA.md` addendum; `NOTICE` claims `github.com/vxcontrol/cloud` is AGPL-3.0 with an official-project exception |
| Primary languages | Go (backend), TypeScript/TSX (frontend), Go `text/template` (agent prompts) |
| Rough LOC | Go 761 files / ~330k lines of which ~83.6k are `_test.go` and ~48.5k generated (`backend/pkg/graph/generated.go`, `backend/gqlgen`). Non-test, non-generated Go ~198k lines. Frontend 423 files / ~91k lines under `frontend/src`. 41 prompt templates / 4,432 lines (`backend/pkg/templates/prompts/*.tmpl`) |
| Last commit | 2026-10-23, `cffed94` "docs: the README links Graphiti to its public repository and names the image PentAGI runs" (`git log -1`). Clone is shallow: `git rev-list --count HEAD` = 1, so history/author metrics are unavailable |

Module is literally named `pentagi` (`backend/go.mod:1`), `go 1.26.5`. Build produces one binary `backend/cmd/pentagi` that serves both API and SPA; `cmd/installer` is a separate Bubbletea TUI installer.

## Architecture

Deployment is a compose stack, not a distributed system: `pentagi` (Go binary), `pgvector` (Postgres + pgvector), `scraper` (headless browser service), optional observability (`docker-compose-observability.yml`), optional Langfuse (`docker-compose-langfuse.yml`), optional Graphiti/neo4j (`docker-compose-graphiti.yml`). `docker-compose.yml:25-31` binds the Docker socket into the app container (`PENTAGI_DOCKER_SOCKET`) — the app creates sibling containers on the host daemon.

Backend package layout (`backend/pkg/`):

- `controller/` — runtime state machines: `flow.go`, `task.go`, `subtask.go`, `assistant.go`, plus one log controller per log type (`termlog.go`, `msglog.go`, `toolcall` via `slog.go`, `agentlog`/`aslog`, `searchlog`, `vecstorelog`, `screenshot`).
- `providers/` — LLM abstraction. One subpackage per vendor (`openai`, `anthropic`, `gemini`, `bedrock`, `ollama`, `deepseek`, `glm`, `kimi`, `minimax`, `mistral`, `qwen`, `xai`, `custom`, `openaicompat`), each with `config.yml` + `models.yml`; `performer.go`/`performers.go` hold the agent loops; `pconfig` holds per-agent model options; `tester/` is an agent-config self-test harness.
- `tools/` — tool registry (`registry.go`, 126 `Name:` entries), executor (`executor.go`), per-agent tool factories (`tools.go`), and implementations: `terminal.go`, `browser.go`, `web_search.go`, `guide.go`, `memory.go`, `graphiti_search.go`, `flow_manager.go`, `file_diff.go`, `code.go`.
- `docker/` — container lifecycle (`client.go`), worker spec/capabilities (`worker_spec.go`), startup sandbox probe (`sandbox.go`, `sandbox_probe.sh`), flow-command process marking (`flow_commands.go`), host worker daemon (`worker_daemon.go`, `worker_spec.go`).
- `database/` (sqlc-generated queries) + `migrations/` (goose, 37 SQL files), `graph/` (gqlgen resolvers + `schema.graphqls` ~1,150 lines), `server/` (gin router, `auth/`, `services/`, `oauth/`, swagger docs), `templates/` (prompt templates + `validator/`), `csum/` (context-window summarizer), `cast/` (chain section model), `graphiti/`, `observability/` (OTel + Langfuse), `flowfiles/` (per-flow file dirs), `resources/` (user resource syncing), `config/`.

Vertical flow: HTTP/GraphQL → `controller.flowController` → `flowWorker` → `taskController`/`taskWorker` → `subtaskController`/`subtaskWorker` → `providers.flowProvider` (agent chains) → `tools` executor → Docker exec. Every layer persists status transitions to Postgres before proceeding (e.g. `backend/pkg/controller/subtask.go:303-306` sets `running` first).

Frontend is a Vite React SPA (`frontend/package.json`) with Apollo Client 4, Radix UI primitives, TanStack Table/Virtual, TipTap editor, `@react-pdf/renderer`; pages are `dashboard`, `flows`, `knowledges`, `resources`, `settings`, `templates` (`frontend/src/pages/`).

## Agent topology

Roles are enumerated twice: as a Postgres enum `MSGCHAIN_TYPE`/`PROMPT_TYPE` (`backend/migrations/sql/20260310_153000_agent_supervision.sql:4-42`) and as the chain→model-options map in `backend/pkg/providers/agent_for_chain.go:8-23`.

| Role | Prompt | Tool surface | Job |
|---|---|---|---|
| `primary_agent` | `prompts/primary_agent.tmpl` ("TEAM ORCHESTRATION MANAGER") | terminal, file, browser, web_search, search/memorist/coder/pentester/maintenance/advice delegations, `done`, optional `ask` | Executes one subtask; delegates; closes with `done` |
| `pentester` | `prompts/pentester.tmpl` ("ADVANCED PENETRATION TESTING SPECIALIST") | terminal, file, browser, guides/graphiti, delegations to coder/installer/memorist/searcher/adviser, `hack_result` | The only leaf agent permitted to run arbitrary commands against targets |
| `coder` | `prompts/coder.tmpl` | terminal, file | Writes scripts/exploits |
| `installer` / `maintenance` | `prompts/installer.tmpl` | terminal | Installs tooling in the sandbox |
| `searcher` | `prompts/searcher.tmpl` | web_search engines, browser | OSINT / CVE research |
| `memorist` | `prompts/memorist.tmpl` | vector-store search over prior chains | Long-term recall; mapped to `OptionsTypeSearcher` |
| `enricher` | `prompts/enricher.tmpl` | vector store | Builds execution context before planning |
| `adviser` (mentor) | `prompts/adviser.tmpl` | none (simple chain) | Consulted on blockers; also used as planner |
| `reflector` | `prompts/reflector.tmpl` | none | Recovers when the model emits prose instead of a tool call |
| `generator` | `prompts/subtasks_generator.tmpl` | none (JSON schema tool `subtask_list`) | Decomposes task into ≤15 subtasks |
| `refiner` | `prompts/subtasks_refiner.tmpl` | none (`subtask_patch`) | Delta-patches remaining plan |
| `reporter` | `prompts/reporter.tmpl` + `task_reporter.tmpl` | none (`report_result`) | Judges success, writes task report |
| `assistant` | `prompts/assistant.tmpl` | terminal/file/browser + flow-manager tools (`get_flow_status`, `stop_flow`, `submit_flow_input`, `patch_flow_subtasks`, `wait_flow_completion`) | Operator-facing chat that can drive a flow |
| `summarizer`, `toolcall_fixer`, `input_toolcall_fixer`, `image_chooser`, `language_chooser`, `flow_descriptor`, `task_descriptor`, `execution_logs`, `full/short_execution_context`, `tool_call_id_collector/detector`, `question_*`, `task_assignment_wrapper` | one template each | n/a | Utility model calls |

Handoff mechanics (OBSERVED): the primary agent's tools named `pentester`, `coder`, `maintenance`, `search`, `memorist`, `advice` are `ExecutorHandler` closures. `handlers.go:672` → `performPentester` (`performers.go:609`) allocates a **new** `msgchain` row of the child type, runs a full nested agent loop with the child's own toolset, and returns the child's `hack_result`/`code_result`/`search_result` string as the tool-call result. Nesting depth is not explicitly capped; it is bounded only by each chain's iteration cap and the parent's remaining tool-call budget (`INFERENCE`).

Prompts are user-editable at runtime: `prompts` table keyed by `(type, user_id)` (`migrations/sql/20241026_115120_initial_state.sql:96-108`), exposed via GraphQL `createPrompt/updatePrompt/validatePrompt`, validated for syntax, empty content, unknown variables and renderability by `backend/pkg/templates/validator/validator.go:28-40`. A user can therefore rewrite the pentester's instructions without touching code — powerful, and a governance risk.

An unusual and reusable design detail: every prompt declares a **two-channel language policy** — engagement log in the operator's language `{{.Lang}}`, technical channel (tool args, commands, stored guides, search queries) strictly English (`primary_agent.tmpl:11-19`, `pentester.tmpl:17-32`). Stored knowledge is anonymised with explicit placeholder rules (`pentester.tmpl:44-52`).

## Orchestration and LLM usage

Plan → execute → refine, driven from `taskWorker.Run` (`backend/pkg/controller/task.go:341-370`):

```
for len(subtasks) < TasksNumberLimit+3 {      // TasksNumberLimit = 15 (provider.go:36)
    st := PopSubtask()                        // first status='created' row (subtasks.go:162-186)
    if st == nil { break }
    st.Run(ctx)                               // one subtask = one primary-agent chain
    if task.IsWaiting() { return }
    RefineSubtasks(ctx)                       // LLM delta-patch of the remaining plan
}
writeResult(ctx)                              // reporter → task status + report msglog
```

- Termination of a subtask is a **barrier tool** `done` (`registry.go:13`) with a `success` bool; the executor treats `done` and `ask` as barriers (`registry.go:100`), so the chain stops on them.
- The loop is double-bounded: `TasksNumberLimit+3` on subtask count and, per chain, `maxGeneralAgentChainIterations = 100` / `maxLimitedAgentChainIterations = 20` (`performer.go:31-42`), configurable via `MAX_GENERAL_AGENT_TOOL_CALLS` / `MAX_LIMITED_AGENT_TOOL_CALLS`.
- Near the limit the loop injects a synthetic "too close to the iteration limit" message and calls the **reflector** to force a graceful close (`performer.go:124-140`), with `maxAgentShutdownIterations = 3` and `maxReflectorCallsPerChain = 3`.
- Loop detection: `repeatingDetector` hashes the last tool name+args; at `RepeatingToolCallThreshold` it answers with the *previous real* tool answer plus a "you are repeating" note, and aborts after `+maxSoftDetectionsBeforeAbort` (4) (`helpers.go:86-117`, `performer.go:321-330`).
- Optional supervision: `executionMonitor` counts identical/total calls and injects a mentor (`advice`) review when thresholds trip, wrapping the answer in `<original_result>`/`<mentor_analysis>` (`performer.go:392-410`); enabled by `EXECUTION_MONITOR_ENABLED` (default off, `README.md:477-488`).
- Optional planning: `performPlanner` (`performers.go:825`) has the adviser emit 3-7 steps before a specialist starts; gated by `AGENT_PLANNING_STEP_ENABLED`.

Retries and validation:

- `maxRetriesToCallFunction = 3` (`performer.go:30`); on error the args are rewritten by a **tool-call-fixer model call** given the tool's JSON schema and the error text (`handlers.go:947-990`), then re-executed. `ErrFlowStateGuard` short-circuits this: a state error is never "fixable" by argument rewriting (`tools/flow_manager.go:14-22`, `performer.go:370-380`).
- `maxRetriesToCallAgentChain = 3` / `maxRetriesToCallSimpleChain = 3`; `retry.go` implements backoff around provider HTTP calls; `callWithSetupRetries` retries provider construction (`providers.go:1215`).
- If the model returns text instead of a tool call, the reflector is invoked and its advice is appended as a human turn, then the chain retried; recursion is explicitly blocked (`performer.go:760-775`).
- **There is no JSON-Schema enforcement on tool arguments.** `customExecutor.Execute` only `json.Unmarshal`s the raw args (`executor.go:296-299`); an unknown tool name returns a soft "unknown tool" string, not an error (`executor.go:291-294`). Correctness relies on the model, the fixer, and handler-level validation. The schemas exist (`reflector.Reflect(&PentesterAction{})` in `registry.go`) and are advertised to the model, but are not checked locally.
- Context growth is handled by `csum.Summarizer` (`backend/pkg/csum/chain_summary.go`): it collapses old sections, rotates the last section, summarizes oversized tool bodies, and repairs dangling tool calls; summaries appear in-context as a `summarization` tool call or a prefixed completion (`pentester.tmpl:187-194`).
- Cost/usage accounting: per-chain `usage_in`/`usage_out` on `msgchains` and Langfuse `Evaluator`/`Agent` observations per prompt render (`provider.go:390-420`).

## State and persistence

Postgres only (`DATABASE_URL`, pgvector image). 37 goose migrations; core tables in `migrations/sql/20241026_115120_initial_state.sql`:

- `flows(status, title, model, model_provider, language, functions JSON, prompts JSON, user_id)` — `functions` stores the per-flow external-function/disabled-tool config; `prompts` stores the rendered prompt set. **No target/scope column exists.**
- `tasks(id, status, title, input, result, flow_id)`, `subtasks(id, status, title, description, result, task_id)`, both with `created/running/waiting/finished/failed` enums.
- `msgchains(type, model, usage_in, usage_out, chain JSON, flow_id, task_id, subtask_id)` — the full `[]llms.MessageContent` per agent chain. This is the resumability primitive.
- `toolcalls(call_id, status, name, args JSON, result, flow_id, task_id, subtask_id)` — one row per tool invocation, written **before** the handler runs (`executor.go:330`) and updated after.
- `termlogs(stdin/stdout/stderr, container_id)`, `msglogs(type, message, result, result_format)`, `agentlogs(initiator, executor, task, result)` for inter-agent handoffs, `searchlogs`, `vecstorelogs`, `screenshots`, `containers(status, local_id, type)`, `assistants`/`assistantlogs`, `prompts`, `providers`, `api_tokens`, `user_preferences`, `flow_templates`, `user_resources`, plus `langchain_pg_collection`/`langchain_pg_embedding` for the guide vector store.
- RBAC tables from the first migration: `roles(Admin,User)`, `privileges(role_id,name)` with granular names (`flows.create`, `termlogs.subscribe`, `anonymize.call`, `templates.edit`, …); a bootstrap `admin@pentagi.com` user with a bcrypt hash and `password_change_required=true` (`initial_state.sql:78-88`).

Durability and resume (OBSERVED): on startup `flowController.LoadFlows` (`controller/flows.go:253`) rebuilds every non-terminal flow; `NewFlowWorker` re-runs `executor.Prepare` (reuses or rebuilds the primary container based on live `IsContainerRunning`, `tools/tools.go:481-545`), `LoadTasks`/`LoadSubtasks`, and `restoreChain` (`providers/helpers.go:469-530`) reloads the last chain of the given type from `msgchains` and prepends the system prompt, falling back to a fresh chain if unmarshal fails. Container reuse is deliberate: "what was installed in it outside /work survives only in this container" (`tools/tools.go:502`).

Not durable: in-memory `repeatingDetector`/`executionMonitor` counters (reset on resume), websocket subscribers (client must reconnect and re-query), flow cancellation state.

## Tool integration and execution

Two very different classes of tool, and the distinction matters for RedFox:

1. **Native Go tools** — `terminal`, `file`, `browser`, `web_search`, `search_guide/store_guide`, `search_answer/store_answer`, `search_code/store_code`, `graphiti_search`, `memorist`, `subtask_list/subtask_patch`, `report_result`, `hack_result`, `done`, `ask`, flow-manager tools.
2. **Security tooling** — there is **no adapter layer**. `pentester.tmpl:274-302` lists what is "pre-installed and current in vxcontrol/kali-linux image" (nmap, masscan, amass, subfinder, dnsx, hydra/ncrack, metasploit, sqlmap, …) and the model invokes them through `terminal` as shell strings. Output is returned as raw text (capped, then summarized); the only parsing guidance is a prompt instruction to prefer structured output (`pentester.tmpl:337`) and the `coder` agent writing parsers.

Terminal execution path: `terminal.Handle` → `ExecCommand` (`tools/terminal.go:196-261`) → `docker.SandboxCommand`/`FlowCommand` = `sh -c 'trap "" HUP; [oom_score_adj bump]; exec sh -c "$0"'` (`docker/flow_commands.go:10-22`) → `ContainerExecCreate{TTY: true}` + `ContainerExecAttach`. A per-process `oom_score_adj` marker makes `Stop` able to kill exactly the processes of one flow task without touching the rest of the sandbox (`flow_commands.go:24-50`). Timeouts: agent-supplied seconds, capped at 3h (`maxExplicitExecCommandTimeout`), default from `TERMINAL_TOOL_TIMEOUT`; `detach=true` returns after 500ms and leaves the process running with `context.WithoutCancel`.

Files reach the container three ways: `file` tool writes/edits via tar stream; per-flow host directories `flowfiles.FlowUploadsDir/FlowContainerDir/FlowResourcesDir` (`pkg/flowfiles/files.go:81-97`) are bind-mounted; per-flow named volume `…-data` mounted at `/work` (`docker/client.go:361-368`).

Container hardening actually applied (`docker/worker_spec.go:18-40`, `docker/client.go:330-450`):

- `CapDrop: ["ALL"]` then an explicit allowlist: CHOWN, DAC_OVERRIDE, FSETID, FOWNER, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE, SYS_PTRACE (+NET_ADMIN if `DOCKER_NET_ADMIN=true`). Comment explicitly forbids SYS_ADMIN/SYS_MODULE/SYS_RAWIO/SYS_BOOT.
- `PidsLimit=2048`, `RestartPolicy=on-failure:5`, json-file logging capped `10m×5`.
- `no-new-privileges` is **deliberately not set**, with a stated rationale — it would break SUID privesc testing and sudo (`client.go:371-374`). This is a conscious trade: fidelity of the pentest vs. sandbox tightness.
- Networking: `DOCKER_NETWORK=host` puts the sandbox on the host network stack (`client.go:393-396`); otherwise bridge with published ports from `portsBase`. There is no egress filter, no DNS allowlist, no per-target routing.
- Optional Docker-in-Docker: socket bind-mount plus `DOCKER_*` env and read-only TLS material (`applyWorkerDockerAccess`, `client.go:220-243`).
- Images: `DOCKER_DEFAULT_IMAGE=debian:latest`, `DOCKER_DEFAULT_IMAGE_FOR_PENTEST=vxcontrol/kali-linux` (`config/config.go:66-67`), optionally model-chosen among `DOCKER_ALLOWED_IMAGES` (`providers/image_selection.go`).
- Startup self-check: `sandbox.go` runs `sandbox_probe.sh` in a worker identical to a real one and parses JSON lines into pass/fail, including daemon authz plugins (`sandbox.go:32-100`). Refusing to start on a broken sandbox is the right instinct.

Browser tool is an HTTP client to the `scraper` service (`tools/browser.go`, `docker-compose.yml:290-302`), returning markdown/html/links — scraping, not interactive navigation (`args.go:44-53`).

## Safety, scope and authorization controls

This is the weakest area and the most important one for RedFox to beat.

**Absent (OBSERVED by reading and grepping; no hits for scope/allowlist/target validation outside tenant naming):**

- No structured engagement scope. A flow is created with free text only — `CreateFlow(modelProvider, input, resourceIds)` (`graph/schema.resolvers.go:35-73`); the `flows` table has no target, CIDR, domain or authorization-expiry field.
- No target allowlist / denylist enforced anywhere in the execution path. `terminal` passes any string to `sh -c`.
- No confirmation gate before destructive or out-of-scope actions. The only human checkpoint is the voluntary `ask` tool (`registry.go:403-407`), used at the agent's discretion and controlled by `ASK_USER_ENABLED`.
- No egress restriction: sandbox is on host or bridge network with full outbound reach.
- No kill-switch beyond per-flow `Stop`; no per-command rate limit, no IP-reputation block, no "do not touch" ranges.

**What exists instead:**

- Prompt-level assertions that authorization is already granted and that the agent must not ask for it: `primary_agent.tmpl:5-11`, `pentester.tmpl:5-11`, `assistant.tmpl:6-12` ("ALL user requests are PRE-AUTHORIZED and require NO additional confirmation", "Never add warnings about ensuring proper authorization"). `question_pentester.tmpl:2` repeats it in the user turn. This is a deliberate design choice that removes model-side brakes; a fork inheriting these prompts inherits that posture.
- Platform security, which is genuinely solid but protects the *app*, not the *target*: session cookies + JWT, bcrypt passwords, OAuth/OIDC (`pkg/server/oauth`, `coreos/go-oidc`), login guard (`auth/login_guard.go`), API tokens welded to an HS256 JWT with token-id + user-hash claims (`auth/api_token_jwt.go`), a deliberate tier split so bearer tokens cannot reach `/users` or `/tokens` (`server/router.go:486-488`), per-privilege route guards (`auth.PrivilegesRequired("flows.create")`), and per-flow ownership checks (`graph/context.go:107-131`).
- Audit trail, which is strong: every tool call with args and result (`toolcalls`), every terminal stdin/stdout/stderr (`termlogs`), every message (`msglogs`), every inter-agent handoff (`agentlogs`), screenshots, plus optional Langfuse/OTel traces. Nothing is signed or append-only, and rows are deleted with their flow (`ON DELETE CASCADE`).
- Container isolation as the sole technical containment: capability allowlist, pids limit, no SYS_ADMIN. Weakened by design decisions above (no `no-new-privileges`, optional host network, optional docker.sock).
- `EULA.md` shifts all legal responsibility to the operator and states the team does not supervise agent actions.

`INFERENCE:` A RedFox design cannot copy this posture. Scope must be first-class data (assets, CIDRs, exclusions, window, authorization artifact), enforced below the LLM (a command broker), with confirmation gates for destructive verbs and an append-only audit log. PentAGI demonstrates that prompt-only authorization is cheap to build and impossible to audit.

## UI and API surface

- **GraphQL** at `/graphql` (`server/router.go:518-523`), gqlgen with `schema.graphqls` (~1,150 lines). Mutations cover flow lifecycle (`createFlow`, `putUserInput`, `stopFlow`, `finishFlow`, `renameFlow`), assistants, providers, prompts, API tokens, favorites, flow templates, knowledge documents, `anonymizeText`, and `testAgent`/`testProvider` for model-config validation (`schema.graphqls:1075-1123`).
- **Subscriptions** over websocket for live UI: flow/task/assistant/file/provider/token/template/resource/knowledge events plus `terminalLogAdded`, `messageLogAdded`, `agentLogAdded`, `searchLogAdded`, `vectorStoreLogAdded`, `toolCallLogAdded`, `screenshotAdded` (`schema.graphqls:1125-1170`).
- **REST** (`/api/v1`) for the same entities: `setFlowsGroup`, `setTasksGroup`, `setSubtasksGroup`, `setContainersGroup`, `setTermlogsGroup`, `setMsglogsGroup`, `setScreenshotsGroup`, `setKnowledgeGroup`, `setResourcesGroup`, `setAnalyticsGroup`, `setPromptsGroup` (`router.go:400-560`), each guarded by `PrivilegesRequired`. Swagger/gin-swagger generated docs live in `pkg/server/docs`.
- **Auth endpoints**: login/logout, OAuth authorize + callbacks (`router.go:477-486`).
- **SPA** served by the same binary with an explicit frontend-route fallback list and immutable asset caching (`router.go:380-424`), so `/flows/42` deep links work and a missing hashed asset 404s instead of returning HTML.
- Static UI is React with Apollo; the interesting bits for us are the live log/tool-call renderers and `frontend/src/lib/report/report-pdf.tsx`.

## Reporting and evidence

- Per task: the `reporter` agent gets the original input, previous tasks, completed subtasks (title/description/status/result) and execution logs, and is told to judge success independently of the subtask claims (`prompts/reporter.tmpl:20-32`, `prompts/task_reporter.tmpl`). Its `report_result` sets `tasks.status` to `finished`/`failed` and writes a markdown `msglogs` row of type `report` (`controller/task.go:382-425`).
- On demand: `taskWorker.Report` and `flowWorker.Report` run the reporter on a detached goroutine with a caller-supplied time budget, because "a report is a model run with a budget measured in minutes, and the caller is an HTTP request" (`controller/flow.go:964-993`).
- Per subtask: `hack_result` (pentester) / `code_result` / `search_result` payloads are stored as `subtasks.result` and as `agentlogs` handoff records.
- Evidence artefacts: raw terminal transcripts (`termlogs`, per container, with stdin colour-framed), tool-call args/results (`toolcalls`), screenshots (`screenshots` table; the browser/terminal path can capture, `tools/screenshot.go`), and user-uploaded flow files (`flowfiles`).
- Export: PDF is rendered **client-side** in the browser (`@react-pdf/renderer`, `frontend/src/lib/report/report-pdf.tsx`), with CJK-aware text splitting (`report-pdf.test.ts:5`). There is no server-side report endpoint, no JSON findings export, and no schema for findings: no asset, CVE, CVSS, evidence-hash or reproduction-step entities anywhere in the migrations. A "report" is a markdown blob plus its source logs.

## Tests and CI

- Go: 258 `_test.go` files, ~83.6k lines (~25% of Go LOC), testify-based, table-driven with `fixtures_test.go` per package. Coverage is broad and behavioural, e.g. `docker/client_test.go` inspects real HostConfig fields (pids limit, restart policy, log rotation, binds), `docker/sandbox_test.go:222-229` asserts forbidden caps are absent, `csum/chain_summary_test.go` has ~1,900 lines of summarizer edge cases, `providers/performer_test.go` drives detector/reflector paths.
- CI `ci.yml`: Node pin check against Dockerfile, prettier, eslint (`--max-warnings 0`), `tsc -b`, vitest, a **GraphQL codegen freshness diff** (regenerate and `git diff --exit-code src/graphql/types.ts`), golangci-lint v2.12.2, `go test ./... -race -v`, then build. Fork-safe (no secrets on `pull_request`).
- E2E `e2e.yml`: Playwright, tiered — `mock-llm` tier (deterministic, OpenAI-compatible mock server at `frontend/e2e/mock-llm/server.mjs` that matches the whole request JSON against `scenario.mjs` rules), visual tier, and a `stand` tier in `e2e-stand.yml` with a `real` spec directory for live-model runs. 47 spec files under `frontend/e2e/specs` (cross, crud, dashboard, flows, real, settings, visual) plus route-manifest / list-order / waitfor-budget / no-automatic-retry gate tests.
- Dedicated harnesses: `cmd/ctester` (chain/tool behaviour), `cmd/etester` (embeddings + vector store), `cmd/ftester` (individual tool functions with mock logs), `providers/tester` (per-agent config probes used by the `testAgent` mutation).

`INFERENCE:` The mock-LLM e2e tier is the single most transferable testing idea here: it exercises the real langchaingo client, streaming and tool-call plumbing while keeping agent behaviour deterministic.

## Capability marks

| Capability | Mark | Evidence |
|---|---|---|
| Multi-agent role decomposition | present | `providers/agent_for_chain.go`, `templates/prompts/*.tmpl`, `migrations/sql/20260310_153000_agent_supervision.sql` |
| Explicit planner / executor split | present | `providers/performers.go:825` (planner), `:96` (generator), `:189` (refiner), `controller/task.go:341` |
| Task queue with dynamic re-planning | present | `controller/task.go:341-370`, `controller/subtasks.go:162` |
| Loop / repetition / runaway control | present | `performer.go:31-42`, `providers/helpers.go:86-117` |
| Graceful termination under limits | present | `performer.go:124-140`, `performReflector` |
| Retry + LLM-based argument repair | present | `performer.go:352-390`, `handlers.go:947` |
| JSON-Schema enforcement of tool args | missing | `tools/executor.go:291-299` (unmarshal only) |
| Sandboxed execution | present | `docker/worker_spec.go:18-40`, `docker/client.go:330-450` |
| Least-privilege container caps | present | `docker/worker_spec.go:26-40` (CapDrop ALL + allowlist) |
| `no-new-privileges` / immutable rootfs | missing | `docker/client.go:371-374` (deliberately omitted) |
| Egress control / target routing | missing | `docker/client.go:393-396`; no filter anywhere |
| Structured security-tool adapters + parsers | missing | `pentester.tmpl:274-302`; tools are shell strings via `terminal` |
| Scope model (assets, CIDR, exclusions) | missing | `schema.graphqls:1077`, `flows` DDL has no target column |
| Scope enforcement below the LLM | missing | `tools/terminal.go:204-260` execs any string |
| Human confirmation gates | weak | `ask` tool only, voluntary: `registry.go:403`, `tools.go:1061` |
| Prompt-level authorization assertions | present (anti-pattern) | `primary_agent.tmpl:5-11`, `pentester.tmpl:5-11` |
| Append-only / tamper-evident audit | weak | `toolcalls`, `termlogs` tables; `ON DELETE CASCADE`, no signing |
| Full-fidelity action logging | present | `executor.go:321-334`, `tools/terminal.go:221` |
| Durable state + crash resume | present | `controller/flows.go:253`, `providers/helpers.go:469`, `msgchains.chain` |
| Multi-tenant isolation | present | `config/tenant.go:57-66` (name/cookie scoping) |
| RBAC + per-resource ownership | present | `migrations/sql/20241026_115120_initial_state.sql:16-70`, `graph/context.go:84-131` |
| API token scoping | present | `server/router.go:486-488`, `auth/api_token_jwt.go` |
| Cost / token accounting | present | `msgchains.usage_in/out`, Langfuse evaluators |
| Context-window management | present | `csum/chain_summary.go`, `performer.go:143-160` |
| Long-term memory (vector + graph) | present | `tools/guide.go`, `tools/memory.go`, `tools/graphiti_search.go`, `pkg/graphiti` |
| Evidence capture (screenshots, transcripts) | weak | `screenshots` table, `tools/screenshot.go`; no finding↔evidence linkage |
| Machine-readable findings (asset/CVE/CVSS) | missing | no such tables in `backend/migrations/sql/` |
| Report generation | present | `prompts/reporter.tmpl`, `controller/task.go:382`; PDF in `frontend/src/lib/report/report-pdf.tsx` |
| Test depth (unit) | present | 258 test files, ~83.6k lines |
| Agent-level E2E with mock LLM | present | `frontend/e2e/mock-llm/server.mjs`, `e2e.yml` |
| CI gates (lint, types, codegen freshness) | present | `.github/workflows/ci.yml` |
| License cleanliness | weak | `NOTICE` (AGPL-3.0 SDK) vs `README.md:4252` (MIT SDK) |

## Strengths worth adopting

1. **The four-level worker tree with DB-backed status enums** (`flow → task → subtask → msgchain`) makes every run inspectable and resumable with plain SQL. Adopt the shape; it is the reason "stop / resume / report on demand" are all easy here.
2. **Every tool call persisted before it executes** (`executor.go:330`), with args, result, owner ids and a stream id. Cheap, and it is what makes the live UI, the audit trail and post-mortems possible.
3. **Full agent chain persisted as JSON per `(flow, task, type)` and reloaded on resume** (`providers/helpers.go:469-530`). Restart-safe without a bespoke event log.
4. **Layered runaway control**: iteration caps per agent class, a repeating-call detector that echoes the real prior answer, a reflector for graceful shutdown near the limit, and an optional mentor. Four independent brakes, each individually simple.
5. **Argument repair as a separate, schema-fed model call** (`handlers.go:947`) rather than regenerating the whole turn — this salvages malformed tool calls without losing the plan.
6. **`ErrFlowStateGuard`-style error taxonomy**: distinguishing "arguments are wrong" from "state forbids this" prevents pointless retries. Small idea, large token saving.
7. **Per-agent tool surfaces built by factory** (`GetPrimaryExecutor` / `GetPentesterExecutor` / `GetAssistantExecutor`, `tools.go:765-1400`) rather than one global tool list — least privilege at the tool level, and each agent's prompt matches its tools.
8. **Capability allowlist with a written rationale for each exception** (`docker/worker_spec.go:26-40` plus the referenced `docker.md` discussion of `no-new-privileges`). The documentation of *why* a control was omitted is more valuable than the control.
9. **Startup sandbox probe** (`docker/sandbox.go`, `sandbox_probe.sh`) that runs in a container identical to a real worker and refuses to start if the daemon is misconfigured. Catches DinD/authz failures before an engagement instead of mid-scan.
10. **Per-flow OOM marker for surgical process kill** (`docker/flow_commands.go:24-50`) — `Stop` kills one task's processes without nuking a sandbox the operator is also using.
11. **Mock-LLM e2e tier** (`frontend/e2e/mock-llm/`) that keeps the real streaming/tool-call plumbing and makes agent behaviour deterministic and CI-able.
12. **Dual-channel language policy with anonymised knowledge storage** (`pentester.tmpl:17-52`): operator-facing text in their language, technical payloads in English, stored guides scrubbed of target IPs/creds. Directly reusable for a multi-tenant knowledge base.
13. **Per-user prompt overrides validated as templates** (`templates/validator`, GraphQL `validatePrompt`) — lets operators tune agents without a redeploy, with syntax/unknown-variable checks.
14. **Tier split so API tokens cannot mint admins** (`router.go:486-488`) — a one-line comment that encodes a real privilege-escalation lesson.
15. **Tenant scoping as a naming primitive** (`config/tenant.go:57-66`) applied to containers, volumes and cookie names, so several instances can share a daemon.

## Weaknesses and gaps

1. **No scope model at all.** Authorization lives only in prose inside prompts, and the prompts actively tell the model not to seek confirmation (`pentester.tmpl:5-11`). Nothing downstream of the model knows what the engagement is allowed to touch, so a prompt injection in scraped content or a hallucinated IP is executed as-is. For a platform whose selling point is autonomy, this is the fatal gap.
2. **No tool adapters or parsers.** "20+ professional tools" (`README.md:60`) are shell invocations whose text output goes back into the context window. There is no nmap XML model, no Nessus/Burp import, no deduplicated finding record — so evidence quality depends entirely on the model's summarization, and results cannot be diffed between runs.
3. **LLM output is not validated against tool schemas.** `executor.go` unmarshals and hopes; recovery is an extra model call. This inflates cost and makes failures non-deterministic.
4. **Reporting is a markdown blob.** No findings schema, no severity/CVSS normalization, no evidence hashing, no reproduction steps as structured data (`backend/migrations/sql/` has no such tables). The PDF is rendered in the browser, so there is no server-side, signed deliverable.
5. **Audit log is mutable and cascades away.** `toolcalls`/`termlogs` rows are deleted with their flow; nothing is signed or append-only. Forensic value depends on operators never deleting a flow.
6. **Sandbox tightness traded for pentest fidelity**: no `no-new-privileges`, optional host networking, optional docker.sock mount (`docker/client.go:220-243`, `:371-374`). Reasonable for a pentester's own sandbox, unacceptable as a default for an autonomous platform running unattended.
7. **Nested delegation has no global depth/budget cap** — each child chain has its own 100-call allowance, so a pathological parent can still burn a large multiple of the nominal budget (`INFERENCE` from `performers.go:609-700` + `performer.go:99-114`).
8. **Subtask loop accounting is odd**: the `for len(subtasks) < TasksNumberLimit+3` guard counts *all* subtasks including completed ones, interacting with refiner additions in a way that is hard to reason about (`controller/task.go:344`). `INFERENCE:` it can silently exit the loop early on long engagements; not proven by test.
9. **License ambiguity.** `NOTICE` says `github.com/vxcontrol/cloud` is AGPL-3.0 "with a special exception for this official PentAGI project"; `README.md:4252` says the SDK code is MIT; `licenses/README.md` claims all dependencies are MIT-compatible. The Go module is a hard dependency of the server (`pkg/config/config.go:17-18`, `pkg/graph/resolver.go:16`). A fork cannot rely on the private exception. See below.
10. **Prompt-as-configuration is unaudited.** Operators can rewrite agent instructions per user with no diff, approval, or record of which prompt version produced a given flow's output; `flows.prompts` snapshots the rendered text, but nothing versions the templates.
11. **`ask` is the only human gate and it is off by default in autonomous runs**; there is no policy layer that says "this class of command requires approval".
12. **Frontend-only PDF export** means the "report" cannot be generated headlessly, e.g. from CI or an API client.
13. **Docs are huge and partly aspirational.** `README.md` is 258 KB; the "2x improvement in result quality" claims (`README.md:488`) carry no link to a benchmark or methodology that was checked here (`UNKNOWN`).

## License and attribution requirements

- Source is MIT: `LICENSE:1-3`, "Copyright (c) 2025 PentAGI Development Team". `NOTICE` requires retaining the copyright and permission notice in copies and substantial portions; it also asserts trademark-ish attribution for the VXControl Cloud SDK integration.
- `EULA.md` is distributed alongside and, by its own terms, governs use of the product as a whole (images, web UI) while the MIT licence prevails for the source code (`EULA.md:17`). It adds acceptable-use restrictions (authorized testing only, no critical infrastructure without validation) and disclaims all liability for agent actions (`EULA.md:25-31`). `INFERENCE:` these are contractual/acceptable-use terms, not copyleft, but an open-source fork should not ship the EULA as if it bound downstream users.
- **The real risk is `github.com/vxcontrol/cloud`.** `NOTICE` states AGPL-3.0 with a special exception limited to "this official PentAGI project"; `README.md:4239-4260` states the SDK code is MIT. The two cannot both be right, and the go.mod pin (`github.com/vxcontrol/cloud v1.0.1`, `backend/go.mod:58`) is imported by the server for the anonymizer and cloud SDK (`pkg/config/config.go:17-18`, `pkg/graph/resolver.go:16`, `cmd/installer/*`). If the AGPL reading is correct, a fork that links it and offers the service over a network inherits AGPL obligations and does **not** benefit from the project-specific exception.
- `github.com/vxcontrol/langchaingo v0.1.14-update.8` (`go.mod:60`) is a fork of langchaingo (MIT upstream); `github.com/vxcontrol/graphiti-go-client v0.9.0` likewise. Both carry vxcontrol provenance and should be licence-checked independently before reuse — `UNKNOWN:` their LICENSE files were not read.
- `licenses/README.md` describes a `scripts/generate-licenses.sh` report baked into the image at `/opt/pentagi/licenses/`. Those generated reports (`backend-licenses.csv`, `frontend-licenses.json`) are **not committed** in this checkout, so the "all dependencies are MIT-compatible" claim could not be verified file-by-file.
- Frontend dependencies that carry their own notice obligations if reused: `@react-pdf/renderer` (MIT), Radix UI (MIT), Apollo Client (MIT), TipTap (MIT core). `UNKNOWN:` full transitive audit not performed.

For RedFox: MIT source is safely reusable with attribution; do **not** take a dependency on `vxcontrol/cloud` (or copy its call sites) until its licence is resolved in writing, and re-implement the anonymizer rather than inheriting an AGPL-tainted path.

## Evidence ledger

- Repo identity, licence text, last commit → `LICENSE:1-3`, `git log -1` (cffed94, 2026-10-23), `git rev-list --count HEAD` = 1 (shallow)
- Module name, Go version, key deps → `backend/go.mod:1-3,58-60`
- LOC counts (Go 330,090 / 761 files; tests 83,622; generated 48,541; frontend 90,982 / 423 files; prompts 4,432 / 41) → computed by line-counting the tree with Python; no repo code executed
- Compose topology and docker.sock bind → `docker-compose.yml:25-31, 226-234, 241-266, 290-302`
- Package layout → `backend/pkg/*` directory listing; `backend/cmd/{pentagi,installer,ctester,etester,ftester}`
- Role/agent list → `backend/pkg/providers/agent_for_chain.go:8-23`; `migrations/sql/20260310_153000_agent_supervision.sql:4-42`
- Primary-agent orchestration prompt → `backend/pkg/templates/prompts/primary_agent.tmpl:1-80`
- Pentester authorisation assertion + tool list + execution rules → `backend/pkg/templates/prompts/pentester.tmpl:5-11, 163-185, 274-302, 337`
- Assistant "pre-authorized" assertion → `backend/pkg/templates/prompts/assistant.tmpl:6-12`
- Dual-channel language policy → `primary_agent.tmpl:11-19`, `pentester.tmpl:17-32`, `reporter.tmpl:7-19`
- Delegation as tool call → `backend/pkg/providers/handlers.go:672`, `providers/performers.go:609-700`
- Task loop, subtask limit, refine-per-subtask → `backend/pkg/controller/task.go:341-370`; `providers/provider.go:36`
- Pop next planned subtask → `backend/pkg/controller/subtasks.go:162-186`
- Subtask run + status transition → `backend/pkg/controller/subtask.go:294-320`
- Iteration caps, reflector shutdown, repeating detector → `backend/pkg/providers/performer.go:31-42, 116-140, 321-330`; `providers/helpers.go:86-141`
- Execution monitor / mentor injection → `backend/pkg/providers/performer.go:392-410`; `README.md:477-488`
- Planner and generator/refiner → `backend/pkg/providers/performers.go:825, 96, 189`
- Tool-call retry + arg repair → `backend/pkg/providers/performer.go:352-390`; `providers/handlers.go:947-990`
- No schema validation / unknown tool tolerated → `backend/pkg/tools/executor.go:291-299`
- Tool call persisted before execution → `backend/pkg/tools/executor.go:321-334`
- Tool registry and barrier classification → `backend/pkg/tools/registry.go:13-56, 100, 403-407`
- Per-agent tool factories → `backend/pkg/tools/tools.go:765-1400`, `1296-1340`
- Container spec, caps, pids, log rotation → `backend/pkg/docker/worker_spec.go:18-40`; `docker/client.go:330-450`
- `no-new-privileges` deliberately omitted → `backend/pkg/docker/client.go:371-374`
- Host network mode → `backend/pkg/docker/client.go:393-396`
- DinD socket/cert injection → `backend/pkg/docker/client.go:220-243`
- Image defaults → `backend/pkg/config/config.go:66-67`; `providers/image_selection.go:14-40`
- Terminal exec path, timeout cap, detach → `backend/pkg/tools/terminal.go:125-260`; `docker/flow_commands.go:10-50`
- Sandbox startup probe → `backend/pkg/docker/sandbox.go:24-100`; `sandbox_probe.sh`
- Flow files / /work volume → `backend/pkg/flowfiles/files.go:81-97`; `docker/client.go:361-368`
- DB schema (flows, tasks, subtasks, msgchains, toolcalls, logs, RBAC) → `backend/migrations/sql/20241026_115120_initial_state.sql:16-108, 111-251`
- Additional tables (api_tokens, preferences, templates, resources, knowledge) → `migrations/sql/20260218_120000_api_tokens.sql`, `20260325_120000_flow_templates.sql`, `20260426_120000_user_resources.sql`, `20260501_120000_knowledge.sql`
- Resume path → `backend/pkg/controller/flows.go:253`; `controller/flow.go:440-520`; `providers/helpers.go:469-530`; `tools/tools.go:481-545`
- Context summarizer → `backend/pkg/csum/chain_summary.go:55-120`; `providers/performer.go:143-160`
- GraphQL schema, mutations, subscriptions → `backend/pkg/graph/schema.graphqls:1075-1170`
- REST groups and privilege guards → `backend/pkg/server/router.go:400-560`
- Token/user tier split → `backend/pkg/server/router.go:486-488`
- Flow ownership + permission checks → `backend/pkg/graph/context.go:84-131`
- JWT API tokens → `backend/pkg/server/auth/api_token_jwt.go:13-60`
- CreateFlow takes free text only → `backend/pkg/graph/schema.resolvers.go:35-73`
- Reporter prompt and independent judgement → `backend/pkg/templates/prompts/reporter.tmpl:20-32`; `task_reporter.tmpl:1-30`
- Report written to task + msglog → `backend/pkg/controller/task.go:382-425`
- On-demand report on detached goroutine → `backend/pkg/controller/flow.go:964-993`
- PDF export client-side → `frontend/src/lib/report/report-pdf.tsx:1-100`
- Test counts and e2e tiers → `find backend -name '*_test.go'` = 258; `.github/workflows/ci.yml`, `e2e.yml`, `e2e-stand.yml`; `frontend/e2e/mock-llm/server.mjs:1-40`; 47 specs under `frontend/e2e/specs`
- Prompt editing + validation → `backend/pkg/templates/validator/validator.go:28-40`; `schema.graphqls:1097-1101`
- Licence conflict → `NOTICE`; `README.md:4239-4260`; `licenses/README.md`; `go.mod:58-60`; `pkg/config/config.go:17-18`; `pkg/graph/resolver.go:16`
- EULA terms → `EULA.md:1-31`