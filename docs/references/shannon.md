# Shannon

Reference analysis of `C:/Users/ImMandatory/RedFox-AI-refs/shannon` (`KeygraphHQ/shannon`), snapshot commit
`c20e119` ("docs: add UTM tags to keygraph.io links (#491)", 2026-11-16). Clone is shallow (depth 1,
`.git/shallow`), so history, release cadence, and contributor base are not observable here.

Method: static reading only. Nothing was built, installed, or executed. Every claim carries a file
path. Claims marked **OBSERVED** are read directly from source/config/docs; **INFERENCE** marks
conclusions drawn from those facts; **UNKNOWN** marks what the snapshot cannot answer.

---

## Identity

**OBSERVED** — Shannon is an autonomous, source-aware ("white-box") web/API penetration tester. It is
positioned as an agent, not a scanner, and its one-line contract is "No exploit, no report"
(`README.md:16`, `README.md:169`, `README.md:401`).

- Vendor: Keygraph. OSS edition is the full local agent; Pro/Enterprise are a different, enhanced build
  with black-box, SCA, secrets, findings management, fix PRs, Jira, RBAC (`README.md:236-257`).
- Scope of analysis is deliberately narrow: Broken Authentication, Broken Authorization, Injection
  (SQL + OS command), XSS, SSRF (`docs/safety.md:36-42`, `COVERAGE.md:15-20`). A sixth internal class,
  `miscellaneous`, catches SAST-sourced weaknesses outside those five
  (`apps/worker/src/types/reconciliation.ts:20`, used by
  `apps/worker/prompts/exploit-miscellaneous.txt:1-8`).
- Explicit non-goals: vulnerable dependencies, weak crypto, insecure configuration, policy findings —
  "issues that it cannot actively exploit" (`docs/safety.md:44`, `COVERAGE.md:22-24`).
- Positioning against humans is honest: "not a replacement for human pentesters" (`README.md:101-111`),
  findings "still require human review" (`README.md:323`).
- Runtime shape: a Node CLI orchestrating a per-scan ephemeral Docker worker plus a local Temporal
  server (`README.md:144-156`, `docker-compose.yml:5-20`).
- **INFERENCE** — The product thesis is *proof density over coverage*: every reported item carries a
  reproducible exploit, at the cost of recall on anything not dynamically provable. The 5 fixed classes
  and the fixed pipeline (`configs/example-config.yaml:7-8`: "Every scan runs all five vulnerability
  classes … There is no setting to narrow that") are a deliberate scope control, not an oversight.

---

## Architecture

**OBSERVED** — pnpm + Turborepo monorepo, two packages (`package.json:6-17`, `pnpm-workspace.yaml`,
`turbo.json`):

```
apps/cli/      @keygraph/shannon  — published to npm, tsdown single-file ESM bundle
apps/worker/   @shannon/worker    — private; Temporal worker + all pipeline/prompt logic
```

- `apps/cli/` — Docker/compose lifecycle, `@temporalio/client` status + bounded lifecycle RPCs,
  interactive setup wizard, path/config resolution (`CLAUDE.md:101-121`). No prompts, no pipeline logic.
- `apps/worker/` — `temporal/` (workflow + activities), `services/` (Temporal-free business logic),
  `ai/pi/` (agent harness integration), `ai/sast/capella/` (agentic SAST child workflow),
  `ai/reconciliation/` (candidate merge → exploit tasks), `collectors/` (structured-output tools),
  `audit/` (crash-safe logging), `prompts/` (all prompt templates), `templates/typst/` (PDF).
- Separation is explicit and commented: activities are thin wrappers, `services/` owns business logic
  and must not import Temporal (`apps/worker/src/temporal/activities.ts` header,
  `CLAUDE.md:192`). `ExploitationCheckerService` is described as "pure domain logic … No Temporal
  dependencies" (`apps/worker/src/services/exploitation-checker.ts:7-14`).
- Composition root: a per-workflow DI container with injectable `CheckpointProvider`,
  `FindingsProvider`, `ReportOutputProvider` (`apps/worker/src/services/container.ts:40-93`). All three
  default to NoOp and nothing in the OSS tree calls `setContainerFactory` (**OBSERVED**: only the
  export exists, `container.ts:113`), so those hooks are dead in OSS and exist for the commercial build
  (**INFERENCE**).
- Container topology: `docker-compose.yml` runs **only** Temporal (`temporalio/temporal:1.7.0`,
  `127.0.0.1:7233`, Web UI `127.0.0.1:8233`). The worker itself is a plain `docker run --rm` per scan,
  not a compose service (`apps/cli/src/docker.ts:424-528`).
- Worker image: 2-stage Chainguard Wolfi build, non-root `pentest` (uid 1001), Chromium, Python 3,
  Typst 0.14.2 binary for PDF, `@playwright/cli@0.1.1` installed globally with its skill copied into
  the image (`Dockerfile:44-131`). Node 22, `NODE_ENV=production` (`Dockerfile:146-154`).
- Entrypoint re-maps uid/gid to the host user then `exec su -m pentest` (`entrypoint.sh:1-17`).
- Sizing (**OBSERVED**, `wc -l`): 217 TS files, **53,113 lines TS** (`apps/worker` 43,917, `apps/cli`
  9,196). Prompts: 63 `.txt` + 23 `.hbs` = **9,471 lines**. Largest modules: `temporal/activities.ts`
  2,068, `temporal/workflows.ts` 1,485, `ai/sast/capella/temporal/workflow.ts` and reconciliation
  modules in the 500–900 range. Prompts are ~18% of total source by line count — a prompt-heavy system
  with a large deterministic harness around it.

**INFERENCE** — The architecture's real bet is that the *harness*, not the prompt, enforces the
methodology: typed tool schemas, per-status validation, queue-ID namespacing, git-scoped checkpoints,
and deterministic renderers. Prompts describe intent; TypeScript refuses non-conforming submissions.

---

## Agent topology

**OBSERVED** — Fixed roster of 14 agent names in execution order (`apps/worker/src/types/agents.ts:15-30`):

```
pre-recon → recon → {injection,xss,auth,ssrf,authz}-vuln → {…}-exploit (+miscellaneous-exploit) → report
```

Plus one non-roster agent, `validate-authentication`, which runs through the same executor before the
pipeline (`apps/worker/src/utils/browser-agents.ts:16-29`, `temporal/workflows.ts:1372-1391`).

Three tiers:

1. **Orchestrator (Temporal workflow)** — deterministic, no I/O (`temporal/workflows.ts:7-16`).
2. **Worker agents (pi sessions)** — one LLM session each, own prompt file, own deliverable filename
   (`apps/worker/src/session-manager.ts` `AGENTS` record; prompts in `apps/worker/prompts/`).
3. **Child sessions (`task` tool)** — the exploit agents must delegate all custom scripting to a
   sub-agent; the child cannot spawn further children (deliberate: `apps/worker/src/ai/pi/task-tool.ts:44`
   "Deliberately excludes `task` (no recursive delegation)"). Usage is accumulated into the parent's
   cost/token totals (`pi-executor.ts:122-136`).

Agent roles as written in prompts:

| Agent | Prompt | Job | Output artifact |
|---|---|---|---|
| `pre-recon` | `prompts/pre-recon-code.txt` (212 l) | read-only source architecture baseline | `pre_recon_deliverable.md` |
| `recon` | `prompts/recon.txt` (190 l) | live attack-surface map via browser; ties runtime to code | `recon_deliverable.md` |
| `*-vuln` ×5 | `prompts/vuln-*.txt` (233–324 l) | white-box data-flow / control analysis; produce candidates | `*_analysis_deliverable.md` + `*_exploitation_queue.json` |
| `*-exploit` ×6 | `prompts/exploit-*.txt` (104–432 l) | drive live exploitation of each queued task | `*_exploitation_evidence.md` + `*_exploit_collector.json` |
| `report` | `prompts/report-executive.txt` (233 l) | select/dedupe findings, emit structured `add_finding` | `comprehensive_security_assessment_report.md` + `report.json` |

Explicit role separation is enforced in prompt language, not just convention: the vuln agent is told
"Your sole responsibility is to identify and precisely document … the Exploitation phase confirms the
*realized* compromise. Do not cross this boundary" (`prompts/vuln-injection.txt:29`). The exploit agent
is told "You are not an analyst; you are an active penetration tester" (`prompts/exploit-injection.txt:2`).

### How "only exploited, with a working PoC" is enforced

This is the load-bearing mechanism, and it is layered — four independent gates, three of them in code:

**Gate 1 — the tool schema has no third bucket.** The exploit agent's only recording tool is
`add_exploit`, whose `status` is `stringEnum(['exploited','blocked'])`
(`apps/worker/src/collectors/exploit-collector.ts:192-199`). There is no "confirmed by analysis" value.
The field description is itself the policy: `"exploited"` only "after reaching Proof of Exploitation
Level 3+ with concrete impact evidence"; `"blocked"` only for "real vulnerabilities where external
factors (NOT security defenses) prevented full exploitation"; defences that worked = false positive,
routed to a workspace file, "not this tool" (`exploit-collector.ts:193-199`).

**Gate 2 — per-status required fields, re-validated in the handler.** The flat tool schema cannot
express a discriminated union, so the handler re-checks against a strict
`Type.Union([ExploitedSchema, BlockedSchema])` via `Value.Check` and returns a **retryable** error
listing the missing instance paths (`exploit-collector.ts:356-390`, `462-472`). To claim `exploited` the
agent must supply `severity`, `severity_rationale`, `impact`, non-empty `exploitation_steps[]` and
non-empty `proof_of_impact` (`exploit-collector.ts:356-370`). A claim with no steps is not storable.
Field descriptions carry the reproducibility bar: "full URLs (protocol + domain + port + path + params),
complete payloads, and copy-paste-ready commands … detailed enough that someone unfamiliar with the
application can follow" (`exploit-collector.ts:236-247`).

**Gate 3 — ID provenance.** `vulnerability_id` must be a task reference (`INJ-01`), not a producer ID
(`INJ-VULN-01`), and must exist in this run's queue; hallucinated or typo'd IDs are rejected with the
valid-ID list and a retryable error (`exploit-collector.ts:487-509`, `isTaskReference` at
`ai/reconciliation/refs.ts:43-48`). Duplicate IDs are rejected non-retryably
(`exploit-collector.ts:511-519`). Producer IDs are additionally redacted from anything the model sees
(`ai/reconciliation/observation-view.ts:22`, `68`) so an internal identity cannot leak into a report.

**Gate 4 — the report agent is told to skip the blocked bucket.** The per-class evidence file renders
three fixed sections: `## Successfully Exploited Vulnerabilities`,
`## Potential Vulnerabilities (Validation Blocked)`, `## Unprocessed Vulnerabilities`
(`services/exploit-renderer.ts:169`, `178`, `187`). The report prompt's KEEP rule only admits entries
under `## {{REPORT_VULN_SUBHEADING}}`, which resolves to `Successfully Exploited Vulnerabilities` in
exploit mode (`services/prompt-manager.ts:448-449`), and its SKIP rule names
`## Potential Vulnerabilities (Validation Blocked)` explicitly (`prompts/report-executive.txt:70-72`).

**OBSERVED weakness in the chain:** the `status` field on the *report* agent's `add_finding` tool is
optional (`collectors/finding-collector.ts:215-219`), and the PDF adapter defaults a missing status to
`exploited` (`services/report-json-adapter.ts:191`, `195`: `f.status ?? 'exploited'`). So gate 4 is a
prompt instruction plus a defaulting convenience, not a hard filter: a report agent that emits a
blocked finding under the wrong heading would be rendered as exploited. There is no code check that the
finding's ID appeared in a `status:"exploited"` collector call before it is admitted to `report.json`.

### Prompt-level anti-fabrication techniques worth noting

- **Verdict taxonomy with a floor below "Low".** Four proof levels, Level 3 = data extraction proven is
  the threshold to claim impact; Levels 1–2 must be labelled `blocked`
  (`prompts/exploit-injection.txt:209-229`). Severity is explicitly decoupled from proof level: "a
  finding proven at Level 4 may still be Low" (`:229`).
- **Severity reasoning as four questions, plus a "floor" that is not a tier**: if nobody ends up holding
  anything they should not, "there is no tier low enough to be correct" — do not submit it
  (`prompts/shared/exploitation/_severity-reasoning.txt:30-39`). Includes two self-check heuristics:
  "your rationale must not refute your finding" and "the criterion you met must be the one you were
  given" (`:34-37`).
- **Bypass exhaustion protocol**: classification is "FORBIDDEN" until multiple distinct techniques have
  actually been tried; minimum 3 payloads to conclude non-exploitable, 8–10 variants before concluding a
  defence holds (`prompts/exploit-injection.txt:185-187`, `238-254`).
- **Reporting standards** explicitly make overstatement a failure of the same order as a miss, forbid
  hedges ("Theoretical, potential, possible — a finding that needs a hedge is not settled. Settle it or
  drop it"), forbid impact-led titles, and require claims no wider than the observation
  (`prompts/shared/exploitation/_reporting-standards.txt:4-19`).
- **Out-of-band is out of scope by design**: exploitation must be provable in-band; if only an OOB
  callback could prove it, record `blocked` with code-level proof and move on
  (`prompts/shared/_exploit-scope.txt:8-10`). This deliberately trades some SSRF/blind-SQLi proof power
  for zero attacker infrastructure.

---

## Orchestration and LLM usage

**OBSERVED** — Temporal is the orchestration substrate; the pipeline is a deterministic workflow with
every side effect in an activity (`temporal/workflows.ts:7-16`, `116-186`).

Phase order in `pentestPipeline` (`temporal/workflows.ts:1292-1442`):

1. `initializeDurableScanState`; optional resume (register attempt → `loadResumeState` → restore git
   checkpoint → mark completed agents).
2. `preflight` (target/repo/config/model validation).
3. `cyber-access` probe (OpenAI/Anthropic only) — see Safety.
4. `syncPlaywrightStealthConfig`; `validate-authentication`.
5. `initDeliverableGit`; `syncCodePathDenyRules`.
6. `pre-recon` → `recon` sequentially; **Capella (agentic SAST) starts concurrently** and each class
   awaits the same settlement promise before reconciliation (`:1404-1409`, `:768-771`).
7. Per-class lanes in parallel, `MAX_CONCURRENT_PIPELINES = 5` (`:186`, `:1420`), each lane =
   vuln agent → join Capella → reconcile → `checkExploitationQueue` → conditional exploit agent
   (`:746-815`). A sixth `miscellaneous` lane runs alongside (`:1419`).
8. Report finalization: renumber → assemble → compact → finalize (JSON+MD+PDF+SARIF) → surface
   (`:1157-1290`).
9. Terminal status: `completed` or `partial`, decided **only** by the durable partial-reason set
   (`:1433-1436`: "PDF and customer-copy warnings never create reasons and never change the status").

Retry/timeout policy is explicit and reasoned:

- Agent activities: `startToCloseTimeout: '2 hours'`, heartbeat 60 min, `maximumAttempts: 50`,
  exponential 5 min → 30 min, with a non-retryable list of error *types* (bad credentials, bad config,
  unreachable target, failed login, provider cyber-gate) that "a retry can never fix"
  (`workflows.ts:87-121`).
- State-mutating report activities use `WAIT_CANCELLATION_COMPLETED` so a cancel cannot race a
  half-written commit; agent activities use `TRY_CANCEL` because "an agent process can simply be killed
  without leaving a half-written checkpoint behind" (`workflows.ts:152-173`).
- Output-validation retries are separate and capped at 3 (`temporal/activities.ts:123`, `459-469`).
- Agent-level retry inside pi is **off** so Temporal owns restarts; provider-level transport retry is
  **on** (`apps/worker/src/ai/pi/retry-settings.ts`, `CLAUDE.md:168`).

Failure isolation: each class lane catches everything except cancellation and returns a per-class
result with a safe message and a partial reason (`class_pipeline_failed` /
`class_reconciliation_failed`) rather than aborting siblings (`workflows.ts:797-814`). The aggregate
fails the phase only when *every* class failed or a result is unattributable (`:858-859`).

Cancellation and failure are handled as distinct terminal states with their own logging path; a thrown
non-`ApplicationFailure` is called out as a footgun that would leave the run stuck RUNNING
(`workflows.ts:1475-1478`).

LLM usage:

- **One model for the whole scan**, `SHANNON_AI_MODEL=<provider>:<model-id>`, default
  `anthropic:claude-sonnet-4-6` (`apps/worker/src/ai/models.ts:84`, `CLAUDE.md:168`). Split on the first
  colon only so Bedrock IDs survive (`models.ts:18` area).
- Curated providers: `anthropic`, `openai`, `xai`, `amazon-bedrock`; any pi-registry provider accepted;
  `SHANNON_AI_BASE_URL` for gateways; `--models-config` for unlisted models
  (`models.ts:54-84`, `:148-151`).
- **Output validation** happens twice: (a) in-session tool-schema validation with retryable errors fed
  back to the model — the explicit design goal is "turns a permanent post-commit failure into an
  in-session correction" (`ai/queue-schemas.ts:318-322`); (b) post-session `AGENT_VALIDATORS` in
  `session-manager.ts:209-247`, with absence of a validator treated as pass, not as failure
  (`ai/pi/pi-executor.ts:198-200`).
- **Structured output** is captured by tools, never by parsing prose: `submit_exploitation_queue`
  (vuln queue), `add_exploit` (evidence), `add_finding` (report). The queue tool's directive is
  blunt: "Do not output JSON as text" (`queue-schemas.ts:344-346`).
- **Termination** is tool-driven: the submit tool returns `terminate: true` on acceptance
  (`queue-schemas.ts:335`); a rejected call deliberately omits `terminate` so the session survives to
  retry (`:222-224`).
- **Harmlessness/refusal detection**: `cyber-access-verification` sends a canned, textbook exploit-plan
  request against a fixed lab host to detect provider-side cyber-safeguard refusals *before* spending a
  scan (`services/cyber-access-verification.ts:7-40`). Blunt and effective for the Anthropic/OpenAI
  refusal problem.

**INFERENCE** — Temporal is doing a lot of product work here: resume, cancel, progress query, per-scan
task-queue isolation, and 2-hour-tolerance agent runs. The cost is a hard local dependency
(`temporalio/temporal` container, `127.0.0.1:7233`) that a reimplementation would need to replace with
something equally durable, or accept losing crash-resume.

---

## State and persistence

**OBSERVED** — Three layers, each with a different job:

1. **Temporal workflow history** — authoritative for in-flight control flow; activities must stay
   deterministic because "Temporal replays them from recorded history" (`workflows.ts:12-15`).
2. **Git, scoped per agent** — each agent activity creates a checkpoint before and commits after,
   limited to the paths that agent writes (`services/agent-execution.ts:231-334`, path derivation in
   `services/agent-git-paths.ts:24-40`). The scoping comment names the exact failure mode if the two
   sides drift: a file "sits uncommitted in the working tree, or is not restored on rollback, with
   neither side raising an error" (`agent-git-paths.ts:39-42`). Rollback is used when validation fails
   so a bad draft cannot poison the next attempt.
3. **Durable run state on disk** — `.shannon/session.json` (attempts, completed agents, report
   progress, partial reasons) and `.shannon/workflow.log` (`audit/utils.ts:57-79`), plus
   `launch.json` written by the CLI *before* the container starts so `stop` can correlate a worker with a
   workflow during the pre-registration window (`CLAUDE.md:108`).

Resume is a first-class path, not an afterthought: `loadResumeState` validates deliverables, restores
the git checkpoint, and deletes incomplete deliverables (`temporal/activities.ts:1556+`,
`CLAUDE.md:172`). URL mismatch on resume is rejected "to prevent cross-target contamination"
(`docs/workspaces.md:17`). A pre-restructure workspace is refused rather than migrated
(`CLAUDE.md:170`) — an unusual and correct choice.

Report finalization is content-addressed: a manifest records sha256 per artifact, and finalization
throws on "any conflict or corruption", including `finalization-stale-sarif` and
`finalization-sarif-digest-mismatch` (`services/report-finalization.ts:95-166`, `285-330`). A durable
report draft short-circuits re-running the pentest phase, with the reason spelled out: re-running "would
only re-pay for the analysis and observe new degradation reasons that the finalized deliverable …
could never carry" (`workflows.ts:1397-1402`).

**INFERENCE** — This is the strongest part of the codebase for a platform builder to copy. The pattern
is: *durable state is append-only and reason-carrying; artifacts are hash-pinned; a resume never
reconstructs a reason from a symptom*. The explicit rule at `workflows.ts:1314` — "Durable reasons are
restored, never reconstructed from session status or errors" — is the whole idea in one line.

---

## Tool integration and execution

**OBSERVED** — Every agent session gets pi's built-ins `read, bash, edit, write, grep, find, ls`
(`ai/pi/pi-executor.ts:60`) plus three custom tools:

- `todo_write` — full-state-replace planning scratchpad; prompts require its use as the work queue
  (`ai/pi/session-tools.ts:25-58`; mandated at `prompts/exploit-injection.txt:90`, `121`).
- `glob` — fast-glob, mtime-sorted; `followSymbolicLinks: false` (`session-tools.ts:61-103`).
- `task` — generic child session for scripted work; no recursion (`task-tool.ts:44`).
- Plus per-agent capture tools (`submit_exploitation_queue`, `add_exploit`, `add_finding`).

Browser automation is **not** an MCP server or a bespoke CDP wrapper: it is the `playwright-cli` **skill**
injected only into browser agents via `skillsOverride`, and everything else runs with `noSkills: true`
(`pi-executor.ts:96-110`). Model-side invocation is `playwright-cli` through `bash` with a per-agent
session id (`prompts/exploit-injection.txt:118`; sessions enumerated as `agent1…agent6` in
`types/agents.ts:38`). Non-browser agents (report, pre-recon, misc exploit) get no skill at all.

Two hard guardrails on the shell:

- **Bounded bash** — a pi `tool_call` pre-hook blocks any `bash` call that omits a timeout or exceeds
  it: default 120 s, hard max 600 s. Rationale is stated exactly: pi applies "NO default and NO upper
  bound", so a hung `playwright-cli` action "hangs the agent indefinitely"
  (`ai/extensions/bash-timeout/index.ts:1-45`).
- **Path denies** — `code_path` avoid rules compile into the `@gotgenes/pi-permission-system`
  extension's global `path` deny surface, which gates read/edit/write/grep/find/ls *and* recognised bash
  file commands, across every tool and child session, and is "not overridable by a per-tool allow"
  (`ai/pi/permission-system.ts:8-19`, `78-93`). Config is written globally so it loads without a session
  context and never lands in the scanned repo (`:105-113`).
  Note the deliberate hole: `external_directory: 'allow'` because the pentest agent legitimately shells
  out beyond the working directory (`:16-19`, `:90`).

Sandboxing, as configured at container spawn (`apps/cli/src/docker.ts:424-528`):

| Control | Setting | Evidence |
|---|---|---|
| Target repo | `:ro` bind mount | `docker.ts:455` |
| Writable overlays | only `.shannon/deliverables`, `.shannon/scratchpad`, `.playwright*` | `docker.ts:457-463` |
| Network | joins `shannon-net` (shared with Temporal); unrestricted egress | `docker.ts:429`, `docker-compose.yml:1-4` |
| seccomp | **`seccomp=unconfined`** container-wide | `docker.ts:493-497` |
| shm | 2 GB (Chromium) | `docker.ts:497` |
| User | non-root `pentest`, uid remapped to host | `Dockerfile:97-99`, `entrypoint.sh:5-17` |
| Lifetime | `docker run -d --rm`, one per scan, own task queue | `docker.ts:425-429`, `CLAUDE.md:194` |
| Credentials | env vars only; `RuntimeCredentialStore` exists specifically so creds "must never touch disk" | `CLAUDE.md:168` |
| Optional pi auth | mounts **only** `~/.pi/agent/auth.json`, read-write, to allow token refresh | `docker.ts:485-488` |

The seccomp decision is documented as a knowing trade with its blast radius spelled out:
"`seccomp=unconfined` is a container-wide setting, not a per-process one: every process here runs
unfiltered, the worker included — not just the browser automation that motivates it"
(`docker.ts:493-496`). No `--cap-drop`, no read-only rootfs, no egress allow-list.

Local-target support is intentional: preflight blocks only the cloud metadata range, and comments say
"RFC1918 and loopback are intentionally allowed — scanning local targets is a supported Shannon use
case", with DNS-rebinding defeated by pinning the resolved addresses into the socket lookup
(`services/preflight.ts:52-91`). That is a genuinely good detail that most tools miss.

**INFERENCE** — Tool integration is *deliberately thin*: seven built-ins, three custom tools, one skill,
one pre-hook extension. The leverage is all in schemas, not in tool count. The flip side is that
"browser automation" means "an LLM typing `playwright-cli` commands into a shell", which is slower and
less reliable than a typed browser tool, and it is why the bash timeout extension had to exist.

---

## Safety, scope and authorization controls

**OBSERVED** — Controls exist at five levels, with sharply uneven strength.

**(a) Declared scope — target and repo, at launch.** Target is `-u <url>`, repo `-r <path>`
(`README.md:148-152`). Preflight validates URL reachability (10 s timeout), repo-is-directory, config
schema, and model resolution (`services/preflight.ts:41-140`). There is **no** authorization attestation
— no signed scope file, no RoE import, no allow-list of hosts, no "I am authorized" gate in code. The
requirement lives in docs and a README warning block: "Run it only against applications and
environments you own or have explicit written authorization to test. Do not run against production"
(`README.md:141-142`, `docs/safety.md:5-9`). The Claude/Cursor plugin skill instructs the *agent* to ask
the user to confirm ownership and non-production before the first `start`, and says "Do not infer either
from a URL, a repository name, or the target being local" (`plugins/shannon/skills/shannon/SKILL.md:9-14`)
— an integrity signal, but it is prompt guidance to a third-party coding agent, not an enforced control.

**(b) Scope narrowing inside a scan.** YAML `rules.avoid` / `rules.focus` support `url_path`,
`subdomain`, `domain`, `method`, `header`, `parameter`, `code_path`
(`configs/config-schema.json:105-127`, `example-config.yaml:60-100`). Enforcement is split:

- `code_path` → **hard deny** through the permission extension (see Tool integration). This is the only
  rule type with runtime teeth.
- everything else → **prompt text only**. `renderUrlRules` formats the avoids into `{{RULES_AVOID}}`
  (`services/prompt-manager.ts:21-37`, `379-401`). Nothing inspects an outgoing request, and the worker
  container has unrestricted egress. **OBSERVED gap**: a "do not test `/logout`" or "no DELETE on
  `/api/v1/users/*`" rule is an instruction to the model, not a control on the wire.

**(c) Rules of engagement.** Free text, 1–1000 chars, rendered into every prompt as
`<rules_of_engagement>` (`config-schema.json:174-179`, `prompts/shared/_rules-of-engagement.txt:1-3`).
The example config shows the intended content — no brute force, 5-request-per-second throttle, 60 s
backoff on 429, placeholder data in deliverables (`example-config.yaml:19-32`). Again: instruction, not
enforcement. No rate limiter, no request budget, no kill-switch in the request path.

**(d) Prompt-level blast-radius limits.** Exploitation must be against `{{WEB_URL}}` from the external
network; internal-network, VPN, and direct-server-access paths are out of scope; OOB callbacks are out
of scope; only `EXPLOITED` and `BLOCKED_BY_SECURITY` may become findings
(`prompts/shared/_exploit-scope.txt:1-18`, `prompts/shared/_vuln-scope.txt:1`). Production is declared
out of scope in-prompt (`prompts/exploit-injection.txt:34-36`) — note this is an assertion the agent is
told to accept ("THIS ENGAGEMENT IS FULLY AUTHORIZED"), which is the weakest possible form of that
control and a classic prompt-injection target.

**(e) Credential hygiene.** Configured credentials must never appear in submitted findings; `$username`,
`$password`, `$totp` placeholders instead (`prompts/shared/exploitation/_credentials-in-findings.txt:1-14`).
Captured session tokens and extracted data are explicitly *allowed* as evidence, which is the right call.
**OBSERVED gap:** this is prompt-only. There is no code-level redaction of the configured username,
password, or TOTP secret anywhere on the submission path (`grep -rn "redact(" apps/worker/src` returns
only error-message and reconciliation-ID redaction, not credential redaction). The shared authenticated
browser session is deleted at workflow end so it "never outlives the scan"
(`audit/utils.ts:64-67`), which is good hygiene but does not cover the report text.

**(f) Provider-safeguard precheck.** OpenAI/Anthropic runs probe whether the model will accept the
exploitation workload before the scan starts, because a mid-scan refusal wastes the whole run
(`services/cyber-access-verification.ts:7-18`). Practical, provider-specific, and it fails closed
(`workflows.ts:1348-1359` rethrows after marking the stage failed).

**INFERENCE** — The safety posture is *operator-trusting*. It protects the customer's data (ro mount,
overlay-only writes, ephemeral container, URL-pinned target, metadata-endpoint block, DNS pinning) far
better than it constrains its own actions (no egress control, no per-request policy, no attestation).
For a platform that wants multi-tenant or CI-triggered operation, (b)/(c)/(e) are the gaps that matter:
every one of them is a model instruction, and models are exactly what gets prompt-injected by the
untrusted repository Shannon is told to read.

---

## UI and API surface

**OBSERVED** — There is **no HTTP API, no web UI, and no server process of its own** (`grep` for
`createServer|express|fastify|.listen(` under `apps/` matches only test fixtures in
`apps/cli/src/exp-php2shell/probe.test.ts`). Surfaces are:

1. **CLI** — `setup, start, stop, reset, logs, status, scans, build, version`
   (`apps/cli/src/index.ts:365-428`). `start` flags: `-u`, `-r`, `-c`, `--models-config`, `-w`,
   `--output`, `--pipeline-testing`, `--keep-container`, `--follow`, `--validate-auth`,
   `--validate-model`, `--exp-php2shell`, `-y`, `--version`
   (`apps/cli/src/commands/start.ts:43-59`). Arg parsing rejects unknown flags loudly and suggests the
   closest match (`apps/cli/src/args.ts:1-11`, `suggest.ts`).
2. **Live terminal tree** — phase/agent rows driven by a Temporal `getProgress` query, plus
   `--json` output; the CLI deliberately shows "model work only" and folds deterministic bookkeeping
   into `+ duration` suffixes (`CLAUDE.md:106`).
3. **Temporal Web UI** — bundled at `127.0.0.1:8233`, loopback-bound (`docker-compose.yml:12`). It is
   the de-facto debugging UI and exposes full workflow history to anyone on the host.
4. **Machine-readable status** — `shannon status --json`, `scans`, `apps/cli/src/scan/status-json.ts`.
5. **Coding-agent plugin** — a Claude Code / Cursor plugin bundle with an agent-facing skill that
   documents the CLI and carries safety instructions (`plugins/shannon/.claude-plugin/plugin.json`,
   `plugins/shannon/skills/shannon/SKILL.md`). Distribution wrapper, not a new surface.
6. **CI integrations** — separate repos, not in this tree: `KeygraphHQ/shannon-action` (GitHub) and
   `shannon-ci` (GitLab), documented at `README.md:183-234`. They consume the CLI and gate on
   `status: exploited` only: "A code-analysis hypothesis does not fail the pipeline"
   (`README.md:196`).

**INFERENCE** — API-less is a defensible v1 choice (no auth surface to get wrong, no tenant model), but
it means programmatic integration is "shell out to the CLI and parse JSON", and the only *inspectable*
runtime state is Temporal's. A platform will need to add a real API; the CLI's `status --json` contract
and `PipelineState` types are the natural seed for it.

---

## Reporting and evidence

**OBSERVED** — Four outputs, from one canonical structured artifact:

1. `report.json` — canonical structured findings, produced by the `report` agent through `add_finding`
   (`collectors/finding-collector.ts:249-257`). This is the source of truth; everything else renders
   from it deterministically.
2. `comprehensive_security_assessment_report.md` → surfaced as `Security-Assessment-Report.md`.
3. `comprehensive_security_assessment_report.pdf` via **Typst** (`templates/typst/report.typ`, binary
   installed at `Dockerfile:81-95`, renderer `services/pdf-renderer.ts`). PDF failure is warning-only
   and "cannot change the commit" (`services/report-finalization.ts:332`).
4. **SARIF 2.1.0**, on by default for exploit runs, opt-out via `report.sarif: "false"`
   (`services/sarif-renderer.ts:7`, `config-schema.json:166-170`). One rule per class
   (`shannon/injection`, …) mapping to OWASP Top Ten 2025 taxonomy; rule IDs are treated as immutable
   because "renaming one detaches every alert filed under it" (`sarif-renderer.ts:33-40`).

Evidence format per finding (`services/report-output-schema.ts:84-98`): `id, title, category, severity,
owaspCategory, authState, summary{vulnerableLocation, overview, impact}, prerequisites,
exploitationSteps[], proofOfImpact[], remediation, notes[], additionalSections[]`. Each step is a list
of prose/code items with an `exact` `content` and a separate `displayContent` used only for PDF line
breaking (`report-output-schema.ts:21-35`) — a small but real correctness detail: the PDF never mutates
the evidence bytes.

Report-level metadata carries an explicit **coverage** contract: `status: 'complete' | 'partial'` plus a
list of `{code, message}` limitations (`report-output-schema.ts:57-65`). The report prompt forbids
calling a scan clean when a `<not_assessed_classes>` block is present, and requires analysis-mode
summaries to say no finding "was confirmed by exploitation" and present severity "as assessed rather
than measured" (`prompts/report-executive.txt:110-115`). Counts are split three ways — exploited, out of
scope, blocked by constraints — with separate breakdowns (`report-output-schema.ts:113-127`).

Report-agent selection logic is a real editorial pass, not a passthrough: title cleanup that strips
consequences and process suffixes, and a one-forward-pass DROP rule for restatements across classes,
with the instruction "Dropping a restatement never drops coverage" and an explicit ban on dropping an
entry because it is the only one of its kind (`prompts/report-executive.txt:79-100`).

Sample reports (`sample-reports/shannon-report-juice-shop.md`, and the Photoview PDFs/SARIF in
`benchmark/`) show the intended texture: `### INJ-VULN-01: SQL Injection Authentication Bypass`, then
Summary table, Prerequisites, numbered exploitation steps with full `curl` invocations, and captured
response excerpts (`sample-reports/shannon-report-juice-shop.md:38-60`). Note the sample still carries
the old `INJ-VULN-01` producer-ID form, which current code rejects in favour of `INJ-01` task refs
(`exploit-collector.ts:487-498`) — the sample predates the reconciliation layer (**INFERENCE**).

**INFERENCE** — This is the best-executed part of the product. Evidence is structured at capture time,
never re-derived from prose; one canonical JSON feeds four renderers; digests are pinned; and the
report's own coverage is an explicit, machine-readable field rather than a paragraph of hedging. The
`displayContent` split and the "restatements never drop coverage" rule are both worth stealing outright.

---

## Tests and CI

**OBSERVED** — Test coverage is thin and CI does not test.

- Exactly **four** test files exist, all in one experimental CLI feature:
  `apps/cli/src/exp-php2shell/{classify,multipart,probe,transport}.test.ts`, using `node:test`
  (`grep 'from .node:test.'`).
- No `test` script exists in the root, `apps/cli`, or `apps/worker` `package.json`. Scripts are
  `build`, `check` (`tsc --noEmit`), `clean`, plus `biome` at root. So even those four tests have no
  documented runner invocation (**OBSERVED**).
- CI is release automation only: `release.yml`, `release-beta.yml`, `rollback.yml`,
  `rollback-beta.yml`. No lint job, no typecheck job, no test job, no security scan. Actions are pinned
  to commit SHAs (good: `release.yml:24-31`), concurrency-gated, and gated on a semantic-release dry-run
  probe (`release.yml:40-58`).
- Linting/formatting: Biome 2, 120 cols, single quotes (`biome.json`, `CLAUDE.md:202`).
- **Benchmark harness: none in-tree.** `benchmark/` holds three PDF + SARIF *outputs* from a Photoview
  run across three models, not a runner. The methodology lives in prose
  (`docs/shannon-xbow-aikido-benchmark.md`): one app (Photoview 2.4.0), admin creds only, hand
  validation, recall approximated from post-version security fixes. Reported results: 18/18, 10/10,
  23 TP + 1 FP out of 24 for DeepSeek v4 Flash / Grok 4.6 / Opus 5, at $6.10 / $35.07 / $115.
  **OBSERVED caveat**: it is a single app, one run per model, vendor-run and vendor-written; the doc
  admits "a different researcher per platform" in the upstream study and that recall is only
  "partial ground truth". It is a credible anecdote, not a benchmark.

**INFERENCE** — 53k LOC of security-critical orchestration with four unit tests and no CI gate is the
single largest engineering gap in the repo. The `checkpointsEnabled` / resume / finalization paths are
exactly the kind of state machine that needs property-style tests, and the mitigation in practice is
defensive coding: hash manifests, fail-closed validation, explicit integrity error codes
(`report-finalization.ts:95-166`).

---

## Capability marks

| # | Area | Mark | Basis |
|---|---|---|---|
| 1 | Architecture and module layout | **Strong** | Clean cli/worker split, services-vs-activities boundary, DI root (`CLAUDE.md:92-172`, `services/container.ts`) |
| 2 | Agent topology | **Strong** | 14 named agents, fixed roster, typed prompts, non-recursive child sessions (`types/agents.ts:15-30`, `task-tool.ts:44`) |
| 3 | Proof-by-exploitation enforcement | **Strong, one leak** | 3 code gates + prompt gate; report `status` optional and defaults to `exploited` (`report-json-adapter.ts:195`) |
| 4 | Prompt engineering quality | **Strong** | Severity floor, bypass exhaustion, overstatement ban, OOB exclusion (`_severity-reasoning.txt`, `_reporting-standards.txt`) |
| 5 | Orchestration / durability | **Strong** | Temporal, per-scan queues, 4 terminal states, cancellation semantics (`workflows.ts:92-186`, `1433-1479`) |
| 6 | LLM output validation | **Strong** | Per-status discriminated re-validation, retryable in-session errors, ID namespacing (`exploit-collector.ts:462-519`) |
| 7 | Termination / failure isolation | **Strong** | Per-class isolation, partial reasons, no-fail-fast aggregation (`workflows.ts:797-859`) |
| 8 | State and persistence | **Strong** | Agent-scoped git, hash-pinned finalization, durable reasons not reconstructed (`workflows.ts:1314`) |
| 9 | Browser automation | **Adequate** | playwright-cli skill + bash, per-agent session ids; string-typed, timeout-guarded (`pi-executor.ts:96-110`) |
| 10 | Container sandboxing | **Partial** | ro repo, non-root, ephemeral — but `seccomp=unconfined`, no cap-drop, open egress (`docker.ts:493-497`) |
| 11 | Scope enforcement | **Partial** | `code_path` hard-denied; URL/method/header rules prompt-only (`permission-system.ts` vs `prompt-manager.ts:379-401`) |
| 12 | Authorization model | **Absent** | No attestation, no scope file, no host allow-list; docs-only (`docs/safety.md:5-9`) |
| 13 | Credential hygiene | **Partial** | Prompt placeholder rule + no-disk creds; no code-level redaction of report text (`_credentials-in-findings.txt`) |
| 14 | Reporting and evidence | **Strong** | Structured at capture, 4 renderers from one JSON, coverage field, Typst + SARIF (`report-output-schema.ts`) |
| 15 | UI / API | **Minimal** | CLI + Temporal Web UI only; no HTTP API, no web UI (`grep` over `apps/`) |
| 16 | Tests | **Weak** | 4 test files, one feature, no test script (`exp-php2shell/*.test.ts`) |
| 17 | CI | **Weak** | Release-only workflows; no lint/typecheck/test gate (`.github/workflows/`) |
| 18 | Benchmark harness | **Absent** | Outputs only; methodology is prose (`docs/shannon-xbow-aikido-benchmark.md`) |
| 19 | Provider abstraction | **Strong** | pi registry, 4 curated + any provider, base URL, models-config (`ai/models.ts:54-151`) |
| 20 | License clarity | **Adequate** | AGPL-3.0 + per-file notices + `THIRD_PARTY_NOTICES.md` (see below) |

Mark scale: Strong = production-grade, worth copying as-is; Adequate = works, known rough edges;
Partial = present but easy to defeat or bypass; Weak/Absent = material gap.

---

## Strengths worth adopting

1. **Enforce the methodology in schemas, not in prose.** The strongest idea in the repo: the exploit
   tool physically cannot store an "exploited" verdict without steps + impact evidence
   (`exploit-collector.ts:356-390`). Copy the pattern — one tool per artifact kind, discriminated by
   status, with per-status required fields re-validated inside the handler.
2. **Retryable rejections instead of hard failures.** Every validation error returns
   `{status:'error', retryable:true, message}` with the specific instance paths, so the model corrects
   in-session; only the duplicate-ID case is non-retryable (`exploit-collector.ts:410-424`,
   `queue-schemas.ts:222-235`). This converts "agent failed" into "agent retried once".
3. **Provenance namespacing with redaction.** Producer IDs (`INJ-VULN-01`) never reach the exploit agent
   or the report; task refs (`INJ-01`) are minted at reconciliation and redacted views are enforced
   (`refs.ts:27-48`, `observation-view.ts:22-80`). This kills a whole class of ID-hallucination and
   identity-leak bugs.
4. **Severity reasoning with a floor and an anti-inflation test.** Four questions, "the burden of proof
   rises with the tier", "where two tiers seem arguable choose the lower", and a non-tier floor for
   harmless defects (`_severity-reasoning.txt:9-49`). This is the best-calibrated severity prompt I have
   read in an OSS tool; it directly attacks the "everything is Critical" failure mode.
5. **Overstatement is treated as a defect.** "Overstating a finding is a reporting failure of the same
   order as missing one"; no hedges; no impact-led titles; claims no wider than the observation
   (`_reporting-standards.txt:4-19`). Encode this in the report-writer role, not just style docs.
6. **Bypass exhaustion as a precondition for classification.** Minimum attempt counts before a "not
   exploitable" verdict is legal (`exploit-injection.txt:185-187`, `238-254`). Cheap, and it removes the
   most common lazy-negative failure.
7. **Evidence structured at capture time, rendered deterministically.** One `report.json` →
   MD + PDF + SARIF, with `displayContent` separate from `exact` content so the PDF cannot corrupt
   evidence (`report-output-schema.ts:21-35`, `services/report-finalization.ts`).
8. **Coverage as a machine-readable field, not a disclaimer.** `{status, limitations[]}` plus the
   `<not_assessed_classes>` rule that forbids calling a partial scan clean
   (`report-output-schema.ts:57-65`, `report-executive.txt:110-115`). Directly reusable for CI gating.
9. **Durable reasons that are restored, never reconstructed** (`workflows.ts:1314`), with a partial vs
   complete distinction that a pipeline can gate on.
10. **Bounded bash as a pre-execution hook** with a stated reason (no default, no upper bound in the
    harness) — 120 s default, 600 s max (`bash-timeout/index.ts:1-45`). Trivial to replicate, prevents
    the classic hung-agent stall.
11. **DNS pinning + metadata-endpoint block, with RFC1918/loopback deliberately allowed**
    (`preflight.ts:52-91`). Shows you can support local targets without leaving a rebinding hole.
12. **Provider-safeguard precheck** so a cyber-policy refusal is discovered in 30 seconds instead of
    two hours in (`cyber-access-verification.ts:7-40`).
13. **Agent-scoped git checkpoints** — commit/rollback limited to the files an agent owns, with the
    drift risk documented at the coupling point (`agent-git-paths.ts:39-42`).

---

## Weaknesses and gaps

1. **No authorization control of any kind.** No attestation, no signed scope, no host allow-list, no
   "authorized" flag. Safety is a README warning plus a prompt assertion ("THIS ENGAGEMENT IS FULLY
   AUTHORIZED", `exploit-injection.txt:35`). For any multi-tenant or CI-triggered deployment this is
   the first thing that must be added.
2. **URL/method/header/parameter scope rules are prompt-only.** Only `code_path` avoids are enforced in
   code; the container has open egress and no request proxy (`prompt-manager.ts:379-401` vs
   `permission-system.ts`). A "no DELETE" or "don't touch /logout" rule can be ignored by the model with
   no detection.
3. **`seccomp=unconfined` container-wide**, no `--cap-drop`, no read-only rootfs
   (`docker.ts:493-497`). The code is candid that this applies to the worker too, not just Chromium —
   but it is still a real reduction in isolation for a process that runs LLM-chosen shell commands.
4. **`status` on `add_finding` is optional and defaults to `exploited`**
   (`finding-collector.ts:215-219`, `report-json-adapter.ts:195`). The "no exploit, no report" invariant
   therefore rests on the report prompt's KEEP/SKIP headings, not on a join back to the exploit
   collector. Fix would be cheap: require the ID to exist in a collector record with
   `status:'exploited'`.
5. **No credential redaction on the report path.** The `$username`/`$password` rule is prompt-only;
   `grep` finds no redaction of configured secrets in submitted findings. A model that ignores the
   instruction writes the engagement password into `report.json`, the PDF, and the SARIF.
6. **Prompt injection is acknowledged, not mitigated.** "Do not scan untrusted or adversarial
   codebases" (`docs/safety.md:32`, `README.md:326`) is the entire control, in a tool whose core value
   is reading arbitrary repositories. No content sandboxing for file reads, no instruction/data
   separation, no canary tokens.
7. **Four unit tests, no test CI.** 53k LOC, four `node:test` files, no `test` script, no lint or
   typecheck job in `.github/workflows/`. Every integrity property (hash manifests, resume, rollback) is
   defended by code review alone.
8. **No benchmark harness.** `benchmark/` is a results folder; the eval is one app, one run per model,
   vendor-run, with recall inferred from post-version fixes. Not reproducible from this repo.
9. **No public API or UI.** Integration is CLI-shelling plus the Temporal Web UI on `127.0.0.1:8233`;
   programmatic access depends on undocumented `status --json` shape stability.
10. **Single-model-per-scan.** No per-stage model routing (cheap model for recon, strong model for
    exploitation), even though the pipeline stages have wildly different difficulty
    (`models.ts:84`, `CLAUDE.md:168`). Purely a cost/quality lever left on the table.
11. **No class selection.** All five classes always run; `agentic_sast` is the only public switch
    (`example-config.yaml:7-8`). Re-scanning a known-XSS app still pays for all five lanes.
12. **DEAD commercial hooks in OSS.** `setContainerFactory` is exported but never called, so
    `CheckpointProvider`/`FindingsProvider`/`ReportOutputProvider` are NoOp
    (`services/container.ts:77-113`). Harmless, but readers will assume resume uses them; it does not —
    resume goes through `loadResumeState`.
13. **Two parallel prompt trees** (`prompts/*.txt` and `prompts/pipeline-testing/*.txt`, 27 top-level
    files vs 12 in the testing tree) plus 20 Capella `.hbs` templates. High drift risk; only `CLAUDE.md`
    convention keeps them aligned.
14. **Shallow-clone analysis limit:** no history, no release cadence, no contributor data, so
    maintainability and bus factor are **UNKNOWN**.
15. **Contribution path closed:** "At this time, Keygraph is not accepting external code contributions"
    (`README.md:360`). AGPL plus no inbound contributions means forking, not collaborating.

---

## License and attribution requirements

**OBSERVED**

- **Primary license: GNU AGPL-3.0** (`LICENSE:1-3`; `README.md:332`; `plugins/shannon/.claude-plugin/plugin.json`).
  Every source file sampled carries an AGPL header ("Copyright (C) 2026 Keygraph, Inc. … GNU Affero
  General Public License version 3"), e.g. `temporal/workflows.ts:1-5`, `collectors/exploit-collector.ts:1-5`.
- **Bundled third-party licenses** in `LICENSES/`: `Apache-2.0.txt`, `MIT-Pi.txt`. Shipped into the
  image at `/usr/share/licenses/shannon/` (`Dockerfile:115-117`).
- **`THIRD_PARTY_NOTICES.md`** records two dependencies with attribution obligations:
  - **Pi** (`github.com/earendil-works/pi`), MIT, © 2025 Mario Zechner — "Shannon uses Pi as part of its
    agent framework". Runtime dependency: `@earendil-works/pi-coding-agent`, `pi-agent-core`, `pi-ai`
    (`apps/worker/package.json:42-44`).
  - **Mantis** (`github.com/google/mantis`), Apache-2.0, upstream commit pinned
    `876a0c8c…`, retrieved 2026-08-25 — "Portions of Shannon's Capella agentic SAST implementation,
    specifically the agent prompts, are derived from the Mantis project". Affected files are named and
    are "individually marked with a provenance header":
    `apps/worker/prompts/partials/` (`capella-*.hbs`) and `apps/worker/prompts/sast/capella/`. The notice
    states the material was "substantially modified by Keygraph" and preserves upstream copyrights.
    Confirmed present: `apps/worker/prompts/partials/capella-{calibration-rules,operating-principles,tools}.hbs`.
  - `@gotgenes/pi-permission-system` is a runtime dependency (`package.json:45`) but is **not** listed in
    `THIRD_PARTY_NOTICES.md` — **OBSERVED gap**, though its own license travels in `node_modules`.

**Practical consequences (**INFERENCE**):**

- AGPL-3.0 §13 means offering Shannon (or a derivative) as a network service obliges you to offer the
  complete corresponding source to users of that service. A hosted autonomous pentest platform built by
  modifying this code inherits that obligation — including any modifications, since there is no linking
  exception to hide behind for a derivative work.
- If the new platform is meant to be proprietary, the safe patterns are: (a) keep Shannon as a separate
  process invoked over a boundary you can argue is aggregation rather than derivation, (b) copy
  *ideas and prompt techniques* rather than code (prompt text is copyrightable as a literary work —
  the Mantis notice is evidence Keygraph treats prompt text as licensed material), or (c) obtain a
  commercial license from Keygraph, which they explicitly offer (`README.md:334-336`).
- Reusing the Mantis-derived Capella prompts carries a **second** obligation: Apache-2.0 §4 requires
  retaining the notice, stating changes, and shipping the license text. The repo already models the
  correct pattern — provenance header per file, pinned upstream commit, named directory list — and that
  pattern is worth copying verbatim into any fork.
- `sample-reports/` and `benchmark/` PDFs contain real-looking exploit output against Juice Shop and
  Photoview; they are evidence artifacts under the same AGPL, not separately licensed assets.

---

## Evidence ledger

Files read (path → what it established):

| Path | Establishes |
|---|---|
| `README.md` | Positioning, "no exploit no report", editions, arch diagram, CI integrations, license, no-external-contributions |
| `LICENSE`, `LICENSES/*`, `THIRD_PARTY_NOTICES.md` | AGPL-3.0 primary; Pi (MIT) and Mantis (Apache-2.0, pinned commit) obligations; named derived prompt dirs |
| `CLAUDE.md` | Authoritative internal architecture: monorepo layout, five-phase pipeline, DI container, audit paths, resume semantics, pi retry split |
| `docs/safety.md` | Authorized-use / non-production policy; mutative effects list; prompt-injection caveat; class scope |
| `docs/workspaces.md` | Workspace layout, resume rules, URL-mismatch rejection |
| `docs/shannon-xbow-aikido-benchmark.md` | Benchmark methodology and results table; admitted limitations |
| `COVERAGE.md` | WST checklist coverage and explicit non-coverage |
| `docker-compose.yml` | Temporal-only infra, loopback-bound ports 7233/8233, `shannon-net` |
| `Dockerfile` | Wolfi 2-stage, non-root uid 1001, Chromium + Python + Typst 0.14.2, playwright-cli 0.1.1, license dirs, `SHANNON_DOCKER=true` |
| `entrypoint.sh` | UID/GID remap then `exec su -m pentest` |
| `package.json`, `apps/*/package.json`, `biome.json`, `turbo.json`, `pnpm-workspace.yaml` | Workspace shape, scripts (no test script), deps incl. pi + pi-permission-system, Biome 120 cols |
| `apps/cli/src/docker.ts` | `docker run --rm -d`, `:ro` repo, writable overlays, `shannon-net`, `seccomp=unconfined`, shm 2 GB, labels, pi-auth mount |
| `apps/cli/src/index.ts`, `args.ts`, `commands/start.ts` | CLI command set and start flags; strict arg parsing |
| `apps/worker/configs/config-schema.json` | Closed config schema: auth (form/sso/api/basic, TOTP, email login), rules avoid/focus types, `agentic_sast`, `exploit`, `report`, `rules_of_engagement` (max 1000) |
| `apps/worker/configs/example-config.yaml` | "Every scan runs all five vulnerability classes … no setting to narrow that"; RoE examples; code_path globs |
| `apps/worker/src/types/agents.ts` | 14-agent roster, playwright session enum, ExploitationDecision |
| `apps/worker/src/temporal/workflows.ts` | Pipeline order, retry/timeout constants, `MAX_CONCURRENT_PIPELINES=5`, per-class isolation, resume, report finalization, terminal status rule, cancel/fail semantics |
| `apps/worker/src/temporal/activities.ts` | Activity wrappers, `MAX_OUTPUT_VALIDATION_RETRIES=3`, heartbeat 2 s, `saveCheckpoint` delegate, resume/report activity surface |
| `apps/worker/src/temporal/pipeline.ts` | Pipeline exported as a library function |
| `apps/worker/src/services/queue-validation.ts` | Queue/deliverable existence rules, fail-closed on unexpected errors, retryable classification |
| `apps/worker/src/services/exploitation-checker.ts` | Pure decision logic; never launders failure into "clean" |
| `apps/worker/src/services/report-output-schema.ts` | Canonical report shape, coverage field, `exact` vs `displayContent` |
| `apps/worker/src/services/report-finalization.ts` | Hash-pinned manifest, integrity error codes, PDF warning-only |
| `apps/worker/src/services/report-json-adapter.ts` | `f.status ?? 'exploited'` default; exploited-only filtering for PDF |
| `apps/worker/src/services/findings-renderer.ts` | Deterministic per-class findings render from queues (analysis mode) |
| `apps/worker/src/services/exploit-renderer.ts` | Three fixed evidence sections incl. `## Potential Vulnerabilities (Validation Blocked)` |
| `apps/worker/src/services/sarif-renderer.ts` | SARIF 2.1.0, per-class rules, OWASP Top Ten 2025 taxonomy, immutable rule IDs |
| `apps/worker/src/services/prompt-manager.ts` | `{{RULES_AVOID}}` URL rules are text; `REPORT_VULN_SUBHEADING` = "Successfully Exploited Vulnerabilities" in exploit mode |
| `apps/worker/src/services/preflight.ts` | URL/repo/config/model validation; metadata-endpoint block; RFC1918/loopback allowed; DNS pinning |
| `apps/worker/src/services/cyber-access-verification.ts` | Provider cyber-safeguard probe design and rationale |
| `apps/worker/src/services/container.ts` | DI container; NoOp providers; unused `setContainerFactory` |
| `apps/worker/src/services/agent-execution.ts`, `agent-git-paths.ts`, `git-manager.ts` | Pre/post git checkpoint, per-agent path scoping, rollback on failure |
| `apps/worker/src/collectors/exploit-collector.ts` | `add_exploit` schema, per-status strict union re-validation, ID namespace checks, duplicate rejection |
| `apps/worker/src/collectors/finding-collector.ts` | `add_finding` schema; optional `status` |
| `apps/worker/src/ai/queue-schemas.ts` | `submit_exploitation_queue`, ID namespace + duplicate rules, `terminate` semantics |
| `apps/worker/src/ai/pi/pi-executor.ts` | Built-in tool set, browser-skill injection, output validation, usage accounting |
| `apps/worker/src/ai/pi/permission-system.ts` | `code_path` deny compilation, `external_directory: allow` |
| `apps/worker/src/ai/pi/session-tools.ts` | `todo_write`, `glob` |
| `apps/worker/src/ai/pi/task-tool.ts` | Non-recursive child delegation |
| `apps/worker/src/ai/extensions/bash-timeout/index.ts` | 120 s default / 600 s max bash guard |
| `apps/worker/src/ai/models.ts` | Provider list, `SHANNON_AI_MODEL`, base URL, default model |
| `apps/worker/src/ai/reconciliation/{refs,observation-view,materialize,publish,form}.ts` | Producer vs task ID namespacing, redaction, schema revalidation before publish, task formation |
| `apps/worker/src/ai/sast/capella/{types.ts,temporal/workflow.ts}` | Capella child workflow stages: architecture → threat-model → plan → research → dedupe → review → critic → confirm → export |
| `apps/worker/src/audit/{audit-session,utils,log-stream}.ts` | `session.json` + `workflow.log` locations, crash-safe append, shared session deleted at workflow end |
| `apps/worker/prompts/exploit-injection.txt` | Role separation, proof levels 1–4, bypass exhaustion, task-agent mandate, evidence checklist |
| `apps/worker/prompts/vuln-injection.txt` | White-box data-flow role; "do not cross this boundary" |
| `apps/worker/prompts/exploit-miscellaneous.txt` | Misc class scope; `status:"exploited"` only after demonstrated impact |
| `apps/worker/prompts/report-executive.txt` | KEEP/SKIP rules, title cleanup, DROP-restatement pass, coverage honesty in summaries |
| `apps/worker/prompts/shared/_exploit-scope.txt` | External-only scope, OOB exclusion, verdict taxonomy |
| `apps/worker/prompts/shared/_target.txt`, `_vuln-scope.txt`, `_rules*.txt` | Filesystem grant (repo ro, deliverables/scratchpad rw), external-attacker scope, rule injection points |
| `apps/worker/prompts/shared/exploitation/_severity-reasoning.txt` | Four-question severity method, tier floor, anti-inflation checks |
| `apps/worker/prompts/shared/exploitation/_reporting-standards.txt` | Overstatement ban, no hedging, narrow-claim rule |
| `apps/worker/prompts/shared/exploitation/_credentials-in-findings.txt` | `$username`/`$password`/`$totp` placeholder rule |
| `apps/worker/prompts/shared/exploitation/_task-formation-procedure.txt`, `task-formation-injection.txt` | LLM grouping of observations into one-proof tasks |
| `apps/cli/src/exp-php2shell/*.test.ts` | Only tests present; `node:test` |
| `.github/workflows/release.yml` (+beta/rollback) | Release-only CI, SHA-pinned actions, no tests/lint |
| `plugins/shannon/**` | Claude/Cursor plugin: agent-facing safety instructions |
| `sample-reports/shannon-report-juice-shop.md` | Report texture: sections, summary table, numbered steps with `curl` |
| `benchmark/*.{pdf,sarif}` | Output artifacts only — no harness |

**Counts (**OBSERVED**, `wc -l` / `find`):** 217 TS files; 53,113 TS lines (worker 43,917 / cli 9,196);
63 `.txt` + 23 `.hbs` prompt files = 9,471 lines; 392 tracked files total; 4 test files; 4 CI workflows.

**UNKNOWNS**

- Commit history, release cadence, contributor count, issue responsiveness (**shallow clone**).
- Runtime behaviour of any agent, actual scan reliability, real FP rate, real cost, model-to-model
  variance. Nothing was executed.
- Whether the commercial build's `CheckpointProvider`/`FindingsProvider` implementations change the
  resume or findings semantics described here.
- Whether `@gotgenes/pi-permission-system` mitigates the bash-command gap in practice (the deny surface
  claims to cover "recognized bash file commands"; the list is not in this repo).
- The `verify-exploit` agent name in `BROWSER_AGENTS` has no corresponding roster entry in
  `ALL_AGENTS` — either a commercial-only agent or dead config (**UNKNOWN** which).
- Effectiveness of the `cyber-access-verification` probe against provider safeguards (logic read, never
  run).
- Legal weight of AGPL §13 for whatever deployment shape the new platform takes — needs counsel, not a
  code read.