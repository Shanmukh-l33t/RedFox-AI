# Design synthesis

Phase 1 output: what the reference projects do well, what they get wrong, and
exactly which decisions RedFox AI took as a result. Every claim about a
reference repo below is backed by a cited file path in the per-repo analyses in
`docs/references/`.

## Method

- Six repositories were cloned to an isolated directory and treated as untrusted
  data. Nothing from them was executed: no installers, no container builds, no
  package managers, no repo scripts. Only files were read.
- Analysis followed the REA (reverse-engineer-anything) skill's evidence
  discipline: observations cite a path, inferences are labelled, and unknowns are
  stated rather than guessed. REA's own guidance is that a complete source
  repository is analysed with ordinary repository tools rather than REA's binary
  providers, and that is what was done. REA's providers (Ghidra, JADX, Kuna,
  tshark, and so on) were not installed and were not needed: no reference target
  was a shipped binary.
- Per-repo analyses: `docs/references/{pentagi,strix,artex,hexstrike,shannon,pentest-swarm-ai}.md`.
- The mission brief also asked for an inventory of pre-existing Hermes pentest
  skills. That inventory is short and honest: **there were none installed.** The
  Hermes profile contains design, research, document and GitHub skills, but no
  recon, enumeration, parsing or reporting skill written for real pentests.
  Nothing was therefore wired in from that column; the capabilities were built
  here and are covered by tests instead. The REA skill was installed as part of
  this work and is what the method above follows.

## Reference inventory

| Repo | License | Primary language | Scale | Shape |
|---|---|---|---|---|
| [pentagi](https://github.com/vxcontrol/pentagi) | MIT + a separate `EULA.md` addendum | Go, TypeScript | ~198k non-test/non-generated Go, ~91k TS | Product: multi-agent pentest platform with queue, UI, observability |
| [strix](https://github.com/usestrix/strix) | Apache-2.0 | Python, Go, TS | ~45k Python src | Agent CLI with sandboxed tooling and a web viewer |
| [ARTEX](https://github.com/BaaRai/ARTEX) | AGPL-3.0 | Go | fork of `Autumn-27/ARTEX` | Planner/worker engine with graph-backed findings |
| [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | MIT | Python | ~2 large files | MCP tool broker: 151 tools over an HTTP daemon |
| [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | AGPL-3.0 | Go | ~77k Go | Planner-less swarm on a shared blackboard |
| [shannon](https://github.com/KeygraphHQ/shannon) | AGPL-3.0 | TypeScript | large (Temporal-based) | White-box web pentester, "no exploit, no report" |

Two licence facts shape how these were used. Three of the six are AGPL-3.0, so
**no code was copied from any reference**; only ideas and interface shapes were
taken. RedFox AI ships Apache-2.0, which is compatible with the MIT and
Apache-2.0 references as *reading material* and imposes nothing on the AGPL ones
because nothing was derived from their source.

## Capability matrix

Mark legend: **P** present and real · **W** weak, opt-in, or bypassable · **M** missing.
Rows are the capabilities the brief asks for; a row that is **M** across the board
is precisely where this project had to add something.

| Capability | pentagi | strix | ARTEX | hexstrike | swarm | shannon | RedFox |
|---|---|---|---|---|---|---|---|
| Authorization record (attestation, ref, operator) | M | M | M | M | W | M | **P** |
| Scope enforcement in the execution path | M | M | W | M | W | M | **P** |
| Autonomy levels gating risk classes | M | M | W | M | W | M | **P** |
| Global kill switch | W | M | M | M | W | W | **P** |
| Append-only, tamper-evident audit | W | M | W | M | W | M | **P** |
| Structured tool parsers (nmap/nuclei/httpx/ffuf) | M | M | W | M | W | M | **P** |
| Findings tied to evidence ids | P | P | P | M | W | P | **P** |
| Proof-before-report enforced in schema | W | P | P | M | M | P | **P** |
| Resumable campaign state | P | W | W | M | W | P | **P** |
| Planner + specialist agents | P | P | P | M | W | P | **P** |
| Provider-agnostic LLM (incl. local) | P | W | P | M | W | W | **P** |
| SARIF output | M | M | M | M | M | M | **P** |
| Web UI with live campaign view | P | P | P | M | P | P | **P** |
| Multi-node scale / queue service | P | W | W | M | W | P | M (single node, stated) |
| Per-tool container isolation | P | P | M | M | M | P | M (stated, see below) |

## What each does well, and what we took

**pentagi** — the persistence model is the best of the six: a four-level worker
tree (`flow → task → subtask → msgchain`) with status enums in the database, every
tool call written *before* it executes, and the whole agent chain stored per
`(flow, task, type)` so a restart resumes without a bespoke event log. We took the
shape: durable tasks with `pending → running → done`, requeued on resume, and
actions recorded before execution.

**strix** — termination is gated on a lifecycle tool, not on the model saying
"done", and evidence ids are verified against the store before being accepted.
We took both: an agent turn cannot end a campaign by prose, and evidence ids are
issued by the runtime that wrote the file, never by a model.

**ARTEX** — the strongest anti-hallucination idea in the set: scanners are parsed
in code so the model never reads raw output, and a finding is verified only when
its quotes appear verbatim in the bound response body. We took the first half
literally: adapters own the parsers (`redfox/adapters/`), and the model sees
normalised observations, never raw tool text.

**shannon** — "no exploit, no report" is enforced by the write path: the exploit
tool physically cannot store an `exploited` verdict without steps and impact
evidence. We took the principle, applied to validation: a finding only reaches
`validated` through a policy-gated action whose response is stored as evidence.

**Pentest-Swarm-AI** — a planner-less blackboard with pheromone weighting is an
elegant coordination primitive, and budget exhaustion producing a partial report
rather than a cancellation is the right product decision. We kept the report-not-cancel
behaviour; we did not adopt the blackboard, because a single planner plus durable
tasks is far easier to debug and this project optimises for auditability.

**hexstrike** — proves the MCP tool-broker shape is cheap (≈15 lines per tool) and
that an `additional_args` escape hatch is ergonomically necessary. It also
demonstrates the failure mode: `shell=True` string execution, no quoting, no auth,
no parsers, no findings model. We took the "cheap to add a tool" property without
the shell: adapters return argv arrays and the runtime is the only process spawner.

## What they get wrong, and what we fixed

1. **None of the six has an authorization model.** This is the finding that
   matters most, and it is unanimous. pentagi keeps authorization in prompt prose
   and tells the model not to seek confirmation; strix's scope template states
   the target list is "not a ceiling"; ARTEX's gate is opt-in and its built-in
   rules can be deleted by an operator; hexstrike has no auth at all on a
   `shell=True` broker; swarm's REST and MCP entry points skip the terms gate;
   shannon has no attestation, no allow-list, no "authorized" flag.
   **RedFox fix:** scope is an engagement record (operator, authorization
   reference, attestation time, allow/deny rules, port spec) that must exist
   before a campaign can start, and it is checked inside the runtime for every
   single action. Deny-by-default, and a network range is not an executable
   target — it has to be expanded to hosts first.
2. **Scope enforcement stops at the prompt.** Every project except ours relies on
   the model reading a scope string and behaving. **RedFox fix:** adapters cannot
   spawn anything; they return `ToolCall(argv, risk)`. `redfox/runtime.py` is the
   only module allowed to import `subprocess`, and it calls the policy gate
   immediately before the spawn. `tests/test_structural_guarantees.py` parses the
   AST of every other module and fails the build if that stops being true.
3. **Raw scanner text goes to the model.** pentagi and strix both hand tool output
   to the LLM; hexstrike has zero parsers. Result quality then depends on the
   model's summarisation, and nothing deduplicates across runs. **RedFox fix:**
   one parser per adapter, producing typed observations; the LLM sees
   `{"host": ..., "port": ...}` and finding candidates, never nmap XML.
4. **Safety controls are optional rows.** ARTEX ships its judge off and its rules
   as deletable data. **RedFox fix:** the autonomy ceiling, risk classes and kill
   switch are code constants and a checked file — there is no configuration key
   that turns the gate off.
5. **Findings without evidence.** Several repos record a label and a severity.
   **RedFox fix:** every finding row carries evidence ids, and each evidence id
   maps to a file written by the runtime with the argv, the exit code and a
   SHA-256 of the output. `redfox report` renders those ids; it cannot invent them.
6. **No machine-readable output.** None of the six emits SARIF, so none drops into
   GitHub code scanning. **RedFox fix:** SARIF 2.1.0 is a first-class output,
   alongside Markdown and HTML.

## What RedFox adds that none of them have

- A **signed-shape authorization record** that gates the whole lifecycle, with the
  same object re-checked at execution time rather than at plan time.
- **Structural** rather than conventional enforcement: adapters are inert by
  construction; the process spawner is one module; a test enforces it.
- **Autonomy levels mapped to risk classes** (passive / active / validation /
  intrusive) so "how autonomous" is a per-engagement ceiling rather than a prompt.
- **Hash-chained audit log** that is verifiable by a third party (`redfox verify-audit`).
- **Evidence ids issued by the runtime**, referenced by findings and rendered into
  every report format.
- **SARIF plus human reports** from one findings table.

## Deliberate deviations from the brief's default stack

The brief allows overriding its table with justification. Four were overridden:

| Default | Chosen | Why |
|---|---|---|
| PostgreSQL + pgvector | SQLite (WAL) + FTS-capable tables | One process, one file, zero services; crash-safe with short transactions; matches the single-node scope actually shipped. pgvector was unnecessary once memory is a small keyed table. |
| Redis + Celery/arq | Durable task table + in-process worker | The durability requirement is "resume after a crash", which a `pending/running/done` table with requeue-on-start satisfies without a second service. The queue is the bottleneck to revisit for multi-node. |
| Postgres-backed memory | Keyed `memory` table with recall | Semantic recall via embeddings was not needed for campaign improvement; recording tool outcomes by key was enough and is inspectable. |
| Next.js UI | Static SPA served by FastAPI | No build step, no `node_modules`, same live view over WebSocket. One dependency fewer in the supply chain of a security tool. |
| Per-tool Docker containers | Native subprocess execution behind the policy gate | Docker was not running on the build host, and container-per-tool is an isolation feature, not the safety boundary. The safety boundary is the policy gate, which exists either way. **This is the biggest omission:** a hostile tool process shares the host user. `docs/ARCHITECTURE.md` states it plainly and names Docker as the next step. |

## What was not studied

- No dynamic analysis of any reference: nothing was executed, so runtime claims in
  their READMEs are not verified here.
- Contributor history is not recoverable: five of six clones are squashed
  snapshots with one visible commit.
- REA's binary providers were not exercised (no shipped binaries were in scope).
- The reference analyses did not audit for vulnerabilities beyond what bears on
  architecture; the injection and auth findings quoted above are the ones visible
  in the code paths being studied.