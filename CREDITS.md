# Credits and attribution

RedFox AI was built after studying six open-source projects. **No code was copied
from any of them**; what follows is an honest record of what was learned and what
was deliberately not copied. Three of the six are AGPL-3.0, which is one more
reason this project is a clean-room implementation of ideas rather than a
derivative: nothing here is derived from their source.

## Reference projects

### [PentAGI](https://github.com/vxcontrol/pentagi) — MIT (+ a separate EULA addendum)

Adopted: the durable worker-tree persistence shape (flow → task → subtask), writing
every tool call *before* executing it, and per-agent chain persistence so a restart
resumes without a bespoke event log.
Rejected: authorization living only in prompt prose.

### [Strix](https://github.com/usestrix/strix) — Apache-2.0

Adopted: termination gated on a lifecycle action rather than the model saying
"done", and evidence ids that are verified against the store instead of trusted
from a model.
Rejected: scope as a suggestion in a prompt template.

### [ARTEX](https://github.com/BaaRai/ARTEX) — AGPL-3.0 (fork of [Autumn-27/ARTEX](https://github.com/Autumn-27))

Adopted: deterministic ingestion — parsers in code, so the model never reads raw
scanner output — and code-owned decisions over model-owned verdicts.
Rejected: an opt-in, operator-deletable safety floor.
The mission brief describes ARTEX as a legitimate framework that was mass-forked
into an attack tool and taken down. **The checkout does not corroborate that
history**: it is a squashed single-commit fork of `Autumn-27/ARTEX` with no record
of the event (`docs/references/artex.md` marks the premise UNKNOWN). What the code
does show is why such an outcome is possible — no authorization object, a scope
gate that ships off, and a safety floor that an operator can delete. That is why
this project's scope gate is not configurable.

### [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) — MIT

Adopted: the tool-broker shape — adding a tool should be a small, local change —
and the ergonomic need for an argument escape hatch.
Rejected: `shell=True` string execution, absent parsers, and a network-exposed
command broker with no authorization model.

### [Pentest Swarm AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) — AGPL-3.0

Adopted: budget exhaustion produces a partial report rather than a cancellation.
Rejected: the planner-less blackboard as the primary coordinator — elegant, but
harder to audit than a single planner with durable tasks.

### [Shannon](https://github.com/KeygraphHQ/shannon) — AGPL-3.0

Adopted: "no exploit, no report" enforced at the write path, not in prose, and
retryable schema rejections instead of hard agent failures.
Rejected: absent authorization and prompt-only scope rules.

## Tooling and standards

- [ProjectDiscovery](https://github.com/projectdiscovery) — nuclei, httpx, subfinder,
  and their nuclei-templates corpus.
- [ffuf](https://github.com/ffuf/ffuf) — content discovery.
- [Nmap](https://nmap.org) — service and version detection (Nmap Public Source
  License; invoked as an external binary, not linked).
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — OASIS.
- [Ollama](https://ollama.com) — local model runtime used for the offline run.

## Method

The reverse-engineering method used for the reference analysis follows the
[REA skill](https://github.com/morluto/rea) (reverse-engineer-anything), including
its evidence discipline: observations cite a file path, inferences are labelled,
and unknowns are stated rather than filled in. REA's providers were not used —
its own guidance is that a complete source repository is analysed with ordinary
repository tools.

## Built with

Hermes Agent (Nous Research) as the orchestrating agent environment; the platform
itself is plain Python and runs without it.