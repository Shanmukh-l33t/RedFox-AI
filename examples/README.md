# Recorded runs

Two real campaigns, both against the lab target in `lab/vulnapp.py`, run over
loopback with the scopes in this directory. Nothing here is mocked: every finding
points at tool output produced by the run.

## `examples/` — L2 assessment (`scope-lab.json`)

Model: `deepseek-v4.1-flash-1017` via an OpenAI-compatible gateway.

| File | What it is |
|---|---|
| `report.sarif` | SARIF 2.1.0, importable by GitHub code scanning |
| `report.md` / `report.html` / `report.pdf` | the human report, three renderings of one findings table |
| `findings.json` | the findings table as stored, including evidence ids |
| `actions.json` | every proposed action with its policy decision |
| `audit.jsonl` | the hash-chained audit log for the run |
| `evidence/` | the raw tool output each finding points at |

Outcome: **25 findings — 12 validated, 13 candidates — from 22 policy-allowed
actions and 0 denials.** The validated set is six `.env` exposures (three nuclei
templates across two ports), two backup archives, two exposed `.git/config` files
and two server-status pages. The candidates are content-discovery hits: a
reachable path is not a vulnerability, so they stay `info`/`candidate`.

## `examples/impact-run/` — the gated intrusive step (`scope-lab-l3.json`)

Same lab, autonomy L3. `redfox impact` was refused, filed an approval, waited for
a human, and only then authenticated and read `/admin/`.

| File | What it is |
|---|---|
| `approvals.json` | the approval record, final status `consumed` with the operator's note |
| `findings.json` | the one validated finding the impact check produced |
| `report.*`, `audit.jsonl`, `evidence/` | the same artefacts as above |

Outcome: **1 finding — "Authenticated access to http://127.0.0.1:8080/admin/" —
validated**, from 2 allowed actions plus 1 refused action that became the
approval. The audit log shows the refusal, the request, the decision and the
consumption.

## What to check

1. Every finding in `findings.json` has a non-empty `evidence_ids`.
2. Each of those ids appears in `evidence/` as a file whose SHA-256 matches the
   `sha256` recorded in the database — `python scripts/verify_evidence.py <id> --home <dir>`
   does this automatically.
3. `audit.jsonl` verifies: `redfox verify-audit` recomputes the chain.
4. The report's findings match the evidence: open the evidence file for a finding
   and confirm the tool output actually shows what the finding claims.

## Reproducing

```bash
python lab/vulnapp.py --port 8080 --admin-port 8081 &
redfox init examples/scope-lab.json
redfox run <engagement-id> --max-steps 24
redfox report <engagement-id>          # report.sarif / .md / .html / .pdf

redfox init examples/scope-lab-l3.json
redfox impact <l3-id>                  # → awaiting_approval
redfox approve <approval-id> --note "approved"
redfox impact <l3-id>                  # → validated impact finding
```

The model used for each run is named in the report header. Findings are whatever
the tools actually returned on that run; a different template set or a different
lab state produces a different set.