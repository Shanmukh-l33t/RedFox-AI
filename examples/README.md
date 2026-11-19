# Recorded run

This directory holds the artefacts of one real campaign against the lab target in
`lab/vulnapp.py`, run on a loopback interface with the scope in
`examples/scope-lab.json`.

| File | What it is |
|---|---|
| `scope-lab.json` | the engagement: scope, authorization attestation, autonomy L2 |
| `report.sarif` | SARIF 2.1.0, importable by GitHub code scanning |
| `report.md` | the human report |
| `report.html` | the same report, print-ready |
| `audit.jsonl` | the hash-chained audit log for the run |
| `findings.json` | the findings table as stored, including evidence ids |
| `actions.json` | every proposed action with its policy decision |
| `evidence/` | the raw tool output each finding points at |

## What to check

1. Every finding in `findings.json` has a non-empty `evidence_ids`.
2. Each of those ids appears in `evidence/` as a file whose SHA-256 matches the
   `sha256` recorded in the database — `python scripts/verify_evidence.py <id>`
   does this automatically.
3. `audit.jsonl` verifies: `redfox verify-audit` recomputes the chain.
4. The report's findings match the evidence: open the evidence file for a finding
   and confirm the tool output actually shows what the finding claims.

## Reproducing it

```bash
python lab/vulnapp.py --port 8080 --admin-port 8081 &
redfox init examples/scope-lab.json
redfox run <engagement-id> --max-steps 14
redfox report <engagement-id>
```

The model used for the recorded run is named in the report header. Findings are
whatever the tools actually returned on that run; a different template set or a
different lab state will produce a different set.