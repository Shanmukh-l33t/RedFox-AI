# Operator runbook

## Before the first run

1. **Confirm authorization in writing.** RedFox stores the reference, not the
   contract. Keep the signed scope document.
2. **Write the scope file.** Copy `examples/scope-template.json`. Include every
   host, URL and CIDR you are authorized to touch, and every exclusion the client
   named. Set `ports` to the smallest range that covers the work.
3. **Pick an autonomy level.**
   - L0/L1 for a first pass on production.
   - L2 when you want validated findings.
   - L3 only in a lab you own or a range you were given, with `lab_isolated: true`.
4. **Check the tool inventory.** `redfox tools` — anything `NOT INSTALLED` will
   cause its task to fail with an explicit error, never a silent skip.

## Starting and monitoring

```bash
redfox init engagement.json
redfox run eng_… --max-steps 20
redfox status eng_…
redfox findings eng_…
```

Watch it live with `redfox serve` and open `http://127.0.0.1:8000`. The event feed
shows every plan, action, denial and validation as it happens.

`--max-steps` bounds the number of planning rounds and task executions. The
default is `REDFOX_MAX_STEPS` (40). A campaign that hits the bound stops cleanly
and can be resumed.

## When the campaign stops early

| Status | Meaning | What to do |
|---|---|---|
| `completed` | report written | open `~/.redfox/reports/<id>/report.html` |
| `halted` | kill switch, or three consecutive policy denials | read the last `action.denied` events; the planner was proposing out-of-scope work — fix the scope file or the prompt state, then re-run |
| `awaiting_approval` | an intrusive action is waiting for a human | `redfox approvals <id>`, then `redfox approve <apr_id>`; `redfox run <id>` continues |
| `paused` | LLM error (no JSON, provider down, rate limit) | fix credentials/model, `redfox run <id>` resumes |
| `running` after a crash | the process died mid-task | just `redfox run <id>`; the stuck task is requeued |

## Approvals

An `intrusive` action files an approval request instead of running. The campaign
stops with status `awaiting_approval` and nothing else is executed until a human
decides.

```bash
redfox impact eng_…            # queue the read-only impact check
# → {"status": "awaiting_approval", actions: 0 allowed, 1 denied}
redfox approvals eng_…         # the pending approval: tool, target, argv, reason
redfox approve apr_… --note "approved by change ticket 4421"
redfox run eng_…               # or `redfox impact eng_…`; the approval is spent here
```

`redfox approve apr_… --deny --note "out of hours"` refuses it; the action stays
blocked and the refusal is written to the audit log. An approval authorizes **one
operation** — it is consumed when that operation ends, pass or fail, and cannot be
replayed. The impact check needs an `impact` block in the engagement config; see
`examples/scope-lab-l3.json`.

## Kill switch

```bash
redfox kill            # writes ~/.redfox/KILL; every subsequent policy check denies
redfox kill --undo     # clears it
```

Behaviour in detail: the campaign loop and every policy check consult the file, so
the next action is refused and the campaign halts. Tools already running when the
file is created finish or time out — they are not terminated by a different
process. The API's `POST /api/kill` also terminates in-flight processes because it
runs inside the campaign process.

## Rate limits and quiet hours

```bash
export REDFOX_RATE_PER_MIN=120        # engagement-wide
export REDFOX_RATE_PER_TARGET=60      # per host/URL
export REDFOX_QUIET_HOURS=22:00-06:00 # no actions inside this window
```

Both are enforced at the policy gate and appear as denial reasons.

## Reports

```bash
redfox report eng_…     # re-render from the database, no new scanning
```

Outputs: `report.sarif` (GitHub code scanning), `report.md`, `report.html`
(print-ready) and `report.pdf`. Every finding in them is joined to evidence ids,
and the report states the audit chain status, wall clock, tool time and model
token spend for the campaign.

## Troubleshooting

**`required tool 'nuclei' is not installed`** — run `scripts/install-tools.sh`
(or `.ps1`), then `redfox tools` to confirm. Nuclei also needs
`nuclei -update-templates` once; without templates it finds nothing.

**`model did not return JSON`** — small local models sometimes fail the schema.
The client retries once. If it keeps failing, use a larger model or a hosted
provider; the campaign pauses rather than proceeding on a guess.

**Everything is denied with "not in the authorized scope"** — the target the
planner chose is not covered. Add it to the scope file (with authorization) or
accept that it is out of scope. Do not widen the scope to make a scan "work".

**Campaign halts after three denials** — that is the out-of-scope spike guard.
Read `redfox status` and the event feed to see what was refused.

**`whatweb` / `sslscan` show NOT INSTALLED** — they need Ruby and a compiled
binary respectively. Their adapters are complete; install the tool and `redfox
tools` will show them as available.