# Verification record

What was actually run, and what it returned. Every number below came out of a
command, not an estimate. Re-run any of it from a clean clone.

Date: 2026-11-19 · Tag: `v0.3.0` · Python 3.14.9 (dev), 3.11/3.12 (CI) · Windows 11

## 1. Safety first, and tested

| Check | Result |
|---|---|
| Scope engine refuses an out-of-scope target | `scope-check … https://example.com/` → `{"allowed": false, "reason": "target https://example.com:443 is not in the authorized scope"}` |
| Over-autonomy action refused | `tests/test_safety_core.py` — an `intrusive` call below L3 is denied and audited |
| Approval cannot be replayed | `tests/test_approval.py` — refused → approved → runs once → consumed |
| Audit chain tamper detection | `redfox verify-audit` → `OK: 39 records verified`; a mutated record fails the chain |
| No process creation outside the runtime | `tests/test_structural_guarantees.py` (AST scan of every module) |

## 2. Green CI

Seven jobs, all green on `c6200c7` (and every commit after):

```
test (ubuntu-latest, 3.11 | 3.12)     success
test (windows-latest, 3.11 | 3.12)    success
Safety invariants                     success
Real tool adapters                    success   ← nmap, httpx, ffuf, nuclei, whatweb against the lab
End-to-end against the lab target     success
```

The `Real tool adapters` job is the one that earns its keep: it installs the
binaries and runs the adapters through the policy gate. It found three defects
that unit tests with fixtures could not (see `docs/SECURITY-REVIEW.md` §11 and the
whatweb parse fallback).

Local suite: **118 passed, 1 skipped** (`whatweb` is not installed on the dev
machine; it runs in CI).

## 3. Real end-to-end run, from a clean clone

Cloned `https://github.com/Shanmukh-l33t/RedFox-AI` into an empty directory,
created a venv, `pip install -e ".[dev]"`, ran `scripts/install-tools.ps1`, started
`lab/vulnapp.py`, and ran a campaign with `deepseek-v4.1-flash-1017` at autonomy L2:

```
ENGAGEMENT=eng_965e61561b94
status          completed
steps           20
findings        26  (9 validated, 15 candidates, 0 rejected)
actions         19 allowed, 0 denied
evidence        19
audit           OK, 39 records verified
report          report.md / .html / .pdf / .sarif
```

Evidence check, same clone:

```
audit chain      : OK — 41 records verified
evidence files   : 19/19 intact
findings         : 26 (9 validated)
All findings are backed by intact, recorded evidence.
```

Report artefacts: SARIF carries 24 results and 20 rules; the first result is
`generic-env` — *Generic Env File Disclosure — http://127.0.0.1:8080/.env*,
severity `high`, CVSS 8.3, status `validated`.

## 4. Reproducible by a stranger

The clone above is that test: no local state, no pre-existing venv, tools
installed by the repository's own script. It found the PowerShell installer bug
that broke every Windows quickstart (`fix(scripts)`), which is exactly the class
of defect a "works on my machine" check misses.

## 5. Honest coverage

Every advertised capability is either implemented or listed under *What it does
not do* in the README, with the reason. `redfox tools` prints `NOT INSTALLED` for
a missing binary instead of pretending; findings that were not reproduced stay
`candidate`.

## 6. Artefacts on record

`examples/` holds the committed run: scope file, SARIF, Markdown, HTML and PDF
reports, findings and actions JSON, the audit log, and the evidence directory.
`examples/impact-run/` holds the gated L3 demonstration with its approval record.

## 7. Clean security posture

Reviewed in [`docs/SECURITY-REVIEW.md`](SECURITY-REVIEW.md): eleven findings, five
fixed with tests (credential redaction before a model prompt, argument injection
through a target string, unbounded output capture, `ValueError` escaping the scope
layer, a same-named binary on `PATH`), and the rest accepted with their trust
boundary written down.

## 8. Soak

Five rounds of ten steps against the live lab with the real model:

```
rounds 5 · total 561 s · median 113 s · denied 0 · audit failures 0 · peak 5.0 MiB
```

## What is still not proven

- **No container isolation.** Tools run as subprocesses under the operator's
  account. This is the largest remaining gap and it is documented as such.
- **`whatweb` and `sslscan` do not run on the Windows dev machine** (no Ruby, no
  compiled binary). Both run in CI on Linux.
- **No multi-node execution.** One SQLite state file, one process.
- **The L3 path was demonstrated, not stress-tested**: one approved impact check,
  once. It has not been run repeatedly against a flaky target.