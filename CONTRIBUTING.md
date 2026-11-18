Contribution guidelines
=======================

RedFox AI is a security tool for authorized testing. Contributions are welcome on
those terms.

## Before you start

- Read `README.md` and `docs/ARCHITECTURE.md`. The policy gate and the
  process-spawner boundary are load-bearing; changes that weaken them will be
  rejected regardless of what they enable.
- For anything larger than a bug fix, open an issue first so the approach can be
  agreed before you write code.

## Non-negotiable

1. **Nothing executes outside `redfox/runtime.py`.** No `subprocess`, no shell, no
   raw socket work in adapters, agents, the API or the CLI. The structural test
   enforces this and will fail your PR.
2. **No feature that bypasses the policy gate.** Not behind a flag, not "for
   tests", not "temporarily". The gate has no off switch.
3. **No fabricated results.** If a tool is unavailable or a check is inconclusive,
   say so in code and in output. A mocked scanner result presented as real is a
   security defect, not a shortcut.
4. **No new capability that makes the tool easier to misuse**: mass exploitation,
   propagation, credential stuffing against third parties, or exfiltration modules.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q                  # must be green
ruff check .                         # if you have ruff
```

Add tests with the change:

- new adapter → a parser test against real captured output in `tests/fixtures/`
- new policy behaviour → a test in `tests/test_safety_core.py` proving both the
  allow and the deny case
- new agent behaviour → a test in `tests/test_planning.py` proving malformed or
  out-of-scope model output is dropped

## Style

- Python 3.11+, typed signatures, `from __future__ import annotations`.
- Standard library first; justify any new dependency in the PR.
- Comments explain *why*, not *what*. A one-line comment on a non-obvious
  constraint is worth more than a paragraph of narration.
- No dead code, no "for later" abstractions.

## Commits and PRs

- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- One logical change per commit.
- In the PR: what changed, why, how it was tested, and anything you deliberately
  left out.

## Security issues

Do not open a public issue. See `SECURITY.md`.