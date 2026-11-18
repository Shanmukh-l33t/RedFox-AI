## What changed

## Why

## How it was tested
- [ ] `pytest -q` is green
- [ ] New adapter has a parser test against real captured output
- [ ] New policy path has both an allow and a deny test

## Safety
- [ ] No process creation outside `redfox/runtime.py`
- [ ] No change that lets an action skip the policy gate
- [ ] No new capability that makes the tool easier to misuse

## Deliberately left out