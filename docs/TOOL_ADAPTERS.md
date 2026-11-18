# Writing a tool adapter

An adapter is a small, inert class. It declares what to run and how to read the
result; the runtime does the running.

## Contract

```python
from redfox.adapters.base import Observation, ToolAdapter
from redfox.models import ExecutionResult, Target, ToolCall

class MyToolAdapter(ToolAdapter):
    name = "mytool"              # task kind the planner may propose
    binary = "mytool"           # must be in runtime.ALLOWED_BINARIES
    risk = "active"             # passive | active | validation | intrusive
    summary = "One line the planner reads."
    phases = ("enumeration",)

    def plan(self, target: Target, ctx: dict) -> list[ToolCall]:
        return [ToolCall(
            tool=self.name, target=target.key,
            argv=("--json", target.host), risk=self.risk, timeout_s=300,
            ports=(443,),                 # declared so policy can check the port spec
            reason="why this is being run",
        )]

    def parse(self, result: ExecutionResult) -> list[Observation]:
        ...
```

Register it in `redfox/adapters/registry.py::build_adapters()` and add the
binary name to `redfox/runtime.py::ALLOWED_BINARIES`.

## Rules

1. **Never execute anything.** No `subprocess`, no `socket`, no `os.system`. The
   structural test enforces this.
2. **Never invent an observation.** If the output is empty, malformed or the tool
   exited non-zero without data, return `[]`. An adapter that fabricates a
   finding is a bug of the worst kind.
3. **Declare the risk class honestly.** `passive` = third-party data only,
   `active` = packets to the target, `validation` = proves an existing candidate,
   `intrusive` = could alter, degrade or lock out the target.
4. **Declare every port** in `ToolCall.ports` so the scope's port spec is checked.
5. **One parser per output format.** Use the tool's structured output (`-oX`,
   `-json`, `-jsonl`, `-of json`) over text scraping whenever it exists.

## File-writing tools

Some tools only write results to a file (ffuf `-o`, whatweb `--log-json`,
sslscan `--xml`). Put the literal `{out}` in argv; the runtime substitutes a path
inside the engagement's evidence directory, reads it back, and appends it to the
captured output under an `[output-file]` marker. The parser then sees one text
blob and can find its JSON.

## Observation types

| Type | Meaning | Engine effect |
|---|---|---|
| `service` | host/port/protocol/product/version | asset upsert |
| `url` | URL, status, title, server, tech | asset upsert, tech memory |
| `host` | a discovered hostname | asset upsert |
| `finding` | a candidate vulnerability with severity/location/template | finding upsert (`candidate`) |
| `path` | a discovered HTTP path | finding upsert (`candidate`, info) |
| `auth` | credential test outcome | finding upsert (`validated` only when accepted) |
| `tls` | protocol/cipher posture | finding upsert when weak protocols are enabled |

## Tests

Add a parser test against **real captured output**, not a hand-written sample:

```bash
./tools/bin/mytool --json ... > tests/fixtures/mytool_lab.json
```

Then in `tests/test_adapters.py`, assert the observation count and one field you
care about. A parser that passes against a fixture captured from the real binary
is worth more than any amount of mocking.