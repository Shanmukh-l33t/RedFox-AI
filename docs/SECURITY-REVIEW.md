# Security review — RedFox AI

A self-review of this codebase for the classes of bug that matter in a tool that
runs other programs against live hosts: injection, unsafe deserialisation, SSRF
in the fetchers, credential leakage, and anything that lets an agent escape the
policy gate.

Reviewed at `v0.2.0` + the fixes below. Every "fixed" item has a regression test
named in the table; the tests are in `tests/test_security_review.py` and
`tests/test_secrets.py`.

Scope of this review: the Python package (`redfox/`), the CLI and API, the report
renderers, and the lab target. Not reviewed: the third-party security tools
themselves, the CI runner, and PyPI dependencies beyond `pip-audit` output.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Credentials were passed to the model in the validator's prompt | Fixed |
| 2 | High | Argument injection: a malformed target reached a tool's argv as an option | Fixed |
| 3 | Medium | Unbounded tool output was read wholly into memory and evidence | Fixed |
| 4 | Medium | Credentials were stored in plaintext in the engagement record | Mitigated |
| 5 | Medium | `parse_target` raised `ValueError` (not `ScopeError`) on `host:port/path` | Fixed |
| 6 | Medium | Security tools can reach hosts outside scope via redirects and embedded URLs | Mitigated (partly) |
| 7 | Low | DNS rebinding can point an authorised hostname at an unauthorised address | Accepted |
| 8 | Low | The API had no authentication, only a loopback bind | Mitigated |
| 9 | Low | Evidence files contain verbatim target responses, including any secrets in them | Accepted |
| 10 | Info | No `subprocess` outside `runtime.py`; binaries are allowlisted | Verified |
| 11 | Low | A same-named program on PATH was run as if it were the scanner | Fixed |

### 1. Credentials in a model prompt (High → fixed)

`engine._validation` passed the whole `auth_check` config — including the
username and password list — to the validator agent, which sends it to whatever
model the operator configured. On a third-party provider that is a credential
disclosure to a processor outside the engagement.

Fixed by `redfox/secrets.redacted()`, which the engine now applies before the
spec reaches an agent: the model sees the login URL and field names, and
`<redacted>` placeholders where the secrets were. It never needs the value to
plan a validation. Test: `test_redacted_strips_every_credential_shape`.

### 2. Argument injection through the target string (High → fixed)

Tools are executed with `create_subprocess_exec` and an argv list — no shell, so
classic shell injection does not apply. But an argv *element* that begins with
`-` is an option to every tool we wrap. `parse_target` accepted any string
without a `/` as a domain, so a scope entry or a planner-proposed target of
`-oN /tmp/owned` would have been handed to nmap as an output-file option rather
than a host.

Fixed by validating hosts before they can become a `Target`: `_valid_host`
rejects leading dashes, whitespace, shell metacharacters, and anything that is
not a hostname by RFC 1123 character rules; `ScopeRule` rejects a leading dash
in a domain rule. Tests: the `test_targets_that_could_be_read_as_options_are_refused`
and `test_urls_with_hostile_hosts_are_refused` parametrisations.

The same review found evidence filenames built from `call.tool`; those are now
slugged (`_slug`) so no name can traverse out of the evidence directory.

### 3. Unbounded output capture (Medium → fixed)

`communicate()` returned the whole of stdout. A tool that floods output — or a
target that makes one — would be fully materialised in memory, then written to an
evidence file, then hashed. On a long campaign that is a denial of service
against the operator.

Fixed: stdout is capped at 8 MB (`MAX_OUTPUT_BYTES`) with a `[truncated: …]`
marker. Redaction is applied to the truncated text, not instead of it. Tests:
`test_output_capture_is_capped`, `test_truncated_output_is_still_redacted`.

### 4. Plaintext credentials in the engagement record (Medium → mitigated)

A scope file with a literal password puts it in the engagement database, in any
backup of it, and in whatever copies it. There is no secrets server in this
product and inventing one would be worse than the problem.

Mitigated: a credential value may be a `${ENV_VAR}` reference. The reference is
what is stored; `redfox/secrets.resolve()` reads the value from the environment
at the moment the request is built. A missing variable is a hard error
(`MissingSecret`) surfaced as a `secrets.missing` event, never a blank password
tried against a live login. Literal values still work for loopback labs, and the
examples use them deliberately.

Tests: `test_reference_reads_environment`,
`test_missing_reference_is_an_error_not_a_blank`,
`test_auth_plan_with_unset_reference_raises`.

### 5. `ValueError` escaping the scope layer (Medium → fixed)

`parse_target("lab.internal:8080/product")` — a host and path written without a
scheme, which is a normal way for a model to name a target — reached
`ipaddress.ip_network` and raised `ValueError`. Callers catch `ScopeError`; an
uncaught `ValueError` in the planning path stops the campaign. Fixed by treating
a non-network string with a `/` as a scheme-less URL, and by converting the
failure into `ScopeError`. Test:
`test_hostname_with_port_and_path_is_not_confused_for_a_domain`.

### 6. Out-of-scope egress from the tools (Medium → accepted)

The policy gate decides whether a **tool invocation** is in scope. It cannot
control what that tool does with the bytes it fetches: `nuclei` templates can
request further URLs found in a response, and vulnerability checks can follow
redirects. A hostile target can therefore cause a scan tool to send requests to a
host the operator did not authorise.

This is inherent to running general-purpose scanners and is not fixable in the
orchestrator; the tool is doing what it is designed to do. The mitigation that
does exist is `REDFOX_ISOLATE=docker` (`redfox/isolation.py`): the tool runs in an
image with no capabilities, no new privileges, and only the evidence directory
mounted, on `REDFOX_DOCKER_NETWORK`. With `bridge` the container cannot reach
anything the network does not route to; with `host` it can, so the network
position is the real scope boundary, not the tool's good behaviour.

What is still not solved: a template that follows an embedded URL leaves through
the container's network. Set `REDFOX_DOCKER_NETWORK` to a segment that cannot
reach anything outside the engagement, or accept the residual risk knowingly.

### 7. DNS rebinding (Low → accepted)

Scope authorises a hostname; resolution happens later, inside the tool. A
record that changes between authorisation and execution points the tool at a
different address. Scope-by-name is what operators actually authorise, and
pinning resolution would break legitimate CDN-fronted targets. Accepted, and
recorded here so the trust boundary is explicit.

### 8. Unauthenticated API (Low → mitigated)

`redfox serve` binds `127.0.0.1` and refuses a non-loopback address without
`--i-know`. There was no authentication: any local process that could reach the
port could start campaigns, read findings, and approve gated actions.

`REDFOX_API_TOKEN` now closes that: when it is set, every `/api` route needs
`Authorization: Bearer <token>` (or `X-RedFox-Token`), compared in constant time,
and the WebSocket requires `?token=`. The UI asks for the token inline and keeps
it in `localStorage`. Unset, the server keeps the old behaviour — loopback and the
shell as the trust boundary — which is stated in `SECURITY.md`. Tests:
`tests/test_api_auth.py`.

### 9. Evidence contains target responses (Low → accepted)

Evidence files hold request and response bodies verbatim, which is the point —
a finding without its response proves nothing. A target that returns secrets
(a misconfigured `.env`, a token in a header) puts them in the evidence
directory. `Authorization`, `Set-Cookie`, `api_key=`-style assignments are
redacted on capture (`runtime.redact`), but arbitrary target data is not. The
engagement directory is operator-controlled data and should be handled with the
same care as the target itself.

### 11. A same-named binary on PATH (Low → fixed, found after the first pass)

`resolve_binary` took the first PATH match for a tool name. `httpx` is also the
name of the Python HTTP library's CLI, so on a machine where that is installed
the adapter ran a different program and parsed nothing — caught when the new
real-tool CI job ran `whatweb`/`httpx` for the first time, and reproduced on a
clean clone.

Fixed: a PATH match must identify itself (`-version` must mention
`projectdiscovery`, or the tool's own name for ffuf/amass) before it is trusted;
binaries installed into `tools/bin` are preferred and are not affected. Test:
`test_a_same_named_binary_on_path_is_not_accepted`.

### 10. Structural invariants (Info → verified)

Checked and covered by `tests/test_structural.py`, which parses the package AST
rather than trusting convention:

- No module outside `redfox/runtime.py` imports `subprocess`, `socket`, or
  `urllib.request` for execution purposes.
- Tool binaries must be in `ALLOWED_BINARIES`.
- Every adapter is inert: `plan()` returns calls, `parse()` returns
  observations, and nothing in `redfox/adapters/` executes.

## What was checked and came back clean

- **SQL**: all values are bound parameters. The one interpolated statement
  (`Store.update_finding`) interpolates column names from a fixed set, never
  from data. Keep it that way: any future dynamic column must be validated
  against an allowlist.
- **HTML report**: every interpolated value is escaped (`report._esc`); CJK and
  control characters are stripped in the PDF renderer.
- **Deserialisation**: `json.loads` only. No `pickle`, no `yaml.load`, no
  `eval`. Tool output is parsed by per-adapter functions that tolerate garbage.
- **Path traversal**: engagement ids and action ids are generated internally;
  tool names are slugged; evidence paths are built under the engagement's own
  directory.
- **Secret leakage in logs**: `runtime.redact` masks `Authorization`, `Cookie`,
  and `password=`-style assignments before anything is written to an evidence
  file or the audit log. The audit log stores the action and its rationale, not
  the request body.

## Not tested

- No dynamic analysis (fuzzing, a real pentest against the platform itself).
- No dependency CVE sweep beyond `pip-audit` in CI.
- The web UI was not tested for XSS with a hostile finding title; the renderer
  escapes, but that is a read of the code, not a test.

## Reproducing

```bash
.venv/Scripts/python.exe -m pytest tests/test_security_review.py tests/test_secrets.py tests/test_structural.py -v
```