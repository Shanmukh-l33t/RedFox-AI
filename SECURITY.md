# Security policy

## Authorized testing only

RedFox AI is a tool for authorized security testing. Running it against systems
you do not own or have written permission to test is illegal in most
jurisdictions (the US CFAA, the UK Computer Misuse Act, India's IT Act §66, and
equivalents elsewhere). The operator attests to authorization in the engagement
record before any action is taken; that attestation is logged.

The project deliberately does not ship:

- mass exploitation of arbitrary targets,
- credential-stuffing against third parties,
- wormable or self-propagating behaviour,
- data-exfiltration modules.

Its purpose is to demonstrate impact on a target you are authorized to test, and
to report it with evidence.

## The platform's own threat model

RedFox is a local operator tool, not a multi-tenant service.

| Risk | Current control |
|---|---|
| Someone else reaches the API | Binds `127.0.0.1` by default and refuses a non-loopback bind without `--i-know`. There is **no authentication** — do not expose it. |
| A malicious scope file | Scope parsing is strict: no wildcards, no `0.0.0.0/0`, exclusions win, ports must be explicit. |
| An adapter being compromised | Adapters cannot execute; the runtime checks a binary allowlist and runs argv-only (no shell). A compromised adapter could still propose an in-scope action, so review adapters you did not write. |
| Command injection through a target string | No shell is ever used; argv items are passed separately, and NUL bytes are rejected. Hostnames that reach a shell are never re-parsed by one. |
| Secrets in tool output | Captured output is redacted for password/token/authorization/cookie patterns before it is written to evidence. |
| Secrets in prompts | The model receives normalised observations, never raw tool output, so credentials in banners do not reach a provider by default. Configure a local model (`ollama`) for sensitive engagements. |
| Log tampering | Audit records are hash-chained; `redfox verify-audit` detects any edit or deletion and reports the first broken line. |
| A runaway campaign | Autonomy ceiling, per-engagement and per-target rate limits, step budget, hard tool timeouts, and a kill switch that halts planning and refuses further actions. |

## Known limitations

- Tool processes run as your user with no filesystem or network isolation. See
  `docs/ARCHITECTURE.md#isolation`. Run the platform in a container or VM with
  restricted egress for anything beyond a lab.
- The database, evidence and audit log are plaintext files under `~/.redfox`.
  Protect that directory like any other engagement record.
- Credentials supplied for the auth-check adapter are stored in the engagement
  record in plaintext. For real engagements, keep them out of the scope file and
  pass them at run time, or run against a local model so nothing leaves the host.
- DNS is not resolved when a scope is checked, so a name that later resolves to
  an out-of-scope address is not detected at the DNS layer. Match on IP/CIDR when
  that matters.

## Reporting a vulnerability in RedFox itself

Do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting on the repository (Security → Report a vulnerability) or
email the maintainer listed in `pyproject.toml`. Include the version, a
description, and a minimal reproduction. We aim to acknowledge within 5 working
days. Please give us a reasonable window before public disclosure.