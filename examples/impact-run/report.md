# Penetration test report — RedFox lab target — gated impact demonstration

> **Authorized testing only. RedFox AI refuses targets that are not present in an operator-attested authorization scope. Unauthorized use is illegal.**

| Field | Value |
|---|---|
| Engagement | `eng_60e88e4dc7c8` |
| Operator | Shanmukh Dheekonda |
| Authorization ref | `LAB-SELF-OWNED-2026-11-19-L3` |
| Attested | 2026-11-19T00:00:00Z |
| Autonomy | L3 |
| Scope | `{"allow": [{"kind": "ip", "value": "127.0.0.1"}, {"kind": "url", "value": "http://127.0.0.1:8080"}], "deny": [], "ports": "8080"}` |
| Generated | 2026-11-19T08:50:57+00:00 |
| Model | deepseek-v4.1-flash-1017 |

## Executive summary

The engagement validated one high-severity finding on http://127.0.0.1:8080/admin/. Using operator-supplied credentials, a user could authenticate and reach the admin page without further authorization checks, and signed-in content was returned. Access to the administrative area therefore depends on valid credentials but is not restricted by an additional role or permission check. Remediation should focus on server-side authorization for /admin/ and enforcing least privilege for accounts that can sign in.

## Findings

Critical 0 · High 1 · Medium 0 · Low 0 · Info 0 — total 1

| # | Severity | Finding | Asset | Status |
|---|---|---|---|---|
| 1 | high | Authenticated access to http://127.0.0.1:8080/admin/ | `http://127.0.0.1:8080/admin/` | validated |

### 1. Authenticated access to http://127.0.0.1:8080/admin/

- **Severity:** high
- **Asset:** `http://127.0.0.1:8080/admin/`
- **Location:** `http://127.0.0.1:8080/admin/`
- **Status:** validated
- **Detected by:** impact_probe

Operator-supplied credentials authenticate and reach http://127.0.0.1:8080/admin/ without further authorization checks. Signed-in content was returned in the response.

**Reproduction**

1. POST http://127.0.0.1:8080/login with the reported credentials
2. GET http://127.0.0.1:8080/admin/ with the session cookie

**Evidence**

- `ev_3a1718a2ae9b` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-l3\evidence\eng_60e88e4dc7c8\act_2a9cd539946c_impact_probe.http
- `ev_61dfe843c0b7` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-l3\evidence\eng_60e88e4dc7c8\act_2ae5f6e71089_impact_probe.http

**Remediation**

Add server-side role or permission checks on /admin/ for every request rather than relying only on authentication, and restrict admin access to accounts explicitly granted that role. Review existing accounts and sessions to confirm least privilege.

## Tooling and actions

- Actions executed: 2
- Actions refused by policy: 1
- Tools used: impact_probe
- Audit chain: 8 records verified
- Tool time: 0.0 s across 2 actions
- Campaign wall clock: 49 s
- Model calls: 0 (0 in / 0 out tokens, deepseek-v4.1-flash-1017)
- Evidence files: 2

## Limitations

- Only findings with recorded evidence are listed.
- Inconclusive checks are labelled as such and are not counted as findings.
- Validation proves the minimum needed; absence of a finding is not proof of safety.
