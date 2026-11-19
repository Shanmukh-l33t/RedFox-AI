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
| Generated | 2026-11-19T07:20:48+00:00 |
| Model | gpt-5-mini |

## Executive summary

During the engagement, operator-supplied credentials were used to authenticate via POST http://127.0.0.1:8080/login and then successfully access the administrative interface at http://127.0.0.1:8080/admin/. The /admin/ endpoint returned signed-in content without any additional authorization checks. This behavior demonstrates missing or insufficient server-side authorization controls on the administrative endpoint. Reproduction steps provided were POST /login with the reported credentials followed by GET /admin/ with the session cookie.

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

Enforce server-side authorization on /admin/ so that only accounts with an administrative role can access it; validate the authenticated user's role on every request and refuse access for non-admins. After applying the change, retest using the reported reproduction steps (POST /login, then GET /admin/ with the session cookie) to confirm only authorized accounts can view signed-in content.

## Tooling and actions

- Actions executed: 2
- Actions refused by policy: 1
- Tools used: impact_probe
- Audit chain: 8 records verified
- Tool time: 0.0 s across 2 actions
- Campaign wall clock: 3 s
- Model calls: 0 (0 in / 0 out tokens, gpt-5-mini)
- Evidence files: 2

## Limitations

- Only findings with recorded evidence are listed.
- Inconclusive checks are labelled as such and are not counted as findings.
- Validation proves the minimum needed; absence of a finding is not proof of safety.
