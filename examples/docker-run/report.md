# Penetration test report — RedFox containerised lab — tools in containers, target on the same network

> **Authorized testing only. RedFox AI refuses targets that are not present in an operator-attested authorization scope. Unauthorized use is illegal.**

| Field | Value |
|---|---|
| Engagement | `eng_2eaf84674c3f` |
| Operator | Shanmukh Dheekonda |
| Authorization ref | `LAB-CONTAINER-2026-11-19` |
| Attested | 2026-11-19T00:00:00Z |
| Autonomy | L2 |
| Scope | `{"allow": [{"kind": "domain", "value": "lab.internal"}, {"kind": "url", "value": "http://lab.internal:8080"}], "deny": [], "ports": "8080"}` |
| Generated | 2026-11-19T20:47:03+00:00 |
| Model | deepseek-v4.1-flash-1017 |

## Executive summary

The engagement covered a single target, http://lab.internal:8080, an HTTP portal hosted at 172.18.0.2, and was limited to that host and port. Four findings were recorded. The most serious is that the application's .env configuration file is publicly readable at /.env; this was confirmed by validation and is rated high, because such files commonly hold credentials, API keys and database connection strings. A .git/config file is also readable (medium), which exposes repository configuration and can help an attacker map the source tree. Two lower-impact items were also confirmed: Apache /server-status is publicly reachable (low), and a separate validation check identified the exposed .env as a CodeIgniter environment file (high). No exploitation or lateral movement was demonstrated; the exposure of these files should be treated as a possible secret compromise until the contents are reviewed.

## Findings

Critical 0 · High 2 · Medium 1 · Low 1 · Info 0 — total 4

| # | Severity | Finding | Asset | Status |
|---|---|---|---|---|
| 1 | high | Codeigniter - .env File Discovery | `http://lab.internal:8080/.env` | validated |
| 2 | high | Exposed .env file | `http://lab.internal:8080/.env` | candidate |
| 3 | medium | Git Configuration - Detect | `http://lab.internal:8080/.git/config` | validated |
| 4 | low | Apache Server Status Disclosure | `http://lab.internal:8080/server-status` | validated |

### 1. Codeigniter - .env File Discovery

- **Severity:** high
- **Asset:** `http://lab.internal:8080/.env`
- **Location:** `http://lab.internal:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

Codeigniter .env file was discovered.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' 'http://lab.internal:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_28eaa561dc55_nuclei.log

**Evidence**

- `ev_57618950c8be` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_28eaa561dc55_nuclei.log

**Remediation**

Remove the .env file from the web-accessible document root and block requests to dotfiles and environment files at the web server or proxy layer. Review the file's contents and rotate any credentials, keys or connection strings it contained.

### 2. Exposed .env file

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://lab.internal:8080/.env`
- **Location:** `http://lab.internal:8080/.env`
- **Status:** candidate
- **Detected by:** nuclei

Nuclei matched the generic-env template against http://lab.internal:8080/.env, indicating that an environment configuration file may be publicly accessible. Such files commonly contain credentials, API keys, database connection strings, or other sensitive configuration.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.4.21' 'http://lab.internal:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_420ef6b517b4_nuclei.log

**Evidence**

- `ev_fefeb3046579` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_420ef6b517b4_nuclei.log

**Remediation**

Remove the .env file from the web-accessible document root, block access to dotfiles and environment files at the web server/proxy layer, and rotate any secrets that may have been exposed.

### 3. Git Configuration - Detect

- **Severity:** medium (CVSS 5.3)
- **Asset:** `http://lab.internal:8080/.git/config`
- **Location:** `http://lab.internal:8080/.git/config`
- **Status:** validated
- **Detected by:** nuclei_validate

Git configuration was detected via the pattern /.git/config and log file on passed URLs.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36' 'http://lab.internal:8080/.git/config'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_f37525b712cc_nuclei.log

**Evidence**

- `ev_481b7e79a1ac` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_f37525b712cc_nuclei.log

**Remediation**

Remove the .git directory from the deployed web root and deny access to /.git/* at the web server or proxy. If source history was reachable, check it for committed secrets and rotate them.

### 4. Apache Server Status Disclosure

- **Severity:** low
- **Asset:** `http://lab.internal:8080/server-status`
- **Location:** `http://lab.internal:8080/server-status`
- **Status:** validated
- **Detected by:** nuclei_validate

Apache /server-status displays information about your Apache status. If you are not using this feature, disable it.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36' 'http://lab.internal:8080/server-status'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_bbf7e9fedce6_nuclei.log

**Evidence**

- `ev_2790e4cd3d4b` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-docker\evidence\eng_2eaf84674c3f\act_bbf7e9fedce6_nuclei.log

**Remediation**

Disable the Apache /server-status handler if it is not needed, or restrict it to localhost or an administrative network. If it is required, require authentication and limit the information it reports.

## Tooling and actions

- Actions executed: 9
- Actions refused by policy: 0
- Tools used: ffuf, httpx, nmap, nuclei, subfinder
- Audit chain: 21 records verified
- Tool time: 0.0 s across 9 actions
- Campaign wall clock: 388 s
- Model calls: 8 (7370 in / 3296 out tokens, deepseek-v4.1-flash-1017)
- Evidence files: 9

## Limitations

- Only findings with recorded evidence are listed.
- Inconclusive checks are labelled as such and are not counted as findings.
- Validation proves the minimum needed; absence of a finding is not proof of safety.
