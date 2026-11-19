# Penetration test report — RedFox lab target (authorized, self-owned)

> **Authorized testing only. RedFox AI refuses targets that are not present in an operator-attested authorization scope. Unauthorized use is illegal.**

| Field | Value |
|---|---|
| Engagement | `eng_4d7ace09c873` |
| Operator | Shanmukh Dheekonda |
| Authorization ref | `LAB-SELF-OWNED-2026-11-19` |
| Attested | 2026-11-19T00:00:00Z |
| Autonomy | L2 |
| Scope | `{"allow": [{"kind": "ip", "value": "127.0.0.1"}, {"kind": "url", "value": "http://127.0.0.1:8080"}, {"kind": "url", "value": "http://127.0.0.1:8081"}], "deny": [], "ports": "8080-8081"}` |
| Generated | 2026-11-19T00:29:59+00:00 |
| Model | qwen2.5:3b-instruct |

## Executive summary

6 finding(s) were validated with recorded evidence (1 critical, 5 high). The highest-impact issues: Codeigniter - .env File Discovery, Generic Env File Disclosure, Laravel - Sensitive Information Disclosure, Valid credentials for http://127.0.0.1:8080/login. Each finding below links to the tool output that proves it.

## Findings

Critical 1 · High 5 · Medium 0 · Low 0 · Info 7 — total 13

| # | Severity | Finding | Asset | Status |
|---|---|---|---|---|
| 1 | critical | Valid credentials for http://127.0.0.1:8080/login | `http://127.0.0.1:8080/login` | validated |
| 2 | high | Codeigniter - .env File Discovery | `http://127.0.0.1:8081/.env` | validated |
| 3 | high | Codeigniter - .env File Discovery | `http://127.0.0.1:8080/.env` | validated |
| 4 | high | Generic Env File Disclosure | `http://127.0.0.1:8080/.env` | validated |
| 5 | high | Generic Env File Disclosure | `http://127.0.0.1:8081/.env` | validated |
| 6 | high | Laravel - Sensitive Information Disclosure | `http://127.0.0.1:8080/.env` | validated |
| 7 | info | Discovered path http://127.0.0.1:8080/admin/ | `http://127.0.0.1:8080/admin/` | candidate |
| 8 | info | Discovered path http://127.0.0.1:8080/backup.zip | `http://127.0.0.1:8080/backup.zip` | candidate |
| 9 | info | Discovered path http://127.0.0.1:8080/files/ | `http://127.0.0.1:8080/files/` | candidate |
| 10 | info | Discovered path http://127.0.0.1:8080/login | `http://127.0.0.1:8080/login` | candidate |
| 11 | info | Discovered path http://127.0.0.1:8080/phpinfo.php | `http://127.0.0.1:8080/phpinfo.php` | candidate |
| 12 | info | Discovered path http://127.0.0.1:8080/search | `http://127.0.0.1:8080/search` | candidate |
| 13 | info | Discovered path http://127.0.0.1:8080/server-status | `http://127.0.0.1:8080/server-status` | candidate |

### 1. Valid credentials for http://127.0.0.1:8080/login

- **Severity:** critical
- **Asset:** `http://127.0.0.1:8080/login`
- **Location:** `http://127.0.0.1:8080/login`
- **Status:** validated
- **Detected by:** authcheck

Operator-supplied credentials for 'admin' were accepted by http://127.0.0.1:8080/login (HTTP 200).

**Reproduction**

1. POST http://127.0.0.1:8080/login with the reported credentials
2. Observed HTTP 200 with authenticated content

**Evidence**

- `ev_9bef6a02a259` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_5b7f7175c813_authcheck.http

### 2. Codeigniter - .env File Discovery

- **Severity:** high
- **Asset:** `http://127.0.0.1:8081/.env`
- **Location:** `http://127.0.0.1:8081/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

Codeigniter .env file was discovered.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' 'http://127.0.0.1:8081/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_3b3895807550_nuclei.log
3. Re-ran nuclei template(s): codeigniter-env

**Evidence**

- `ev_ee497b292b84` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_3b3895807550_nuclei.log

### 3. Codeigniter - .env File Discovery

- **Severity:** high
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

Codeigniter .env file was discovered.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_f4cfadabb145_nuclei.log
3. Re-ran nuclei template(s): codeigniter-env

**Evidence**

- `ev_1b8e1bdfb610` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_f4cfadabb145_nuclei.log

### 4. Generic Env File Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.5 Safari/605.1.15' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_652b354c66da_nuclei.log
3. Re-ran nuclei template(s): generic-env

**Evidence**

- `ev_8eba3385ca55` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_652b354c66da_nuclei.log

### 5. Generic Env File Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8081/.env`
- **Location:** `http://127.0.0.1:8081/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.3 Safari/605.1.15' 'http://127.0.0.1:8081/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_adc50199b80e_nuclei.log
3. Re-ran nuclei template(s): generic-env

**Evidence**

- `ev_55e2f7cc3432` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_adc50199b80e_nuclei.log

### 6. Laravel - Sensitive Information Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3) AppleWebKit/619.29 (KHTML, like Gecko) Version/17.0.14 Safari/619.29' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_8761665890c2_nuclei.log
3. Re-ran nuclei template(s): laravel-env

**Evidence**

- `ev_485ce17b90ca` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_8761665890c2_nuclei.log

### 7. Discovered path http://127.0.0.1:8080/admin/

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/admin/`
- **Location:** `http://127.0.0.1:8080/admin/`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (192 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 8. Discovered path http://127.0.0.1:8080/backup.zip

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/backup.zip`
- **Location:** `http://127.0.0.1:8080/backup.zip`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (16 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 9. Discovered path http://127.0.0.1:8080/files/

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/files/`
- **Location:** `http://127.0.0.1:8080/files/`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (216 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 10. Discovered path http://127.0.0.1:8080/login

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/login`
- **Location:** `http://127.0.0.1:8080/login`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (210 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 11. Discovered path http://127.0.0.1:8080/phpinfo.php

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/phpinfo.php`
- **Location:** `http://127.0.0.1:8080/phpinfo.php`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (213 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 12. Discovered path http://127.0.0.1:8080/search

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/search`
- **Location:** `http://127.0.0.1:8080/search`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (75 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

### 13. Discovered path http://127.0.0.1:8080/server-status

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/server-status`
- **Location:** `http://127.0.0.1:8080/server-status`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (185 bytes).

**Evidence**

- `ev_8c4ccca78133` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-final\evidence\eng_4d7ace09c873\act_b34c694f9e9a_ffuf.log

## Tooling and actions

- Actions executed: 12
- Actions refused by policy: 0
- Tools used: authcheck, ffuf, httpx, nuclei
- Audit chain: 26 records verified

## Limitations

- Only findings with recorded evidence are listed.
- Inconclusive checks are labelled as such and are not counted as findings.
- Validation proves the minimum needed; absence of a finding is not proof of safety.
