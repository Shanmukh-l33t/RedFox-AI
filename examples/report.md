# Penetration test report — RedFox lab target (authorized, self-owned)

> **Authorized testing only. RedFox AI refuses targets that are not present in an operator-attested authorization scope. Unauthorized use is illegal.**

| Field | Value |
|---|---|
| Engagement | `eng_ce49e2303238` |
| Operator | Shanmukh Dheekonda |
| Authorization ref | `LAB-SELF-OWNED-2026-11-19` |
| Attested | 2026-11-19T00:00:00Z |
| Autonomy | L2 |
| Scope | `{"allow": [{"kind": "ip", "value": "127.0.0.1"}, {"kind": "url", "value": "http://127.0.0.1:8080"}, {"kind": "url", "value": "http://127.0.0.1:8081"}], "deny": [], "ports": "8080-8081"}` |
| Generated | 2026-11-19T08:34:05+00:00 |
| Model | deepseek-v4.1-flash-1017 |

## Executive summary

An authorized scan of the self-owned RedFox lab target covered two local HTTP services on 127.0.0.1, ports 8080 and 8081, and produced twelve validated findings across the two hosts. The most serious issue is that both hosts serve their application .env file at /.env, exposing database credentials and tokens; this is reported as high severity through the CodeIgniter, generic, and Laravel detections, which all point at the same exposed file on each port. Four medium-severity findings cover downloadable backup archives at /backup.zip and exposed Git metadata at /.git/config on both ports, either of which can leak source code and configuration. Two low-severity findings are Apache /server-status pages that disclose server activity information on 8080 and 8081. No other vulnerabilities, exploitation results, or tool coverage are included in these findings.

## Findings

Critical 0 · High 6 · Medium 4 · Low 2 · Info 13 — total 25

| # | Severity | Finding | Asset | Status |
|---|---|---|---|---|
| 1 | high | Codeigniter - .env File Discovery | `http://127.0.0.1:8081/.env` | validated |
| 2 | high | Codeigniter - .env File Discovery | `http://127.0.0.1:8080/.env` | validated |
| 3 | high | Generic Env File Disclosure | `http://127.0.0.1:8080/.env` | validated |
| 4 | high | Generic Env File Disclosure | `http://127.0.0.1:8081/.env` | validated |
| 5 | high | Laravel - Sensitive Information Disclosure | `http://127.0.0.1:8080/.env` | validated |
| 6 | high | Laravel - Sensitive Information Disclosure | `http://127.0.0.1:8081/.env` | validated |
| 7 | medium | Compressed Backup File - Detect | `http://127.0.0.1:8081/backup.zip` | validated |
| 8 | medium | Compressed Backup File - Detect | `http://127.0.0.1:8080/backup.zip` | validated |
| 9 | medium | Git Configuration - Detect | `http://127.0.0.1:8080/.git/config` | validated |
| 10 | medium | Git Configuration - Detect | `http://127.0.0.1:8081/.git/config` | validated |
| 11 | low | Apache Server Status Disclosure | `http://127.0.0.1:8080/server-status` | validated |
| 12 | low | Apache Server Status Disclosure | `http://127.0.0.1:8081/server-status` | validated |
| 13 | info | Discovered path http://127.0.0.1:8080/admin/ | `http://127.0.0.1:8080/admin/` | candidate |
| 14 | info | Discovered path http://127.0.0.1:8080/backup.zip | `http://127.0.0.1:8080/backup.zip` | candidate |
| 15 | info | Discovered path http://127.0.0.1:8080/phpinfo.php | `http://127.0.0.1:8080/phpinfo.php` | candidate |
| 16 | info | Discovered path http://127.0.0.1:8080/search | `http://127.0.0.1:8080/search` | candidate |
| 17 | info | Discovered path http://127.0.0.1:8080/server-status | `http://127.0.0.1:8080/server-status` | candidate |
| 18 | info | Discovered path http://127.0.0.1:8081/admin/ | `http://127.0.0.1:8081/admin/` | candidate |
| 19 | info | Discovered path http://127.0.0.1:8081/backup.zip | `http://127.0.0.1:8081/backup.zip` | candidate |
| 20 | info | Discovered path http://127.0.0.1:8081/files/ | `http://127.0.0.1:8081/files/` | candidate |
| 21 | info | Discovered path http://127.0.0.1:8081/internal | `http://127.0.0.1:8081/internal` | candidate |
| 22 | info | Discovered path http://127.0.0.1:8081/login | `http://127.0.0.1:8081/login` | candidate |
| 23 | info | Discovered path http://127.0.0.1:8081/phpinfo.php | `http://127.0.0.1:8081/phpinfo.php` | candidate |
| 24 | info | Discovered path http://127.0.0.1:8081/search | `http://127.0.0.1:8081/search` | candidate |
| 25 | info | Discovered path http://127.0.0.1:8081/server-status | `http://127.0.0.1:8081/server-status` | candidate |

### 1. Codeigniter - .env File Discovery

- **Severity:** high
- **Asset:** `http://127.0.0.1:8081/.env`
- **Location:** `http://127.0.0.1:8081/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

Codeigniter .env file was discovered.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36' 'http://127.0.0.1:8081/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_19d0d19da67f_nuclei.log

**Evidence**

- `ev_731592002254` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_19d0d19da67f_nuclei.log

**Remediation**

Stop serving .env from the web root on port 8081 and return 403 or 404 for dotfiles, then rotate any database credentials or tokens the file contained.

### 2. Codeigniter - .env File Discovery

- **Severity:** high
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

Codeigniter .env file was discovered.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux i686; rv:1.9.7.20) Gecko/ Firefox/3.6.7' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_a15078b16a76_nuclei.log

**Evidence**

- `ev_0275d2172cd5` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_a15078b16a76_nuclei.log

**Remediation**

Block web access to .env on port 8080 via server configuration that denies dotfile requests, and rotate the secrets it exposed.

### 3. Generic Env File Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.13 Safari/605.1.15' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_512560822a36_nuclei.log
3. Re-ran nuclei template(s): generic-env

**Evidence**

- `ev_abf07f11e678` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_512560822a36_nuclei.log

**Remediation**

Treat the .env file on port 8080 as compromised: rotate the database credentials and tokens it contains, keep secrets in environment variables outside the web root, and deny direct requests to the file.

### 4. Generic Env File Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8081/.env`
- **Location:** `http://127.0.0.1:8081/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1' 'http://127.0.0.1:8081/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_7c117f7d32e3_nuclei.log
3. Re-ran nuclei template(s): generic-env

**Evidence**

- `ev_3ae012d13906` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_7c117f7d32e3_nuclei.log

**Remediation**

Treat the .env file on port 8081 as compromised: rotate the database credentials and tokens it contains, move secrets outside the web root, and deny direct requests to the file.

### 5. Laravel - Sensitive Information Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8080/.env`
- **Location:** `http://127.0.0.1:8080/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36' 'http://127.0.0.1:8080/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_e6af54a8ee5b_nuclei.log
3. Re-ran nuclei template(s): laravel-env

**Evidence**

- `ev_861ec23ce25a` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_e6af54a8ee5b_nuclei.log

**Remediation**

Remove the Laravel .env from public reach on port 8080 and rotate the application key, database credentials, and any tokens it held.

### 6. Laravel - Sensitive Information Disclosure

- **Severity:** high (CVSS 8.3)
- **Asset:** `http://127.0.0.1:8081/.env`
- **Location:** `http://127.0.0.1:8081/.env`
- **Status:** validated
- **Detected by:** nuclei_validate

A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36' 'http://127.0.0.1:8081/.env'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ba26266aa4d7_nuclei.log
3. Re-ran nuclei template(s): laravel-env

**Evidence**

- `ev_55bf1daad011` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ba26266aa4d7_nuclei.log

**Remediation**

Remove the Laravel .env from public reach on port 8081 and rotate the application key, database credentials, and any tokens it held.

### 7. Compressed Backup File - Detect

- **Severity:** medium (CVSS 5.3)
- **Asset:** `http://127.0.0.1:8081/backup.zip`
- **Location:** `http://127.0.0.1:8081/backup.zip`
- **Status:** validated
- **Detected by:** nuclei_validate

Multiple compressed backup files were detected.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Kubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36' 'http://127.0.0.1:8081/backup.zip'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_39c90ac50ffc_nuclei.log

**Evidence**

- `ev_f292f8f6a2db` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_39c90ac50ffc_nuclei.log

**Remediation**

Remove backup.zip from the web root on port 8081, store backups outside the served directory, and require authentication for any download path.

### 8. Compressed Backup File - Detect

- **Severity:** medium (CVSS 5.3)
- **Asset:** `http://127.0.0.1:8080/backup.zip`
- **Location:** `http://127.0.0.1:8080/backup.zip`
- **Status:** validated
- **Detected by:** nuclei_validate

Multiple compressed backup files were detected.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.8' 'http://127.0.0.1:8080/backup.zip'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_cb53c8208309_nuclei.log
3. Re-ran nuclei template(s): zip-backup-files

**Evidence**

- `ev_ccc7283d77d9` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_cb53c8208309_nuclei.log

**Remediation**

Remove backup.zip from the web root on port 8080, store backups outside the served directory, and require authentication for any download path.

### 9. Git Configuration - Detect

- **Severity:** medium (CVSS 5.3)
- **Asset:** `http://127.0.0.1:8080/.git/config`
- **Location:** `http://127.0.0.1:8080/.git/config`
- **Status:** validated
- **Detected by:** nuclei_validate

Git configuration was detected via the pattern /.git/config and log file on passed URLs.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Ubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36' 'http://127.0.0.1:8080/.git/config'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_77e5048d06c5_nuclei.log
3. Re-ran nuclei template(s): git-config

**Evidence**

- `ev_272ab8f32172` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_77e5048d06c5_nuclei.log

**Remediation**

Deny access to the .git directory on port 8080 so /.git/config and repository contents are not served, and rebuild the deployment without repository metadata.

### 10. Git Configuration - Detect

- **Severity:** medium (CVSS 5.3)
- **Asset:** `http://127.0.0.1:8081/.git/config`
- **Location:** `http://127.0.0.1:8081/.git/config`
- **Status:** validated
- **Detected by:** nuclei_validate

Git configuration was detected via the pattern /.git/config and log file on passed URLs.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Kubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36' 'http://127.0.0.1:8081/.git/config'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_b8e7ce22cd18_nuclei.log

**Evidence**

- `ev_bdf99a7804ea` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_b8e7ce22cd18_nuclei.log

**Remediation**

Deny access to the .git directory on port 8081 so /.git/config and repository contents are not served, and deploy builds without repository metadata.

### 11. Apache Server Status Disclosure

- **Severity:** low
- **Asset:** `http://127.0.0.1:8080/server-status`
- **Location:** `http://127.0.0.1:8080/server-status`
- **Status:** validated
- **Detected by:** nuclei_validate

Apache /server-status displays information about your Apache status. If you are not using this feature, disable it.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0' 'http://127.0.0.1:8080/server-status'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_b7792a8a8968_nuclei.log

**Evidence**

- `ev_c75d3a478aac` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_b7792a8a8968_nuclei.log

**Remediation**

Disable mod_status or restrict /server-status on port 8080 to localhost or trusted administrative addresses.

### 12. Apache Server Status Disclosure

- **Severity:** low
- **Asset:** `http://127.0.0.1:8081/server-status`
- **Location:** `http://127.0.0.1:8081/server-status`
- **Status:** validated
- **Detected by:** nuclei_validate

Apache /server-status displays information about your Apache status. If you are not using this feature, disable it.

**Reproduction**

1. Replay: curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; PPC Mac OS X 10_8_9 rv:6.0; ms-MY) AppleWebKit/532.11.2 (KHTML, like Gecko) Version/5.0 Safari/532.11.2' 'http://127.0.0.1:8081/server-status'
2. Evidence file: C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_375aa3ca9878_nuclei.log
3. Re-ran nuclei template(s): apache-server-status

**Evidence**

- `ev_5b59096fb2bd` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_375aa3ca9878_nuclei.log

**Remediation**

Disable mod_status or restrict /server-status on port 8081 to localhost or trusted administrative addresses.

### 13. Discovered path http://127.0.0.1:8080/admin/

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/admin/`
- **Location:** `http://127.0.0.1:8080/admin/`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (192 bytes).

**Evidence**

- `ev_1aaee89c9e6f` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_0d43553bb144_ffuf.log

### 14. Discovered path http://127.0.0.1:8080/backup.zip

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/backup.zip`
- **Location:** `http://127.0.0.1:8080/backup.zip`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (16 bytes).

**Evidence**

- `ev_1aaee89c9e6f` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_0d43553bb144_ffuf.log

### 15. Discovered path http://127.0.0.1:8080/phpinfo.php

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/phpinfo.php`
- **Location:** `http://127.0.0.1:8080/phpinfo.php`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (213 bytes).

**Evidence**

- `ev_1aaee89c9e6f` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_0d43553bb144_ffuf.log

### 16. Discovered path http://127.0.0.1:8080/search

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/search`
- **Location:** `http://127.0.0.1:8080/search`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (75 bytes).

**Evidence**

- `ev_1aaee89c9e6f` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_0d43553bb144_ffuf.log

### 17. Discovered path http://127.0.0.1:8080/server-status

- **Severity:** info
- **Asset:** `http://127.0.0.1:8080/server-status`
- **Location:** `http://127.0.0.1:8080/server-status`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (185 bytes).

**Evidence**

- `ev_1aaee89c9e6f` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_0d43553bb144_ffuf.log

### 18. Discovered path http://127.0.0.1:8081/admin/

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/admin/`
- **Location:** `http://127.0.0.1:8081/admin/`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (192 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 19. Discovered path http://127.0.0.1:8081/backup.zip

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/backup.zip`
- **Location:** `http://127.0.0.1:8081/backup.zip`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (16 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 20. Discovered path http://127.0.0.1:8081/files/

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/files/`
- **Location:** `http://127.0.0.1:8081/files/`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (216 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 21. Discovered path http://127.0.0.1:8081/internal

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/internal`
- **Location:** `http://127.0.0.1:8081/internal`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (106 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 22. Discovered path http://127.0.0.1:8081/login

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/login`
- **Location:** `http://127.0.0.1:8081/login`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (210 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 23. Discovered path http://127.0.0.1:8081/phpinfo.php

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/phpinfo.php`
- **Location:** `http://127.0.0.1:8081/phpinfo.php`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (213 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 24. Discovered path http://127.0.0.1:8081/search

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/search`
- **Location:** `http://127.0.0.1:8081/search`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (75 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

### 25. Discovered path http://127.0.0.1:8081/server-status

- **Severity:** info
- **Asset:** `http://127.0.0.1:8081/server-status`
- **Location:** `http://127.0.0.1:8081/server-status`
- **Status:** candidate
- **Detected by:** ffuf

Content discovery returned HTTP 200 (185 bytes).

**Evidence**

- `ev_92543fdde0f3` — C:\Users\ImMandatory\AppData\Local\hermes\cache\scratch\rf-ds3\evidence\eng_ce49e2303238\act_ad3147928101_ffuf.log

## Tooling and actions

- Actions executed: 22
- Actions refused by policy: 0
- Tools used: ffuf, httpx, nmap, nuclei
- Audit chain: 48 records verified
- Tool time: 0.0 s across 22 actions
- Campaign wall clock: 1258 s
- Model calls: 17 (26356 in / 14275 out tokens, deepseek-v4.1-flash-1017)
- Evidence files: 22

## Limitations

- Only findings with recorded evidence are listed.
- Inconclusive checks are labelled as such and are not counted as findings.
- Validation proves the minimum needed; absence of a finding is not proof of safety.
