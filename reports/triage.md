# Web Attack Detection Triage

- Requests analyzed: 8
- Findings: 10
- Risk score: 100/100

## IP Risk

- `198.51.100.25`: 6 finding(s), 4 request(s), types=web.burst, web.scanner, web.sensitive_path, web.sqli
- `198.51.100.22`: 1 finding(s), 1 request(s), types=web.sqli
- `198.51.100.23`: 1 finding(s), 1 request(s), types=web.xss
- `198.51.100.24`: 2 finding(s), 1 request(s), types=web.scanner, web.sensitive_path
- `203.0.113.10`: 0 finding(s), 1 request(s), types=none

## Analyst Queue

- `high` web.sqli: Request path contains SQL injection indicators.
- `high` web.sqli: Request path contains SQL injection indicators.
- `high` web.xss: Request path contains cross-site scripting indicators.
- `medium` web.scanner: Request user agent matches a known scanner signature.
- `medium` web.scanner: Request user agent matches a known scanner signature.
- `medium` web.sensitive_path: Request targeted a sensitive or administrative path.
- `medium` web.sensitive_path: Request targeted a sensitive or administrative path.
- `medium` web.sensitive_path: Request targeted a sensitive or administrative path.
