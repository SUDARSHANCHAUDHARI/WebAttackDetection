# Web Attack Detection Report

## Summary

- Requests analyzed: 5
- Findings: 5
- Risk score: 100/100

## Attack Types

- `web.sqli`: 2
- `web.xss`: 1
- `web.scanner`: 2

## Top IPs

- `198.51.100.25`: 2 finding(s)
- `198.51.100.22`: 1 finding(s)
- `198.51.100.23`: 1 finding(s)
- `198.51.100.24`: 1 finding(s)

## Findings

### Request path contains SQL injection indicators.

- Severity: `high`
- Type: `web.sqli`
- Evidence: `{'ip': '198.51.100.22', 'path': '/search?q=union%20select%20user,email%20from%20users', 'matched': 'select', 'status': 403}`

### Request path contains SQL injection indicators.

- Severity: `high`
- Type: `web.sqli`
- Evidence: `{'ip': '198.51.100.25', 'path': '/product?id=1%20or%201=1', 'matched': 'or 1=1', 'status': 403}`

### Request path contains cross-site scripting indicators.

- Severity: `high`
- Type: `web.xss`
- Evidence: `{'ip': '198.51.100.23', 'path': '/login?next=%3Cscript%3Ealert(1)%3C/script%3E', 'matched': '<script', 'status': 403}`

### Request user agent matches a known scanner signature.

- Severity: `medium`
- Type: `web.scanner`
- Evidence: `{'ip': '198.51.100.24', 'user_agent': 'sqlmap/1.7', 'matched': 'sqlmap'}`

### Request user agent matches a known scanner signature.

- Severity: `medium`
- Type: `web.scanner`
- Evidence: `{'ip': '198.51.100.25', 'user_agent': 'Nikto', 'matched': 'nikto'}`

