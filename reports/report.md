# Web Attack Detection Report

## Executive Summary

- Requests analyzed: 8
- Findings: 10
- Risk score: 100/100
- Highest severity: `high`

## Attack Types

- `web.sqli`: 2
- `web.xss`: 1
- `web.scanner`: 2
- `web.sensitive_path`: 4
- `web.burst`: 1

## Top IPs

- `198.51.100.25`: 6 finding(s)
- `198.51.100.24`: 2 finding(s)
- `198.51.100.22`: 1 finding(s)
- `198.51.100.23`: 1 finding(s)

## Priority Queue

1. **high** - Request path contains SQL injection indicators. (web.sqli)
2. **high** - Request path contains SQL injection indicators. (web.sqli)
3. **high** - Request path contains cross-site scripting indicators. (web.xss)
4. **medium** - Request user agent matches a known scanner signature. (web.scanner)
5. **medium** - Request user agent matches a known scanner signature. (web.scanner)

## Findings

### Request path contains SQL injection indicators.

- Severity: `high`
- Type: `web.sqli`
- Evidence: `{'ip': '198.51.100.22', 'path': '/search?q=union%20select%20user,email%20from%20users', 'matched': 'select', 'status': 403}`
- Recommended next step: Review the target endpoint, confirm parameterized queries, and preserve request context.

### Request path contains SQL injection indicators.

- Severity: `high`
- Type: `web.sqli`
- Evidence: `{'ip': '198.51.100.25', 'path': '/product?id=1%20or%201=1', 'matched': 'or 1=1', 'status': 403}`
- Recommended next step: Review the target endpoint, confirm parameterized queries, and preserve request context.

### Request path contains cross-site scripting indicators.

- Severity: `high`
- Type: `web.xss`
- Evidence: `{'ip': '198.51.100.23', 'path': '/login?next=%3Cscript%3Ealert(1)%3C/script%3E', 'matched': '<script', 'status': 403}`
- Recommended next step: Confirm output encoding and input validation on the affected endpoint.

### Request user agent matches a known scanner signature.

- Severity: `medium`
- Type: `web.scanner`
- Evidence: `{'ip': '198.51.100.24', 'user_agent': 'sqlmap/1.7', 'matched': 'sqlmap'}`
- Recommended next step: Rate-limit or block scanner traffic after confirming it is not authorized testing.

### Request user agent matches a known scanner signature.

- Severity: `medium`
- Type: `web.scanner`
- Evidence: `{'ip': '198.51.100.25', 'user_agent': 'Nikto', 'matched': 'nikto'}`
- Recommended next step: Rate-limit or block scanner traffic after confirming it is not authorized testing.

### Request targeted a sensitive or administrative path.

- Severity: `medium`
- Type: `web.sensitive_path`
- Evidence: `{'ip': '198.51.100.24', 'path': '/admin', 'matched': '/admin', 'status': 404}`
- Recommended next step: Verify the path is not exposed publicly and add routing or WAF protections.

### Request targeted a sensitive or administrative path.

- Severity: `medium`
- Type: `web.sensitive_path`
- Evidence: `{'ip': '198.51.100.25', 'path': '/.env', 'matched': '/.env', 'status': 404}`
- Recommended next step: Verify the path is not exposed publicly and add routing or WAF protections.

### Request targeted a sensitive or administrative path.

- Severity: `medium`
- Type: `web.sensitive_path`
- Evidence: `{'ip': '198.51.100.25', 'path': '/wp-admin', 'matched': '/wp-admin', 'status': 404}`
- Recommended next step: Verify the path is not exposed publicly and add routing or WAF protections.

### Request targeted a sensitive or administrative path.

- Severity: `medium`
- Type: `web.sensitive_path`
- Evidence: `{'ip': '198.51.100.25', 'path': '/phpmyadmin', 'matched': '/phpmyadmin', 'status': 404}`
- Recommended next step: Verify the path is not exposed publicly and add routing or WAF protections.

### Multiple web requests from one IP occurred in a short window.

- Severity: `medium`
- Type: `web.burst`
- Evidence: `{'ip': '198.51.100.25', 'requests': 4, 'window_seconds': 24, 'first_seen': '17/May/2026:10:02:00 +0000', 'last_seen': '17/May/2026:10:02:24 +0000'}`
- Recommended next step: Check whether the burst came from an authorized scanner before blocking the IP.

