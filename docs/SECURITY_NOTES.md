# Security Notes

This project is defensive and analysis-only. Use it only with web logs from systems you own or have permission to investigate.

## Data Handling

- Web logs can contain source IPs, user agents, URL paths, query strings, referrers, and session identifiers.
- Redact tokens, customer identifiers, private hostnames, and sensitive query parameters before sharing reports.
- Do not commit production nginx logs.
- Sample data uses documentation IP ranges and synthetic payloads.

## Detection Caveats

- Findings are triage signals, not proof of compromise.
- Authorized scanners can look identical to hostile scanners without context.
- SQLi/XSS pattern checks should be paired with application logs and WAF telemetry for final incident review.
