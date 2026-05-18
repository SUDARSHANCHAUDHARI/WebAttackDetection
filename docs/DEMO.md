# Demo

Run the included safe nginx access log:

```bash
python3 dashboard/app.py --log data/nginx-web-attacks.log --out-dir reports
```

Expected output:

```text
Analyzed 8 requests
Generated 10 finding(s)
Risk score: 100/100
```

Generated artifacts:

- `reports/events.json`
- `reports/findings.json`
- `reports/summary.json`
- `reports/ip-risk.json`
- `reports/report.md`
- `reports/triage.md`

The sample demonstrates SQL injection, XSS, scanner user agents, sensitive path probing, and a short request burst from one source IP.
