# Web Attack Detection

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Web log detection lab for SQL injection, XSS, suspicious user agents, and risk summaries.

- **Portfolio group:** Cybersecurity lab project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/WebAttackDetection
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/WebAttackDetection`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

## Core Features

- SQLi pattern detection
- XSS pattern detection
- suspicious user agents
- attack frequency chart
- risk explanation

## Status

Working CLI MVP.

## Quick Start

Analyze the included sample nginx log:

```bash
python3 dashboard/app.py --log data/nginx-web-attacks.log --out-dir reports
```

Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## MVP Capabilities

- Parses nginx combined access logs.
- Detects SQL injection indicators.
- Detects XSS payload indicators.
- Flags suspicious scanner user agents.
- Flags sensitive/admin path probing.
- Detects compact request bursts from one IP.
- Scores overall request risk.
- Writes JSON events, findings, summary, IP risk table, Markdown report, and triage handoff.

## Demo Artifacts

- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Demo walkthrough](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Sample report](reports/report.md)
- [Sample triage report](reports/triage.md)
- [Sample IP risk table](reports/ip-risk.json)

## Docker Demo

```bash
docker compose run --rm web-attack-demo
```

## Roadmap

- Add allowlist/suppression support for authorized scanners.
- Add request-window tuning through config.
- Add endpoint-level risk grouping.
- Add dashboard charts for attack frequency and IP activity.
- Prepare GitHub release `v0.1.0-mvp`.
