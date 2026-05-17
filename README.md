# Web Attack Detection

**Goal:** Detect SQLi and XSS attempts from web logs.

**MVP:** Parse nginx logs and flag suspicious requests.

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
- Scores overall request risk.
- Writes JSON events, JSON findings, JSON summary, and a Markdown report.

## Repository Status

This repository contains the production-ready foundation for the Web Attack Detection MVP. The current codebase is scaffolded and ready for focused implementation work.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
