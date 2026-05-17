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
- Scores overall request risk.
- Writes JSON events, JSON findings, JSON summary, and a Markdown report.

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
