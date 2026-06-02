# Web Attack Detection

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-MVP-green)](#status)
[![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#safe-use)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Web log detection lab for SQL injection, XSS, suspicious user agents, scanner activity, and risk-scored request summaries.

---

## Overview

Web Attack Detection is a defensive analysis tool that parses nginx combined access logs and flags common web attacks: SQL injection patterns, XSS payloads, scanner-style user agents, sensitive path probing, and high-rate request bursts. Outputs include JSON findings, an IP risk table, a Markdown report, and a triage handoff for analysts.

## Features

- Parses nginx combined access logs
- Detects SQL injection indicators
- Detects XSS payload indicators
- Flags suspicious scanner user agents
- Flags sensitive / admin path probing
- Detects compact request bursts from a single IP
- Scores overall request risk per IP
- Writes JSON events, findings, summary, IP risk table, Markdown report, and triage handoff

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- No third-party Python packages (standard library only)
- Optional: Docker for the demo container

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/WebAttackDetection.git
cd WebAttackDetection
pip install .
```

This registers the `web-attack-detection` CLI command.

To run without installing:

```bash
python3 main.py --help
```

## Usage

Analyze the included sample nginx log:

```bash
python3 main.py --log data/nginx-web-attacks.log --out-dir reports
```

Generated outputs in `reports/`:

- `events.json` — parsed access events
- `findings.json` — detected attack indicators
- `summary.json` — counts and severity breakdown
- `ip-risk.json` — per-IP risk score table
- `report.md` — full Markdown detection report
- `triage.md` — analyst triage checklist

## Project Structure

```
WebAttackDetection/
├── dashboard/      CLI dashboard (entrypoint)
├── src/            Parsers and detectors
├── data/           Safe sample nginx logs
├── reports/        Example generated output
├── docker/         Dockerfile + compose support
├── docs/           Architecture, security notes, demo
├── tests/          Unit tests
├── main.py         CLI entrypoint
├── pyproject.toml  Package metadata
└── LICENSE
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Docker Demo

```bash
docker compose run --rm web-attack-demo
```

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, and lab environments you own or have explicit written permission to assess. The included sample log is synthetic and safe for public demo use.

## Status

Working CLI MVP with tests, sample data, and Docker support.

## Roadmap

- Allowlist / suppression support for authorized scanners
- Request-window tuning through config
- Endpoint-level risk grouping
- Dashboard charts for attack frequency and IP activity
- GitHub release `v0.1.0-mvp`

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software with attribution.

## Author

**Sudarshan Chaudhari** — [SudarshanTechLabs](https://github.com/SUDARSHANCHAUDHARI)
Bangkok, Thailand

For inquiries: open an issue on [GitHub](https://github.com/SUDARSHANCHAUDHARI/WebAttackDetection/issues).
