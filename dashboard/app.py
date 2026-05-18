"""CLI dashboard for web attack detection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.nginx_parser import parse_nginx_file
from src.risk_score import build_ip_risk, build_markdown_report, build_triage_report, detect_request_bursts, summarize
from src.sqli_detector import detect_sqli
from src.xss_detector import detect_sensitive_paths, detect_suspicious_user_agents, detect_xss


def analyze(log_path: Path, out_dir: Path) -> dict:
    """Analyze an nginx log and write report artifacts."""
    events = parse_nginx_file(log_path)
    findings = [
        *detect_sqli(events),
        *detect_xss(events),
        *detect_suspicious_user_agents(events),
        *detect_sensitive_paths(events),
        *detect_request_bursts(events),
    ]
    summary = summarize(events, findings)
    ip_risk = build_ip_risk(events, findings)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "events.json").write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "ip-risk.json").write_text(json.dumps(ip_risk, indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(build_markdown_report(summary, findings), encoding="utf-8")
    (out_dir / "triage.md").write_text(build_triage_report(summary, ip_risk, findings), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect SQLi, XSS, and scanners in nginx logs")
    parser.add_argument("--log", type=Path, default=Path("data/nginx-web-attacks.log"))
    parser.add_argument("--out-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    summary = analyze(args.log, args.out_dir)
    print(f"Analyzed {summary['requests']} requests")
    print(f"Generated {summary['findings']} finding(s)")
    print(f"Risk score: {summary['risk_score']}/100")


if __name__ == "__main__":
    main()
