"""Tests for the Web Attack Detection MVP."""

from __future__ import annotations

import unittest
from pathlib import Path

from dashboard.app import analyze
from src.nginx_parser import parse_nginx_file
from src.risk_score import summarize
from src.sqli_detector import detect_sqli
from src.xss_detector import detect_suspicious_user_agents, detect_xss


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data/nginx-web-attacks.log"


class WebAttackDetectionTests(unittest.TestCase):
    def test_parses_nginx_sample(self) -> None:
        events = parse_nginx_file(SAMPLE)

        self.assertEqual(len(events), 5)
        self.assertEqual(events[0]["ip"], "203.0.113.10")

    def test_detects_sqli_xss_and_scanners(self) -> None:
        events = parse_nginx_file(SAMPLE)
        findings = [*detect_sqli(events), *detect_xss(events), *detect_suspicious_user_agents(events)]
        kinds = {finding["kind"] for finding in findings}

        self.assertIn("web.sqli", kinds)
        self.assertIn("web.xss", kinds)
        self.assertIn("web.scanner", kinds)

    def test_summary_and_report_outputs(self) -> None:
        events = parse_nginx_file(SAMPLE)
        findings = [*detect_sqli(events), *detect_xss(events), *detect_suspicious_user_agents(events)]
        summary = summarize(events, findings)

        self.assertEqual(summary["requests"], 5)
        self.assertGreater(summary["risk_score"], 0)

    def test_cli_analyze_writes_outputs(self) -> None:
        out_dir = ROOT / "reports"
        summary = analyze(SAMPLE, out_dir)

        self.assertGreaterEqual(summary["findings"], 4)
        self.assertTrue((out_dir / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
