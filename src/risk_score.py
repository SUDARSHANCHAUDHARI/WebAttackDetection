"""Risk scoring and reporting helpers."""

from __future__ import annotations

from collections import Counter


SEVERITY_POINTS = {"critical": 90, "high": 70, "medium": 40, "low": 10}


def score_findings(findings: list[dict]) -> int:
    """Return a normalized 0-100 risk score."""
    if not findings:
        return 0
    score = sum(SEVERITY_POINTS.get(str(finding.get("severity")), 0) for finding in findings)
    return min(100, score)


def summarize(events: list[dict], findings: list[dict]) -> dict:
    """Return dashboard summary data."""
    attacks_by_kind = Counter(str(finding["kind"]) for finding in findings)
    findings_by_ip = Counter(str(finding.get("evidence", {}).get("ip", "unknown")) for finding in findings)
    return {
        "requests": len(events),
        "findings": len(findings),
        "risk_score": score_findings(findings),
        "attacks_by_kind": dict(attacks_by_kind),
        "top_ips": [{"ip": ip, "findings": count} for ip, count in findings_by_ip.most_common(5)],
    }


def build_markdown_report(summary: dict, findings: list[dict]) -> str:
    """Return a Markdown web attack report."""
    lines = [
        "# Web Attack Detection Report",
        "",
        "## Summary",
        "",
        f"- Requests analyzed: {summary['requests']}",
        f"- Findings: {summary['findings']}",
        f"- Risk score: {summary['risk_score']}/100",
        "",
        "## Attack Types",
        "",
    ]
    for kind, count in summary["attacks_by_kind"].items():
        lines.append(f"- `{kind}`: {count}")
    lines.extend(["", "## Top IPs", ""])
    for item in summary["top_ips"]:
        lines.append(f"- `{item['ip']}`: {item['findings']} finding(s)")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No web attacks detected.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding['summary']}",
                "",
                f"- Severity: `{finding['severity']}`",
                f"- Type: `{finding['kind']}`",
                f"- Evidence: `{finding['evidence']}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
