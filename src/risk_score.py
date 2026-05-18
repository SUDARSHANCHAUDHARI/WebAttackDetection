"""Risk scoring and reporting helpers."""

from __future__ import annotations

from collections import Counter


SEVERITY_POINTS = {"critical": 90, "high": 70, "medium": 40, "low": 10}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
NEXT_STEPS = {
    "web.sqli": "Review the target endpoint, confirm parameterized queries, and preserve request context.",
    "web.xss": "Confirm output encoding and input validation on the affected endpoint.",
    "web.scanner": "Rate-limit or block scanner traffic after confirming it is not authorized testing.",
    "web.sensitive_path": "Verify the path is not exposed publicly and add routing or WAF protections.",
    "web.burst": "Check whether the burst came from an authorized scanner before blocking the IP.",
}


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
    by_severity = Counter(str(finding["severity"]) for finding in findings)
    return {
        "requests": len(events),
        "findings": len(findings),
        "risk_score": score_findings(findings),
        "attacks_by_kind": dict(attacks_by_kind),
        "by_severity": dict(by_severity),
        "highest_severity": max(
            (str(finding["severity"]) for finding in findings),
            key=lambda item: SEVERITY_ORDER.get(item, 0),
            default="none",
        ),
        "top_ips": [{"ip": ip, "findings": count} for ip, count in findings_by_ip.most_common(5)],
    }


def build_ip_risk(events: list[dict], findings: list[dict]) -> list[dict]:
    """Return per-IP risk rows for dashboard triage."""
    requests_by_ip = Counter(str(event["ip"]) for event in events)
    findings_by_ip = Counter(str(finding.get("evidence", {}).get("ip", "unknown")) for finding in findings)
    kinds_by_ip: dict[str, set[str]] = {}
    max_severity: dict[str, str] = {}
    for finding in findings:
        ip = str(finding.get("evidence", {}).get("ip", "unknown"))
        kinds_by_ip.setdefault(ip, set()).add(str(finding.get("kind")))
        severity = str(finding.get("severity", "low"))
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity.get(ip, "low"), 0):
            max_severity[ip] = severity
    rows = []
    for ip in sorted(set(requests_by_ip) | set(findings_by_ip)):
        rows.append(
            {
                "ip": ip,
                "requests": requests_by_ip.get(ip, 0),
                "findings": findings_by_ip.get(ip, 0),
                "max_severity": max_severity.get(ip, "low"),
                "attack_types": sorted(kinds_by_ip.get(ip, set())),
            }
        )
    return sorted(rows, key=lambda row: (-SEVERITY_ORDER.get(row["max_severity"], 0), -row["findings"], row["ip"]))


def detect_request_bursts(events: list[dict], threshold: int = 4, window_seconds: int = 120) -> list[dict]:
    """Detect a compact burst of requests from one IP."""
    findings: list[dict] = []
    by_ip: dict[str, list[dict]] = {}
    for event in events:
        by_ip.setdefault(str(event["ip"]), []).append(event)
    for ip, ip_events in by_ip.items():
        ordered = sorted(ip_events, key=lambda item: int(item.get("timestamp_epoch", 0)))
        if len(ordered) < threshold:
            continue
        window = int(ordered[-1]["timestamp_epoch"]) - int(ordered[0]["timestamp_epoch"])
        if window <= window_seconds:
            findings.append(
                {
                    "kind": "web.burst",
                    "severity": "medium",
                    "summary": "Multiple web requests from one IP occurred in a short window.",
                    "evidence": {
                        "ip": ip,
                        "requests": len(ordered),
                        "window_seconds": window,
                        "first_seen": ordered[0]["timestamp"],
                        "last_seen": ordered[-1]["timestamp"],
                    },
                }
            )
    return findings


def build_markdown_report(summary: dict, findings: list[dict]) -> str:
    """Return a Markdown web attack report."""
    sorted_findings = sorted(findings, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 0), reverse=True)
    lines = [
        "# Web Attack Detection Report",
        "",
        "## Executive Summary",
        "",
        f"- Requests analyzed: {summary['requests']}",
        f"- Findings: {summary['findings']}",
        f"- Risk score: {summary['risk_score']}/100",
        f"- Highest severity: `{summary['highest_severity']}`",
        "",
        "## Attack Types",
        "",
    ]
    for kind, count in summary["attacks_by_kind"].items():
        lines.append(f"- `{kind}`: {count}")
    lines.extend(["", "## Top IPs", ""])
    for item in summary["top_ips"]:
        lines.append(f"- `{item['ip']}`: {item['findings']} finding(s)")
    lines.extend(["", "## Priority Queue", ""])
    if not sorted_findings:
        lines.append("No immediate analyst queue was generated.")
    for index, finding in enumerate(sorted_findings[:5], start=1):
        lines.append(f"{index}. **{finding['severity']}** - {finding['summary']} ({finding['kind']})")
    lines.extend(["", "## Findings", ""])
    if not sorted_findings:
        lines.append("No web attacks detected.")
    for finding in sorted_findings:
        kind = str(finding["kind"])
        lines.extend(
            [
                f"### {finding['summary']}",
                "",
                f"- Severity: `{finding['severity']}`",
                f"- Type: `{kind}`",
                f"- Evidence: `{finding['evidence']}`",
                f"- Recommended next step: {NEXT_STEPS.get(kind, 'Review this request with the original web log context.')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def build_triage_report(summary: dict, ip_risk: list[dict], findings: list[dict]) -> str:
    """Return a compact analyst triage report."""
    lines = [
        "# Web Attack Detection Triage",
        "",
        f"- Requests analyzed: {summary['requests']}",
        f"- Findings: {summary['findings']}",
        f"- Risk score: {summary['risk_score']}/100",
        "",
        "## IP Risk",
        "",
    ]
    for row in ip_risk:
        types = ", ".join(row["attack_types"]) if row["attack_types"] else "none"
        lines.append(f"- `{row['ip']}`: {row['findings']} finding(s), {row['requests']} request(s), types={types}")
    lines.extend(["", "## Analyst Queue", ""])
    if not findings:
        lines.append("- No immediate analyst queue was generated.")
    for finding in sorted(findings, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 0), reverse=True)[:8]:
        lines.append(f"- `{finding['severity']}` {finding['kind']}: {finding['summary']}")
    return "\n".join(lines).rstrip() + "\n"
