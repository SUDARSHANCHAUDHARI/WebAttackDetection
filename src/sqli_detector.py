"""Detect SQL injection patterns."""

from __future__ import annotations


SQLI_MARKERS = (
    " union select ",
    "select ",
    " or 1=1",
    "' or '1'='1",
    "information_schema",
    "sleep(",
    "benchmark(",
    "--",
)


def detect_sqli(events: list[dict]) -> list[dict]:
    """Return SQLi findings from HTTP request events."""
    findings: list[dict] = []
    for event in events:
        decoded = f" {event.get('decoded_path', '')} "
        marker = next((item for item in SQLI_MARKERS if item in decoded), "")
        if not marker:
            continue
        findings.append(
            {
                "kind": "web.sqli",
                "severity": "high",
                "summary": "Request path contains SQL injection indicators.",
                "evidence": {
                    "ip": event.get("ip"),
                    "path": event.get("path"),
                    "matched": marker.strip(),
                    "status": event.get("status"),
                },
            }
        )
    return findings
