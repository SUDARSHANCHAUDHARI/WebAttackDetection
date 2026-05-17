"""Detect XSS and scanner patterns."""

from __future__ import annotations


XSS_MARKERS = ("<script", "javascript:", "onerror=", "onload=", "%3cscript")
SCANNER_AGENTS = ("sqlmap", "nikto", "acunetix", "zap", "nuclei")


def detect_xss(events: list[dict]) -> list[dict]:
    """Return XSS findings from HTTP request events."""
    findings: list[dict] = []
    for event in events:
        decoded = str(event.get("decoded_path", ""))
        marker = next((item for item in XSS_MARKERS if item in decoded), "")
        if marker:
            findings.append(
                {
                    "kind": "web.xss",
                    "severity": "high",
                    "summary": "Request path contains cross-site scripting indicators.",
                    "evidence": {
                        "ip": event.get("ip"),
                        "path": event.get("path"),
                        "matched": marker,
                        "status": event.get("status"),
                    },
                }
            )
    return findings


def detect_suspicious_user_agents(events: list[dict]) -> list[dict]:
    """Return suspicious scanner user-agent findings."""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        user_agent = str(event.get("user_agent", "")).lower()
        marker = next((item for item in SCANNER_AGENTS if item in user_agent), "")
        key = (str(event.get("ip", "")), marker)
        if not marker or key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "kind": "web.scanner",
                "severity": "medium",
                "summary": "Request user agent matches a known scanner signature.",
                "evidence": {
                    "ip": event.get("ip"),
                    "user_agent": event.get("user_agent"),
                    "matched": marker,
                },
            }
        )
    return findings
