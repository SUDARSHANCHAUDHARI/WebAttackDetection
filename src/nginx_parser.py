"""Parse nginx combined access logs."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus


NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d+) (?P<size>\S+) "
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def timestamp_to_epoch(timestamp: str) -> int:
    """Return epoch seconds for nginx combined-log timestamps."""
    return int(datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").timestamp())


def parse_nginx_log(text: str) -> list[dict]:
    """Return normalized request events."""
    events: list[dict] = []
    for line in text.splitlines():
        match = NGINX_RE.match(line)
        if not match:
            continue
        path = match.group("path")
        events.append(
            {
                "ip": match.group("ip"),
                "timestamp": match.group("timestamp"),
                "timestamp_epoch": timestamp_to_epoch(match.group("timestamp")),
                "method": match.group("method"),
                "path": path,
                "decoded_path": unquote_plus(path).lower(),
                "status": int(match.group("status")),
                "user_agent": match.group("user_agent"),
                "raw": line,
            }
        )
    return events


def parse_nginx_file(path: Path) -> list[dict]:
    """Parse an nginx access log file."""
    return parse_nginx_log(path.read_text(encoding="utf-8", errors="replace"))
