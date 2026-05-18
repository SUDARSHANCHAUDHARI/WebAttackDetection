# Production Readiness

## Current Status

This repository has a working local MVP with deterministic nginx parsing, safe sample data, generated reports, and tests. It is not production complete yet.

## Required Before Public Release

- Add log size limits and streaming parsing for hosted uploads.
- Validate nginx log format and report parse errors.
- Add structured logging without leaking secrets.
- Add allowlist/suppression workflow for authorized scanners.
- Add authentication and authorization before storing multi-user logs.
- Add retention controls for uploaded web logs and reports.
- Run dependency and secret scans before release.

## Definition of Done

- CI passes on pull requests.
- README has setup, usage, and security notes.
- Sample data is safe to publish.
- Error paths are handled clearly.
- No secrets or local machine paths are committed.
