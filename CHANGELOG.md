# Changelog

## 0.4.0 - 2026-04-25

- Added a new streamed encryption format for large files.
- Added per-chunk integrity verification for chunked encrypted files.
- Improved `status` so it reflects real monitor state instead of static placeholders.
- Cleaned user-facing mojibake from CLI modules and reports.
- Added Windows Task Scheduler helpers for the breach monitor.
- Expanded tests for v2 encryption headers, tamper detection, and status recommendations.

## 0.3.0

- Fixed hidden volume metadata leakage.
- Fixed Office metadata stripping so ZIP containers are rewritten instead of appended.
- Added chunked encryption mode for large files.
- Added Linux and macOS service helpers for the monitor.

## 0.2.0

- Added breach monitor daemon and notifications.
- Added password manager import support for Bitwarden, 1Password, and KeePass XML.
- Added hidden volumes, metadata stripping, and audit reports.

## 0.1.0

- Initial public toolkit release.
