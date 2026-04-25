# datasec

[![CI](https://github.com/estebanddlc/datasec/actions/workflows/tests.yml/badge.svg)](https://github.com/estebanddlc/datasec/actions/workflows/tests.yml)

Local-first personal security toolkit for people who want practical visibility into breach exposure, password hygiene, document metadata, and encrypted file handling.

> Disclaimer: for personal and authorized defensive use only.

## Why this version is more serious

`datasec` now leans into features that hold up better under real usage instead of demo-only behavior:

- Streamed encryption for large files, so multi-GB inputs do not require loading every encrypted chunk into RAM first.
- Per-chunk integrity verification in the chunked format, which detects reordered, deleted, or modified encrypted blocks before decrypting output.
- Status reporting backed by the actual monitor state in `~/.datasec/monitor_state.json`.
- Service helpers for Linux, macOS, and now Windows Task Scheduler so the breach monitor can run like a real background job.

## Install

```bash
git clone https://github.com/estebanddlc/datasec
cd datasec
pip install -r requirements.txt
pip install .
datasec --help
```

Python 3.10+ is required.

For local development:

```bash
pip install -e ".[dev]"
pytest -q
```

## Core commands

| Command | Purpose |
| --- | --- |
| `datasec breach EMAIL` | Check an email against known HIBP breaches |
| `datasec monitor ...` | Persisted breach monitoring with alerts |
| `datasec pwaudit FILE` | Audit password exports and vault dumps |
| `datasec encrypt FILE` | Encrypt or decrypt files |
| `datasec meta strip FILE` | Remove metadata from PDFs, images, and Office docs |
| `datasec report generate` | Produce a timestamped posture report |
| `datasec status` | Show actual local monitor and config state |

## Useful workflows

### Streamed encryption

```bash
datasec encrypt backup.tar
datasec encrypt backup.tar.enc --decrypt
```

Small files use a compact single-pass format. Large files automatically switch to streamed chunk mode with chunk-level tamper detection.

### Password audit

```bash
datasec pwaudit vault.json
datasec pwaudit export.1pux
datasec pwaudit keepass.xml
```

For HIBP password checks, only the SHA-1 prefix is sent upstream.

### Breach monitoring

```bash
datasec monitor configure --api-key YOUR_HIBP_KEY
datasec monitor add you@example.com
datasec monitor run --once
datasec status
```

### Metadata hygiene

```bash
datasec meta show document.pdf
datasec meta strip document.pdf
datasec meta strip secret.docx --encrypt
```

## Background services

- Linux: `services/datasec-monitor.service`
- macOS: `services/com.datasec.monitor.plist`
- Windows: `services/install-task.ps1` and `services/remove-task.ps1`

The Windows scripts register a per-user scheduled task that runs `datasec monitor run --once` at logon and then every 6 hours.

## Security notes

- Password breach checks use k-anonymity against the HIBP range API.
- Large-file encryption now uses streamed chunk mode with per-chunk tamper detection.
- Hidden volumes are designed for plausible deniability at rest, not against live-memory forensics.
- Reports are hashed with SHA-256 and can also be signed with GPG.

## What still needs work

- Real KDBX support instead of KeePass XML-only import.
- Better OSINT signal quality to reduce false positives.
- Machine-readable report export formats such as JSON.
- Cleaner encoding and localization consistency across the CLI.

## Tests

```bash
pytest -q
```

The test suite covers breach-monitor state, password parsing, encryption roundtrips, tamper detection, metadata stripping, hidden volumes, and report hashing.

## Project status

The current release is `0.4.0`. See [CHANGELOG.md](./CHANGELOG.md) for release notes and upgrade history.

## License

MIT
