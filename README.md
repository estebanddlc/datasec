# datasec

Personal data protection toolkit — built for people who want full control over their own security data, locally, without trusting third-party services.

> **Disclaimer:** For personal and educational use only. Do not scan data belonging to others without consent.

---

## Why datasec

Most security tools either require cloud accounts, send your data to external servers, or solve only one problem. datasec does everything locally:

- **Audit your Bitwarden/1Password vault against HIBP** without sending your passwords anywhere — not even to HIBP servers in full (k-anonymity)
- **Strip metadata from files before encrypting or sharing** — one command instead of three tools
- **Monitor your emails for new breaches** with OS notifications and optional email alerts, no account required
- **Create files with plausible deniability** — two passwords, two contents, indistinguishable volume
- **Generate a signed, timestamped security report** with SHA-256 hash for auditable evidence of your security posture

---

## Requirements

- Python 3.10+
- pip

---

## Installation

```bash
git clone https://github.com/estebanddlc/datasec
cd datasec
pip install -r requirements.txt
python -m datasec.main --help
```

Or install as a package:

```bash
pip install .
datasec --help
```

---

## Modules

### Core

| Command | Description |
|---------|-------------|
| `breach` | Check email in known breaches via HIBP |
| `encrypt` | AES-256 file encryption / decryption |
| `osint` | Map your digital footprint in public sources |
| `pwaudit` | Audit passwords: weak, reused, compromised |
| `status` | Security status dashboard |

### New features

| Command | Description |
|---------|-------------|
| `monitor` | Breach monitor daemon with OS + email alerts |
| `pwaudit` (extended) | Native Bitwarden / 1Password / KeePass parser |
| `hv` | Hidden volumes with plausible deniability |
| `meta` | Metadata inspector and stripper |
| `report` | SHA-256 signed security posture reports |

---

## Usage

### Password audit — native vault formats

```bash
# Auto-detected from file extension
python -m datasec.main pwaudit vault.json          # Bitwarden JSON export
python -m datasec.main pwaudit export.1pux         # 1Password export
python -m datasec.main pwaudit keepass.xml         # KeePass XML export

# Explicit format
python -m datasec.main pwaudit vault.json --formato bitwarden
```

Your passwords never leave your machine. Only the first 5 characters of each SHA-1 hash are sent to HIBP (k-anonymity).

Export instructions:
- **Bitwarden:** Settings → Export Vault → Format: JSON (unencrypted)
- **1Password:** File → Export → All Items → .1pux
- **KeePass:** File → Export → KeePass XML (2.x)

---

### Breach monitor

```bash
# Setup
python -m datasec.main monitor configure --api-key YOUR_HIBP_KEY
python -m datasec.main monitor configure --interval 24
python -m datasec.main monitor configure \
  --smtp-host smtp.gmail.com --smtp-user you@gmail.com \
  --smtp-pass YOUR_APP_PASSWORD

# Add emails to watch
python -m datasec.main monitor add you@email.com
python -m datasec.main monitor add work@company.com

# Run once (good for cron)
python -m datasec.main monitor run --once

# Run as daemon
python -m datasec.main monitor run

# Check status
python -m datasec.main monitor status
```

State is saved in `~/.datasec/monitor_state.json` (chmod 600).

---

### Hidden volumes (plausible deniability)

```bash
# Create a volume with two passwords
python -m datasec.main hv create real_document.pdf decoy_document.pdf

# Open — whichever password you enter determines what you get
python -m datasec.main hv open document.pdf.hv
```

If coerced, reveal only the decoy password. The volume file is indistinguishable from random data and contains no headers or markers that reveal which password is "real".

---

### Metadata stripping

```bash
# Inspect metadata
python -m datasec.main meta show document.pdf
python -m datasec.main meta show photo.jpg

# Strip metadata
python -m datasec.main meta strip document.pdf
python -m datasec.main meta strip photo.jpg -o photo_clean.jpg

# Strip then encrypt in one command
python -m datasec.main meta strip sensitive.pdf --encrypt
```

Supported: PDF, JPEG, PNG, TIFF, DOCX, XLSX, PPTX.

What gets removed: author, creator, GPS coordinates, camera make/model, software used, revision history, company name, last modified by.

---

### Encrypt / decrypt

```bash
python -m datasec.main encrypt sensitive.pdf
python -m datasec.main encrypt sensitive.pdf.enc --decrypt
python -m datasec.main encrypt file.pdf -o file_encrypted.pdf.enc
```

AES-256-CBC via Fernet, PBKDF2-HMAC-SHA256 with 480,000 iterations (OWASP 2023), 32-byte random salt per file.

---

### Signed security reports

```bash
# Generate report
python -m datasec.main report generate \
  -e you@email.com \
  -p vault.json -f bitwarden

# With GPG signature
python -m datasec.main report generate -e you@email.com --sign-gpg

# Verify integrity later
python -m datasec.main report verify ~/.datasec/reports/datasec_report_20260424_120000.txt
```

Reports are saved to `~/.datasec/reports/` with a `.sha256` hash file. Useful for auditable evidence of your security posture at a specific point in time.

---

### OSINT self-scan

```bash
python -m datasec.main osint you@email.com --type email
python -m datasec.main osint "Your Name"  --type nombre
python -m datasec.main osint yourusername --type usuario
python -m datasec.main osint "+15551234567" --type telefono
```

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

36 tests covering: password strength, k-anonymity enforcement, key derivation, encrypt/decrypt roundtrips, breach monitor state and detection, Bitwarden/KeePass parsers, hidden volume roundtrip and deniability, metadata stripping, report generation and tamper detection.

---

## Security design

| Feature | How it works |
|---------|-------------|
| Password HIBP check | k-anonymity — only first 5 chars of SHA-1 hash sent |
| File encryption | AES-256-CBC, key derived in memory, never written to disk |
| Hidden volumes | Both passwords produce valid output; file looks like random data |
| Monitor state | Saved to `~/.datasec/` with chmod 600 |
| Reports | SHA-256 hash + optional GPG detached signature |
| OSINT | Public HTTP reads only, no personal data sent to third parties |

---

## Project structure

```
datasec/
├── datasec/
│   ├── main.py               # CLI entry point
│   ├── breach_scanner.py     # HIBP email + password check
│   ├── breach_monitor.py     # Background monitor daemon
│   ├── encryptor.py          # AES-256 file encryption
│   ├── hidden_volume.py      # Deniable encryption
│   ├── metadata_stripper.py  # Metadata inspector + stripper
│   ├── osint_scanner.py      # OSINT footprint scanner
│   ├── password_auditor.py   # Password strength + HIBP check
│   ├── pm_parser.py          # Bitwarden / 1Password / KeePass parser
│   ├── audit_report.py       # Signed security reports
│   └── status_report.py      # Status dashboard
├── tests/
│   ├── test_datasec.py
│   └── test_new_features.py
├── pyproject.toml
├── requirements.txt
└── LICENSE
```

---

## Roadmap

- [ ] Watch mode: file system watcher for auto-encrypt on save
- [ ] KDBX support (encrypted KeePass database, not just XML export)
- [ ] PDF report export
- [ ] Shodan integration for IP/domain exposure check
- [ ] Support for Mexico-specific breaches (INE, SAT, IMSS)

---

## License

MIT
