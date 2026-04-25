"""
Tests for datasec new features:
- Breach Monitor (state management)
- Password Manager parsers (Bitwarden, 1Password, KeePass)
- Hidden Volume (deniable encryption)
- Metadata Stripper (PDF, image, Office)
- Audit Report (hash integrity)
"""

import json
import os
import hashlib
import zipfile
import struct
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Breach Monitor ─────────────────────────────────────────────────────────

from datasec.breach_monitor import _breach_fingerprint, _load_state, _save_state

class TestBreachMonitor:
    def test_fingerprint_is_deterministic(self):
        breaches = [
            {"Name": "Adobe", "BreachDate": "2013-10-04"},
            {"Name": "LinkedIn", "BreachDate": "2012-05-05"},
        ]
        fp1 = _breach_fingerprint(breaches)
        fp2 = _breach_fingerprint(breaches)
        assert fp1 == fp2

    def test_fingerprint_changes_on_new_breach(self):
        b1 = [{"Name": "Adobe", "BreachDate": "2013-10-04"}]
        b2 = [{"Name": "Adobe", "BreachDate": "2013-10-04"},
              {"Name": "LinkedIn", "BreachDate": "2012-05-05"}]
        assert _breach_fingerprint(b1) != _breach_fingerprint(b2)

    def test_fingerprint_order_independent(self):
        b1 = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
        b2 = [{"Name": "LinkedIn"}, {"Name": "Adobe"}]
        assert _breach_fingerprint(b1) == _breach_fingerprint(b2)

    def test_state_roundtrip(self, tmp_path):
        """State saves and loads correctly."""
        import datasec.breach_monitor as bm
        original_state_file = bm.STATE_FILE
        bm.STATE_FILE = tmp_path / "monitor_state.json"
        bm.STATE_DIR  = tmp_path

        state = {
            "emails": {"test@example.com": {"fingerprint": "abc123", "breach_count": 2}},
            "api_key": "testkey",
            "interval_hours": 12,
        }
        _save_state(state)
        loaded = _load_state()

        assert loaded["api_key"] == "testkey"
        assert loaded["interval_hours"] == 12
        assert "test@example.com" in loaded["emails"]

        bm.STATE_FILE = original_state_file
        bm.STATE_DIR  = original_state_file.parent

    def test_new_breach_detection(self, monkeypatch, tmp_path):
        """Detects new breach when fingerprint changes."""
        import datasec.breach_monitor as bm

        bm.STATE_FILE = tmp_path / "state.json"
        bm.STATE_DIR  = tmp_path

        initial_breaches = [{"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Emails"]}]
        new_breaches     = [
            {"Name": "Adobe",    "BreachDate": "2013-10-04", "DataClasses": ["Emails"]},
            {"Name": "LinkedIn", "BreachDate": "2012-05-05", "DataClasses": ["Passwords"]},
        ]

        state = {
            "emails": {
                "user@test.com": {
                    "fingerprint":  _breach_fingerprint(initial_breaches),
                    "breach_names": ["Adobe"],
                    "breach_count": 1,
                    "last_checked": "2026-01-01T00:00:00",
                }
            },
            "api_key": "fakekey",
            "smtp": {},
        }
        _save_state(state)

        notified = []
        monkeypatch.setattr(bm, "_fetch_breaches", lambda e, k: new_breaches)
        monkeypatch.setattr(bm, "_notify_os",      lambda t, m: notified.append(m))
        monkeypatch.setattr(bm, "_notify_email",   lambda *a, **kw: None)

        updated = bm._check_all_emails(state)
        assert len(notified) == 1
        assert "LinkedIn" in notified[0]


# ── Password Manager Parsers ───────────────────────────────────────────────

from datasec.pm_parser import parse_bitwarden, parse_keepass_xml, detect_and_parse

class TestPasswordManagerParsers:
    def test_bitwarden_parses_login_items(self, tmp_path):
        bw_export = {
            "encrypted": False,
            "items": [
                {
                    "type": 1,
                    "name": "GitHub",
                    "login": {
                        "username": "user@example.com",
                        "password": "supersecret123",
                        "uris": [{"uri": "https://github.com"}]
                    }
                },
                {
                    "type": 2,  # Card — should be skipped
                    "name": "Visa",
                    "card": {"number": "4111111111111111"}
                }
            ]
        }
        path = tmp_path / "bitwarden.json"
        path.write_text(json.dumps(bw_export))

        entries = parse_bitwarden(str(path))
        assert len(entries) == 1
        assert entries[0]["password"] == "supersecret123"
        assert entries[0]["username"] == "user@example.com"
        assert "github.com" in entries[0]["site"]
        assert entries[0]["source"] == "bitwarden"

    def test_bitwarden_skips_empty_passwords(self, tmp_path):
        bw_export = {
            "items": [
                {"type": 1, "name": "NoPass", "login": {"username": "u", "password": "", "uris": []}},
                {"type": 1, "name": "WithPass", "login": {"username": "u", "password": "abc123", "uris": []}},
            ]
        }
        path = tmp_path / "bw.json"
        path.write_text(json.dumps(bw_export))
        entries = parse_bitwarden(str(path))
        assert len(entries) == 1
        assert entries[0]["password"] == "abc123"

    def test_keepass_xml_parses_entries(self, tmp_path):
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String><Key>Title</Key><Value>GitHub</Value></String>
        <String><Key>UserName</Key><Value>myuser</Value></String>
        <String><Key>Password</Key><Value>kp_password_123</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
      </Entry>
      <Group>
        <Name>Subgroup</Name>
        <Entry>
          <String><Key>Title</Key><Value>Gmail</Value></String>
          <String><Key>UserName</Key><Value>me@gmail.com</Value></String>
          <String><Key>Password</Key><Value>gmail_pass_456</Value></String>
          <String><Key>URL</Key><Value>https://mail.google.com</Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>'''
        path = tmp_path / "keepass.xml"
        path.write_text(xml_content)

        entries = parse_keepass_xml(str(path))
        assert len(entries) == 2
        passwords = {e["password"] for e in entries}
        assert "kp_password_123" in passwords
        assert "gmail_pass_456" in passwords

    def test_auto_detect_bitwarden(self, tmp_path):
        bw = {"items": [{"type": 1, "name": "X", "login": {"username": "u", "password": "p123", "uris": []}}]}
        path = tmp_path / "vault.json"
        path.write_text(json.dumps(bw))
        entries, manager = detect_and_parse(str(path))
        assert manager == "Bitwarden"
        assert len(entries) == 1

    def test_auto_detect_keepass(self, tmp_path):
        xml = '''<?xml version="1.0"?><KeePassFile><Root><Group>
          <Entry>
            <String><Key>Password</Key><Value>test</Value></String>
            <String><Key>Title</Key><Value>Site</Value></String>
            <String><Key>UserName</Key><Value>u</Value></String>
            <String><Key>URL</Key><Value>https://site.com</Value></String>
          </Entry>
        </Group></Root></KeePassFile>'''
        path = tmp_path / "db.xml"
        path.write_text(xml)
        entries, manager = detect_and_parse(str(path))
        assert manager == "KeePass"


# ── Hidden Volume ──────────────────────────────────────────────────────────

from datasec.hidden_volume import (create_volume, open_volume, _derive_key,
                                    _aes_encrypt, _aes_decrypt, SALT_SIZE, IV_SIZE,
                                    VOLUME_SIZE, HEADER_SIZE, INNER_REGION_SIZE, MAGIC)

class TestHiddenVolume:
    def test_encrypt_decrypt_roundtrip(self):
        key  = _derive_key("testpassword", os.urandom(SALT_SIZE))
        iv   = os.urandom(IV_SIZE)
        data = b"sensitive content here 1234567890"
        ct   = _aes_encrypt(key, iv, data)
        pt   = _aes_decrypt(key, iv, ct)
        assert pt == data

    def test_wrong_key_returns_none(self):
        key1 = _derive_key("correct", os.urandom(SALT_SIZE))
        key2 = _derive_key("wrong",   os.urandom(SALT_SIZE))
        iv   = os.urandom(IV_SIZE)
        ct   = _aes_encrypt(key1, iv, b"secret data padded properly here")
        pt   = _aes_decrypt(key2, iv, ct)
        assert pt is None

    def test_volume_is_fixed_size(self, tmp_path):
        """Volume must always be VOLUME_SIZE regardless of content size."""
        real_file  = tmp_path / "real.txt"
        decoy_file = tmp_path / "decoy.txt"
        volume     = tmp_path / "test.hv"

        real_file.write_bytes(b"small")
        decoy_file.write_bytes(b"x")

        with patch("datasec.hidden_volume.getpass.getpass") as mock_pw:
            mock_pw.side_effect = ["rp", "rp", "dp", "dp"]
            create_volume(str(real_file), str(decoy_file), str(volume))

        assert volume.stat().st_size == VOLUME_SIZE

    def test_full_volume_roundtrip(self, tmp_path):
        """Real and decoy passwords each return correct content."""
        real_file  = tmp_path / "real.txt"
        decoy_file = tmp_path / "decoy.txt"
        volume     = tmp_path / "test.hv"
        out_real   = tmp_path / "out_real.txt"
        out_decoy  = tmp_path / "out_decoy.txt"

        real_file.write_bytes(b"TOP SECRET: nuclear codes 12345")
        decoy_file.write_bytes(b"Shopping list: milk, eggs, bread")

        with patch("datasec.hidden_volume.getpass.getpass") as mock_pw:
            mock_pw.side_effect = ["realpass123!", "realpass123!", "decoypass456!", "decoypass456!"]
            create_volume(str(real_file), str(decoy_file), str(volume))

        with patch("datasec.hidden_volume.getpass.getpass", return_value="realpass123!"):
            open_volume(str(volume), str(out_real))
        assert out_real.read_bytes() == b"TOP SECRET: nuclear codes 12345"

        with patch("datasec.hidden_volume.getpass.getpass", return_value="decoypass456!"):
            open_volume(str(volume), str(out_decoy))
        assert out_decoy.read_bytes() == b"Shopping list: milk, eggs, bread"

    def test_volume_no_cleartext_markers(self, tmp_path):
        """Volume must contain no plaintext — no MAGIC, no content, no padding_len."""
        real_file  = tmp_path / "real.txt"
        decoy_file = tmp_path / "decoy.txt"
        volume     = tmp_path / "test.hv"

        real_file.write_bytes(b"CLASSIFIED DOCUMENT EYES ONLY")
        decoy_file.write_bytes(b"grocery list nothing here")

        with patch("datasec.hidden_volume.getpass.getpass") as mock_pw:
            mock_pw.side_effect = ["p1", "p1", "p2", "p2"]
            create_volume(str(real_file), str(decoy_file), str(volume))

        raw = volume.read_bytes()
        assert b"CLASSIFIED" not in raw
        assert b"grocery"    not in raw
        assert MAGIC         not in raw   # magic only appears inside decrypted plaintext

    def test_padding_len_not_in_cleartext(self, tmp_path):
        """
        Critical: the boundary between outer and inner regions must not be
        stored as cleartext anywhere in the volume (v1 bug — fixed in v2).
        """
        real_file  = tmp_path / "r.txt"
        decoy_file = tmp_path / "d.txt"
        volume     = tmp_path / "t.hv"
        real_file.write_bytes(b"real content here 1234")
        decoy_file.write_bytes(b"decoy content here 5678")

        with patch("datasec.hidden_volume.getpass.getpass") as mock_pw:
            mock_pw.side_effect = ["pw1", "pw1", "pw2", "pw2"]
            create_volume(str(real_file), str(decoy_file), str(volume))

        raw = volume.read_bytes()
        # The inner region always starts at a fixed known offset — no need
        # to store it. Verify no 4-byte value in the header area leaks layout.
        header = raw[:HEADER_SIZE]
        # Header contains only salts and IVs — all should be high-entropy
        # (not small integers that would indicate padding_len)
        import struct
        for i in range(0, HEADER_SIZE - 4, 4):
            val = struct.unpack(">I", header[i:i+4])[0]
            # A padding_len would typically be 512-767 (MIN_PADDING range)
            # Salts/IVs should not have such small values in their first bytes
            # This is a statistical check — extremely unlikely to false positive
            assert val > 1000 or val == 0, \
                f"Suspicious small value {val} at header offset {i} — may be leaked metadata"


# ── Metadata Stripper ──────────────────────────────────────────────────────

from datasec.metadata_stripper import extract_metadata, _is_sensitive, strip_metadata

class TestMetadataStripper:
    def test_sensitive_key_detection(self):
        assert _is_sensitive("GPS GPSLatitude")   is True
        assert _is_sensitive("Creator")            is True
        assert _is_sensitive("Last Modified By")   is True
        assert _is_sensitive("Software")           is True
        assert _is_sensitive("ImageWidth")         is False
        assert _is_sensitive("FileSize")           is False

    def test_pdf_metadata_strip(self, tmp_path):
        """Strip metadata from a PDF and verify fields are removed."""
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.add_metadata({
            "/Author":   "John Doe",
            "/Creator":  "Microsoft Word",
            "/Producer": "Adobe Acrobat",
        })
        pdf_path = tmp_path / "test.pdf"
        with open(pdf_path, "wb") as f:
            writer.write(f)

        out_path = tmp_path / "test_clean.pdf"
        result = strip_metadata(str(pdf_path), str(out_path))

        assert result is not None
        assert out_path.exists()
        meta_after = extract_metadata(str(out_path))
        # Author should be gone
        assert "Author" not in meta_after

    def test_image_metadata_strip(self, tmp_path):
        """Strip EXIF from JPEG."""
        from PIL import Image
        img = Image.new("RGB", (100, 100), color=(255, 0, 0))
        img_path = tmp_path / "test.jpg"
        img.save(str(img_path), "JPEG")

        out_path = tmp_path / "test_clean.jpg"
        result = strip_metadata(str(img_path), str(out_path))
        assert result is not None
        assert out_path.exists()

    def test_office_zip_fully_rewritten_not_appended(self, tmp_path):
        """
        Critical: old metadata must not survive in the ZIP file.
        The v1 bug used append mode which leaves old entries readable.
        """
        import zipfile, xml.etree.ElementTree as ET

        # Build a minimal DOCX with author metadata
        docx_path = tmp_path / "test.docx"
        core_with_author = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>John Secret Doe</dc:creator>
  <cp:lastModifiedBy>John Secret Doe</cp:lastModifiedBy>
</cp:coreProperties>'''

        with zipfile.ZipFile(docx_path, "w") as z:
            z.writestr("docProps/core.xml", core_with_author)
            z.writestr("docProps/app.xml",  "<Properties/>")
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml",   "<document/>")

        out_path = tmp_path / "test_clean.docx"
        result = strip_metadata(str(docx_path), str(out_path))
        assert result is not None

        # Read raw bytes — "John Secret Doe" must not appear ANYWHERE in the file
        raw = out_path.read_bytes()
        assert b"John Secret Doe" not in raw, \
            "Original author survived in ZIP — append mode bug not fixed"

        # Also verify the file is a valid ZIP with only one core.xml entry
        with zipfile.ZipFile(out_path, "r") as z:
            core_entries = [n for n in z.namelist() if n == "docProps/core.xml"]
            assert len(core_entries) == 1, \
                f"Expected 1 core.xml entry, found {len(core_entries)} — duplicate entries detected"

    def test_unsupported_format_returns_none(self, tmp_path):
        f = tmp_path / "test.zip"
        f.write_bytes(b"fake zip content")
        result = strip_metadata(str(f))
        assert result is None


# ── Audit Report ───────────────────────────────────────────────────────────

from datasec.audit_report import generate_report, verify_report

class TestAuditReport:
    def test_report_generates_and_hashes(self, tmp_path):
        report_path = generate_report(
            emails=[],
            password_file=None,
            output_dir=str(tmp_path),
        )
        assert report_path is not None
        path = Path(report_path)
        assert path.exists()

        hash_path = Path(str(path) + ".sha256")
        assert hash_path.exists()

        # Verify hash is correct
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        stored   = hash_path.read_text().split()[0]
        assert expected == stored

    def test_report_verify_passes_for_intact_report(self, tmp_path):
        report_path = generate_report(output_dir=str(tmp_path))
        result = verify_report(report_path)
        assert result is True

    def test_report_verify_fails_for_tampered_report(self, tmp_path):
        report_path = generate_report(output_dir=str(tmp_path))
        path = Path(report_path)

        # Tamper with the report
        content = path.read_text()
        path.write_text(content + "\nTAMPERED LINE")

        result = verify_report(report_path)
        assert result is False

    def test_report_contains_required_sections(self, tmp_path):
        report_path = generate_report(
            emails=["test@example.com"],
            output_dir=str(tmp_path),
        )
        content = Path(report_path).read_text()
        assert "SECTION 1: BREACH STATUS"    in content
        assert "SECTION 2: PASSWORD AUDIT"   in content
        assert "SECTION 3: SECURITY CHECKLIST" in content
        assert "SECTION 4: RECOMMENDATIONS"  in content
        assert "test@example.com"             in content
