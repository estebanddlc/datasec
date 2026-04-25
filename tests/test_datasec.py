"""
Tests for the core datasec toolkit.
Run with: pytest tests/
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datasec.breach_scanner import check_password
from datasec.encryptor import CHUNK_SIZE, MAGIC, SALT_SIZE, _derive_key
from datasec.password_auditor import _analyze_strength


class TestPasswordStrength:
    def test_weak_short_password(self):
        strength, issues = _analyze_strength("abc")
        assert strength == "debil"
        assert any("corta" in issue for issue in issues)

    def test_weak_common_pattern(self):
        strength, _ = _analyze_strength("123456")
        assert strength == "debil"

    def test_weak_only_letters(self):
        strength, _ = _analyze_strength("abcdefgh")
        assert strength in ("debil", "media")

    def test_strong_password(self):
        strength, issues = _analyze_strength("X9#mK2$pL7@nQ4!w")
        assert strength == "fuerte"
        assert issues == []

    def test_medium_password(self):
        strength, _ = _analyze_strength("Password1")
        assert strength in ("media", "debil")

    def test_repeated_chars(self):
        _, issues = _analyze_strength("aaaa1234")
        assert any("patron" in issue for issue in issues)


class TestKAnonymity:
    def test_sha1_prefix_only(self, monkeypatch):
        captured_urls = []

        class MockResponse:
            status_code = 200
            text = ""

        def mock_get(url, **kwargs):
            captured_urls.append(url)
            return MockResponse()

        import datasec.breach_scanner as scanner

        monkeypatch.setattr(scanner.requests, "get", mock_get)

        password = "supersecretpassword123"
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        result = check_password(password)

        assert len(captured_urls) == 1
        assert full_hash[:5] in captured_urls[0]
        assert password not in captured_urls[0]
        assert full_hash not in captured_urls[0]
        assert result == 0

    def test_pwned_password_detected(self, monkeypatch):
        password = "password123"
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        suffix = full_hash[5:]

        class MockResponse:
            status_code = 200
            text = f"{suffix}:58247\nABCDE12345:1"

        import datasec.breach_scanner as scanner

        monkeypatch.setattr(scanner.requests, "get", lambda *args, **kwargs: MockResponse())
        assert check_password(password) == 58247

    def test_safe_password_returns_zero(self, monkeypatch):
        class MockResponse:
            status_code = 200
            text = "AAAAA11111:5\nBBBBB22222:3"

        import datasec.breach_scanner as scanner

        monkeypatch.setattr(scanner.requests, "get", lambda *args, **kwargs: MockResponse())
        assert check_password("thispasswordisnotintheresponse!") == 0


class TestEncryptor:
    def test_key_derivation_deterministic(self):
        salt = os.urandom(SALT_SIZE)
        assert _derive_key("mypassword", salt) == _derive_key("mypassword", salt)

    def test_different_salts_produce_different_keys(self):
        salt1 = os.urandom(SALT_SIZE)
        salt2 = os.urandom(SALT_SIZE)
        assert _derive_key("mypassword", salt1) != _derive_key("mypassword", salt2)

    def test_different_passwords_produce_different_keys(self):
        salt = os.urandom(SALT_SIZE)
        assert _derive_key("password1", salt) != _derive_key("password2", salt)

    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        from unittest.mock import patch

        from datasec.encryptor import decrypt_file, encrypt_file

        original = tmp_path / "test.txt"
        encrypted = tmp_path / "test.txt.enc"
        decrypted = tmp_path / "test_dec.txt"
        original.write_text("datos sensibles de prueba 123")

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            decrypt_file(str(encrypted), str(decrypted))

        assert decrypted.read_text() == "datos sensibles de prueba 123"

    def test_wrong_password_fails(self, tmp_path):
        from unittest.mock import patch

        from datasec.encryptor import decrypt_file, encrypt_file

        original = tmp_path / "secret.txt"
        encrypted = tmp_path / "secret.txt.enc"
        decrypted = tmp_path / "secret_dec.txt"
        original.write_text("contenido secreto")

        with patch("datasec.encryptor._get_password", return_value="correctpassword"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        with patch("datasec.encryptor._get_password", return_value="wrongpassword"):
            decrypt_file(str(encrypted), str(decrypted))

        assert not decrypted.exists()

    def test_small_files_use_v2_header(self, tmp_path):
        from unittest.mock import patch

        from datasec.encryptor import encrypt_file

        original = tmp_path / "tiny.txt"
        encrypted = tmp_path / "tiny.txt.enc"
        original.write_text("hello world")

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        assert encrypted.read_bytes().startswith(MAGIC)

    def test_chunked_tamper_is_detected(self, tmp_path):
        from unittest.mock import patch

        from datasec.encryptor import decrypt_file, encrypt_file

        original = tmp_path / "large.bin"
        encrypted = tmp_path / "large.bin.enc"
        decrypted = tmp_path / "large.bin.dec"
        original.write_bytes(b"A" * (CHUNK_SIZE + 1024))

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        raw = bytearray(encrypted.read_bytes())
        raw[-1] ^= 0x01
        encrypted.write_bytes(raw)

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            decrypt_file(str(encrypted), str(decrypted))

        assert not decrypted.exists()
