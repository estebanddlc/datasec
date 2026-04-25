"""
Tests for datasec toolkit.
Run with: pytest tests/
"""

import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Password Auditor tests ─────────────────────────────────────────────────

from datasec.password_auditor import _analyze_strength

class TestPasswordStrength:
    def test_weak_short_password(self):
        strength, issues = _analyze_strength("abc")
        assert strength == "débil"
        assert any("corta" in i for i in issues)

    def test_weak_common_pattern(self):
        strength, issues = _analyze_strength("123456")
        assert strength == "débil"

    def test_weak_only_letters(self):
        strength, issues = _analyze_strength("abcdefgh")
        assert strength in ("débil", "media")

    def test_strong_password(self):
        strength, issues = _analyze_strength("X9#mK2$pL7@nQ4!w")
        assert strength == "fuerte"
        assert issues == []

    def test_medium_password(self):
        strength, issues = _analyze_strength("Password1")
        assert strength in ("media", "débil")

    def test_repeated_chars(self):
        strength, issues = _analyze_strength("aaaa1234")
        assert any("patrón" in i for i in issues)


# ── Breach Scanner k-anonymity tests ──────────────────────────────────────

from datasec.breach_scanner import check_password

class TestKAnonymity:
    def test_sha1_prefix_only(self, monkeypatch):
        """Verifica que NUNCA se envía la contraseña completa — solo 5 chars del hash."""
        captured_urls = []

        class MockResponse:
            status_code = 200
            text = ""  # empty = password not found

        def mock_get(url, **kwargs):
            captured_urls.append(url)
            return MockResponse()

        import datasec.breach_scanner as bs
        monkeypatch.setattr(bs.requests, "get", mock_get)

        password = "supersecretpassword123"
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        result = check_password(password)

        assert len(captured_urls) == 1
        # La URL solo contiene el prefijo de 5 chars, nunca la contraseña ni el hash completo
        assert full_hash[:5] in captured_urls[0]
        assert password not in captured_urls[0]
        assert full_hash not in captured_urls[0]
        assert result == 0

    def test_pwned_password_detected(self, monkeypatch):
        """Verifica que detecta correctamente una contraseña comprometida."""
        password = "password123"
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        suffix = full_hash[5:]

        class MockResponse:
            status_code = 200
            text = f"{suffix}:58247\nABCDE12345:1"

        import datasec.breach_scanner as bs
        monkeypatch.setattr(bs.requests, "get", lambda *a, **kw: MockResponse())

        result = check_password(password)
        assert result == 58247

    def test_safe_password_returns_zero(self, monkeypatch):
        class MockResponse:
            status_code = 200
            text = "AAAAA11111:5\nBBBBB22222:3"  # no match

        import datasec.breach_scanner as bs
        monkeypatch.setattr(bs.requests, "get", lambda *a, **kw: MockResponse())

        result = check_password("thispasswordisnotintheresponse!")
        assert result == 0


# ── Encryptor tests ────────────────────────────────────────────────────────

from datasec.encryptor import _derive_key, SALT_SIZE

class TestEncryptor:
    def test_key_derivation_deterministic(self):
        """Misma contraseña + salt siempre produce la misma clave."""
        import os
        salt = os.urandom(SALT_SIZE)
        key1 = _derive_key("mypassword", salt)
        key2 = _derive_key("mypassword", salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self):
        """Salts distintos producen claves distintas (rainbow table resistance)."""
        import os
        salt1 = os.urandom(SALT_SIZE)
        salt2 = os.urandom(SALT_SIZE)
        key1 = _derive_key("mypassword", salt1)
        key2 = _derive_key("mypassword", salt2)
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self):
        import os
        salt = os.urandom(SALT_SIZE)
        key1 = _derive_key("password1", salt)
        key2 = _derive_key("password2", salt)
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        """Cifrar y descifrar un archivo produce el contenido original."""
        from unittest.mock import patch
        from datasec.encryptor import encrypt_file, decrypt_file

        original = tmp_path / "test.txt"
        original.write_text("datos sensibles de prueba 123")
        encrypted = tmp_path / "test.txt.enc"
        decrypted = tmp_path / "test_dec.txt"

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        with patch("datasec.encryptor._get_password", return_value="TestPass123!"):
            decrypt_file(str(encrypted), str(decrypted))

        assert decrypted.read_text() == "datos sensibles de prueba 123"

    def test_wrong_password_fails(self, tmp_path):
        """Contraseña incorrecta no produce output."""
        from unittest.mock import patch
        from datasec.encryptor import encrypt_file, decrypt_file

        original = tmp_path / "secret.txt"
        original.write_text("contenido secreto")
        encrypted = tmp_path / "secret.txt.enc"
        decrypted = tmp_path / "secret_dec.txt"

        with patch("datasec.encryptor._get_password", return_value="correctpassword"):
            with patch("datasec.encryptor.Confirm.ask", return_value=False):
                encrypt_file(str(original), str(encrypted))

        with patch("datasec.encryptor._get_password", return_value="wrongpassword"):
            decrypt_file(str(encrypted), str(decrypted))

        assert not decrypted.exists()
