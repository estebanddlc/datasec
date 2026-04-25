"""
Hidden volume implementation for deniable encryption.

Design notes:
  - One real password unlocks the sensitive payload.
  - One decoy password unlocks the harmless payload.
  - The volume has a fixed size and stores no plaintext layout metadata.
"""

import getpass
import os
import struct
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel

console = Console()

MAGIC = b"DATASEC_HV_V1"
SALT_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERS = 480_000
KEY_SIZE = 32
HEADER_SIZE = SALT_SIZE * 2 + IV_SIZE * 2
VOLUME_SIZE = 4 * 1024 * 1024
INNER_REGION_SIZE = 512 * 1024
MAX_OUTER_PAYLOAD = VOLUME_SIZE - HEADER_SIZE - INNER_REGION_SIZE - 512
MAX_INNER_PAYLOAD = INNER_REGION_SIZE - 512


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes | None:
    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


def _try_decrypt_region(key: bytes, iv: bytes, region: bytes, max_payload: int) -> bytes | None:
    """Try increasing ciphertext lengths until a valid payload is found."""
    upper = min(len(region), max_payload + 512)
    for block_end in range(16, upper + 1, 16):
        plaintext = _aes_decrypt(key, iv, region[:block_end])
        if plaintext and plaintext[: len(MAGIC)] == MAGIC:
            size = struct.unpack(">I", plaintext[len(MAGIC) : len(MAGIC) + 4])[0]
            return plaintext[len(MAGIC) + 4 : len(MAGIC) + 4 + size]
    return None


def create_volume(real_file: str, decoy_file: str, output_path: str = None):
    real_path = Path(real_file)
    decoy_path = Path(decoy_file)

    if not real_path.exists():
        console.print(f"[red]File not found: {real_file}[/red]")
        return
    if not decoy_path.exists():
        console.print(f"[red]File not found: {decoy_file}[/red]")
        return

    real_data = real_path.read_bytes()
    decoy_data = decoy_path.read_bytes()

    if len(real_data) > MAX_OUTER_PAYLOAD:
        console.print(f"[red]Real file too large. Max: {MAX_OUTER_PAYLOAD // 1024}KB[/red]")
        return
    if len(decoy_data) > MAX_INNER_PAYLOAD:
        console.print(f"[red]Decoy file too large. Max: {MAX_INNER_PAYLOAD // 1024}KB[/red]")
        return

    console.print(
        Panel(
            "[bold]Creating hidden volume[/bold]\n\n"
            "You will set [bold red]two[/bold red] passwords:\n"
            "  [cyan]Real password[/cyan]  -> unlocks sensitive content\n"
            "  [cyan]Decoy password[/cyan] -> unlocks harmless content\n\n"
            f"[dim]Volume is always {VOLUME_SIZE // 1024 // 1024}MB so content size is hidden.[/dim]",
            border_style="cyan",
        )
    )

    console.print("\n[bold]Real password[/bold]:")
    real_pass = getpass.getpass("  Password: ")
    real_pass2 = getpass.getpass("  Confirm:  ")
    if real_pass != real_pass2:
        console.print("[red]Passwords do not match.[/red]")
        return

    console.print("\n[bold]Decoy password[/bold]:")
    decoy_pass = getpass.getpass("  Password: ")
    decoy_pass2 = getpass.getpass("  Confirm:  ")
    if decoy_pass != decoy_pass2:
        console.print("[red]Passwords do not match.[/red]")
        return

    if real_pass == decoy_pass:
        console.print("[red]Real and decoy passwords must be different.[/red]")
        return

    outer_salt = os.urandom(SALT_SIZE)
    inner_salt = os.urandom(SALT_SIZE)
    outer_iv = os.urandom(IV_SIZE)
    inner_iv = os.urandom(IV_SIZE)

    outer_key = _derive_key(real_pass, outer_salt)
    inner_key = _derive_key(decoy_pass, inner_salt)

    outer_pt = MAGIC + struct.pack(">I", len(real_data)) + real_data
    inner_pt = MAGIC + struct.pack(">I", len(decoy_data)) + decoy_data

    outer_ct = _aes_encrypt(outer_key, outer_iv, outer_pt)
    inner_ct = _aes_encrypt(inner_key, inner_iv, inner_pt)

    volume = bytearray(os.urandom(VOLUME_SIZE))

    position = 0
    volume[position : position + SALT_SIZE] = outer_salt
    position += SALT_SIZE
    volume[position : position + SALT_SIZE] = inner_salt
    position += SALT_SIZE
    volume[position : position + IV_SIZE] = outer_iv
    position += IV_SIZE
    volume[position : position + IV_SIZE] = inner_iv

    volume[HEADER_SIZE : HEADER_SIZE + len(outer_ct)] = outer_ct

    inner_start = VOLUME_SIZE - INNER_REGION_SIZE
    volume[inner_start : inner_start + len(inner_ct)] = inner_ct

    out_path = Path(output_path) if output_path else Path(str(real_path) + ".hv")
    out_path.write_bytes(bytes(volume))

    console.print(
        Panel(
            f"[bold green]Hidden volume created[/bold green]\n\n"
            f"  Volume:        [cyan]{out_path}[/cyan]\n"
            f"  Volume size:   {VOLUME_SIZE // 1024 // 1024}MB fixed\n"
            f"  Real payload:  {len(real_data):,} bytes\n"
            f"  Decoy payload: {len(decoy_data):,} bytes\n\n"
            "[yellow]Store both passwords safely.[/yellow]\n"
            "[dim]This protects data at rest, not live memory inspection.[/dim]",
            border_style="green",
        )
    )


def open_volume(volume_path: str, output_path: str = None):
    path = Path(volume_path)
    if not path.exists():
        console.print(f"[red]Volume not found: {volume_path}[/red]")
        return

    console.print(f"\n[bold]Opening volume:[/bold] [cyan]{path.name}[/cyan]\n")
    password = getpass.getpass("  Password: ")

    data = path.read_bytes()

    position = 0
    outer_salt = data[position : position + SALT_SIZE]
    position += SALT_SIZE
    inner_salt = data[position : position + SALT_SIZE]
    position += SALT_SIZE
    outer_iv = data[position : position + IV_SIZE]
    position += IV_SIZE
    inner_iv = data[position : position + IV_SIZE]

    outer_region = data[HEADER_SIZE : VOLUME_SIZE - INNER_REGION_SIZE]
    inner_region = data[VOLUME_SIZE - INNER_REGION_SIZE :]

    outer_key = _derive_key(password, outer_salt)
    content = _try_decrypt_region(outer_key, outer_iv, outer_region, MAX_OUTER_PAYLOAD)
    if content is not None:
        _write_output(content, path, output_path)
        return

    inner_key = _derive_key(password, inner_salt)
    content = _try_decrypt_region(inner_key, inner_iv, inner_region, MAX_INNER_PAYLOAD)
    if content is not None:
        _write_output(content, path, output_path)
        return

    console.print(
        Panel(
            "[bold red]Could not decrypt volume[/bold red]\n\n"
            "  - Wrong password\n"
            "  - File corrupted or modified\n"
            "  - Not a datasec hidden volume",
            border_style="red",
        )
    )


def _write_output(content: bytes, volume_path: Path, output_path: str | None):
    if output_path:
        out_path = Path(output_path)
    else:
        stem = volume_path.stem if volume_path.suffix == ".hv" else volume_path.name
        out_path = volume_path.parent / stem

    out_path.write_bytes(content)
    console.print(
        Panel(
            f"[bold green]Volume opened[/bold green]\n\n"
            f"  Output: [cyan]{out_path}[/cyan]\n"
            f"  Size:   {len(content):,} bytes",
            border_style="green",
        )
    )
