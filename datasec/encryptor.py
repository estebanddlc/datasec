"""
Modulo 2: Encryptor
Cifrado AES-256 de archivos con Fernet (cryptography library).
La clave se deriva de una contrasena con PBKDF2-HMAC-SHA256 + salt aleatorio.
"""

import base64
import getpass
import hmac
import os
import struct
from hashlib import sha256
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm

console = Console()

LEGACY_MAGIC = b"DATASEC_ENC_V1:"
MAGIC = b"DATASEC_ENC_V2:"
MODE_SINGLE = b"S"
MODE_CHUNKED = b"C"
SALT_SIZE = 32
ITERATIONS = 480_000
CHUNK_SIZE = 64 * 1024 * 1024
MAC_SIZE = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 desde una contrasena usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _get_password(confirm: bool = False) -> str:
    """Solicita contrasena de forma segura sin mostrarla en pantalla."""
    password = getpass.getpass("  Encryption password: ")
    if not password:
        console.print("[red]La contrasena no puede estar vacia.[/red]")
        raise SystemExit(1)
    if confirm:
        password2 = getpass.getpass("  Confirm password: ")
        if password != password2:
            console.print("[red]Las contrasenas no coinciden.[/red]")
            raise SystemExit(1)
    return password


def _derive_chunk_mac_key(key: bytes) -> bytes:
    return sha256(key + b":datasec-chunk-mac:v2").digest()


def _chunk_mac(mac_key: bytes, index: int, ciphertext: bytes) -> bytes:
    payload = struct.pack(">II", index, len(ciphertext)) + ciphertext
    return hmac.new(mac_key, payload, sha256).digest()


def _encrypt_small_file(path: Path, out_path: Path, fernet: Fernet, salt: bytes):
    with open(path, "rb") as source:
        data = source.read()
    encrypted = fernet.encrypt(data)
    with open(out_path, "wb") as target:
        target.write(MAGIC)
        target.write(salt)
        target.write(MODE_SINGLE)
        target.write(encrypted)


def _encrypt_large_file(path: Path, out_path: Path, fernet: Fernet, salt: bytes, mac_key: bytes):
    with open(path, "rb") as source, open(out_path, "wb") as target:
        target.write(MAGIC)
        target.write(salt)
        target.write(MODE_CHUNKED)
        target.write(struct.pack(">I", 0))  # chunk_count placeholder

        chunk_count = 0
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            ciphertext = fernet.encrypt(chunk)
            mac = _chunk_mac(mac_key, chunk_count, ciphertext)
            target.write(struct.pack(">I", len(ciphertext)))
            target.write(ciphertext)
            target.write(mac)
            chunk_count += 1

        target.seek(len(MAGIC) + SALT_SIZE + len(MODE_CHUNKED))
        target.write(struct.pack(">I", chunk_count))


def encrypt_file(input_path: str, output_path: str = None):
    path = Path(input_path)

    with open(path, "rb") as handle:
        header = handle.read(max(len(MAGIC), len(LEGACY_MAGIC)))
    if header.startswith(MAGIC) or header.startswith(LEGACY_MAGIC):
        console.print("[yellow]This file is already encrypted with datasec.[/yellow]")
        return

    out_path = Path(output_path) if output_path else path.with_suffix(path.suffix + ".enc")

    console.print(f"\n[bold]Encrypting:[/bold] [cyan]{path.name}[/cyan]")
    console.print(f"[dim]   Output: {out_path}[/dim]\n")

    password = _get_password(confirm=True)
    file_size = path.stat().st_size

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Deriving key (PBKDF2-SHA256)...", total=None)

        salt = os.urandom(SALT_SIZE)
        key = _derive_key(password, salt)
        fernet = Fernet(key)

        progress.update(task, description="Encrypting...")

        if file_size <= CHUNK_SIZE:
            _encrypt_small_file(path, out_path, fernet, salt)
        else:
            _encrypt_large_file(path, out_path, fernet, salt, _derive_chunk_mac_key(key))

        progress.update(task, description="Done.")

    enc_size = out_path.stat().st_size
    mode = "streamed + per-chunk integrity" if file_size > CHUNK_SIZE else "single-pass"
    console.print(
        Panel(
            f"[bold green]File encrypted successfully[/bold green]\n\n"
            f"  Encrypted file:  [cyan]{out_path}[/cyan]\n"
            f"  Original size:   {file_size:,} bytes\n"
            f"  Encrypted size:  {enc_size:,} bytes\n"
            f"  Format:          datasec v2 ({mode})\n"
            f"  Algorithm:       AES-256-CBC (Fernet)\n"
            f"  KDF:             PBKDF2-HMAC-SHA256 ({ITERATIONS:,} iterations)\n\n"
            f"[yellow]If you lose the password, the file is unrecoverable.[/yellow]",
            title="Encryption complete",
            border_style="green",
        )
    )

    if Confirm.ask("\n  [yellow]Delete the original file?[/yellow]", default=False):
        path.unlink()
        console.print(f"  [dim]{path.name} deleted[/dim]")


def _decrypt_legacy(remainder: bytes, password: str, salt: bytes) -> bytes:
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    try:
        num_chunks = struct.unpack(">I", remainder[:4])[0]
    except struct.error:
        num_chunks = 0

    if 1 < num_chunks <= 1000:
        try:
            offset = 4
            chunks = []
            for _ in range(num_chunks):
                clen = struct.unpack(">I", remainder[offset:offset + 4])[0]
                offset += 4
                chunk_ct = remainder[offset:offset + clen]
                offset += clen
                chunks.append(fernet.decrypt(chunk_ct))
            return b"".join(chunks)
        except Exception:
            return fernet.decrypt(remainder)

    return fernet.decrypt(remainder)


def _decrypt_v2_stream(handle, password: str, salt: bytes) -> bytes:
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    mode = handle.read(1)

    if mode == MODE_SINGLE:
        return fernet.decrypt(handle.read())

    if mode != MODE_CHUNKED:
        raise ValueError("Unknown encryption mode")

    chunk_count_raw = handle.read(4)
    if len(chunk_count_raw) != 4:
        raise ValueError("Missing chunk count")
    chunk_count = struct.unpack(">I", chunk_count_raw)[0]
    mac_key = _derive_chunk_mac_key(key)

    chunks = []
    for index in range(chunk_count):
        chunk_len_raw = handle.read(4)
        if len(chunk_len_raw) != 4:
            raise ValueError("Unexpected end of file while reading chunk length")
        chunk_len = struct.unpack(">I", chunk_len_raw)[0]
        ciphertext = handle.read(chunk_len)
        mac = handle.read(MAC_SIZE)
        if len(ciphertext) != chunk_len or len(mac) != MAC_SIZE:
            raise ValueError("Unexpected end of file while reading chunk payload")
        expected_mac = _chunk_mac(mac_key, index, ciphertext)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Chunk integrity verification failed")
        chunks.append(fernet.decrypt(ciphertext))

    trailing = handle.read(1)
    if trailing:
        raise ValueError("Encrypted file has trailing bytes")

    return b"".join(chunks)


def decrypt_file(input_path: str, output_path: str = None):
    path = Path(input_path)

    with open(path, "rb") as handle:
        header = handle.read(max(len(MAGIC), len(LEGACY_MAGIC)))

    if header.startswith(MAGIC):
        magic = MAGIC
    elif header.startswith(LEGACY_MAGIC):
        magic = LEGACY_MAGIC
    else:
        console.print("[red]This file was not encrypted with datasec or is corrupted.[/red]")
        return

    if output_path:
        out_path = Path(output_path)
    else:
        name = path.stem if path.suffix == ".enc" else path.name + ".dec"
        out_path = path.parent / name

    console.print(f"\n[bold]Decrypting:[/bold] [cyan]{path.name}[/cyan]")
    console.print(f"[dim]   Output: {out_path}[/dim]\n")

    password = _get_password(confirm=False)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Deriving key...", total=None)

            with open(path, "rb") as handle:
                handle.read(len(magic))
                salt = handle.read(SALT_SIZE)
                progress.update(task, description="Decrypting...")

                if magic == LEGACY_MAGIC:
                    data = _decrypt_legacy(handle.read(), password, salt)
                else:
                    data = _decrypt_v2_stream(handle, password, salt)

            with open(out_path, "wb") as target:
                target.write(data)

        console.print(
            Panel(
                f"[bold green]File decrypted successfully[/bold green]\n\n"
                f"  Decrypted file: [cyan]{out_path}[/cyan]\n"
                f"  Size:           {len(data):,} bytes",
                border_style="green",
            )
        )

    except Exception:
        console.print(
            Panel(
                "[bold red]Decryption failed[/bold red]\n\n"
                "Possible causes:\n"
                "  - Wrong password\n"
                "  - File corrupted or modified\n"
                "  - File not encrypted with this tool",
                border_style="red",
            )
        )
        if out_path.exists():
            out_path.unlink()
