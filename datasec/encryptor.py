"""
Módulo 2: Encryptor
Cifrado AES-256 de archivos con Fernet (cryptography library)
La clave se deriva de una contraseña con PBKDF2-HMAC-SHA256 + salt aleatorio
"""

import os
import struct
import getpass
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

console = Console()

MAGIC = b"DATASEC_ENC_V1:"  # Header para identificar archivos cifrados
SALT_SIZE = 32
ITERATIONS = 480_000  # OWASP 2023 recommendation para PBKDF2-SHA256


def _derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 desde una contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _get_password(confirm: bool = False) -> str:
    """Solicita contraseña de forma segura sin mostrarla en pantalla."""
    password = getpass.getpass("  🔑 Contraseña de cifrado: ")
    if not password:
        console.print("[red]La contraseña no puede estar vacía.[/red]")
        raise SystemExit(1)
    if confirm:
        password2 = getpass.getpass("  🔑 Confirma contraseña: ")
        if password != password2:
            console.print("[red]Las contraseñas no coinciden.[/red]")
            raise SystemExit(1)
    return password


def encrypt_file(input_path: str, output_path: str = None):
    path = Path(input_path)

    # Verify not already encrypted
    with open(path, "rb") as f:
        header = f.read(len(MAGIC))
    if header == MAGIC:
        console.print("[yellow]⚠ This file is already encrypted with datasec.[/yellow]")
        return

    out_path = Path(output_path) if output_path else path.with_suffix(path.suffix + ".enc")

    console.print(f"\n[bold]🔒 Encrypting:[/bold] [cyan]{path.name}[/cyan]")
    console.print(f"[dim]   Output: {out_path}[/dim]\n")

    password = _get_password(confirm=True)
    file_size = path.stat().st_size

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  transient=True) as progress:
        task = progress.add_task("Deriving key (PBKDF2-SHA256)...", total=None)

        salt = os.urandom(SALT_SIZE)
        key  = _derive_key(password, salt)
        fernet = Fernet(key)

        progress.update(task, description="Encrypting...")

        # Stream large files in chunks to avoid loading GBs into memory
        CHUNK = 64 * 1024 * 1024  # 64MB chunks

        if file_size <= CHUNK:
            # Small file — single pass
            with open(path, "rb") as f:
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(out_path, "wb") as f:
                f.write(MAGIC)
                f.write(salt)
                f.write(encrypted)
        else:
            # Large file — encrypt in chunks, each chunk independently
            # Format: MAGIC | salt | num_chunks(4B) | [chunk_len(4B) | chunk_ct]...
            chunks = []
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    chunks.append(fernet.encrypt(chunk))

            with open(out_path, "wb") as f:
                f.write(MAGIC)
                f.write(salt)
                f.write(struct.pack(">I", len(chunks)))
                for chunk_ct in chunks:
                    f.write(struct.pack(">I", len(chunk_ct)))
                    f.write(chunk_ct)

        progress.update(task, description="Done.")

    enc_size = out_path.stat().st_size
    console.print(Panel(
        f"[bold green]✓ File encrypted successfully[/bold green]\n\n"
        f"  Encrypted file:  [cyan]{out_path}[/cyan]\n"
        f"  Original size:   {file_size:,} bytes\n"
        f"  Encrypted size:  {enc_size:,} bytes\n"
        f"  Algorithm:       AES-256-CBC (Fernet)\n"
        f"  KDF:             PBKDF2-HMAC-SHA256 ({ITERATIONS:,} iterations)\n\n"
        f"[yellow]⚠ If you lose the password, the file is unrecoverable.[/yellow]",
        title="Encryption complete", border_style="green"
    ))

    if Confirm.ask("\n  [yellow]Delete the original file?[/yellow]", default=False):
        path.unlink()
        console.print(f"  [dim]✓ {path.name} deleted[/dim]")


def decrypt_file(input_path: str, output_path: str = None):
    path = Path(input_path)

    with open(path, "rb") as f:
        header = f.read(len(MAGIC))

    if header != MAGIC:
        console.print("[red]This file was not encrypted with datasec or is corrupted.[/red]")
        return

    if output_path:
        out_path = Path(output_path)
    else:
        name = path.stem if path.suffix == ".enc" else path.name + ".dec"
        out_path = path.parent / name

    console.print(f"\n[bold]🔓 Decrypting:[/bold] [cyan]{path.name}[/cyan]")
    console.print(f"[dim]   Output: {out_path}[/dim]\n")

    password = _get_password(confirm=False)

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      transient=True) as progress:
            task = progress.add_task("Deriving key...", total=None)

            with open(path, "rb") as f:
                f.read(len(MAGIC))          # skip magic
                salt      = f.read(SALT_SIZE)
                remainder = f.read()

            key    = _derive_key(password, salt)
            fernet = Fernet(key)

            progress.update(task, description="Decrypting...")

            # Detect chunked format: starts with a 4-byte chunk count
            # that when interpreted as big-endian uint32 is a plausible small number
            try:
                num_chunks = struct.unpack(">I", remainder[:4])[0]
            except struct.error:
                num_chunks = 0

            if 1 < num_chunks <= 1000:
                # Try chunked format
                try:
                    offset = 4
                    chunks = []
                    for _ in range(num_chunks):
                        clen = struct.unpack(">I", remainder[offset:offset+4])[0]
                        offset += 4
                        chunk_ct = remainder[offset:offset+clen]
                        offset  += clen
                        chunks.append(fernet.decrypt(chunk_ct))
                    data = b"".join(chunks)
                except Exception:
                    # Not actually chunked — fall through to single-pass
                    data = fernet.decrypt(remainder)
            else:
                data = fernet.decrypt(remainder)

            with open(out_path, "wb") as f:
                f.write(data)

        console.print(Panel(
            f"[bold green]✓ File decrypted successfully[/bold green]\n\n"
            f"  Decrypted file: [cyan]{out_path}[/cyan]\n"
            f"  Size:           {len(data):,} bytes",
            border_style="green"
        ))

    except Exception:
        console.print(Panel(
            "[bold red]✗ Decryption failed[/bold red]\n\n"
            "Possible causes:\n"
            "  • Wrong password\n"
            "  • File corrupted or modified\n"
            "  • File not encrypted with this tool",
            border_style="red"
        ))
        if out_path.exists():
            out_path.unlink()
