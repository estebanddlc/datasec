"""
Módulo: Hidden Volume (Deniable Encryption)

Implementación honesta de negación plausible:
  - Una contraseña "real"   → descifra contenido sensible (outer region)
  - Una contraseña "señuelo" → descifra contenido inocente (inner region)

DISEÑO — por qué esto es diferente al v1:
  El volumen tiene tamaño FIJO (4MB). No se almacena ningún metadato en
  cleartext (ni padding_len, ni tamaños, ni markers). El volumen completo
  parece datos aleatorios.

  Layout:
    [header: outer_salt(32) inner_salt(32) outer_iv(16) inner_iv(16)]
    [outer region: HEADER_SIZE → VOLUME_SIZE-INNER_REGION_SIZE] ← real content aquí
    [inner region: VOLUME_SIZE-INNER_REGION_SIZE → VOLUME_SIZE]  ← decoy content aquí
    Todo el espacio no usado es ruido aleatorio generado en la creación.

  Para abrir: se prueba la contraseña en la región outer y luego en la inner.
  El atacante ve 4MB de datos que parecen aleatorios. No puede saber cuál
  región tiene contenido real porque ambas tienen ciphertext válido rodeado
  de ruido. El tamaño del volumen no revela el tamaño del contenido.

LIMITACIÓN DOCUMENTADA (honesta):
  Esto protege contra un atacante que solo tiene el archivo en reposo.
  No protege contra análisis forense de RAM en ejecución ni contra
  observación del proceso. Para threat models más severos: VeraCrypt.
"""

import os
import struct
import getpass
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend

console = Console()

MAGIC             = b"DATASEC_HV_V1"   # 13 bytes — inside plaintext, never visible in volume
SALT_SIZE         = 32
IV_SIZE           = 16
PBKDF2_ITERS      = 480_000
KEY_SIZE          = 32
HEADER_SIZE       = SALT_SIZE * 2 + IV_SIZE * 2   # 96 bytes
VOLUME_SIZE       = 4 * 1024 * 1024               # 4MB fixed
INNER_REGION_SIZE = 512 * 1024                    # 512KB for inner/decoy content
MAX_OUTER_PAYLOAD = VOLUME_SIZE - HEADER_SIZE - INNER_REGION_SIZE - 512
MAX_INNER_PAYLOAD = INNER_REGION_SIZE - 512


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def _aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes | None:
    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


def _try_decrypt_region(key: bytes, iv: bytes, region: bytes) -> bytes | None:
    """Try to decrypt blocks of increasing size until MAGIC is found."""
    for block_end in range(16, min(len(region), MAX_OUTER_PAYLOAD + 512) + 1, 16):
        pt = _aes_decrypt(key, iv, region[:block_end])
        if pt and pt[:13] == MAGIC:
            size = struct.unpack(">I", pt[13:17])[0]
            return pt[17:17 + size]
    return None


# ── Public API ─────────────────────────────────────────────────────────────

def create_volume(real_file: str, decoy_file: str, output_path: str = None):
    real_path  = Path(real_file)
    decoy_path = Path(decoy_file)

    if not real_path.exists():
        console.print(f"[red]File not found: {real_file}[/red]")
        return
    if not decoy_path.exists():
        console.print(f"[red]File not found: {decoy_file}[/red]")
        return

    real_data  = real_path.read_bytes()
    decoy_data = decoy_path.read_bytes()

    if len(real_data) > MAX_OUTER_PAYLOAD:
        console.print(f"[red]Real file too large. Max: {MAX_OUTER_PAYLOAD // 1024}KB[/red]")
        return
    if len(decoy_data) > MAX_INNER_PAYLOAD:
        console.print(f"[red]Decoy file too large. Max: {MAX_INNER_PAYLOAD // 1024}KB[/red]")
        return

    console.print(Panel(
        "[bold]Creating hidden volume[/bold]\n\n"
        "You will set [bold red]TWO[/bold red] passwords:\n"
        "  [cyan]Real password[/cyan]  → unlocks your sensitive content\n"
        "  [cyan]Decoy password[/cyan] → unlocks an innocent-looking file\n\n"
        f"[dim]Volume is always {VOLUME_SIZE // 1024 // 1024}MB — content size is not revealed.[/dim]",
        border_style="cyan"
    ))

    console.print("\n[bold]Real password[/bold]:")
    real_pass  = getpass.getpass("  Password: ")
    real_pass2 = getpass.getpass("  Confirm:  ")
    if real_pass != real_pass2:
        console.print("[red]Passwords do not match.[/red]")
        return

    console.print("\n[bold]Decoy password[/bold]:")
    decoy_pass  = getpass.getpass("  Password: ")
    decoy_pass2 = getpass.getpass("  Confirm:  ")
    if decoy_pass != decoy_pass2:
        console.print("[red]Passwords do not match.[/red]")
        return

    if real_pass == decoy_pass:
        console.print("[red]Real and decoy passwords must be different.[/red]")
        return

    outer_salt = os.urandom(SALT_SIZE)
    inner_salt = os.urandom(SALT_SIZE)
    outer_iv   = os.urandom(IV_SIZE)
    inner_iv   = os.urandom(IV_SIZE)

    outer_key  = _derive_key(real_pass,  outer_salt)
    inner_key  = _derive_key(decoy_pass, inner_salt)

    outer_pt   = MAGIC + struct.pack(">I", len(real_data))  + real_data
    inner_pt   = MAGIC + struct.pack(">I", len(decoy_data)) + decoy_data

    outer_ct   = _aes_encrypt(outer_key, outer_iv, outer_pt)
    inner_ct   = _aes_encrypt(inner_key, inner_iv, inner_pt)

    # Build fixed-size volume — start with random noise
    volume = bytearray(os.urandom(VOLUME_SIZE))

    # Header at byte 0 (salts + IVs only)
    pos = 0
    volume[pos:pos+SALT_SIZE] = outer_salt; pos += SALT_SIZE
    volume[pos:pos+SALT_SIZE] = inner_salt; pos += SALT_SIZE
    volume[pos:pos+IV_SIZE]   = outer_iv;   pos += IV_SIZE
    volume[pos:pos+IV_SIZE]   = inner_iv

    # Outer ciphertext immediately after header
    volume[HEADER_SIZE:HEADER_SIZE + len(outer_ct)] = outer_ct

    # Inner ciphertext at start of inner region (end of volume)
    inner_start = VOLUME_SIZE - INNER_REGION_SIZE
    volume[inner_start:inner_start + len(inner_ct)] = inner_ct

    out_path = Path(output_path) if output_path else Path(str(real_path) + ".hv")
    out_path.write_bytes(bytes(volume))

    console.print(Panel(
        f"[bold green]✓ Hidden volume created[/bold green]\n\n"
        f"  Volume:        [cyan]{out_path}[/cyan]\n"
        f"  Volume size:   {VOLUME_SIZE // 1024 // 1024}MB (fixed — content size hidden)\n"
        f"  Real payload:  {len(real_data):,} bytes\n"
        f"  Decoy payload: {len(decoy_data):,} bytes\n\n"
        f"[yellow]Store both passwords safely. Losing either means losing that content.[/yellow]\n"
        f"[dim]Limitation: protects files at rest. Not RAM-forensic resistant.[/dim]",
        border_style="green"
    ))


def open_volume(volume_path: str, output_path: str = None):
    path = Path(volume_path)
    if not path.exists():
        console.print(f"[red]Volume not found: {volume_path}[/red]")
        return

    console.print(f"\n[bold]🔓 Opening volume:[/bold] [cyan]{path.name}[/cyan]\n")
    password = getpass.getpass("  Password: ")

    data = path.read_bytes()

    # Parse header
    pos = 0
    outer_salt = data[pos:pos+SALT_SIZE]; pos += SALT_SIZE
    inner_salt = data[pos:pos+SALT_SIZE]; pos += SALT_SIZE
    outer_iv   = data[pos:pos+IV_SIZE];   pos += IV_SIZE
    inner_iv   = data[pos:pos+IV_SIZE]

    outer_region = data[HEADER_SIZE:VOLUME_SIZE - INNER_REGION_SIZE]
    inner_region = data[VOLUME_SIZE - INNER_REGION_SIZE:]

    # Try outer region with this password
    outer_key = _derive_key(password, outer_salt)
    content   = _try_decrypt_region(outer_key, outer_iv, outer_region)
    if content is not None:
        _write_output(content, path, output_path)
        return

    # Try inner region with this password
    inner_key = _derive_key(password, inner_salt)
    content   = _try_decrypt_region(inner_key, inner_iv, inner_region)
    if content is not None:
        _write_output(content, path, output_path)
        return

    console.print(Panel(
        "[bold red]✗ Could not decrypt volume[/bold red]\n\n"
        "  • Wrong password\n"
        "  • File corrupted or modified\n"
        "  • Not a datasec hidden volume",
        border_style="red"
    ))


def _write_output(content: bytes, volume_path: Path, output_path: str | None):
    if output_path:
        out = Path(output_path)
    else:
        stem = volume_path.stem if volume_path.suffix == ".hv" else volume_path.name
        out  = volume_path.parent / stem
    out.write_bytes(content)
    console.print(Panel(
        f"[bold green]✓ Volume opened[/bold green]\n\n"
        f"  Output: [cyan]{out}[/cyan]\n"
        f"  Size:   {len(content):,} bytes",
        border_style="green"
    ))
