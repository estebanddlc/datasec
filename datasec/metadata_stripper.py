"""
Módulo 9: Metadata Stripper
Extrae y elimina metadatos de archivos antes de cifrarlos o compartirlos.
Soporta: PDF, JPEG/PNG/TIFF (EXIF), DOCX/XLSX/PPTX (Office XML)
Puede encadenar strip → encrypt en un solo comando.
"""

import os
import io
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule

console = Console()

# ── Metadata extraction ────────────────────────────────────────────────────

def _extract_pdf_metadata(path: Path) -> dict:
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        meta = reader.metadata or {}
        return {k.lstrip("/"): str(v) for k, v in meta.items() if v}
    except Exception as e:
        return {"error": str(e)}


def _extract_image_metadata(path: Path) -> dict:
    results = {}
    try:
        import exifread
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        for tag, val in tags.items():
            results[tag] = str(val)
    except Exception:
        pass

    # Also try Pillow for basic info
    try:
        from PIL import Image
        img = Image.open(path)
        info = img.info
        for k, v in info.items():
            if k not in ("exif", "icc_profile", "photoshop"):
                results[f"PIL:{k}"] = str(v)
    except Exception:
        pass

    return results


def _extract_office_metadata(path: Path) -> dict:
    """Extracts metadata from DOCX/XLSX/PPTX (all are ZIP+XML)."""
    results = {}
    try:
        with zipfile.ZipFile(path, "r") as z:
            # Core properties
            if "docProps/core.xml" in z.namelist():
                import xml.etree.ElementTree as ET
                xml = z.read("docProps/core.xml").decode("utf-8", errors="replace")
                root = ET.fromstring(xml)
                ns = {
                    "dc":      "http://purl.org/dc/elements/1.1/",
                    "cp":      "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dcterms": "http://purl.org/dc/terms/",
                }
                fields = [
                    ("dc:creator",          "Creator"),
                    ("cp:lastModifiedBy",   "Last Modified By"),
                    ("dcterms:created",     "Created"),
                    ("dcterms:modified",    "Modified"),
                    ("cp:revision",         "Revision"),
                    ("dc:description",      "Description"),
                    ("dc:subject",          "Subject"),
                ]
                for xpath, label in fields:
                    prefix, tag = xpath.split(":")
                    elem = root.find(f"{{{ns[prefix]}}}{tag}")
                    if elem is not None and elem.text:
                        results[label] = elem.text

            # App properties
            if "docProps/app.xml" in z.namelist():
                import xml.etree.ElementTree as ET
                xml = z.read("docProps/app.xml").decode("utf-8", errors="replace")
                root = ET.fromstring(xml)
                ns_app = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
                for child in root:
                    tag = child.tag.replace(f"{{{ns_app}}}", "")
                    if child.text and tag in ("Application", "Company", "Template", "Manager"):
                        results[tag] = child.text

    except Exception as e:
        results["error"] = str(e)
    return results


def extract_metadata(filepath: str) -> dict:
    path = Path(filepath)
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _extract_pdf_metadata(path)
    elif suffix in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".heic", ".webp"):
        return _extract_image_metadata(path)
    elif suffix in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"):
        return _extract_office_metadata(path)
    else:
        return {}


# ── Metadata display ───────────────────────────────────────────────────────

SENSITIVE_KEYS = {
    "author", "creator", "producer", "lastmodifiedby", "last modified by",
    "company", "manager", "template", "revision",
    "image unique id", "exif imageuniqueId",
    "gps gpslatitude", "gps gpslongitude", "gps gpsaltitude",
    "gps", "make", "model",                     # camera make/model
    "software",                                  # software used
    "xp author", "xp comment",
}

def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in SENSITIVE_KEYS) or "gps" in k


def display_metadata(filepath: str) -> dict:
    path = Path(filepath)
    meta = extract_metadata(filepath)

    if not meta:
        console.print(f"[green]✓ No extractable metadata found in {path.name}[/green]")
        return {}

    sensitive_count = sum(1 for k in meta if _is_sensitive(k))

    color = "red" if sensitive_count > 0 else "yellow"
    console.print(Panel(
        f"[bold {color}]{'⚠ ' if sensitive_count else ''}{len(meta)} metadata fields found"
        f"{f', {sensitive_count} sensitive' if sensitive_count else ''}[/bold {color}]",
        title=f"[bold]Metadata: {path.name}[/bold]",
        border_style=color
    ))

    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
    table.add_column("Field", min_width=28)
    table.add_column("Value", min_width=40)
    table.add_column("Risk", min_width=8)

    for key, value in sorted(meta.items()):
        val_display = str(value)[:80] + ("..." if len(str(value)) > 80 else "")
        if _is_sensitive(key):
            risk = "[red]HIGH[/red]"
            key_display = f"[red]{key}[/red]"
        else:
            risk = "[dim]low[/dim]"
            key_display = f"[dim]{key}[/dim]"
        table.add_row(key_display, val_display, risk)

    console.print(table)
    return meta


# ── Metadata stripping ─────────────────────────────────────────────────────

def _strip_pdf(path: Path, out_path: Path) -> bool:
    try:
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(str(path))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # Write with blank metadata
        writer.add_metadata({})

        with open(out_path, "wb") as f:
            writer.write(f)
        return True
    except Exception as e:
        console.print(f"[red]PDF strip error: {e}[/red]")
        return False


def _strip_image(path: Path, out_path: Path) -> bool:
    try:
        from PIL import Image
        img = Image.open(path)

        # Create new image without EXIF
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)

        # Preserve format
        fmt = img.format or "JPEG"
        save_kwargs = {}
        if fmt in ("JPEG", "JPG"):
            save_kwargs["quality"] = 95
            save_kwargs["optimize"] = True

        clean.save(str(out_path), format=fmt, **save_kwargs)
        return True
    except Exception as e:
        console.print(f"[red]Image strip error: {e}[/red]")
        return False


def _strip_office(path: Path, out_path: Path) -> bool:
    """
    Strips metadata from DOCX/XLSX/PPTX by rewriting the full ZIP.
    Using append mode leaves old entries readable by forensic tools —
    we rewrite every entry to guarantee the original metadata is gone.
    """
    blank_core = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>
</cp:coreProperties>'''.format(now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    blank_app = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
</Properties>'''

    try:
        with zipfile.ZipFile(path, "r") as src:
            # Write a brand new ZIP — every entry is rewritten from scratch
            # This guarantees no old metadata entry survives anywhere in the file
            with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename == "docProps/core.xml":
                        dst.writestr(item, blank_core)
                    elif item.filename == "docProps/app.xml":
                        dst.writestr(item, blank_app)
                    else:
                        dst.writestr(item, src.read(item.filename))
        return True
    except Exception as e:
        console.print(f"[red]Office strip error: {e}[/red]")
        return False


def strip_metadata(filepath: str, output_path: str = None, then_encrypt: bool = False) -> str | None:
    """
    Strip all metadata from a file. Returns output path.
    If then_encrypt=True, pipes result into encryptor.
    """
    path   = Path(filepath)
    suffix = path.suffix.lower()

    if output_path:
        out_path = Path(output_path)
    else:
        out_path = path.parent / (path.stem + "_clean" + path.suffix)

    console.print(f"\n[bold]🧹 Stripping metadata:[/bold] [cyan]{path.name}[/cyan]")

    # Show before
    meta_before = extract_metadata(filepath)

    success = False
    if suffix == ".pdf":
        success = _strip_pdf(path, out_path)
    elif suffix in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"):
        success = _strip_image(path, out_path)
    elif suffix in (".docx", ".xlsx", ".pptx"):
        success = _strip_office(path, out_path)
    else:
        console.print(f"[yellow]No metadata stripper for {suffix} files.[/yellow]")
        console.print("[dim]Supported: PDF, JPEG, PNG, TIFF, DOCX, XLSX, PPTX[/dim]")
        return None

    if not success:
        return None

    meta_after = extract_metadata(str(out_path))
    removed = len(meta_before) - len(meta_after)

    console.print(Panel(
        f"[bold green]✓ Metadata stripped[/bold green]\n\n"
        f"  Output:          [cyan]{out_path}[/cyan]\n"
        f"  Fields removed:  {max(removed, 0)} of {len(meta_before)}\n"
        f"  Fields remaining: {len(meta_after)}",
        border_style="green"
    ))

    if then_encrypt:
        console.print("\n[dim]Piping to encryptor...[/dim]")
        from datasec.encryptor import encrypt_file
        encrypt_file(str(out_path))

    return str(out_path)
