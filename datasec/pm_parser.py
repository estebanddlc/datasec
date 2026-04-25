"""
Módulo 7: Password Manager Parser
Lee exports nativos de Bitwarden, 1Password (1PUX), y KeePass (KDBX/XML).
Normaliza todo a {site, username, password} para el auditor.
"""

import json
import csv
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator
from rich.console import Console

console = Console()


# ── Bitwarden ──────────────────────────────────────────────────────────────

def parse_bitwarden(filepath: str) -> list[dict]:
    """
    Parses Bitwarden JSON export.
    Export path: Settings → Export Vault → File Format: .json
    """
    path = Path(filepath)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    entries = []
    items = data.get("items", [])

    for item in items:
        # type 1 = login
        if item.get("type") != 1:
            continue
        login = item.get("login", {})
        password = login.get("password", "")
        if not password:
            continue

        # Bitwarden stores multiple URIs
        uris = login.get("uris", [])
        site = uris[0].get("uri", item.get("name", "unknown")) if uris else item.get("name", "unknown")

        # Strip protocol for cleaner display
        for prefix in ("https://", "http://", "www."):
            if site.startswith(prefix):
                site = site[len(prefix):]
                break

        entries.append({
            "site":     site[:50],
            "username": login.get("username", ""),
            "password": password,
            "source":   "bitwarden",
        })

    return entries


# ── 1Password ─────────────────────────────────────────────────────────────

def parse_1password(filepath: str) -> list[dict]:
    """
    Parses 1Password .1pux export (ZIP containing export.data as JSON).
    Export path: File → Export → All Items → .1pux format
    """
    path = Path(filepath)
    entries = []

    # .1pux is a ZIP file
    with zipfile.ZipFile(path, "r") as z:
        if "export.data" not in z.namelist():
            console.print("[red]Invalid .1pux file: missing export.data[/red]")
            return []
        with z.open("export.data") as f:
            data = json.load(f)

    accounts = data.get("accounts", [])
    for account in accounts:
        for vault in account.get("vaults", []):
            for item in vault.get("items", []):
                # Skip deleted, trashed
                if item.get("trashed"):
                    continue

                category = item.get("categoryUuid", "")
                overview = item.get("overview", {})
                details  = item.get("details", {})

                # Only login items (001)
                if category != "001":
                    continue

                password = ""
                username = ""

                for field in details.get("loginFields", []):
                    if field.get("designation") == "password":
                        password = field.get("value", "")
                    if field.get("designation") == "username":
                        username = field.get("value", "")

                if not password:
                    # Try sections
                    for section in details.get("sections", []):
                        for field in section.get("fields", []):
                            if field.get("kind") == "concealed":
                                password = field.get("value", {}).get("concealed", "")

                if not password:
                    continue

                site = overview.get("url", overview.get("title", "unknown"))
                for prefix in ("https://", "http://", "www."):
                    if site.startswith(prefix):
                        site = site[len(prefix):]
                        break

                entries.append({
                    "site":     site[:50],
                    "username": username,
                    "password": password,
                    "source":   "1password",
                })

    return entries


# ── KeePass XML ────────────────────────────────────────────────────────────

def parse_keepass_xml(filepath: str) -> list[dict]:
    """
    Parses KeePass XML export (.xml unencrypted).
    Export path: File → Export → KeePass XML (2.x)
    Note: This reads the UNENCRYPTED export. Prefer KDBX for storage.
    """
    path = Path(filepath)
    entries = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        console.print(f"[red]Failed to parse KeePass XML: {e}[/red]")
        return []

    def _get_value(entry_elem: ET.Element, key: str) -> str:
        for string in entry_elem.findall("String"):
            k = string.find("Key")
            v = string.find("Value")
            if k is not None and v is not None and k.text == key:
                return v.text or ""
        return ""

    def _walk_groups(element: ET.Element):
        for entry in element.findall("Entry"):
            password = _get_value(entry, "Password")
            if not password:
                continue
            entries.append({
                "site":     _get_value(entry, "URL") or _get_value(entry, "Title") or "unknown",
                "username": _get_value(entry, "UserName"),
                "password": password,
                "source":   "keepass",
            })
        for group in element.findall("Group"):
            _walk_groups(group)

    # KeePass XML structure: <KeePassFile><Root><Group>...
    root_group = root.find("Root")
    start = root_group if root_group is not None else root
    _walk_groups(start)
    return entries


# ── Auto-detect format ─────────────────────────────────────────────────────

def detect_and_parse(filepath: str) -> tuple[list[dict], str]:
    """
    Auto-detects the password manager format and returns (entries, manager_name).
    Supports: Bitwarden JSON, 1Password 1PUX, KeePass XML.
    """
    path = Path(filepath)
    suffix = path.suffix.lower()

    # 1Password .1pux
    if suffix == ".1pux":
        console.print("[dim]Detected: 1Password export (.1pux)[/dim]")
        return parse_1password(filepath), "1Password"

    # KeePass XML
    if suffix == ".xml":
        console.print("[dim]Detected: KeePass XML export[/dim]")
        return parse_keepass_xml(filepath), "KeePass"

    # JSON — could be Bitwarden or generic
    if suffix == ".json":
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return [], "unknown"

        # Bitwarden signature: has "encrypted" key or "items" list with "type" field
        if "items" in data and isinstance(data["items"], list):
            if data.get("encrypted") is True:
                console.print("[red]This is an encrypted Bitwarden export.[/red]")
                console.print("[dim]Re-export with encryption disabled: Settings → Export Vault → Format: JSON (unencrypted)[/dim]")
                return [], "bitwarden-encrypted"
            console.print("[dim]Detected: Bitwarden JSON export[/dim]")
            return parse_bitwarden(filepath), "Bitwarden"

        return [], "unknown-json"

    # CSV — try as generic (Bitwarden also exports CSV)
    if suffix == ".csv":
        console.print("[dim]Detected: CSV export (generic/Bitwarden)[/dim]")
        return [], "csv"  # falls back to existing password_auditor CSV parser

    return [], "unknown"
