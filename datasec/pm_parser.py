"""
Module 7: Password Manager Parser
Reads native exports from Bitwarden, 1Password (.1pux), and KeePass XML.
Normalizes them into {site, username, password} rows for the auditor.
"""

import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from rich.console import Console

console = Console()


def parse_bitwarden(filepath: str) -> list[dict]:
    """Parse a Bitwarden JSON export."""
    path = Path(filepath)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    entries = []
    for item in data.get("items", []):
        if item.get("type") != 1:
            continue
        login = item.get("login", {})
        password = login.get("password", "")
        if not password:
            continue

        uris = login.get("uris", [])
        site = uris[0].get("uri", item.get("name", "unknown")) if uris else item.get("name", "unknown")
        for prefix in ("https://", "http://", "www."):
            if site.startswith(prefix):
                site = site[len(prefix):]
                break

        entries.append(
            {
                "site": site[:50],
                "username": login.get("username", ""),
                "password": password,
                "source": "bitwarden",
            }
        )

    return entries


def parse_1password(filepath: str) -> list[dict]:
    """Parse a 1Password .1pux export."""
    path = Path(filepath)
    entries = []

    with zipfile.ZipFile(path, "r") as archive:
        if "export.data" not in archive.namelist():
            console.print("[red]Invalid .1pux file: missing export.data[/red]")
            return []
        with archive.open("export.data") as handle:
            data = json.load(handle)

    for account in data.get("accounts", []):
        for vault in account.get("vaults", []):
            for item in vault.get("items", []):
                if item.get("trashed"):
                    continue

                if item.get("categoryUuid", "") != "001":
                    continue

                overview = item.get("overview", {})
                details = item.get("details", {})
                password = ""
                username = ""

                for field in details.get("loginFields", []):
                    if field.get("designation") == "password":
                        password = field.get("value", "")
                    if field.get("designation") == "username":
                        username = field.get("value", "")

                if not password:
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

                entries.append(
                    {
                        "site": site[:50],
                        "username": username,
                        "password": password,
                        "source": "1password",
                    }
                )

    return entries


def parse_keepass_xml(filepath: str) -> list[dict]:
    """Parse an unencrypted KeePass XML export."""
    path = Path(filepath)
    entries = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as exc:
        console.print(f"[red]Failed to parse KeePass XML: {exc}[/red]")
        return []

    def _get_value(entry_elem: ET.Element, key: str) -> str:
        for string in entry_elem.findall("String"):
            key_elem = string.find("Key")
            value_elem = string.find("Value")
            if key_elem is not None and value_elem is not None and key_elem.text == key:
                return value_elem.text or ""
        return ""

    def _walk_groups(element: ET.Element):
        for entry in element.findall("Entry"):
            password = _get_value(entry, "Password")
            if not password:
                continue
            entries.append(
                {
                    "site": _get_value(entry, "URL") or _get_value(entry, "Title") or "unknown",
                    "username": _get_value(entry, "UserName"),
                    "password": password,
                    "source": "keepass",
                }
            )
        for group in element.findall("Group"):
            _walk_groups(group)

    start = root.find("Root")
    _walk_groups(start if start is not None else root)
    return entries


def detect_and_parse(filepath: str) -> tuple[list[dict], str]:
    """Auto-detect a supported password export format."""
    path = Path(filepath)
    suffix = path.suffix.lower()

    if suffix == ".1pux":
        console.print("[dim]Detected: 1Password export (.1pux)[/dim]")
        return parse_1password(filepath), "1Password"

    if suffix == ".xml":
        console.print("[dim]Detected: KeePass XML export[/dim]")
        return parse_keepass_xml(filepath), "KeePass"

    if suffix == ".json":
        with open(path, encoding="utf-8") as handle:
            try:
                data = json.load(handle)
            except json.JSONDecodeError:
                return [], "unknown"

        if "items" in data and isinstance(data["items"], list):
            if data.get("encrypted") is True:
                console.print("[red]This is an encrypted Bitwarden export.[/red]")
                console.print("[dim]Re-export it as an unencrypted JSON export first.[/dim]")
                return [], "bitwarden-encrypted"
            console.print("[dim]Detected: Bitwarden JSON export[/dim]")
            return parse_bitwarden(filepath), "Bitwarden"

        return [], "unknown-json"

    if suffix == ".csv":
        console.print("[dim]Detected: CSV export (generic/Bitwarden)[/dim]")
        return [], "csv"

    return [], "unknown"
