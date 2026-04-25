"""
Module 4: Password Auditor
Analyzes password files and flags weak, reused, and breached passwords.
"""

import csv
import json
import re
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TimeRemainingColumn
from rich.rule import Rule
from rich.table import Table

console = Console()

COMMON_PATTERNS = [
    r"^1234",
    r"^password",
    r"^contrasena",
    r"^qwerty",
    r"^abc123",
    r"^admin",
    r"^letmein",
    r"^\d{4,8}$",
    r"^[a-zA-Z]+$",
    r"^(.)\1{3,}",
]

COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in COMMON_PATTERNS]


def _load_passwords(filepath: str, formato: str) -> list[dict]:
    """Load passwords from different formats into {site, username, password} rows."""
    path = Path(filepath)
    entries = []

    if formato == "txt":
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) == 3:
                    entries.append({"site": parts[0], "username": parts[1], "password": parts[2]})
                elif len(parts) == 1:
                    entries.append({"site": "unknown", "username": "", "password": parts[0]})

    elif formato == "csv":
        with open(path, encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                password = (
                    row.get("password")
                    or row.get("contrasena")
                    or row.get("Password")
                    or row.get("pass")
                    or ""
                )
                site = row.get("site") or row.get("sitio") or row.get("url") or row.get("name") or "unknown"
                username = (
                    row.get("username")
                    or row.get("usuario")
                    or row.get("email")
                    or row.get("user")
                    or ""
                )
                if password:
                    entries.append({"site": site, "username": username, "password": password})

    elif formato == "json":
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            for item in data:
                entries.append(
                    {
                        "site": item.get("site", item.get("sitio", "unknown")),
                        "username": item.get("username", item.get("usuario", "")),
                        "password": item.get("password", item.get("contrasena", "")),
                    }
                )
        elif isinstance(data, dict):
            for site, password in data.items():
                if isinstance(password, str):
                    entries.append({"site": site, "username": "", "password": password})

    return entries


def _analyze_strength(password: str) -> tuple[str, list[str]]:
    """Return strength label and issue list."""
    issues = []

    if len(password) < 8:
        issues.append("muy corta (< 8 chars)")
    elif len(password) < 12:
        issues.append("corta (< 12 chars recomendado)")

    if not re.search(r"[A-Z]", password):
        issues.append("sin mayusculas")
    if not re.search(r"[a-z]", password):
        issues.append("sin minusculas")
    if not re.search(r"\d", password):
        issues.append("sin numeros")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        issues.append("sin simbolos")

    for pattern in COMPILED_PATTERNS:
        if pattern.search(password):
            issues.append("patron comun detectado")
            break

    if len(issues) >= 3:
        return "debil", issues
    if len(issues) >= 1:
        return "media", issues
    return "fuerte", []


def audit_passwords(filepath: str, formato: str):
    console.print(f"\n[bold]Auditing passwords:[/bold] [cyan]{filepath}[/cyan]\n")

    try:
        entries = _load_passwords(filepath, formato)
    except Exception as exc:
        console.print(f"[red]Failed to read file: {exc}[/red]")
        console.print("[dim]Expected .txt format: one password per line or site:user:password[/dim]")
        return

    if not entries:
        console.print("[yellow]No passwords were found in that file.[/yellow]")
        return

    console.print(f"[dim]{len(entries)} passwords found. Running local analysis...[/dim]\n")

    results = []
    counts = Counter(entry["password"] for entry in entries)

    for entry in entries:
        password = entry["password"]
        strength, issues = _analyze_strength(password)
        reused = counts[password] > 1
        if reused:
            issues.append(f"reutilizada {counts[password]}x")
        results.append({**entry, "strength": strength, "issues": issues, "reused": reused, "pwned": -1})

    weak_or_reused = [row for row in results if row["strength"] != "fuerte" or row["reused"]]
    if weak_or_reused:
        console.print(f"[dim]Checking {len(weak_or_reused)} weak/reused passwords against HIBP...[/dim]")
        console.print("[dim]Only the SHA-1 prefix leaves your machine.[/dim]\n")

        from datasec.breach_scanner import check_password

        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("Checking...", total=len(weak_or_reused))
            for row in weak_or_reused:
                row["pwned"] = check_password(row["password"])
                time.sleep(0.7)
                progress.advance(task)

    _display_results(results)


def _display_results(results: list[dict]):
    total = len(results)
    weak = sum(1 for row in results if row["strength"] == "debil")
    medium = sum(1 for row in results if row["strength"] == "media")
    strong = sum(1 for row in results if row["strength"] == "fuerte")
    reused = sum(1 for row in results if row["reused"])
    pwned = sum(1 for row in results if row["pwned"] > 0)

    score = int((strong / total) * 100) if total else 0
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    console.print(
        Panel(
            f"  Total: {total}  |  "
            f"[red]Weak: {weak}[/red]  |  "
            f"[yellow]Medium: {medium}[/yellow]  |  "
            f"[green]Strong: {strong}[/green]  |  "
            f"[red]Reused: {reused}[/red]  |  "
            f"[red]Breached: {pwned}[/red]\n\n"
            f"  Security score: [{score_color}]{score}/100[/{score_color}]",
            title="[bold]Audit summary[/bold]",
            border_style=score_color,
        )
    )

    critical = [row for row in results if row["strength"] == "debil" or row["pwned"] > 0 or row["reused"]]
    if critical:
        console.print(f"\n[bold red]{len(critical)} password(s) need immediate attention:[/bold red]\n")

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
        table.add_column("Site", min_width=18)
        table.add_column("User", min_width=15, style="dim")
        table.add_column("Status", min_width=12)
        table.add_column("Issues")

        for row in sorted(
            critical,
            key=lambda item: (item["pwned"] > 0, item["reused"], item["strength"] == "debil"),
            reverse=True,
        ):
            if row["pwned"] > 0:
                status = f"[red]BREACH({row['pwned']:,}x)[/red]"
            elif row["reused"]:
                status = "[yellow]REUSED[/yellow]"
            else:
                status = "[red]WEAK[/red]"

            issues = ", ".join(row["issues"][:3])
            table.add_row(row["site"][:20], (row["username"] or "-")[:18], status, issues)

        console.print(table)

    console.print()
    console.print(Rule("[dim]Recommendations[/dim]"))
    recommendations = [
        "Use a password manager such as Bitwarden or 1Password.",
        "Give every site a unique random password of 20+ characters.",
        "Enable 2FA on all critical services.",
        "Change breached passwords today, not later.",
    ]
    for item in recommendations:
        console.print(f"  - {item}")
    console.print()
