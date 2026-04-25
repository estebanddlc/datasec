"""
Módulo 4: Password Auditor
Analiza un archivo de contraseñas (txt/csv/json) y detecta:
- Contraseñas débiles (longitud, complejidad)
- Contraseñas reutilizadas
- Contraseñas comprometidas en breaches (via HIBP k-anonymity)
"""

import re
import json
import csv
import time
from pathlib import Path
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.rule import Rule
from rich import print as rprint

console = Console()

# Patrones de contraseñas comunes
COMMON_PATTERNS = [
    r"^1234",
    r"^password",
    r"^contraseña",
    r"^qwerty",
    r"^abc123",
    r"^admin",
    r"^letmein",
    r"^\d{4,8}$",       # Solo números
    r"^[a-zA-Z]+$",     # Solo letras
    r"^(.)\1{3,}",      # Caracteres repetidos (aaaa, 1111)
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in COMMON_PATTERNS]


def _load_passwords(filepath: str, formato: str) -> list[dict]:
    """Carga contraseñas desde diferentes formatos. Retorna lista de {site, username, password}"""
    path = Path(filepath)
    entries = []

    if formato == "txt":
        # Formato: una contraseña por línea, o "sitio:usuario:contraseña"
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) == 3:
                    entries.append({"site": parts[0], "username": parts[1], "password": parts[2]})
                elif len(parts) == 1:
                    entries.append({"site": "desconocido", "username": "", "password": parts[0]})

    elif formato == "csv":
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Intentar detectar columnas automáticamente
                password = (row.get("password") or row.get("contraseña") or
                           row.get("Password") or row.get("pass") or "")
                site = (row.get("site") or row.get("sitio") or
                       row.get("url") or row.get("name") or "desconocido")
                username = (row.get("username") or row.get("usuario") or
                           row.get("email") or row.get("user") or "")
                if password:
                    entries.append({"site": site, "username": username, "password": password})

    elif formato == "json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for item in data:
                entries.append({
                    "site": item.get("site", item.get("sitio", "desconocido")),
                    "username": item.get("username", item.get("usuario", "")),
                    "password": item.get("password", item.get("contraseña", ""))
                })
        elif isinstance(data, dict):
            for site, pwd in data.items():
                if isinstance(pwd, str):
                    entries.append({"site": site, "username": "", "password": pwd})

    return entries


def _analyze_strength(password: str) -> tuple[str, list[str]]:
    """Retorna (nivel: 'débil'/'media'/'fuerte', lista de problemas)"""
    issues = []

    if len(password) < 8:
        issues.append("muy corta (< 8 chars)")
    elif len(password) < 12:
        issues.append("corta (< 12 chars recomendado)")

    if not re.search(r"[A-Z]", password):
        issues.append("sin mayúsculas")
    if not re.search(r"[a-z]", password):
        issues.append("sin minúsculas")
    if not re.search(r"\d", password):
        issues.append("sin números")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        issues.append("sin símbolos")

    for pattern in COMPILED_PATTERNS:
        if pattern.search(password):
            issues.append("patrón común detectado")
            break

    if len(issues) >= 3:
        return "débil", issues
    elif len(issues) >= 1:
        return "media", issues
    else:
        return "fuerte", []


def audit_passwords(filepath: str, formato: str):
    console.print(f"\n[bold]🔑 Auditando contraseñas:[/bold] [cyan]{filepath}[/cyan]\n")

    try:
        entries = _load_passwords(filepath, formato)
    except Exception as e:
        console.print(f"[red]Error al leer el archivo: {e}[/red]")
        console.print("[dim]Formato esperado para .txt: una por línea o 'sitio:usuario:contraseña'[/dim]")
        return

    if not entries:
        console.print("[yellow]No se encontraron contraseñas en el archivo.[/yellow]")
        return

    console.print(f"[dim]  {len(entries)} contraseñas encontradas. Analizando...[/dim]\n")

    # ── Análisis local (rápido) ─────────────────────────────────────────────
    results = []
    all_passwords = [e["password"] for e in entries]
    password_counts = Counter(all_passwords)

    for entry in entries:
        pwd = entry["password"]
        strength, issues = _analyze_strength(pwd)
        reused = password_counts[pwd] > 1
        if reused:
            issues.append(f"reutilizada {password_counts[pwd]}x")
        results.append({**entry, "strength": strength, "issues": issues, "reused": reused, "pwned": -1})

    # ── HIBP check (respeta rate limit: 1.5 req/seg) ────────────────────────
    weak_or_reused = [r for r in results if r["strength"] != "fuerte" or r["reused"]]
    if weak_or_reused:
        console.print(f"[dim]Verificando {len(weak_or_reused)} contraseñas débiles/reutilizadas contra HIBP...[/dim]")
        console.print("[dim](Usa k-anonymity — tu contraseña NUNCA sale de tu máquina completa)[/dim]\n")

        from datasec.breach_scanner import check_password

        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("Verificando...", total=len(weak_or_reused))
            for r in weak_or_reused:
                r["pwned"] = check_password(r["password"])
                time.sleep(0.7)  # Rate limit HIBP: max 1.5/seg
                progress.advance(task)

    # ── Mostrar resultados ──────────────────────────────────────────────────
    _display_results(results)


def _display_results(results: list[dict]):
    # Estadísticas
    total = len(results)
    weak = sum(1 for r in results if r["strength"] == "débil")
    medium = sum(1 for r in results if r["strength"] == "media")
    strong = sum(1 for r in results if r["strength"] == "fuerte")
    reused = sum(1 for r in results if r["reused"])
    pwned = sum(1 for r in results if r["pwned"] > 0)

    score = int((strong / total) * 100) if total > 0 else 0
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    console.print(Panel(
        f"  Total: {total}  |  "
        f"[red]Débiles: {weak}[/red]  |  "
        f"[yellow]Medias: {medium}[/yellow]  |  "
        f"[green]Fuertes: {strong}[/green]  |  "
        f"[red]Reutilizadas: {reused}[/red]  |  "
        f"[red]En breaches: {pwned}[/red]\n\n"
        f"  Puntuación de seguridad: [{score_color}]{score}/100[/{score_color}]",
        title="[bold]Resumen de auditoría[/bold]",
        border_style=score_color
    ))

    # Tabla de problemas críticos
    critical = [r for r in results if r["strength"] == "débil" or r["pwned"] > 0 or r["reused"]]
    if critical:
        console.print(f"\n[bold red]⚠ {len(critical)} contraseñas requieren atención inmediata:[/bold red]\n")

        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0,1))
        table.add_column("Sitio", min_width=18)
        table.add_column("Usuario", min_width=15, style="dim")
        table.add_column("Estado", min_width=8)
        table.add_column("Problemas")

        for r in sorted(critical, key=lambda x: (x["pwned"] > 0, x["reused"], x["strength"] == "débil"), reverse=True):
            if r["pwned"] > 0:
                estado = f"[red]BREACH({r['pwned']:,}x)[/red]"
            elif r["reused"]:
                estado = "[yellow]REUSADA[/yellow]"
            else:
                estado = "[red]DÉBIL[/red]"

            issues_str = ", ".join(r["issues"][:3])
            # Ocultar contraseña — mostrar solo longitud
            table.add_row(
                r["site"][:20],
                (r["username"] or "—")[:18],
                estado,
                issues_str
            )

        console.print(table)

    # Recomendaciones
    console.print()
    console.print(Rule("[dim]Recomendaciones[/dim]"))
    recs = [
        "Usa un gestor de contraseñas: [cyan]Bitwarden[/cyan] (gratis) o [cyan]1Password[/cyan]",
        "Cada sitio debe tener una contraseña única y aleatoria de 20+ caracteres",
        "Activa autenticación de dos factores (2FA) en todos los servicios críticos",
        "Las contraseñas en breaches deben cambiarse HOY, no mañana",
    ]
    for r in recs:
        console.print(f"  • {r}")
    console.print()
