"""
Módulo 1: Breach Scanner
Verifica si un email aparece en filtraciones conocidas via HaveIBeenPwned API v3
También revisa contraseñas con k-anonymity (nunca envía la contraseña completa)
"""

import hashlib
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich import print as rprint
from datetime import datetime

console = Console()

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PWNED_URL  = "https://api.pwnedpasswords.com/range/{prefix}"
HEADERS = {
    "User-Agent": "datasec-personal-toolkit/1.0",
    "hibp-api-key": ""  # Opcional: agrega tu API key de HIBP para quitar rate limits
}


def scan_email(email: str, full: bool = False):
    console.print(f"\n[bold]🔍 Escaneando:[/bold] [cyan]{email}[/cyan]\n")

    # ── HIBP breach check ──────────────────────────────────────────────────
    try:
        url = HIBP_BREACH_URL.format(email=email)
        params = {"truncateResponse": "false"}
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)

        if resp.status_code == 404:
            console.print(Panel(
                "[bold green]✓ Sin filtraciones encontradas[/bold green]\n"
                "[dim]Este email no aparece en ninguna filtración conocida indexada por HIBP.[/dim]",
                title="Resultado", border_style="green"
            ))
            _show_recommendations(breached=False)
            return

        if resp.status_code == 401:
            console.print("[yellow]⚠ Se requiere API key de HIBP para consultas de email.[/yellow]")
            console.print("[dim]Obtén una gratis en: https://haveibeenpwned.com/API/Key[/dim]")
            console.print("[dim]Luego ponla en modules/breach_scanner.py en la variable HEADERS.[/dim]\n")
            _fallback_manual_check(email)
            return

        if resp.status_code == 429:
            console.print("[red]Rate limit alcanzado. Espera 1 minuto e intenta de nuevo.[/red]")
            return

        if resp.status_code != 200:
            console.print(f"[red]Error HTTP {resp.status_code}[/red]")
            return

        breaches = resp.json()
        _display_breaches(email, breaches, full)

    except requests.exceptions.ConnectionError:
        console.print("[red]Sin conexión a internet o HIBP no disponible.[/red]")
    except Exception as e:
        console.print(f"[red]Error inesperado: {e}[/red]")


def check_password(password: str) -> int:
    """
    Verifica si una contraseña fue comprometida usando k-anonymity.
    NUNCA envía la contraseña completa — solo los primeros 5 caracteres del hash SHA-1.
    Retorna el número de veces que aparece en filtraciones (0 = segura).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_PWNED_URL.format(prefix=prefix),
            timeout=10
        )
        if resp.status_code != 200:
            return -1

        for line in resp.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0

    except Exception:
        return -1


def _display_breaches(email: str, breaches: list, full: bool):
    total = len(breaches)
    severity_counts = {"Alta": 0, "Media": 0, "Baja": 0}

    # Clasificar por severidad
    sensitive_data = {"Passwords", "Credit cards", "Bank accounts", "SSN", "Passport numbers"}
    for b in breaches:
        data_classes = set(b.get("DataClasses", []))
        if data_classes & sensitive_data:
            severity_counts["Alta"] += 1
        elif len(data_classes) > 3:
            severity_counts["Media"] += 1
        else:
            severity_counts["Baja"] += 1

    # Panel resumen
    color = "red" if severity_counts["Alta"] > 0 else "yellow" if severity_counts["Media"] > 0 else "cyan"
    console.print(Panel(
        f"[bold {color}]⚠ {total} filtraciones encontradas[/bold {color}]\n"
        f"[red]Alta severidad: {severity_counts['Alta']}[/red]  "
        f"[yellow]Media: {severity_counts['Media']}[/yellow]  "
        f"[dim]Baja: {severity_counts['Baja']}[/dim]",
        title=f"[bold]Resultados para {email}[/bold]",
        border_style=color
    ))

    # Tabla de breaches
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0,1))
    table.add_column("Sitio", style="bold", min_width=20)
    table.add_column("Fecha", style="dim", min_width=12)
    table.add_column("Severidad", min_width=8)
    table.add_column("Datos expuestos", min_width=30)

    for b in sorted(breaches, key=lambda x: x.get("BreachDate",""), reverse=True):
        data_classes = b.get("DataClasses", [])
        has_sensitive = bool(set(data_classes) & sensitive_data)
        sev = "[red]Alta[/red]" if has_sensitive else "[yellow]Media[/yellow]" if len(data_classes) > 3 else "[dim]Baja[/dim]"

        if full:
            datos = ", ".join(data_classes)
        else:
            datos = ", ".join(data_classes[:3])
            if len(data_classes) > 3:
                datos += f" [dim]+{len(data_classes)-3} más[/dim]"

        table.add_row(
            b.get("Name", "?"),
            b.get("BreachDate", "?")[:7],
            sev,
            datos
        )

    console.print(table)
    _show_recommendations(breached=True, high=severity_counts["Alta"] > 0)


def _fallback_manual_check(email: str):
    """Links alternativos para verificar manualmente sin API key."""
    console.print(Panel(
        "[bold yellow]Verificación manual recomendada:[/bold yellow]\n\n"
        f"[cyan]1.[/cyan] https://haveibeenpwned.com/account/{email}\n"
        "[cyan]2.[/cyan] https://dehashed.com (busca email o dominio)\n"
        "[cyan]3.[/cyan] https://intelx.io (indexa breaches de LATAM también)\n"
        "[cyan]4.[/cyan] https://breachdirectory.org\n\n"
        "[dim]Para automatizar esto completamente, obtén una API key gratuita en\n"
        "https://haveibeenpwned.com/API/Key y agrégala en modules/breach_scanner.py[/dim]",
        title="Recursos alternativos",
        border_style="yellow"
    ))


def _show_recommendations(breached: bool, high: bool = False):
    if not breached:
        recs = [
            "✓ Sigue usando contraseñas únicas por sitio",
            "✓ Activa 2FA en todos tus servicios críticos",
            "✓ Vuelve a escanear en 3 meses",
        ]
        color = "green"
    elif high:
        recs = [
            "🔴 Cambia tu contraseña en TODOS los sitios afectados AHORA",
            "🔴 Si reutilizas contraseñas, cámbialas en todos lados",
            "🔴 Activa 2FA inmediatamente en email y banco",
            "🟡 Revisa movimientos bancarios de los últimos 3 meses",
            "🟡 Considera alertas de crédito en el Buró de Crédito",
        ]
        color = "red"
    else:
        recs = [
            "🟡 Cambia contraseñas en los sitios afectados",
            "🟡 Activa 2FA donde no lo tengas",
            "🟡 Usa un gestor de contraseñas (Bitwarden es gratis)",
        ]
        color = "yellow"

    console.print("\n[bold]Recomendaciones:[/bold]")
    for r in recs:
        console.print(f"  {r}")
    console.print()
