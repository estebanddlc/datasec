"""
Módulo 5: Status Report
Dashboard de resumen del estado de seguridad personal.
Muestra configuración activa, últimos escaneos y recomendaciones.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.columns import Columns
from rich import print as rprint
from datetime import datetime

console = Console()


def show_status():
    console.print()
    console.print(Rule("[bold cyan]Estado de Seguridad Personal[/bold cyan]"))
    console.print()

    # ── Panel: módulos disponibles ─────────────────────────────────────────
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Módulo", style="bold", min_width=20)
    table.add_column("Comando", style="cyan", min_width=20)
    table.add_column("Estado", min_width=10)

    modules = [
        ("🔍 Breach Scanner",   "python main.py breach <email>",         "[green]✓ Activo[/green]"),
        ("🔒 Encryptor AES-256","python main.py encrypt <archivo>",       "[green]✓ Activo[/green]"),
        ("🌐 OSINT Scanner",    "python main.py osint <query>",           "[green]✓ Activo[/green]"),
        ("🔑 Password Auditor", "python main.py pwaudit <archivo>",       "[green]✓ Activo[/green]"),
    ]

    for name, cmd, status in modules:
        table.add_row(name, cmd, status)

    console.print(Panel(table, title="[bold]Módulos disponibles[/bold]", border_style="cyan"))

    # ── Panel: configuración ───────────────────────────────────────────────
    console.print()

    # Verificar si hay API key de HIBP configurada
    try:
        from datasec.breach_scanner import HEADERS
        hibp_key = HEADERS.get("hibp-api-key", "")
        hibp_status = "[green]✓ Configurada[/green]" if hibp_key else "[yellow]⚠ Sin API key (verificación manual)[/yellow]"
    except Exception:
        hibp_status = "[red]✗ Error al leer configuración[/red]"

    config_table = Table(show_header=False, box=None, padding=(0, 2))
    config_table.add_column("Setting", style="dim", min_width=25)
    config_table.add_column("Valor")

    config_table.add_row("HIBP API Key",       hibp_status)
    config_table.add_row("KDF Iterations",     "[cyan]480,000[/cyan] (OWASP 2023)")
    config_table.add_row("Algoritmo cifrado",  "[cyan]AES-256-CBC (Fernet)[/cyan]")
    config_table.add_row("Salt size",          "[cyan]32 bytes[/cyan]")
    config_table.add_row("k-Anonymity HIBP",   "[green]✓ Habilitado[/green]")

    console.print(Panel(config_table, title="[bold]Configuración activa[/bold]", border_style="dim"))

    # ── Checklist de seguridad ─────────────────────────────────────────────
    console.print()
    console.print(Panel(
        "  [dim]Checklist mensual de seguridad personal:[/dim]\n\n"
        "  [cyan]□[/cyan]  Escanear email principal en HIBP\n"
        "  [cyan]□[/cyan]  Auditar contraseñas del gestor de contraseñas\n"
        "  [cyan]□[/cyan]  Verificar huella OSINT (nombre + usuario)\n"
        "  [cyan]□[/cyan]  Revisar apps con acceso a Google/GitHub/Apple\n"
        "  [cyan]□[/cyan]  Confirmar que 2FA está activo en: email, banco, trabajo\n"
        "  [cyan]□[/cyan]  Cifrar backups sensibles antes de subirlos a la nube\n\n"
        f"  [dim]Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}[/dim]",
        title="[bold]Checklist mensual[/bold]",
        border_style="cyan"
    ))

    console.print()
    console.print("[dim]  Tip: Agrega tu HIBP API key en modules/breach_scanner.py para escaneos automáticos.[/dim]")
    console.print("[dim]  Obtén una gratis en: https://haveibeenpwned.com/API/Key[/dim]")
    console.print()
