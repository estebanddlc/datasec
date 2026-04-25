"""
Modulo 5: Status Report
Dashboard del estado de seguridad personal con datos reales del monitor.
"""

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console()


def _load_monitor_state() -> dict:
    try:
        from datasec.breach_monitor import _load_state

        return _load_state()
    except Exception:
        return {"emails": {}, "api_key": "", "smtp": {}, "interval_hours": 24}


def _format_last_checked(value: str | None) -> str:
    if not value:
        return "[dim]Never[/dim]"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        local_time = parsed.astimezone()
        return local_time.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value[:16].replace("T", " ")


def _build_modules_table() -> Table:
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Module", style="bold", min_width=22)
    table.add_column("Command", style="cyan", min_width=26)
    table.add_column("What changed")

    rows = [
        ("Breach monitor", "datasec monitor run", "Persistent state + alerts"),
        ("Password audit", "datasec pwaudit FILE", "Vault-aware imports"),
        ("Encryptor", "datasec encrypt FILE", "Streaming large files safely"),
        ("Metadata scrubber", "datasec meta strip FILE", "Office rewrite without ZIP ghosts"),
        ("Audit reports", "datasec report generate", "Hashable evidence output"),
    ]
    for row in rows:
        table.add_row(*row)
    return table


def _build_monitor_table(state: dict) -> Table:
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Email", style="cyan", min_width=28)
    table.add_column("Breaches", min_width=10)
    table.add_column("Last check", min_width=18)
    table.add_column("Status", min_width=14)

    emails = state.get("emails", {})
    if not emails:
        table.add_row("-", "0", "Never", "[yellow]No targets[/yellow]")
        return table

    for email, meta in sorted(emails.items()):
        count = meta.get("breach_count", 0)
        if count > 0:
            status = "[red]Needs review[/red]"
            count_display = f"[red]{count}[/red]"
        elif meta.get("last_checked"):
            status = "[green]Clean[/green]"
            count_display = "[green]0[/green]"
        else:
            status = "[yellow]Pending[/yellow]"
            count_display = "[yellow]?[/yellow]"

        table.add_row(
            email,
            count_display,
            _format_last_checked(meta.get("last_checked")),
            status,
        )
    return table


def _build_config_table(state: dict) -> Table:
    config = Table(show_header=False, box=None, padding=(0, 2))
    config.add_column("Setting", style="dim", min_width=24)
    config.add_column("Value")
    config.add_row("HIBP API key", "[green]Configured[/green]" if state.get("api_key") else "[yellow]Missing[/yellow]")
    config.add_row("Monitor interval", f"[cyan]{state.get('interval_hours', 24)}h[/cyan]")
    config.add_row("Email alerts", "[green]Configured[/green]" if state.get("smtp", {}).get("host") else "[yellow]Disabled[/yellow]")
    config.add_row("Encryptor format", "[cyan]datasec v2[/cyan] streamed chunk mode")
    config.add_row("Chunk integrity", "[green]Enabled[/green] per encrypted chunk")
    config.add_row("Generated", datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"))
    return config


def _build_recommendations(state: dict) -> list[str]:
    emails = state.get("emails", {})
    recs = []
    if not state.get("api_key"):
        recs.append("Add your HIBP key with `datasec monitor configure --api-key ...` to unlock automated breach checks.")
    if not emails:
        recs.append("Register at least one address with `datasec monitor add you@example.com` so `status` reflects real exposure.")
    if emails and not any(meta.get("last_checked") for meta in emails.values()):
        recs.append("Run `datasec monitor run --once` to establish a real baseline before trusting the dashboard.")
    if state.get("emails") and any(meta.get("breach_count", 0) > 0 for meta in emails.values()):
        recs.append("Generate an auditable snapshot with `datasec report generate --email ...` after remediation.")
    if not state.get("smtp", {}).get("host"):
        recs.append("Configure SMTP if you want the monitor to behave like a real alerting service instead of a manual checker.")
    if not recs:
        recs.append("Your monitor looks configured; next meaningful upgrade is automating execution through the service files.")
    return recs


def show_status():
    state = _load_monitor_state()
    console.print()
    console.print(Rule("[bold cyan]datasec status[/bold cyan]"))
    console.print()

    console.print(Panel(_build_modules_table(), title="[bold]Capabilities[/bold]", border_style="cyan"))
    console.print()
    console.print(Panel(_build_monitor_table(state), title="[bold]Monitor state[/bold]", border_style="cyan"))
    console.print()
    console.print(Panel(_build_config_table(state), title="[bold]Active config[/bold]", border_style="dim"))
    console.print()

    recommendations = "\n".join(f"  {index}. {item}" for index, item in enumerate(_build_recommendations(state), 1))
    console.print(Panel(recommendations, title="[bold]Next actions[/bold]", border_style="green"))
    console.print()
