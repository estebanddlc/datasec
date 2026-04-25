"""
Module 1: Breach Scanner
Checks whether an email appears in known breaches via the HaveIBeenPwned API.
Also checks passwords with k-anonymity without sending the full password.
"""

import hashlib

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PWNED_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HEADERS = {
    "User-Agent": "datasec-personal-toolkit/1.0",
    "hibp-api-key": "",
}


def scan_email(email: str, full: bool = False):
    console.print(f"\n[bold]Scanning:[/bold] [cyan]{email}[/cyan]\n")

    try:
        url = HIBP_BREACH_URL.format(email=email)
        params = {"truncateResponse": "false"}
        response = requests.get(url, headers=HEADERS, params=params, timeout=10)

        if response.status_code == 404:
            console.print(
                Panel(
                    "[bold green]No known breaches found[/bold green]\n"
                    "[dim]This email does not appear in HIBP's indexed breach data.[/dim]",
                    title="Result",
                    border_style="green",
                )
            )
            _show_recommendations(breached=False)
            return

        if response.status_code == 401:
            console.print("[yellow]HIBP requires an API key for email breach lookups.[/yellow]")
            console.print("[dim]Get one at: https://haveibeenpwned.com/API/Key[/dim]")
            console.print("[dim]Then store it through the monitor config flow or HEADERS.[/dim]\n")
            _fallback_manual_check(email)
            return

        if response.status_code == 429:
            console.print("[red]Rate limit reached. Wait a minute and try again.[/red]")
            return

        if response.status_code != 200:
            console.print(f"[red]HTTP error {response.status_code}[/red]")
            return

        breaches = response.json()
        _display_breaches(email, breaches, full)

    except requests.exceptions.ConnectionError:
        console.print("[red]No internet connection or HIBP is unavailable.[/red]")
    except Exception as exc:
        console.print(f"[red]Unexpected error: {exc}[/red]")


def check_password(password: str) -> int:
    """
    Check whether a password appears in known breaches using k-anonymity.
    Returns the number of times it appeared. Zero means not found.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(HIBP_PWNED_URL.format(prefix=prefix), timeout=10)
        if response.status_code != 200:
            return -1

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return -1


def _display_breaches(email: str, breaches: list, full: bool):
    total = len(breaches)
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    sensitive_data = {"Passwords", "Credit cards", "Bank accounts", "SSN", "Passport numbers"}

    for breach in breaches:
        data_classes = set(breach.get("DataClasses", []))
        if data_classes & sensitive_data:
            severity_counts["High"] += 1
        elif len(data_classes) > 3:
            severity_counts["Medium"] += 1
        else:
            severity_counts["Low"] += 1

    color = "red" if severity_counts["High"] > 0 else "yellow" if severity_counts["Medium"] > 0 else "cyan"
    console.print(
        Panel(
            f"[bold {color}]{total} breach(es) found[/bold {color}]\n"
            f"[red]High: {severity_counts['High']}[/red]  "
            f"[yellow]Medium: {severity_counts['Medium']}[/yellow]  "
            f"[dim]Low: {severity_counts['Low']}[/dim]",
            title=f"[bold]Results for {email}[/bold]",
            border_style=color,
        )
    )

    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
    table.add_column("Site", style="bold", min_width=20)
    table.add_column("Date", style="dim", min_width=12)
    table.add_column("Severity", min_width=8)
    table.add_column("Exposed data", min_width=30)

    for breach in sorted(breaches, key=lambda item: item.get("BreachDate", ""), reverse=True):
        data_classes = breach.get("DataClasses", [])
        has_sensitive = bool(set(data_classes) & sensitive_data)
        severity = (
            "[red]High[/red]"
            if has_sensitive
            else "[yellow]Medium[/yellow]"
            if len(data_classes) > 3
            else "[dim]Low[/dim]"
        )

        if full:
            exposed = ", ".join(data_classes)
        else:
            exposed = ", ".join(data_classes[:3])
            if len(data_classes) > 3:
                exposed += f" [dim]+{len(data_classes) - 3} more[/dim]"

        table.add_row(
            breach.get("Name", "?"),
            breach.get("BreachDate", "?")[:7],
            severity,
            exposed,
        )

    console.print(table)
    _show_recommendations(breached=True, high=severity_counts["High"] > 0)


def _fallback_manual_check(email: str):
    console.print(
        Panel(
            "[bold yellow]Manual verification suggested:[/bold yellow]\n\n"
            f"[cyan]1.[/cyan] https://haveibeenpwned.com/account/{email}\n"
            "[cyan]2.[/cyan] https://dehashed.com\n"
            "[cyan]3.[/cyan] https://intelx.io\n"
            "[cyan]4.[/cyan] https://breachdirectory.org\n\n"
            "[dim]For full automation, configure a HIBP API key in datasec.[/dim]",
            title="Alternatives",
            border_style="yellow",
        )
    )


def _show_recommendations(breached: bool, high: bool = False):
    if not breached:
        recommendations = [
            "Keep using unique passwords per site.",
            "Enable 2FA on critical services.",
            "Run another scan in a few months.",
        ]
    elif high:
        recommendations = [
            "Change passwords on affected sites immediately.",
            "Replace any reused password everywhere it appears.",
            "Enable 2FA on email, banking, and work accounts now.",
            "Review financial activity and other sensitive exposure.",
        ]
    else:
        recommendations = [
            "Rotate passwords on affected sites.",
            "Enable 2FA wherever it is still missing.",
            "Use a password manager for unique credentials.",
        ]

    console.print("\n[bold]Recommendations:[/bold]")
    for item in recommendations:
        console.print(f"  - {item}")
    console.print()
