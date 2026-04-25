"""
Module 6: Breach Monitor
Background breach monitoring with persisted state and optional alerts.
"""

import hashlib
import json
import os
import signal
import smtplib
import sys
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import schedule
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console()

STATE_DIR = Path.home() / ".datasec"
STATE_FILE = STATE_DIR / "monitor_state.json"
PID_FILE = STATE_DIR / "monitor.pid"

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_HEADERS = {
    "User-Agent": "datasec-personal-toolkit/1.0",
    "hibp-api-key": "",
}


def _load_state() -> dict:
    STATE_DIR.mkdir(exist_ok=True)
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"emails": {}, "api_key": "", "smtp": {}, "interval_hours": 24}


def _save_state(state: dict):
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        STATE_FILE.chmod(0o600)
    except Exception:
        pass


def _breach_fingerprint(breaches: list) -> str:
    """Hash breach names and dates so changes map to newly observed breaches."""
    key = "|".join(sorted(f"{breach['Name']}:{breach.get('BreachDate', '')}" for breach in breaches))
    return hashlib.sha256(key.encode()).hexdigest()


def _fetch_breaches(email: str, api_key: str) -> list | None:
    """Return breach list, empty list if clean, or None on API failure."""
    headers = {**HIBP_HEADERS, "hibp-api-key": api_key}
    try:
        response = requests.get(
            HIBP_BREACH_URL.format(email=email),
            headers=headers,
            params={"truncateResponse": "false"},
            timeout=15,
        )
        if response.status_code == 404:
            return []
        if response.status_code == 200:
            return response.json()
        if response.status_code == 429:
            time.sleep(60)
            return None
        return None
    except Exception:
        return None


def _notify_os(title: str, message: str):
    """Send a desktop notification when available."""
    try:
        from plyer import notification

        notification.notify(title=title, message=message, app_name="datasec", timeout=10)
    except Exception:
        pass


def _notify_email(smtp_cfg: dict, to_email: str, new_breaches: list):
    """Send an email alert for newly detected breaches."""
    if not smtp_cfg.get("host") or not smtp_cfg.get("user"):
        return

    breach_lines = "\n".join(
        f"  - {breach['Name']} ({breach.get('BreachDate', '?')[:7]}): {', '.join(breach.get('DataClasses', [])[:3])}"
        for breach in new_breaches
    )

    body = f"""datasec breach alert

New breaches detected for: {to_email}
Detected at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

{breach_lines}

Recommended actions:
  1. Change the affected passwords immediately
  2. Enable 2FA if it is still missing
  3. Check for password reuse across other services

-- datasec monitor
"""

    message = MIMEMultipart()
    message["From"] = smtp_cfg["user"]
    message["To"] = to_email
    message["Subject"] = f"[datasec] New breach detected: {to_email}"
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL(smtp_cfg["host"], int(smtp_cfg.get("port", 465))) as server:
            server.login(smtp_cfg["user"], smtp_cfg["password"])
            server.sendmail(smtp_cfg["user"], to_email, message.as_string())
    except Exception as exc:
        console.print(f"[yellow]Email notification failed: {exc}[/yellow]")


def _check_all_emails(state: dict) -> dict:
    """Run one full monitoring cycle and persist updated state."""
    api_key = state.get("api_key", "")
    if not api_key:
        console.print("[yellow]No HIBP API key configured. Use: datasec monitor configure --api-key KEY[/yellow]")
        return state

    emails = state.get("emails", {})
    if not emails:
        console.print("[dim]No emails registered. Use: datasec monitor add EMAIL[/dim]")
        return state

    now = datetime.now(timezone.utc).isoformat()

    for email, meta in emails.items():
        breaches = _fetch_breaches(email, api_key)
        if breaches is None:
            console.print(f"[yellow]Could not check {email} (API error)[/yellow]")
            continue

        current_fp = _breach_fingerprint(breaches)
        previous_fp = meta.get("fingerprint", "")

        if current_fp != previous_fp and previous_fp:
            previous_names = set(meta.get("breach_names", []))
            current_names = {breach["Name"] for breach in breaches}
            new_names = current_names - previous_names
            new_breaches = [breach for breach in breaches if breach["Name"] in new_names]

            console.print(f"\n[bold red]New breach for {email}:[/bold red]")
            for breach in new_breaches:
                exposed = ", ".join(breach.get("DataClasses", [])[:4])
                console.print(f"  [red]-[/red] {breach['Name']} - {exposed}")

            _notify_os(
                f"datasec: New breach for {email}",
                f"{len(new_breaches)} new breach(es): {', '.join(breach['Name'] for breach in new_breaches[:3])}",
            )
            _notify_email(state.get("smtp", {}), email, new_breaches)

        elif not previous_fp:
            count = len(breaches)
            if count > 0:
                console.print(f"[yellow]Baseline set for {email}: {count} existing breach(es)[/yellow]")
            else:
                console.print(f"[green]Baseline set for {email}: clean[/green]")

        emails[email] = {
            "fingerprint": current_fp,
            "breach_names": [breach["Name"] for breach in breaches],
            "breach_count": len(breaches),
            "last_checked": now,
        }
        time.sleep(1.5)

    state["emails"] = emails
    _save_state(state)
    return state


def monitor_add_email(email: str):
    state = _load_state()
    if email in state["emails"]:
        console.print(f"[yellow]{email} is already being monitored.[/yellow]")
        return
    state["emails"][email] = {"fingerprint": "", "breach_names": [], "breach_count": 0, "last_checked": None}
    _save_state(state)
    console.print(f"[green]Added {email} to monitoring list.[/green]")


def monitor_remove_email(email: str):
    state = _load_state()
    if email not in state["emails"]:
        console.print(f"[yellow]{email} was not found in the monitoring list.[/yellow]")
        return
    del state["emails"][email]
    _save_state(state)
    console.print(f"[green]Removed {email}.[/green]")


def monitor_configure(
    api_key: str = None,
    interval: int = None,
    smtp_host: str = None,
    smtp_user: str = None,
    smtp_pass: str = None,
    smtp_port: int = 465,
):
    state = _load_state()
    if api_key:
        state["api_key"] = api_key
        console.print("[green]HIBP API key saved.[/green]")
    if interval:
        state["interval_hours"] = interval
        console.print(f"[green]Check interval set to {interval}h.[/green]")
    if smtp_host:
        state["smtp"] = {
            "host": smtp_host,
            "user": smtp_user,
            "password": smtp_pass,
            "port": smtp_port,
        }
        console.print("[green]SMTP configured for email alerts.[/green]")
    _save_state(state)


def monitor_status():
    state = _load_state()
    emails = state.get("emails", {})

    console.print()
    console.print(Rule("[bold cyan]Breach Monitor Status[/bold cyan]"))

    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Email", style="cyan", min_width=28)
    table.add_column("Breaches", min_width=10)
    table.add_column("Last Checked", min_width=20)

    if not emails:
        console.print("[dim]No emails registered. Use: datasec monitor add YOUR@EMAIL.COM[/dim]")
        return

    for email, meta in emails.items():
        count = meta.get("breach_count", "?")
        last = meta.get("last_checked", "Never")
        if last and last != "Never":
            last = last[:16].replace("T", " ")
        count_display = f"[red]{count}[/red]" if isinstance(count, int) and count > 0 else f"[green]{count}[/green]"
        table.add_row(email, count_display, last)

    console.print(table)
    console.print(f"\n[dim]Check interval: {state.get('interval_hours', 24)}h[/dim]")
    console.print(f"[dim]HIBP API key: {'set' if state.get('api_key') else 'NOT SET'}[/dim]")
    console.print(f"[dim]Email alerts: {'configured' if state.get('smtp', {}).get('host') else 'not configured'}[/dim]")


def monitor_run(once: bool = False):
    """Start the monitor, or run once with once=True."""
    state = _load_state()

    console.print(
        Panel(
            "[bold green]datasec breach monitor running[/bold green]\n"
            f"[dim]Monitoring {len(state.get('emails', {}))} email(s) every {state.get('interval_hours', 24)}h[/dim]\n"
            "[dim]Press Ctrl+C to stop[/dim]",
            border_style="green",
        )
    )

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    def job():
        nonlocal state
        console.print(f"\n[dim]{datetime.now().strftime('%Y-%m-%d %H:%M')} - running check...[/dim]")
        state = _check_all_emails(state)

    if once:
        job()
        return

    job()
    schedule.every(state.get("interval_hours", 24)).hours.do(job)

    def _handle_exit(sig, frame):
        console.print("\n[dim]Monitor stopped.[/dim]")
        if PID_FILE.exists():
            PID_FILE.unlink()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    while True:
        schedule.run_pending()
        time.sleep(60)
