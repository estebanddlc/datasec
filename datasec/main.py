#!/usr/bin/env python3
"""
datasec - Personal Data Protection Toolkit
Breach scanning, file encryption, OSINT self-scan, password audit,
hidden volumes, metadata stripping, breach monitoring, and signed reports.
"""

import click
from rich.console import Console

console = Console()

BANNER = """
[bold cyan]DATASEC[/]
[dim]Personal Data Protection Toolkit - github.com/estebanddlc/datasec[/]
"""


@click.group()
def cli():
    """datasec - Your personal data protection toolkit."""
    pass


@cli.command()
@click.argument("email")
@click.option("--full", is_flag=True, help="Show full detail for each breach")
def breach(email, full):
    """Check if your email appeared in known data breaches."""
    from datasec.breach_scanner import scan_email

    scan_email(email, full)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--decrypt", is_flag=True, help="Decrypt instead of encrypt")
@click.option("--output", "-o", default=None, help="Output path (optional)")
def encrypt(path, decrypt, output):
    """Encrypt or decrypt files with AES-256."""
    from datasec.encryptor import decrypt_file, encrypt_file

    if decrypt:
        decrypt_file(path, output)
    else:
        encrypt_file(path, output)


@cli.command()
@click.argument("query")
@click.option(
    "--type",
    "query_type",
    type=click.Choice(["email", "nombre", "usuario", "telefono"]),
    default="email",
    show_default=True,
)
def osint(query, query_type):
    """Scan your digital footprint across public sources."""
    from datasec.osint_scanner import scan_footprint

    scan_footprint(query, query_type)


@cli.command()
@click.argument("archivo", type=click.Path(exists=True))
@click.option(
    "--formato",
    type=click.Choice(["txt", "csv", "json", "bitwarden", "1password", "keepass"]),
    default=None,
    help="File format (auto-detected if omitted)",
)
def pwaudit(archivo, formato):
    """Audit passwords: detect weak, reused, and compromised."""
    import time
    from collections import Counter

    from datasec.password_auditor import _analyze_strength, _display_results, audit_passwords
    from datasec.pm_parser import detect_and_parse

    if formato in ("bitwarden", "1password", "keepass") or formato is None:
        entries, manager = detect_and_parse(archivo)
        if entries:
            all_passwords = [entry["password"] for entry in entries]
            counts = Counter(all_passwords)
            results = []
            for entry in entries:
                password = entry["password"]
                strength, issues = _analyze_strength(password)
                reused = counts[password] > 1
                if reused:
                    issues.append(f"reused {counts[password]}x")
                results.append(
                    {
                        **entry,
                        "strength": strength,
                        "issues": issues,
                        "reused": reused,
                        "pwned": -1,
                    }
                )

            weak_or_reused = [row for row in results if row["strength"] != "fuerte" or row["reused"]]
            if weak_or_reused:
                console.print(f"[dim]Checking {len(weak_or_reused)} passwords against HIBP...[/dim]")
                from datasec.breach_scanner import check_password
                from rich.progress import BarColumn, Progress, TimeRemainingColumn

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
            return

    audit_passwords(archivo, formato or "txt")


@cli.command()
def status():
    """Show a summary of your personal security status."""
    from datasec.status_report import show_status

    show_status()


@cli.group()
def monitor():
    """Background breach monitor with OS and email alerts."""
    pass


@monitor.command("add")
@click.argument("email")
def monitor_add(email):
    """Add an email to the monitoring list."""
    from datasec.breach_monitor import monitor_add_email

    monitor_add_email(email)


@monitor.command("remove")
@click.argument("email")
def monitor_remove(email):
    """Remove an email from the monitoring list."""
    from datasec.breach_monitor import monitor_remove_email

    monitor_remove_email(email)


@monitor.command("configure")
@click.option("--api-key", default=None, help="HaveIBeenPwned API key")
@click.option("--interval", default=None, type=int, help="Check interval in hours (default: 24)")
@click.option("--smtp-host", default=None, help="SMTP host (for example smtp.gmail.com)")
@click.option("--smtp-user", default=None, help="SMTP username/email")
@click.option("--smtp-pass", default=None, help="SMTP password or app password")
@click.option("--smtp-port", default=465, help="SMTP port (default: 465)")
def monitor_configure(api_key, interval, smtp_host, smtp_user, smtp_pass, smtp_port):
    """Configure monitoring: API key, interval, and email alerts."""
    from datasec.breach_monitor import monitor_configure

    monitor_configure(api_key, interval, smtp_host, smtp_user, smtp_pass, smtp_port)


@monitor.command("status")
def monitor_status_cmd():
    """Show monitoring status for all registered emails."""
    from datasec.breach_monitor import monitor_status

    monitor_status()


@monitor.command("run")
@click.option("--once", is_flag=True, help="Run once and exit (no daemon)")
def monitor_run(once):
    """Start the breach monitor daemon, or run once with --once."""
    from datasec.breach_monitor import monitor_run

    monitor_run(once)


@cli.group()
def hv():
    """Hidden volumes with plausible deniability."""
    pass


@hv.command("create")
@click.argument("real_file", type=click.Path(exists=True))
@click.argument("decoy_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output .hv path")
def hv_create(real_file, decoy_file, output):
    """Create a hidden volume with a real file and a decoy file."""
    from datasec.hidden_volume import create_volume

    create_volume(real_file, decoy_file, output)


@hv.command("open")
@click.argument("volume", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Output file path")
def hv_open(volume, output):
    """Open a hidden volume using the real or decoy password."""
    from datasec.hidden_volume import open_volume

    open_volume(volume, output)


@cli.group()
def meta():
    """Inspect and strip metadata from files."""
    pass


@meta.command("show")
@click.argument("file", type=click.Path(exists=True))
def meta_show(file):
    """Show metadata from a PDF, image, or Office document."""
    from datasec.metadata_stripper import display_metadata

    display_metadata(file)


@meta.command("strip")
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None)
@click.option("--encrypt", "then_encrypt", is_flag=True, help="Encrypt the cleaned file after stripping")
def meta_strip(file, output, then_encrypt):
    """Strip metadata and optionally encrypt the cleaned file."""
    from datasec.metadata_stripper import strip_metadata

    strip_metadata(file, output, then_encrypt)


@cli.group()
def report():
    """Generate and verify signed security posture reports."""
    pass


@report.command("generate")
@click.option("--email", "-e", multiple=True, help="Email(s) to include")
@click.option("--passwords", "-p", default=None, help="Password file to audit")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["txt", "csv", "json", "bitwarden", "1password", "keepass"]),
    default="txt",
)
@click.option("--output-dir", default=None)
@click.option("--sign-gpg", is_flag=True, help="Sign with GPG")
@click.option("--gpg-key", default=None, help="GPG key ID")
def report_generate(email, passwords, format, output_dir, sign_gpg, gpg_key):
    """Generate a timestamped SHA-256 security posture report."""
    from datasec.audit_report import generate_report

    generate_report(list(email), passwords, format, output_dir, sign_gpg, gpg_key)


@report.command("verify")
@click.argument("report_file", type=click.Path(exists=True))
def report_verify(report_file):
    """Verify the SHA-256 integrity of a report."""
    from datasec.audit_report import verify_report

    verify_report(report_file)


def main():
    console.print(BANNER)
    cli()


if __name__ == "__main__":
    main()
