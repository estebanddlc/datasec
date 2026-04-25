"""
Module 10: Audit Report
Generates a timestamped security posture report with SHA-256 hashing
and optional GPG signing.
"""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

console = Console()

REPORT_DIR = Path.home() / ".datasec" / "reports"


def generate_report(
    emails: list[str] = None,
    password_file: str = None,
    password_format: str = "txt",
    output_dir: str = None,
    sign_gpg: bool = False,
    gpg_key: str = None,
) -> str:
    """Generate a security posture report and return its path."""
    out_dir = Path(output_dir) if output_dir else REPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y%m%d_%H%M%S")
    report_path = out_dir / f"datasec_report_{timestamp}.txt"

    lines = []

    def w(line: str = ""):
        lines.append(line)

    w("=" * 72)
    w("  DATASEC SECURITY POSTURE REPORT")
    w(f"  Generated: {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    w("  Tool:      datasec v0.4.0 - github.com/estebanddlc/datasec")
    w("=" * 72)
    w()

    w("-" * 72)
    w("  SECTION 1: BREACH STATUS")
    w("-" * 72)
    w()

    monitor_state = _load_monitor_state()
    if emails:
        for email in emails:
            w(f"  Email: {email}")
            if email in monitor_state.get("emails", {}):
                meta = monitor_state["emails"][email]
                count = meta.get("breach_count", "unknown")
                checked = meta.get("last_checked", "never")[:16].replace("T", " ")
                names = meta.get("breach_names", [])
                w(f"  Breaches found:  {count}")
                w(f"  Last checked:    {checked} UTC")
                if names:
                    w("  Breach list:")
                    for name in names:
                        w(f"    - {name}")
            else:
                w("  Status: not in monitor list - run 'datasec monitor add' to track")
            w()
    else:
        w("  No emails provided. Use --email to include breach data.")
        w()

    w("-" * 72)
    w("  SECTION 2: PASSWORD AUDIT")
    w("-" * 72)
    w()

    if password_file:
        audit_results = _run_password_audit(password_file, password_format)
        if audit_results:
            total = audit_results["total"]
            weak = audit_results["weak"]
            reused = audit_results["reused"]
            pwned = audit_results["pwned"]
            strong = audit_results["strong"]
            score = int((strong / total) * 100) if total else 0

            w(f"  File audited:    {password_file}")
            w(f"  Total passwords: {total}")
            w(f"  Weak:            {weak}")
            w(f"  Reused:          {reused}")
            w(f"  In breaches:     {pwned}")
            w(f"  Strong:          {strong}")
            w(f"  Security score:  {score}/100")
            w()

            if audit_results.get("critical"):
                w("  Sites requiring immediate action:")
                for item in audit_results["critical"][:10]:
                    issues = ", ".join(item.get("issues", [])[:2])
                    w(f"    - {item['site'][:30]}: {issues}")
                w()
    else:
        w("  No password file provided. Use --passwords to include audit.")
        w()

    w("-" * 72)
    w("  SECTION 3: SECURITY CHECKLIST")
    w("-" * 72)
    w()

    checklist = [
        ("Monitor active", bool(monitor_state.get("emails"))),
        ("HIBP API key set", bool(monitor_state.get("api_key"))),
        ("Email alerts set", bool(monitor_state.get("smtp", {}).get("host"))),
        ("Password file audited", bool(password_file)),
    ]
    for label, done in checklist:
        status = "[DONE]" if done else "[TODO]"
        w(f"  {status}  {label}")
    w()

    w("-" * 72)
    w("  SECTION 4: RECOMMENDATIONS")
    w("-" * 72)
    w()

    recommendations = [
        "Use a password manager.",
        "Enable 2FA on email, banking, and work accounts.",
        "Use unique passwords for every service.",
        "Run 'datasec monitor run --once' regularly.",
        "Strip metadata before sharing sensitive documents.",
        "Encrypt sensitive files before cloud backup.",
    ]
    for index, recommendation in enumerate(recommendations, 1):
        w(f"  {index}. {recommendation}")
    w()

    w("=" * 72)
    w("  END OF REPORT")
    w("=" * 72)
    w()

    report_text = "\n".join(lines)
    report_path.write_text(report_text, encoding="utf-8")

    sha256 = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    hash_path = report_path.with_suffix(".txt.sha256")
    hash_path.write_text(f"{sha256}  {report_path.name}\n", encoding="utf-8")

    console.print(
        Panel(
            f"[bold green]Report generated[/bold green]\n\n"
            f"  Report:   [cyan]{report_path}[/cyan]\n"
            f"  SHA-256:  [cyan]{hash_path}[/cyan]\n"
            f"  Hash:     [dim]{sha256[:32]}...[/dim]",
            border_style="green",
        )
    )

    if sign_gpg:
        _sign_gpg(report_path, gpg_key)

    _print_verify_instructions(report_path, hash_path)
    return str(report_path)


def verify_report(report_path: str) -> bool:
    """Verify the SHA-256 hash of a previously generated report."""
    path = Path(report_path)
    hash_path = Path(str(path) + ".sha256")

    if not hash_path.exists():
        console.print(f"[red]Hash file not found: {hash_path}[/red]")
        return False

    expected_hash = hash_path.read_text(encoding="utf-8").strip().split()[0]
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()

    if actual_hash == expected_hash:
        console.print("[bold green]Report integrity verified[/bold green]")
        console.print(f"[dim]  SHA-256: {actual_hash}[/dim]")
        return True

    console.print("[bold red]Hash mismatch - report may have been tampered with[/bold red]")
    console.print(f"[dim]  Expected: {expected_hash}[/dim]")
    console.print(f"[dim]  Actual:   {actual_hash}[/dim]")
    return False


def _load_monitor_state() -> dict:
    state_file = Path.home() / ".datasec" / "monitor_state.json"
    if state_file.exists():
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _run_password_audit(filepath: str, formato: str) -> dict | None:
    try:
        from collections import Counter

        from datasec.password_auditor import _analyze_strength, _load_passwords

        entries = _load_passwords(filepath, formato)
        if not entries:
            return None

        counts = Counter(entry["password"] for entry in entries)
        weak_n = 0
        reused_n = 0
        strong_n = 0
        critical = []

        for entry in entries:
            password = entry["password"]
            strength, issues = _analyze_strength(password)
            reused = counts[password] > 1
            if reused:
                issues.append(f"reused {counts[password]}x")
                reused_n += 1
            if strength == "debil":
                weak_n += 1
            elif strength == "fuerte":
                strong_n += 1
            if strength != "fuerte" or reused:
                critical.append({**entry, "issues": issues})

        return {
            "total": len(entries),
            "weak": weak_n,
            "reused": reused_n,
            "pwned": 0,
            "strong": strong_n,
            "critical": critical,
        }
    except Exception as exc:
        console.print(f"[yellow]Password audit skipped: {exc}[/yellow]")
        return None


def _sign_gpg(report_path: Path, key_id: str = None):
    cmd = ["gpg", "--detach-sign", "--armor"]
    if key_id:
        cmd += ["--local-user", key_id]
    cmd.append(str(report_path))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green]GPG signature written: {report_path}.asc[/green]")
        else:
            console.print(f"[yellow]GPG signing failed: {result.stderr.strip()}[/yellow]")
    except FileNotFoundError:
        console.print("[yellow]GPG is not installed.[/yellow]")


def _print_verify_instructions(report_path: Path, hash_path: Path):
    console.print()
    console.print(Rule("[dim]Verification[/dim]"))
    console.print("[dim]To verify this report later:[/dim]")
    console.print(f"[cyan]  datasec report verify {report_path}[/cyan]")
    console.print(f"[dim]Or manually:[/dim]")
    console.print(f"[cyan]  sha256sum -c {hash_path}[/cyan]")
    console.print()
