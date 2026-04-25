"""
Módulo 3: OSINT Self-Scanner
Escanea tu huella digital en fuentes públicas y abiertas.
Busca en Google (dorks), Pastebin, GitHub, registros WHOIS, y más.
"""

import requests
import urllib.parse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import print as rprint

console = Console()


# ── Fuentes por tipo de query ──────────────────────────────────────────────

DORKS = {
    "email": [
        '"{query}" site:pastebin.com',
        '"{query}" site:github.com',
        '"{query}" filetype:sql OR filetype:txt OR filetype:csv',
        '"{query}" intext:password OR intext:contraseña',
        '"{query}" site:linkedin.com',
    ],
    "nombre": [
        '"{query}" site:linkedin.com',
        '"{query}" site:facebook.com',
        '"{query}" site:twitter.com',
        '"{query}" redes sociales México',
    ],
    "usuario": [
        '"{query}" site:github.com',
        '"{query}" site:reddit.com',
        '"{query}" site:twitter.com',
        '"{query}" site:instagram.com',
        '"{query}" site:pastebin.com',
    ],
    "telefono": [
        '"{query}" site:truecaller.com',
        '"{query}" WhatsApp OR Telegram',
        '"{query}" Mexico OR México directorio',
        '"{query}" site:listaspam.com',
    ]
}

# Plataformas donde verificar si existe un usuario (por nombre de usuario)
USERNAME_PLATFORMS = {
    "GitHub":    "https://github.com/{u}",
    "Twitter/X": "https://twitter.com/{u}",
    "Instagram": "https://instagram.com/{u}",
    "Reddit":    "https://reddit.com/user/{u}",
    "LinkedIn":  "https://linkedin.com/in/{u}",
    "TikTok":    "https://tiktok.com/@{u}",
    "Twitch":    "https://twitch.tv/{u}",
    "YouTube":   "https://youtube.com/@{u}",
    "Telegram":  "https://t.me/{u}",
    "GitLab":    "https://gitlab.com/{u}",
    "Keybase":   "https://keybase.io/{u}",
    "Pastebin":  "https://pastebin.com/u/{u}",
}

# Headers realistas para no ser bloqueado trivialmente
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}


def scan_footprint(query: str, query_type: str):
    console.print(f"\n[bold]🌐 OSINT scan:[/bold] [cyan]{query}[/cyan] [dim]({query_type})[/dim]\n")

    # 1. Google dorks
    _show_dorks(query, query_type)

    # 2. Username check (solo para email y usuario)
    if query_type in ("usuario", "email"):
        username = query.split("@")[0] if query_type == "email" else query
        _check_username_presence(username)

    # 3. Recursos específicos para México
    _show_mx_resources(query, query_type)

    # 4. Recomendaciones finales
    _show_osint_tips(query_type)


def _show_dorks(query: str, query_type: str):
    console.print(Rule("[dim]Google Dorks — copia y pega en Google[/dim]"))
    console.print("[dim]Busca filtraciones, menciones públicas y datos expuestos\n[/dim]")

    table = Table(show_header=False, box=None, padding=(0, 1), min_width=70)
    table.add_column("", style="dim", width=3)
    table.add_column("Búsqueda", style="cyan")

    dorks = DORKS.get(query_type, DORKS["email"])
    for i, dork in enumerate(dorks, 1):
        search_string = dork.format(query=query)
        encoded = urllib.parse.quote(search_string)
        table.add_row(
            f"{i}.",
            f"{search_string}\n[dim]  → https://google.com/search?q={encoded}[/dim]"
        )

    console.print(table)
    console.print()


def _check_username_presence(username: str):
    console.print(Rule("[dim]Presencia en plataformas (verificación HTTP)[/dim]"))
    console.print(f"[dim]Verificando si '{username}' existe en plataformas conocidas...\n[/dim]")

    found = []
    not_found = []
    errors = []

    for platform, url_template in USERNAME_PLATFORMS.items():
        url = url_template.format(u=username)
        try:
            resp = requests.get(url, headers=REQUEST_HEADERS, timeout=6, allow_redirects=True)

            # Heurística: 200 = probablemente existe, 404 = no existe
            # Algunos sitios devuelven 200 aunque no exista (falso positivo posible)
            if resp.status_code == 200:
                # Verificación extra: si la página contiene el username en el título
                page_lower = resp.text.lower()
                username_lower = username.lower()
                if username_lower in page_lower[:3000]:  # Solo revisar primeros 3KB
                    found.append((platform, url))
                else:
                    # Puede existir pero no confirmado
                    found.append((platform, f"{url} [dim](posible)[/dim]"))
            elif resp.status_code == 404:
                not_found.append(platform)
            else:
                errors.append(f"{platform} (HTTP {resp.status_code})")

        except requests.exceptions.Timeout:
            errors.append(f"{platform} (timeout)")
        except Exception:
            errors.append(platform)

    if found:
        console.print(f"[bold green]Encontrado en {len(found)} plataformas:[/bold green]")
        for platform, url in found:
            console.print(f"  [green]●[/green] [bold]{platform}[/bold] → {url}")
        console.print()

    if not_found:
        console.print(f"[dim]No encontrado en: {', '.join(not_found)}[/dim]")

    if errors:
        console.print(f"[dim]No verificado: {', '.join(errors)}[/dim]")

    console.print()


def _show_mx_resources(query: str, query_type: str):
    console.print(Rule("[dim]Recursos específicos para México[/dim]"))
    encoded = urllib.parse.quote(query)

    resources = []

    if query_type == "email":
        resources = [
            ("Filtración SAT/INE (Dehashed)", f"https://dehashed.com/search?query={encoded}"),
            ("IntelX — indexa breaches LATAM", f"https://intelx.io/?s={encoded}"),
            ("Breach Directory", f"https://breachdirectory.org/"),
            ("Ragine — buscador dark web indexado", "https://ragine.com"),
        ]
    elif query_type == "nombre":
        resources = [
            ("Búsqueda CURP (si aplica)", f"https://www.gob.mx/curp/"),
            ("Registros públicos MX", "https://www.rpc.gob.mx/"),
            ("Directorio IMSS (trabajadores)", "https://serviciosdigitales.imss.gob.mx"),
        ]
    elif query_type == "telefono":
        resources = [
            ("TrueCaller (quién llama)", f"https://www.truecaller.com/search/mx/{query}"),
            ("Lista Spam MX", "https://www.listaspam.com/"),
            ("NumLookup", f"https://www.numlookup.com/?number={query}"),
        ]
    elif query_type == "usuario":
        resources = [
            ("Sherlock Project (CLI avanzado)", "https://github.com/sherlock-project/sherlock"),
            ("WhatsMyName", "https://whatsmyname.app/"),
            ("Namechk", f"https://namechk.com/"),
        ]

    if resources:
        for name, url in resources:
            console.print(f"  [cyan]→[/cyan] [bold]{name}[/bold]\n    [dim]{url}[/dim]")
    console.print()


def _show_osint_tips(query_type: str):
    tips = {
        "email": [
            "Usa alias de email (+alias@gmail.com) para detectar quién filtró tus datos",
            "Considera un email dedicado para servicios de poca confianza",
            "Revisa en Settings de Gmail si hay accesos no autorizados",
        ],
        "nombre": [
            "Googlea tu nombre entre comillas cada 3 meses",
            "Solicita eliminación de datos a sitios de 'people search' que te indexen",
            "Configura Google Alerts para tu nombre: alerts.google.com",
        ],
        "usuario": [
            "Usa usernames distintos en plataformas críticas vs recreativas",
            "Revisa si tu usuario aparece en breaches vía breachdirectory.org",
            "Considera el username como dato de identificación — puede linkear cuentas",
        ],
        "telefono": [
            "Registra tu número en REPEP (Registro para no recibir publicidad): repep.profeco.gob.mx",
            "Nunca compartas tu número de teléfono en redes sociales públicas",
            "Usa un número virtual (Google Voice, Hushed) para registros en apps",
        ]
    }

    console.print(Panel(
        "\n".join(f"  • {t}" for t in tips.get(query_type, [])),
        title="[bold]Recomendaciones OSINT[/bold]",
        border_style="cyan"
    ))
