from typing import Dict, List
from datetime import datetime
from pathlib import Path
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_report(data: Dict, changes: Dict):
    console.print()
    console.print(Panel.fit(
        "[bold cyan]ATTACK SURFACE MANAGER[/bold cyan]\n[dim]by 404sec[/dim]",
        border_style="cyan"
    ))

    console.print(f"\n[bold]Date du scan :[/bold] {data.get('scan_date', 'N/A')}")
    console.print(f"[bold]Hôtes découverts :[/bold] {len(data.get('hosts', {}))}")

    # Tableau des hôtes
    table = Table(title="Actifs découverts", box=box.SIMPLE)
    table.add_column("Hostname", style="cyan")
    table.add_column("Ports ouverts")
    table.add_column("Services")

    for host, info in data.get("hosts", {}).items():
        ports = ", ".join(map(str, info.get("open_ports", []))) or "-"
        services = ", ".join(info.get("services", [])) or "-"
        table.add_row(host, ports, services)

    console.print(table)

    # Certificats
    console.print("\n[bold]Certificats TLS[/bold]")
    for cert in data.get("certificates", []):
        if not cert.get("valid"):
            continue
        days = cert.get("days_left")
        color = "green"
        if days is not None and days < 0:
            color = "red"
        elif days is not None and days < 30:
            color = "yellow"
        console.print(f"  [{color}]{cert['hostname']} — {days} jours restants[/{color}]")

    # Changements
    if changes.get("new_hosts") or changes.get("new_ports") or changes.get("new_certs_expiring"):
        console.print("\n[bold red]⚠ Changements détectés depuis le dernier scan[/bold red]")
        if changes["new_hosts"]:
            console.print(f"  Nouveaux hôtes : {', '.join(changes['new_hosts'])}")
        if changes["new_ports"]:
            for item in changes["new_ports"]:
                console.print(f"  Nouveaux ports sur {item['hostname']} : {item['ports']}")
        if changes["new_certs_expiring"]:
            for item in changes["new_certs_expiring"]:
                console.print(f"  Certificat bientôt expiré : {item['hostname']} ({item['days_left']} jours)")
    else:
        console.print("\n[green]Aucun nouveau changement critique détecté.[/green]")


def export_json(data: Dict, changes: Dict, output_path: Path):
    payload = {
        "tool": "ATTACK SURFACE MANAGER",
        "author": "404sec",
        "scan_date": data.get("scan_date"),
        "hosts": data.get("hosts"),
        "certificates": data.get("certificates"),
        "changes": changes
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    console.print(f"\n[green]✓ Rapport JSON : {output_path}[/green]")


def export_html(data: Dict, changes: Dict, output_path: Path):
    rows = ""
    for host, info in data.get("hosts", {}).items():
        ports = ", ".join(map(str, info.get("open_ports", []))) or "-"
        services = ", ".join(info.get("services", [])) or "-"
        rows += f"<tr><td>{host}</td><td>{ports}</td><td>{services}</td></tr>"

    cert_rows = ""
    for cert in data.get("certificates", []):
        if cert.get("valid"):
            days = cert.get("days_left", "N/A")
            cert_rows += f"<tr><td>{cert['hostname']}</td><td>{days}</td><td>{cert.get('not_after', '')}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Attack Surface Manager - Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f1419; color: #e7e9ea; padding: 30px; }}
        h1 {{ color: #1d9bf0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #2f3336; }}
        th {{ background: #15202b; color: #8b98a5; }}
        .alert {{ background: rgba(244,33,46,0.1); padding: 12px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🗺️ ATTACK SURFACE MANAGER</h1>
    <p>by 404sec — {data.get('scan_date', '')}</p>

    <h2>Actifs découverts</h2>
    <table>
        <thead><tr><th>Hostname</th><th>Ports ouverts</th><th>Services</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>

    <h2>Certificats TLS</h2>
    <table>
        <thead><tr><th>Hostname</th><th>Jours restants</th><th>Expiration</th></tr></thead>
        <tbody>{cert_rows}</tbody>
    </table>
"""

    if changes.get("new_hosts") or changes.get("new_ports"):
        html += "<div class='alert'><strong>⚠ Nouveaux actifs / ports détectés</strong><ul>"
        for h in changes.get("new_hosts", []):
            html += f"<li>Nouvel hôte : {h}</li>"
        for item in changes.get("new_ports", []):
            html += f"<li>Nouveaux ports sur {item['hostname']} : {item['ports']}</li>"
        html += "</ul></div>"

    html += """
    <p style="color:#8b98a5;font-size:13px;margin-top:40px;">
        ATTACK SURFACE MANAGER — Outil défensif. Utilisation uniquement sur périmètre autorisé.
    </p>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[green]✓ Rapport HTML : {output_path}[/green]")
