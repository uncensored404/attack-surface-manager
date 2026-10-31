#!/usr/bin/env python3
"""
ATTACK SURFACE MANAGER — Cartographie de la surface d'attaque
Author: 404sec
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console

from core.scope import load_scope
from core.subdomains import discover_subdomains
from core.port_scanner import scan_hosts
from core.tls_monitor import monitor_certificates
from core.state import load_previous_state, save_state, compare_states
from core.report import print_report, export_json, export_html

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="ATTACK SURFACE MANAGER — Cartographie de surface d'attaque (by 404sec)"
    )
    parser.add_argument("--scope", required=True, help="Fichier de périmètre autorisé (scope.txt)")
    parser.add_argument("--ports", default=None, help="Ports à scanner (ex: 80,443,8080)")
    parser.add_argument("-o", "--output", default="asm_report", help="Nom de base des rapports")
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument("--no-json", action="store_true")

    args = parser.parse_args()
    scope_path = Path(args.scope)

    console.print("\n[bold cyan]🗺️  ATTACK SURFACE MANAGER[/bold cyan] — by 404sec\n")
    console.print("[yellow]Rappel : n'utilisez cet outil que sur un périmètre explicitement autorisé.[/yellow]\n")

    # 1. Chargement du scope (obligatoire)
    try:
        scope = load_scope(scope_path)
        console.print(f"[green][+] Scope chargé : {len(scope)} entrée(s)[/green]")
        for s in scope:
            console.print(f"    • {s}")
    except Exception as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)

    # 2. Découverte de sous-domaines
    console.print("\n[bold]Phase 1 — Découverte des actifs[/bold]")
    hosts = discover_subdomains(scope, scope)
    console.print(f"[green][+] {len(hosts)} hôte(s) dans le périmètre[/green]")

    if not hosts:
        console.print("[yellow]Aucun hôte résolvable trouvé dans le scope.[/yellow]")
        sys.exit(0)

    # 3. Scan de ports
    console.print("\n[bold]Phase 2 — Scan de ports[/bold]")
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    port_results = scan_hosts(hosts, ports)

    # 4. Certificats TLS
    console.print("\n[bold]Phase 3 — Surveillance des certificats TLS[/bold]")
    # On ne teste le TLS que sur les hôtes qui ont 443 ou 8443 ouvert
    tls_hosts = []
    for r in port_results:
        if 443 in r["open_ports"] or 8443 in r["open_ports"]:
            tls_hosts.append(r["hostname"])
        elif not r["open_ports"]:
            # On tente quand même 443
            tls_hosts.append(r["hostname"])

    cert_results = monitor_certificates(list(set(tls_hosts)))

    # 5. Construction de l'état actuel
    current_state = {
        "scan_date": datetime.now().isoformat(),
        "hosts": {},
        "certificates": cert_results
    }
    for r in port_results:
        current_state["hosts"][r["hostname"]] = {
            "open_ports": r["open_ports"],
            "services": r["services"]
        }

    # 6. Comparaison avec l'état précédent
    previous = load_previous_state()
    changes = compare_states(current_state, previous)
    save_state(current_state)

    # 7. Rapport
    print_report(current_state, changes)

    output_base = Path(args.output)
    if not args.no_json:
        export_json(current_state, changes, output_base.with_suffix(".json"))
    if not args.no_html:
        export_html(current_state, changes, output_base.with_suffix(".html"))

    console.print("\n[green][+] Cartographie terminée.[/green]\n")


if __name__ == "__main__":
    main()
