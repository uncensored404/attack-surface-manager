from typing import List, Set
import dns.resolver
from rich.console import Console

console = Console()

# Liste de sous-domaines courants à tester (bruteforce léger et contrôlé)
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap",
    "api", "dev", "test", "staging", "stage", "beta",
    "admin", "portal", "app", "cdn", "static", "assets",
    "blog", "shop", "store", "vpn", "remote", "git",
    "gitlab", "jenkins", "ci", "docs", "status", "monitor",
    "db", "mysql", "postgres", "redis", "ftp", "sftp",
    "ns1", "ns2", "dns", "mx", "autodiscover", "lyncdiscover",
    "office", "exchange", "owa", "vpn", "firewall", "proxy"
]


def discover_subdomains(base_domains: List[str], scope: List[str]) -> List[str]:
    """Découverte passive + légère de sous-domaines dans le scope."""
    found: Set[str] = set()

    for domain in base_domains:
        # On ignore les wildcards pour le moment
        if domain.startswith("*."):
            domain = domain[2:]

        console.print(f"[cyan][*] Résolution et découverte pour {domain}[/cyan]")

        # Le domaine lui-même
        if _resolves(domain):
            found.add(domain)

        # Sous-domaines courants
        for sub in COMMON_SUBDOMAINS:
            candidate = f"{sub}.{domain}"
            if _resolves(candidate):
                found.add(candidate)
                console.print(f"  [green]+[/green] {candidate}")

    # Filtrage strict sur le scope
    in_scope = [h for h in found if _is_in_scope(h, scope)]
    return sorted(in_scope)


def _resolves(hostname: str) -> bool:
    try:
        dns.resolver.resolve(hostname, "A")
        return True
    except Exception:
        try:
            dns.resolver.resolve(hostname, "AAAA")
            return True
        except Exception:
            return False


def _is_in_scope(hostname: str, scope: List[str]) -> bool:
    hostname = hostname.lower()
    for entry in scope:
        entry = entry.lower()
        if entry.startswith("*."):
            base = entry[2:]
            if hostname == base or hostname.endswith("." + base):
                return True
        elif hostname == entry or hostname.endswith("." + entry):
            return True
    return False
