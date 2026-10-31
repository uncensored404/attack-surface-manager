from typing import List, Dict
import socket
import ssl
from datetime import datetime, timezone
from rich.console import Console

console = Console()


def check_certificate(hostname: str, port: int = 443) -> Dict:
    """Récupère les informations du certificat TLS."""
    result = {
        "hostname": hostname,
        "port": port,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_left": None,
        "error": None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                result["valid"] = True
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))

                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")

                if not_after:
                    expire = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["not_after"] = expire.isoformat()
                    result["days_left"] = (expire - datetime.now(timezone.utc)).days

                if not_before:
                    result["not_before"] = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()

    except Exception as e:
        result["error"] = str(e)

    return result


def monitor_certificates(hostnames: List[str]) -> List[Dict]:
    results = []
    for host in hostnames:
        console.print(f"[cyan][*] Vérification certificat : {host}[/cyan]")
        cert_info = check_certificate(host)
        results.append(cert_info)

        if cert_info["valid"]:
            days = cert_info["days_left"]
            if days is not None and days < 0:
                console.print(f"  [red]EXPIRÉ depuis {-days} jours[/red]")
            elif days is not None and days < 30:
                console.print(f"  [yellow]Expire dans {days} jours[/yellow]")
            else:
                console.print(f"  [green]Valide — {days} jours restants[/green]")
        else:
            console.print(f"  [dim]Pas de certificat TLS valide ({cert_info['error']})[/dim]")

    return results
