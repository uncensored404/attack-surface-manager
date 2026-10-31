from typing import List, Dict
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()

# Ports courants à scanner (liste raisonnable)
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 8888]


def scan_host(hostname: str, ports: List[int] = None, timeout: float = 1.2) -> Dict:
    """Scan de ports TCP simple et non agressif."""
    ports = ports or DEFAULT_PORTS
    open_ports = []

    def check_port(port: int) -> int | None:
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return port
        except (socket.timeout, socket.error, OSError):
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort()
    return {
        "hostname": hostname,
        "open_ports": open_ports,
        "services": [_guess_service(p) for p in open_ports]
    }


def scan_hosts(hostnames: List[str], ports: List[int] = None) -> List[Dict]:
    results = []
    for host in hostnames:
        console.print(f"[cyan][*] Scan de ports sur {host}[/cyan]")
        result = scan_host(host, ports)
        if result["open_ports"]:
            console.print(f"  [green]Ports ouverts : {result['open_ports']}[/green]")
        results.append(result)
    return results


def _guess_service(port: int) -> str:
    services = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt"
    }
    return services.get(port, f"Unknown-{port}")
