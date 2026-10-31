from pathlib import Path
from typing import Dict, List, Set
import json
from datetime import datetime


STATE_FILE = Path("data/last_state.json")


def load_previous_state() -> Dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(data: Dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["last_scan"] = datetime.now().isoformat()
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def compare_states(current: Dict, previous: Dict) -> Dict:
    """Compare l'état actuel avec le précédent et détecte les nouveautés."""
    changes = {
        "new_hosts": [],
        "new_ports": [],
        "new_certs_expiring": [],
        "removed_hosts": []
    }

    prev_hosts = set(previous.get("hosts", {}).keys())
    curr_hosts = set(current.get("hosts", {}).keys())

    changes["new_hosts"] = sorted(curr_hosts - prev_hosts)
    changes["removed_hosts"] = sorted(prev_hosts - curr_hosts)

    # Nouveaux ports
    for host in curr_hosts:
        prev_ports = set(previous.get("hosts", {}).get(host, {}).get("open_ports", []))
        curr_ports = set(current.get("hosts", {}).get(host, {}).get("open_ports", []))
        new_p = curr_ports - prev_ports
        if new_p:
            changes["new_ports"].append({
                "hostname": host,
                "ports": sorted(new_p)
            })

    # Certificats qui commencent à être critiques
    for cert in current.get("certificates", []):
        days = cert.get("days_left")
        if days is not None and 0 <= days <= 30:
            changes["new_certs_expiring"].append({
                "hostname": cert["hostname"],
                "days_left": days
            })

    return changes
