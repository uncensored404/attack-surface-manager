from pathlib import Path
from typing import List, Set
import re


def load_scope(scope_file: Path) -> List[str]:
    """Charge le fichier de périmètre autorisé."""
    if not scope_file.exists():
        raise FileNotFoundError(
            f"Fichier de scope introuvable : {scope_file}\n"
            "Créez un fichier scope.txt listant les domaines autorisés."
        )

    domains = []
    with open(scope_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Nettoyage basique
            line = line.lower().replace("https://", "").replace("http://", "").split("/")[0]
            if line:
                domains.append(line)

    if not domains:
        raise ValueError("Le fichier de scope est vide. Ajoutez au moins un domaine autorisé.")

    return domains


def is_in_scope(hostname: str, scope: List[str]) -> bool:
    """Vérifie si un hostname appartient au périmètre autorisé."""
    hostname = hostname.lower().rstrip(".")
    for entry in scope:
        entry = entry.lower()
        if entry.startswith("*."):
            # Wildcard : *.exemple.com
            base = entry[2:]
            if hostname == base or hostname.endswith("." + base):
                return True
        elif hostname == entry:
            return True
    return False
