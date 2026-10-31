# 🗺️ ATTACK SURFACE MANAGER

**Cartographie de la surface d'attaque — by 404sec**

---

### Description

ATTACK SURFACE MANAGER est un outil défensif destiné aux entreprises qui souhaitent connaître et suivre leurs actifs exposés sur Internet.

Il permet d’inventorier les domaines et sous-domaines autorisés, d’identifier les services exposés, de surveiller les certificats TLS et de détecter les changements dans la surface d’attaque.

### Fonctionnalités

- Inventaire des domaines et sous-domaines (périmètre autorisé)
- Identification des services exposés
- Détection des certificats TLS arrivant à expiration
- Suivi des ports accessibles
- Comparaison quotidienne de la surface d’exposition
- Alertes sur les nouveaux actifs découverts
- Export de rapports (JSON + HTML)

### ⚠️ Périmètre autorisé obligatoire

Le scanner **refuse de fonctionner** sans un fichier de scope (`scope.txt`) listant explicitement les domaines autorisés.  
N’utilisez cet outil que sur des actifs que vous possédez ou pour lesquels vous avez une autorisation.

### Installation

```bash
git clone https://github.com/404sec/attack-surface-manager.git
cd attack-surface-manager
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration du périmètre

Créez un fichier `scope.txt` à la racine :

```
exemple.com
api.exemple.com
*.exemple.com
```

### Utilisation

```bash
python asm.py --scope scope.txt
python asm.py --scope scope.txt --ports 80,443,8080,8443
python asm.py --scope scope.txt --output rapport_asm
```

### Auteur

**404sec**

### Disclaimer

Outil purement défensif.  
Toute utilisation sur un périmètre non autorisé est interdite et illégale.
