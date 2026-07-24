# Framework d'automatisation de pentest

Couche d'**orchestration** Python autour d'outils de pentest éprouvés (nmap,
whatweb, nikto, sqlmap, hydra, ZAP). Le framework ne réimplémente **aucun**
scanner : il déclenche les bons outils selon le contexte détecté, normalise
leurs sorties dans un schéma commun, et produit un rapport structuré.

Cibles **strictement** limitées (garde-fou de scope bloquant) :

- **OWASP Juice Shop** — web app classique (SPA Angular)
- **VAmPI** — API REST volontairement vulnérable (OWASP API Top 10)

---

## Architecture

```
DevSecOps/
├── core/
│   ├── scope.py        # GARDE-FOU : refuse toute cible hors whitelist AVANT tout réseau
│   ├── recon.py        # wrappers nmap / whatweb / nikto (subprocess -> objets Python)
│   ├── probe.py        # découverte ACTIVE : login + paramètres injectables
│   ├── detect.py       # résultats recon/probe -> findings normalisés (validés)
│   ├── exploit.py      # déclenchement RÉEL et CONDITIONNEL de sqlmap / hydra
│   └── report.py       # findings -> rapport JSON + HTML (+ PDF si weasyprint)
├── config/
│   ├── targets.yaml    # whitelist des cibles autorisées (host/port/ips)
│   └── wordlists/      # users.txt / passwords.txt pour hydra
├── findings_schema.json# schéma JSON commun des findings
├── scripts_kali/       # commandes canoniques + preuve de limite (BOLA)
│   ├── run_nmap.sh  run_nikto.sh  run_sqlmap.sh  run_hydra.sh
│   └── run_bola_check.py   # PREUVE : vuln BOLA ratée par les scans auto
├── ui/app.py           # dashboard Streamlit
├── tests/              # tests unitaires (scope.py en priorité)
├── logs/audit.log      # journal d'audit de chaque tentative (autorisé/refusé)
├── main.py             # CLI d'entrée
└── requirements.txt
```

### Chaîne recon → détection → exploitation

1. **Recon** (`recon.py`) : nmap (ports/versions), whatweb (stack), nikto (vulns génériques).
2. **Découverte active** (`probe.py`) : sonde des chemins usuels pour repérer les
   endpoints de **login** et les **paramètres GET** de type recherche (réponse JSON).
   Infère les champs (`email`/`username`) et un marqueur d'échec fiable.
3. **Détection** (`detect.py`) : normalise le tout en findings, dont `login_form`
   et `suspicious_parameter` qui servent de **déclencheurs**.
4. **Exploitation** (`exploit.py`) — déclenchée par ces findings :
   - `suspicious_parameter` → **sqlmap** (SQLi sur le paramètre GET) ;
   - `login_form` → **hydra** (brute-force avec les wordlists) **et** **sqlmap**
     (SQLi sur le champ identifiant, en POST JSON).

Résultats réels obtenus sur les cibles :
- **Juice Shop** : sqlmap confirme une **injection SQL** sur `/rest/products/search?q=`.
- **VAmPI** : hydra **casse les identifiants faibles** par défaut
  (`admin:pass1`, `name1:pass1`, `name2:pass2`) sur `/users/v1/login`.

---

## Prérequis

- **Python 3.11+**
- **Outils Kali** (installés au niveau système, PAS via pip). Sur le bureau Kali :
  ```bash
  which nmap nikto sqlmap hydra whatweb || \
    sudo apt update && sudo apt install -y nmap nikto sqlmap hydra whatweb
  # ZAP / nuclei (optionnels, pour VAmPI et le scan de CVE) :
  sudo apt install -y zaproxy
  ```
- **Cibles en Docker**, joignables depuis Kali :
  ```bash
  docker run -d -p 3000:3000 bkimminich/juice-shop
  docker run -d -p 5000:5000 erev0s/vampi
  # Vérifier la connectivité (hostname Docker, sinon localhost) :
  curl -s http://juiceshop:3000 >/dev/null && echo "juiceshop OK"
  curl -s http://vampi:5000     >/dev/null && echo "vampi OK"
  ```
  Si les hostnames `juiceshop`/`vampi` ne résolvent pas, `localhost:3000` et
  `localhost:5000` sont déjà dans la whitelist (`config/targets.yaml`).

---

## Installation

Le framework s'exécute **dans le conteneur Kali** (les outils et les hostnames
`juiceshop`/`vampi` n'existent que là). `setup.sh` détecte l'environnement et
s'occupe de tout.

**Depuis un terminal HÔTE** (macOS/Windows/Linux avec Docker) — le script
**lance les cibles manquantes** (Juice Shop/VAmPI), synchronise le code dans le
conteneur Kali, s'y installe, puis ouvre un shell Kali avec le venv actif :

```bash
./setup.sh
# -> vous vous retrouvez dans :  (.venv) root@kali:/root/DevSecOps#
./setup.sh --no-targets   # sans (re)lancer les conteneurs cibles
```

> Sur une machine où VAmPI/Juice Shop ne sont pas installés, `setup.sh` les
> démarre automatiquement sur le réseau de Kali (images surchargables via
> `VAMPI_IMAGE` / `JUICESHOP_IMAGE`).

**Depuis un terminal DANS Kali** (bureau `http://localhost:18090`) — à
`source`-er pour que le venv reste actif dans le shell :

```bash
source setup.sh              # tout-en-un : outils + venv + deps + diagnostic
source setup.sh --no-apt     # sans installer les outils système (déjà présents)
```

> Variables surchargables si votre conteneur a un autre nom :
> `KALI_CONTAINER=<nom> ./setup.sh` (défaut : `lac-kali-kali-1`).

**Option B — manuelle** :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Diagnostic des prérequis

```bash
python main.py doctor
```

Vérifie en une commande : présence des outils Kali (nmap, whatweb, nikto,
sqlmap, hydra), dépendances Python, chargement de la config de scope, et
**connectivité aux cibles** (testée uniquement sur les cibles whitelistées,
via le garde-fou). Sortie codée couleur, code retour non nul si un prérequis
bloquant manque.

---

## Lancement en 1 commande

```bash
python main.py scan --target juiceshop --full
```

Autres usages :

```bash
python main.py targets                                   # liste la whitelist
python main.py doctor                                    # diagnostic prérequis
python main.py scan --target vampi --steps recon,detect,report
python main.py scan --target 8.8.8.8                     # -> REFUSÉ (hors scope)
streamlit run ui/app.py                                  # dashboard web
```

---

## Le garde-fou de scope (sécurité non négociable)

`core/scope.py` **empêche techniquement** (pas seulement avertit) tout appel
réseau vers une cible absente de `config/targets.yaml` :

- `scope.assert_in_scope(target)` est appelé **au début de chaque fonction**
  qui émet une requête réseau (recon, detect actif, exploit) — pas seulement
  au niveau CLI.
- Hors scope → `ScopeError` levée **avant** toute requête, et tentative
  journalisée dans `logs/audit.log` (cible, verdict, raison).
- Vérification sur le couple **(host, port)** + option de résolution DNS/IP
  (défense en profondeur contre typo/rebinding).

Démonstration :

```bash
$ python main.py scan --target 8.8.8.8
[main] REFUSÉ — CIBLE HORS SCOPE : '8.8.8.8'. Requête réseau BLOQUÉE avant émission.
```

Tests (cas autorisé ET refusé) :

```bash
pytest tests/ -q          # 20 tests, dont 17 sur scope.py
```

---

## Outils orchestrés (réutilisation, pas réimplémentation)

| Étape | Outil | Licence | Pourquoi ce choix |
|-------|-------|---------|-------------------|
| Ports/services | **nmap** | NPSL (open source) | Standard de fait, sortie XML parsable, détection de version `-sV`. |
| Fingerprint techno | **whatweb** | GPLv3 | Identifie la stack (Express, Angular…), sortie JSON. |
| Scan web générique (Juice Shop) | **nikto** | GPL | Rapide, CLI simple, sortie CSV parsable. |
| Scan API (VAmPI) | **OWASP ZAP** | Apache 2.0 | Consomme la spec **OpenAPI/Swagger** de VAmPI et génère des tests. Préféré à **Burp Community** car scriptable en CLI/CI (`zap-api-scan.py`), Burp étant orienté GUI interactif. |
| CVE connues (option) | **nuclei** | MIT | Templates communautaires à jour. |
| Exploitation SQLi | **sqlmap** | GPLv2 | Référence pour l'injection SQL, mode `--batch` non interactif. |
| Brute-force login | **hydra** | AGPL | Référence pour le brute-force de formulaires d'auth. |

Le framework **décide** quel outil déclencher selon le contexte (ex : sqlmap
seulement si un paramètre suspect est détecté) et **normalise** chaque sortie
dans `findings_schema.json`. Aucun scanner « maison ».

---

## Preuve de la limite de l'automatisation (BOLA sur VAmPI)

Livrable spécifique : montrer une vuln que le scan **automatique** rate, puis
l'exploiter **manuellement**.

1. **Scan automatique** (ne détecte rien de spécifique) :
   ```bash
   nikto -h vampi -p 5000                  # aucune alerte BOLA
   # ou zap-api-scan.py -t http://vampi:5000/openapi.json -f openapi
   ```
2. **Script manuel** (exploite la BOLA) :
   ```bash
   python scripts_kali/run_bola_check.py --target vampi
   ```
   Le script authentifie `userB`, requête les données privées de `userA`
   (livre + secret) via l'identifiant dans l'URL, et prouve que le secret de
   `userA` est renvoyé à `userB`.

**Pourquoi le scan auto échoue (raison technique)** : le serveur renvoie deux
réponses HTTP 200 valides. Un scanner générique n'a **aucun modèle métier** lui
permettant de savoir que la donnée renvoyée à `userB` appartient en réalité à
`userA`. Détecter la BOLA exige de **rejouer la même requête avec deux
contextes d'authentification différents** et de **comparer sémantiquement** les
réponses — ce qu'aucun scanner générique ne fait nativement.

---

## Limites structurelles d'un pentest 100 % automatique (à documenter)

**Sur Juice Shop (web app)**
- **Logique métier** : manipuler le prix d'un article, accéder aux commandes
  d'autrui — un scanner voit une requête valide, il ignore que la donnée
  n'appartient pas légitimement à l'utilisateur courant.
- **JS côté client (SPA Angular)** : Nikto ne rend pas le DOM dynamique ; des
  routes entières restent invisibles sans crawler headless (ZAP Ajax Spider).

**Sur VAmPI (API REST)**
- **Découverte dépendante du Swagger** : un endpoint non documenté dans la spec
  OpenAPI n'est découvert par aucun scanner.
- **BOLA/IDOR** : comparaison contextuelle entre deux auth (cf. ci-dessus).
- **Mass assignment / excessive data exposure** : un scanner voit un champ JSON
  en trop (`is_admin`) mais ignore, sans modèle de données, s'il est sensible.
- **Abus de logique métier / rate limiting** : nécessite un scénario scripté.
- **Attaques JWT** (`alg=none`, clé faible, expiration non vérifiée) : hors
  d'un scan générique sans plugin/config dédié.

---

## Gestion d'erreurs

Jamais de crash silencieux : outil absent → message d'installation clair et
étape ignorée ; timeout réseau → `ReconTimeoutError` ; cible injoignable →
message explicite ; sortie inattendue → conservée en brut dans `raw_output/`.

## Sortie

- Rapports : `reports/report_<cible>.json` et `.html` (PDF si `weasyprint`).
- Audit : `logs/audit.log` (chaque tentative, autorisée ou refusée).
- Sorties brutes des outils : `raw_output/`.
