#!/usr/bin/env bash
# =============================================================================
# setup.sh — installation en une commande du framework de pentest.
#
# Enchaîne : vérif/installation des outils Kali -> venv Python -> dépendances
# -> diagnostic (python main.py doctor).
#
# Usage :
#   ./setup.sh              # setup complet
#   ./setup.sh --no-apt     # ne pas tenter d'installer les outils système
#
# À exécuter DEPUIS l'environnement où le framework tournera (bureau Kali de
# préférence : les outils y sont déjà présents).
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

NO_APT=0
[ "${1:-}" = "--no-apt" ] && NO_APT=1

PY=python3
TOOLS=(nmap whatweb nikto sqlmap hydra)

echo "==> 1/4 Vérification des outils Kali"
MISSING=()
for t in "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "    [OK] $t"
  else
    echo "    [MANQUANT] $t"
    MISSING+=("$t")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  if [ "$NO_APT" -eq 1 ]; then
    echo "    (--no-apt) installation système ignorée. Outils manquants : ${MISSING[*]}"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "==> Installation des outils manquants (sudo apt) : ${MISSING[*]}"
    SUDO=""
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    $SUDO apt-get update -y
    $SUDO apt-get install -y "${MISSING[@]}"
  else
    echo "    apt-get indisponible : installez manuellement ${MISSING[*]}"
    echo "    (le framework fonctionnera en mode dégradé pour les outils absents)"
  fi
fi

echo "==> 2/4 Création de l'environnement virtuel Python (.venv)"
if [ ! -d .venv ]; then
  "$PY" -m venv .venv
  echo "    .venv créé"
else
  echo "    .venv déjà présent"
fi

echo "==> 3/4 Installation des dépendances Python"
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
echo "    dépendances installées"

echo "==> 4/4 Diagnostic de l'environnement"
./.venv/bin/python main.py doctor || true

cat <<'EOF'

=============================================================================
Setup terminé. Prochaines étapes :

  source .venv/bin/activate
  python main.py doctor                       # revérifier les prérequis
  python main.py scan --target juiceshop --full
  streamlit run ui/app.py                     # interface graphique

Cibles Docker (si non lancées) :
  docker run -d -p 3000:3000 bkimminich/juice-shop
  docker run -d --name vampi --network lac-kali_default \
    --network-alias vampi erev0s/vampi
=============================================================================
EOF
