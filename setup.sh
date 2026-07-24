#!/usr/bin/env bash
# =============================================================================
# setup.sh — installation TOUT-EN-UN du framework de pentest.
#
# Enchaîne : vérif/installation des outils Kali -> venv Python -> dépendances
# -> diagnostic (python main.py doctor) -> ACTIVATION du venv.
#
# Usage recommandé (active le venv dans VOTRE shell) :
#   source setup.sh              # ou :  . setup.sh
#   source setup.sh --no-apt     # sans tenter d'installer les outils système
#
# Lancé avec ./setup.sh, tout est installé mais le venv ne peut pas rester
# activé dans le shell appelant (limite technique des sous-processus) : le
# script vous le rappelle à la fin.
#
# À exécuter DEPUIS l'environnement où le framework tournera (bureau Kali de
# préférence : les outils y sont déjà présents).
# =============================================================================

# --- Détection : le script est-il sourcé (source setup.sh) ou exécuté ? ------
_SOURCED=0
if [ -n "${BASH_SOURCE:-}" ]; then
  [ "${BASH_SOURCE[0]}" != "$0" ] && _SOURCED=1
  _SELF="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_EVAL_CONTEXT:-}" ]; then
  case "$ZSH_EVAL_CONTEXT" in *:file) _SOURCED=1 ;; esac
  _SELF="$0"
else
  _SELF="$0"
fi

# En mode sourcé, on N'ACTIVE PAS 'set -e' (cela tuerait le shell de
# l'utilisateur à la moindre erreur). En mode exécuté, on veut l'arrêt strict.
if [ "$_SOURCED" -eq 0 ]; then
  set -euo pipefail
fi

# On travaille dans le dossier du script sans déplacer durablement le shell.
_PROJECT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
_ORIG_DIR="$(pwd)"
cd "$_PROJECT_DIR"

_NO_APT=0
[ "${1:-}" = "--no-apt" ] && _NO_APT=1

_PY=python3
_TOOLS=(nmap whatweb nikto sqlmap hydra)

echo "==> 1/5 Vérification des outils Kali"
_MISSING=()
for t in "${_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "    [OK] $t"
  else
    echo "    [MANQUANT] $t"
    _MISSING+=("$t")
  fi
done

if [ "${#_MISSING[@]}" -gt 0 ]; then
  if [ "$_NO_APT" -eq 1 ]; then
    echo "    (--no-apt) installation système ignorée. Manquants : ${_MISSING[*]}"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "==> Installation des outils manquants (sudo apt) : ${_MISSING[*]}"
    _SUDO=""
    [ "$(id -u)" -ne 0 ] && _SUDO="sudo"
    $_SUDO apt-get update -y
    $_SUDO apt-get install -y "${_MISSING[@]}"
  else
    echo "    apt-get indisponible : installez manuellement ${_MISSING[*]}"
    echo "    (le framework fonctionnera en mode dégradé pour les outils absents)"
  fi
fi

echo "==> 2/5 Création de l'environnement virtuel Python (.venv)"
if [ ! -d .venv ]; then
  "$_PY" -m venv .venv
  echo "    .venv créé"
else
  echo "    .venv déjà présent"
fi

echo "==> 3/5 Installation des dépendances Python"
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
echo "    dépendances installées"

echo "==> 4/5 Diagnostic de l'environnement"
./.venv/bin/python main.py doctor || true

echo "==> 5/5 Activation du venv"
# shellcheck disable=SC1091
source .venv/bin/activate
echo "    venv activé : $(command -v python)"

if [ "$_SOURCED" -eq 1 ]; then
  cat <<'EOF'

=============================================================================
Setup terminé — le venv est ACTIF dans ce shell. Vous pouvez lancer :

  python main.py scan --target juiceshop --full
  streamlit run ui/app.py

Cibles Docker (si 'doctor' les signale injoignables) :
  docker run -d -p 3000:3000 bkimminich/juice-shop
  docker run -d --name vampi --network lac-kali_default \
    --network-alias vampi erev0s/vampi
=============================================================================
EOF
  # En mode sourcé : on rend la main sans quitter le shell, dans le dossier
  # projet (pratique pour enchaîner les commandes). Pas d'appel à 'exit'.
  cd "$_PROJECT_DIR"
else
  cat <<'EOF'

=============================================================================
Setup terminé. ATTENTION : lancé avec ./setup.sh, le venv N'EST PAS resté
activé dans votre shell (limite des sous-processus).

Pour tout faire en une seule commande, relancez avec :
  source setup.sh

Ou activez le venv manuellement :
  source .venv/bin/activate
  python main.py scan --target juiceshop --full
=============================================================================
EOF
  cd "$_ORIG_DIR"
fi
