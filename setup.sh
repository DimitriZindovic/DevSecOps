#!/usr/bin/env bash
# =============================================================================
# setup.sh — installation TOUT-EN-UN, exécutée LÀ OÙ IL FAUT (dans Kali).
#
# Le framework doit tourner DANS le conteneur Kali (outils nmap/sqlmap/... et
# hostnames juiceshop/vampi n'existent que là). Ce script gère les deux cas :
#
#   • Lancé DEPUIS L'HÔTE (pas d'outils Kali) : il synchronise le code dans le
#     conteneur Kali, s'y relance, puis ouvre un shell Kali (venv actif).
#         ./setup.sh
#
#   • Lancé DANS KALI : installe venv + deps, lance le diagnostic, et — si
#     sourcé — active le venv dans le shell courant.
#         source setup.sh              # tout-en-un, venv reste actif
#         source setup.sh --no-apt     # sans installer les outils système
#
# Variables surchargables :
#   KALI_CONTAINER   (défaut: lac-kali-kali-1)   nom du conteneur Kali
#   KALI_PROJECT_DIR (défaut: /root/DevSecOps)   dossier cible dans Kali
# =============================================================================

KALI_CONTAINER="${KALI_CONTAINER:-lac-kali-kali-1}"
KALI_PROJECT_DIR="${KALI_PROJECT_DIR:-/root/DevSecOps}"

# --- Détection : sourcé (source setup.sh) ou exécuté (./setup.sh) ? ----------
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

_PROJECT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
_ORIG_DIR="$(pwd)"

_NO_APT=0
for a in "$@"; do [ "$a" = "--no-apt" ] && _NO_APT=1; done

# --- Sommes-nous dans l'environnement Kali ? --------------------------------
_in_kali() {
  if command -v nmap >/dev/null 2>&1 && command -v sqlmap >/dev/null 2>&1; then
    return 0
  fi
  grep -qi kali /etc/os-release 2>/dev/null && return 0
  return 1
}

# =============================================================================
# CAS 1 — on est sur l'HÔTE : relayer vers le conteneur Kali.
# =============================================================================
if ! _in_kali; then
  echo "==> Environnement hôte détecté (outils Kali absents)."

  if ! command -v docker >/dev/null 2>&1; then
    echo "[ERREUR] 'docker' introuvable et hors Kali."
    echo "         Ouvrez un terminal DANS le bureau Kali (http://localhost:18090)"
    echo "         et relancez-y :  source setup.sh"
    [ "$_SOURCED" -eq 1 ] && return 1 || exit 1
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx "$KALI_CONTAINER"; then
    echo "[ERREUR] conteneur Kali '$KALI_CONTAINER' introuvable ou arrêté."
    echo "         Démarrez-le, ou précisez :  KALI_CONTAINER=<nom> ./setup.sh"
    echo "         Conteneurs actifs :"
    docker ps --format '           - {{.Names}}'
    [ "$_SOURCED" -eq 1 ] && return 1 || exit 1
  fi

  echo "==> Synchronisation du code vers ${KALI_CONTAINER}:${KALI_PROJECT_DIR}"
  docker exec -i "$KALI_CONTAINER" mkdir -p "$KALI_PROJECT_DIR"
  tar --exclude='./.venv' --exclude='./.git' --exclude='*/__pycache__' \
      --exclude='./reports/*.json' --exclude='./reports/*.html' \
      -czf - -C "$_PROJECT_DIR" . \
    | docker exec -i "$KALI_CONTAINER" tar -xzf - -C "$KALI_PROJECT_DIR"

  echo "==> Installation dans Kali puis ouverture d'un shell (venv actif)"
  _TTY=""; [ -t 1 ] && _TTY="-t"
  # Dans Kali : install (exécuté) -> puis shell interactif via l'rcfile généré
  # par l'étape d'install (qui active le venv et se place dans le projet).
  _REMOTE="cd '$KALI_PROJECT_DIR' && ./setup.sh --no-apt >/tmp/setup_kali.log 2>&1; \
tail -n 30 /tmp/setup_kali.log; \
exec bash --rcfile '$KALI_PROJECT_DIR/.kali_shellrc' -i"
  if [ "$_SOURCED" -eq 1 ]; then
    docker exec -i $_TTY "$KALI_CONTAINER" bash -lc "$_REMOTE"
    return 0
  else
    exec docker exec -i $_TTY "$KALI_CONTAINER" bash -lc "$_REMOTE"
  fi
fi

# =============================================================================
# CAS 2 — on est DANS Kali : installation réelle.
# =============================================================================
# En mode sourcé, pas de 'set -e' (sinon on tuerait le shell de l'utilisateur).
if [ "$_SOURCED" -eq 0 ]; then
  set -euo pipefail
fi

cd "$_PROJECT_DIR"

_PY=python3
_TOOLS=(nmap whatweb nikto sqlmap hydra)

echo "==> 1/6 Vérification des outils Kali"
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
  fi
fi

echo "==> 2/6 Création de l'environnement virtuel Python (.venv)"
if [ ! -d .venv ]; then
  "$_PY" -m venv .venv
  echo "    .venv créé"
else
  echo "    .venv déjà présent"
fi

echo "==> 3/6 Installation des dépendances Python"
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
echo "    dépendances installées"

echo "==> 4/6 Génération de l'rcfile d'activation (.kali_shellrc)"
cat > "$_PROJECT_DIR/.kali_shellrc" <<RC
[ -f ~/.bashrc ] && source ~/.bashrc
cd "$_PROJECT_DIR"
source .venv/bin/activate
echo "[venv actif] python = \$(command -v python)"
RC
echo "    .kali_shellrc généré"

echo "==> 5/6 Diagnostic de l'environnement"
./.venv/bin/python main.py doctor || true

echo "==> 6/6 Activation du venv"
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
  cd "$_PROJECT_DIR"
else
  cat <<'EOF'

=============================================================================
Setup terminé (dans Kali). Pour garder le venv actif dans CE shell, relancez :
  source setup.sh
Sinon activez-le manuellement :
  source .venv/bin/activate
=============================================================================
EOF
  cd "$_ORIG_DIR"
fi
