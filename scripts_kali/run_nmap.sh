set -euo pipefail

HOST="${1:?Usage: run_nmap.sh <host> [ports]}"
PORTS="${2:-}"

command -v nmap >/dev/null 2>&1 || {
  echo "[erreur] nmap absent. Installez : sudo apt install -y nmap" >&2
  exit 127
}

if [ -n "$PORTS" ]; then
  exec nmap -sV -oX - -p "$PORTS" "$HOST"
else
  exec nmap -sV -oX - "$HOST"
fi
