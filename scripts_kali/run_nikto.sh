set -euo pipefail

HOST="${1:?Usage: run_nikto.sh <host> <port>}"
PORT="${2:?Usage: run_nikto.sh <host> <port>}"

command -v nikto >/dev/null 2>&1 || {
  echo "[erreur] nikto absent. Installez : sudo apt install -y nikto" >&2
  exit 127
}

exec nikto -h "$HOST" -p "$PORT" -Format csv -o -
