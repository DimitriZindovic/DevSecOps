set -euo pipefail

URL="${1:?Usage: run_sqlmap.sh <url>}"

command -v sqlmap >/dev/null 2>&1 || {
  echo "[erreur] sqlmap absent. Installez : sudo apt install -y sqlmap" >&2
  exit 127
}

exec sqlmap -u "$URL" --batch --level=1 --risk=1 --flush-session
