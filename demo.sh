#!/usr/bin/env bash
# =============================================================================
# demo.sh — démonstration MAINS LIBRES du framework (pour vidéo muette).
#
# Défile tout seul, sans clavier. Les bannières et les blocs "RÉSULTAT" affichés
# à l'écran remplacent la voix : la vidéo se comprend juste en regardant.
#
# Usage (DANS Kali, venv actif — sinon lancez d'abord `source setup.sh`) :
#   ./demo.sh                 # mains libres, rythme par défaut
#   ./demo.sh --slow          # pauses de lecture plus longues
#   ./demo.sh --fast          # pauses plus courtes
#   ./demo.sh --step          # pause manuelle (Entrée) au lieu de l'auto
#   DELAY=9 ./demo.sh         # régler finement la pause de lecture (secondes)
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

# --- Rythme -----------------------------------------------------------------
STEP=0
DELAY="${DELAY:-7}"          # pause de lecture entre étapes (secondes)
case "${1:-}" in
  --step) STEP=1 ;;
  --slow) DELAY=10 ;;
  --fast) DELAY=4 ;;
esac

PY="./.venv/bin/python"; [ -x "$PY" ] || PY="python"

# --- Couleurs / helpers -----------------------------------------------------
B="\033[1m"; DIM="\033[2m"; C="\033[96m"; G="\033[92m"; Y="\033[93m"
R="\033[91m"; M="\033[95m"; N="\033[0m"; BG="\033[7m"

banner() {
  printf "\n\n${B}${C}╔══════════════════════════════════════════════════════════════╗${N}\n"
  printf     "${B}${C}║${N}  ${B}%-58s${N}${B}${C}║${N}\n" "$1"
  printf     "${B}${C}╚══════════════════════════════════════════════════════════════╝${N}\n\n"
  sleep 1.5
}
note()   { printf "${Y}  %s${N}\n" "$1"; sleep 1; }
cmd()    { printf "\n${DIM}# commande :${N}\n${G}\$ %s${N}\n" "$*"; sleep 1.5; eval "$@"; }
result() {
  printf "\n${B}${M}  ┌─ RÉSULTAT ${N}\n"
  while IFS= read -r line; do printf "${B}${M}  │${N} %s\n" "$line"; done <<< "$1"
  printf "${B}${M}  └────────────${N}\n"
}
pause()  { if [ "$STEP" -eq 1 ]; then printf "\n${DIM}[Entrée]${N}"; read -r _; else sleep "$DELAY"; fi; }

clear 2>/dev/null || true

# --- 0. Titre ---------------------------------------------------------------
banner "FRAMEWORK D'AUTOMATISATION DE PENTEST"
note "Orchestration Python : nmap · whatweb · nikto · sqlmap · hydra"
note "Cibles autorisées uniquement : OWASP Juice Shop (web) + VAmPI (API)"
cmd "ls"
pause

# --- 1. Diagnostic ----------------------------------------------------------
banner "1. DIAGNOSTIC DE L'ENVIRONNEMENT"
note "Une commande vérifie outils, dépendances, scope et connectivité des cibles."
cmd "$PY main.py doctor"
result "Environnement pret : outils presents, Juice Shop + VAmPI joignables."
pause

# --- 2. Garde-fou de scope --------------------------------------------------
banner "2. GARDE-FOU DE SECURITE"
note "Cibles autorisées (config/targets.yaml) :"
cmd "$PY main.py targets"
note "Tentative sur une IP externe -> doit etre REFUSEE avant tout reseau."
cmd "$PY main.py scan --target 8.8.8.8 ; echo \"code de sortie = \$?\""
result "CIBLE HORS SCOPE BLOQUEE : aucune requete reseau n'est partie (exit=2)."
pause
note "La tentative est journalisée (audit) et couverte par les tests :"
cmd "tail -n 3 logs/audit.log"
cmd "$PY -m pytest tests/test_scope.py -q"
result "Refus trace dans logs/audit.log + tests de scope au vert."
pause

# --- 3. Scan Juice Shop -----------------------------------------------------
banner "3. SCAN AUTOMATIQUE — JUICE SHOP"
note "recon -> detect -> exploit -> report. sqlmap est declenche sur la recherche."
cmd "$PY main.py scan --target juiceshop --steps recon,detect,exploit,report"
JS=$($PY - <<'PY'
import json
d=json.load(open('reports/report_juiceshop.json'))
out=[f"resume: {d['summary']}"]
for f in d['findings']:
    if f['status']=='exploited' or f['severity'] in ('critical','high'):
        out.append(f"[{f['severity']}/{f['status']}] {f['evidence']['tool']} : {f['description'][:70]}")
print("\n".join(out))
PY
)
result "$JS"
pause

# --- 4. Scan VAmPI ----------------------------------------------------------
banner "4. SCAN AUTOMATIQUE — VAmPI (API REST)"
note "hydra brute-force le login, sqlmap teste le champ identifiant."
cmd "$PY main.py scan --target vampi --steps recon,detect,exploit,report"
VP=$($PY - <<'PY'
import json
d=json.load(open('reports/report_vampi.json'))
out=[f"resume: {d['summary']}"]
for f in d['findings']:
    if f['status']=='exploited' or f['severity'] in ('critical','high'):
        out.append(f"[{f['severity']}/{f['status']}] {f['evidence']['tool']} : {f['description'][:70]}")
print("\n".join(out))
PY
)
result "$VP"
pause

# --- 5. Limite de l'automatisation : BOLA -----------------------------------
banner "5. LA LIMITE : LA FAILLE BOLA QUE LES SCANS RATENT"
note "Le scan automatique de VAmPI n'a remonte AUCUNE faille d'autorisation :"
cmd "grep -i bola reports/report_vampi.json || echo '(aucun finding BOLA dans le scan auto)'"
result "SCAN AUTOMATIQUE : ne detecte PAS la BOLA (deux HTTP 200 valides pour lui)."
pause
note "Le script manuel compare deux contextes d'auth : userB lit les donnees de userA."
cmd "$PY scripts_kali/run_bola_check.py --target vampi ; echo \"code de sortie = \$?\""
result "SCRIPT MANUEL : BOLA CONFIRMEE — userB lit le secret prive de userA."
pause

# --- 6. Restitution ---------------------------------------------------------
banner "6. RESTITUTION : RAPPORTS + INTERFACE"
note "Chaque scan produit un rapport JSON + HTML :"
cmd "ls -1 reports/*.json reports/*.html"
note "Interface graphique (cible dans la whitelist uniquement) :"
note "    streamlit run ui/app.py"
result "Rapports normalises exportes + dashboard Streamlit disponible."
pause

# --- 7. Fin -----------------------------------------------------------------
banner "SYNTHESE"
note "AUTOMATISABLE : recon, detection normalisee, exploitation ciblee, reporting."
note "NON AUTOMATISABLE : logique metier, BOLA/IDOR — prouve manuellement ci-dessus."
printf "\n${B}${G}  ✓ Fin de la demonstration.${N}\n\n"
sleep 2
