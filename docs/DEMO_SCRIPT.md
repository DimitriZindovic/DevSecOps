# Storyboard vidéo démo (muette, 5–10 min)

Vidéo **sans voix ni sous-titres** : ce sont les bannières et les blocs
`RÉSULTAT` affichés par `demo.sh` qui portent le sens. La vidéo se comprend
juste en regardant l'écran.

## Avant de filmer (checklist)
- [ ] Juice Shop + VAmPI joignables (`python main.py doctor` tout vert).
- [ ] Terminal DANS Kali, venv actif (`source setup.sh`), police ≥ 18 pt, plein écran.
- [ ] Lancer le déroulé mains libres : `./demo.sh` (ou `--slow` si besoin de lire plus).
- [ ] (Option) navigateur ouvert pour montrer `reports/report_vampi.html` et l'UI.

## Lancement
```bash
./demo.sh            # mains libres, rythme par défaut (DELAY=7 s)
./demo.sh --slow     # pauses de lecture plus longues (10 s)
./demo.sh --fast     # pauses plus courtes (4 s)
DELAY=9 ./demo.sh    # réglage fin de la pause de lecture
```

---

## Déroulé (ce qui apparaît à l'écran)

| Scène | Bannière | Commande | Résultat visible |
|-------|----------|----------|------------------|
| 0 | Titre du framework | `ls` | arborescence du projet |
| 1 | Diagnostic | `python main.py doctor` | tout vert, cibles joignables |
| 2 | Garde-fou : cibles | `python main.py targets` | juiceshop + vampi |
| 2 | Garde-fou : refus | `python main.py scan --target 8.8.8.8` | **REFUSÉ** (exit=2) |
| 2 | Audit + tests | `tail logs/audit.log` ; `pytest tests/test_scope.py` | refus tracé, tests au vert |
| 3 | Scan Juice Shop | `python main.py scan --target juiceshop --steps recon,detect,exploit,report` | **[critical] sqlmap : SQLi** |
| 4 | Scan VAmPI | `python main.py scan --target vampi --steps recon,detect,exploit,report` | **[critical] hydra : creds faibles + sqlmap : SQLi** |
| 5 | Limite (scan) | `grep -i bola reports/report_vampi.json` | *rien* : le scan rate la BOLA |
| 5 | Limite (manuel) | `python scripts_kali/run_bola_check.py --target vampi` | **BOLA CONFIRMÉE** |
| 6 | Restitution | `ls reports/*.html` (+ ouvrir le HTML / `streamlit run ui/app.py`) | rapports + dashboard |
| 7 | Synthèse | — | automatisable vs non automatisable |

## Le fil (compréhensible sans un mot)
1. **Prêt et sûr** (1‑2) → refuse le hors‑scope.
2. **Exploite vraiment** (3‑4) → findings `critical / exploited` (sqlmap + hydra).
3. **A une limite** (5) → scan = rien, script manuel = BOLA prouvée.
4. **Restitue** (6) → rapport + interface.

Le contraste **scène 5 (rien) vs scène 5 (faille prouvée)** est le moment fort.

## Plan B (≈ 5 min)
Scènes 1 → 2 → 3 → 5 → 7. Les scènes **2 (garde-fou)** et **5 (BOLA)** sont
obligatoires : ce sont les deux points clés du rendu.
