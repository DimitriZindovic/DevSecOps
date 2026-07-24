from __future__ import annotations

import argparse
import shutil
import sys
import traceback

from core import scope

ALL_STEPS = ["recon", "detect", "exploit", "report"]

# Outils Kali attendus (nom -> paquet apt pour l'installation).
REQUIRED_TOOLS = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "hydra": "hydra",
}

# Modules Python requis (nom d'import -> paquet pip).
REQUIRED_PY = {
    "yaml": "PyYAML",
    "jsonschema": "jsonschema",
    "requests": "requests",
    "jinja2": "Jinja2",
}

OK = "\033[92mOK\033[0m"
KO = "\033[91mMANQUANT\033[0m"
WARN = "\033[93mATTENTION\033[0m"


def _print(msg: str) -> None:
    print(f"[main] {msg}", flush=True)


def cmd_targets() -> int:
    guard = scope.get_guard()
    print("Cibles autorisées (config/targets.yaml) :")
    for name, t in guard.targets.items():
        print(f"  - {name:12} {t.base_url()}  hosts={list(t.hosts)} ports={list(t.ports)}")
    return 0


def cmd_doctor() -> int:
    """Diagnostique les prérequis : outils Kali, deps Python, scope, connectivité.

    N'émet AUCUNE requête hors whitelist : la connectivité n'est testée que sur
    les cibles autorisées, après passage par le garde-fou de scope.
    """
    problems = 0

    print("=== Outils Kali (subprocess) ===")
    for tool, pkg in REQUIRED_TOOLS.items():
        path = shutil.which(tool)
        if path:
            print(f"  [{OK}] {tool:8} -> {path}")
        else:
            problems += 1
            print(f"  [{KO}] {tool:8} -> à installer : sudo apt install -y {pkg}")

    print("\n=== Dépendances Python ===")
    for mod, pkg in REQUIRED_PY.items():
        try:
            __import__(mod)
            print(f"  [{OK}] {pkg}")
        except ImportError:
            problems += 1
            print(f"  [{KO}] {pkg} -> pip install {pkg}")

    print("\n=== Configuration de scope ===")
    try:
        guard = scope.get_guard()
        print(f"  [{OK}] {len(guard.targets)} cible(s) chargée(s) : "
              f"{', '.join(guard.targets)}")
    except scope.ScopeError as exc:
        problems += 1
        print(f"  [{KO}] config/targets.yaml : {exc}")
        return 1

    print("\n=== Connectivité des cibles (scope-guardée) ===")
    try:
        import requests
    except ImportError:
        print(f"  [{WARN}] module 'requests' absent : test de connectivité ignoré")
        requests = None
    if requests is not None:
        import time

        for name, t in guard.targets.items():
            reachable = False
            for host in t.hosts:
                url = f"{t.scheme}://{host}:{t.ports[0]}"
                try:
                    scope.assert_in_scope(url)  # garde-fou avant toute requête
                except scope.ScopeError:
                    continue
                # 2 tentatives + timeout large : VAmPI (émulé) peut être lent à
                # froid, ce qui provoquerait un faux « injoignable ».
                for attempt in range(2):
                    try:
                        requests.get(url, timeout=8)
                        print(f"  [{OK}] {name:10} joignable via {url}")
                        reachable = True
                        break
                    except requests.RequestException:
                        if attempt == 0:
                            time.sleep(1)
                if reachable:
                    break
            if not reachable:
                print(f"  [{WARN}] {name:10} injoignable "
                      f"(cible Docker lancée ? hostname résolu ?)")

    print()
    if problems:
        _print(f"Diagnostic terminé : {problems} problème(s) bloquant(s) détecté(s).")
        return 1
    _print("Diagnostic terminé : environnement prêt.")
    return 0


def cmd_scan(target: str, steps: list[str]) -> int:
    try:
        allowed = scope.assert_in_scope(target)
    except scope.ScopeError as exc:
        _print(f"REFUSÉ — {exc}")
        return 2

    _print(f"Cible autorisée : {allowed.name} ({allowed.base_url()})")
    _print(f"Étapes : {', '.join(steps)}")

    from core import detect, exploit, probe, recon, report

    findings: list[dict] = []

    nmap_result = whatweb_result = nikto_result = probe_result = None
    if "recon" in steps:
        _print("RECON : nmap / whatweb / nikto / probe actif")
        try:
            nmap_result = recon.run_nmap(allowed.name)
            _print(f"  nmap : {len(nmap_result.ports)} port(s)")
        except recon.ToolNotFoundError as exc:
            _print(f"  nmap ignoré : {exc}")
        except recon.ReconError as exc:
            _print(f"  nmap erreur : {exc}")
        try:
            whatweb_result = recon.run_whatweb(allowed.name)
            _print(f"  whatweb : {len(whatweb_result.plugins)} plugin(s)")
        except recon.ToolNotFoundError as exc:
            _print(f"  whatweb ignoré : {exc}")
        except recon.ReconError as exc:
            _print(f"  whatweb erreur : {exc}")
        try:
            nikto_result = recon.run_nikto(allowed.name)
            _print(f"  nikto : {len(nikto_result.items)} alerte(s)")
        except recon.ToolNotFoundError as exc:
            _print(f"  nikto ignoré : {exc}")
        except recon.ReconError as exc:
            _print(f"  nikto erreur : {exc}")
        try:
            probe_result = probe.probe_target(allowed.name)
            _print(
                f"  probe : {len(probe_result.login_endpoints)} login, "
                f"{len(probe_result.param_endpoints)} paramètre(s) injectable(s)"
            )
        except Exception as exc:
            _print(f"  probe erreur : {exc}")

    if "detect" in steps:
        _print("DETECT : normalisation des résultats en findings")
        if nmap_result:
            findings += detect.detect_from_nmap(nmap_result)
        if whatweb_result:
            findings += detect.detect_from_whatweb(whatweb_result)
        if nikto_result:
            findings += detect.detect_from_nikto(nikto_result)
        if probe_result:
            findings += detect.detect_from_probe(probe_result)
        _print(f"  {len(findings)} finding(s) normalisé(s)")

    if "exploit" in steps:
        _print("EXPLOIT : déclenchement réel et conditionnel (sqlmap/hydra)")
        if not probe_result:
            _print("  pas de découverte active : rien à exploiter")
        else:
            decisions = exploit.plan_exploits(probe_result)
            if not decisions:
                _print("  aucun déclencheur d'exploitation détecté")
            for d in decisions:
                _print(f"  -> {d.tool}/{d.kind} : {d.reason}")
            try:
                findings += exploit.run_plan(allowed.name, decisions)
            except recon.ToolNotFoundError as exc:
                _print(f"  exploit ignoré : {exc}")

    if "report" in steps:
        _print("REPORT : génération JSON + HTML")
        produced = report.generate_all(allowed.name, findings, steps)
        for kind, path in produced.items():
            _print(f"  {kind.upper()} : {path}")

    _print("Terminé.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="lancer un scan sur une cible whitelistée")
    p_scan.add_argument("--target", required=True, help="alias/host/URL de la cible")
    p_scan.add_argument(
        "--steps",
        default="recon,detect,report",
        help="étapes séparées par des virgules (recon,detect,exploit,report)",
    )
    p_scan.add_argument(
        "--full", action="store_true", help="lance toutes les étapes"
    )

    sub.add_parser("targets", help="lister les cibles autorisées")
    sub.add_parser("doctor", help="diagnostiquer les prérequis (outils, deps, cibles)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "targets":
            return cmd_targets()
        if args.command == "doctor":
            return cmd_doctor()
        if args.command == "scan":
            steps = ALL_STEPS if args.full else [
                s.strip() for s in args.steps.split(",") if s.strip()
            ]
            invalid = [s for s in steps if s not in ALL_STEPS]
            if invalid:
                _print(f"Étapes inconnues : {invalid}. Valides : {ALL_STEPS}")
                return 2
            return cmd_scan(args.target, steps)
    except scope.ScopeError as exc:
        _print(f"REFUSÉ (scope) — {exc}")
        return 2
    except KeyboardInterrupt:
        _print("Interrompu par l'utilisateur.")
        return 130
    except Exception as exc:
        _print(f"Erreur inattendue : {exc}")
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
