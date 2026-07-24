from __future__ import annotations

import argparse
import sys
import traceback

from core import scope

ALL_STEPS = ["recon", "detect", "exploit", "report"]


def _print(msg: str) -> None:
    print(f"[main] {msg}", flush=True)


def cmd_targets() -> int:
    guard = scope.get_guard()
    print("Cibles autorisées (config/targets.yaml) :")
    for name, t in guard.targets.items():
        print(f"  - {name:12} {t.base_url()}  hosts={list(t.hosts)} ports={list(t.ports)}")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "targets":
            return cmd_targets()
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
