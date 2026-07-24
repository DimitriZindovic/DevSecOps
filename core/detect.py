from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.probe import ProbeResult
from core.recon import NiktoResult, NmapResult, ServicePort, WhatWebResult

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PROJECT_ROOT / "findings_schema.json"

_VALIDATOR = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_id(target: str, module: str, ftype: str, marker: str) -> str:
    digest = hashlib.sha1(f"{target}|{module}|{ftype}|{marker}".encode()).hexdigest()
    return f"{module}-{ftype}-{digest[:10]}"


def make_finding(
    target: str,
    module: str,
    ftype: str,
    severity: str,
    description: str,
    command: str,
    output: str,
    tool: str = "",
    status: str = "detected",
    references: list[str] | None = None,
    marker: str | None = None,
) -> dict[str, Any]:
    finding = {
        "id": _finding_id(target, module, ftype, marker or description),
        "target": target,
        "module": module,
        "type": ftype,
        "severity": severity,
        "description": description,
        "evidence": {"command": command, "output": output[:4000], "tool": tool},
        "status": status,
        "timestamp": _now_iso(),
    }
    if references:
        finding["references"] = references
    return finding


def validate_finding(finding: dict[str, Any]) -> None:
    global _VALIDATOR
    if _VALIDATOR is None:
        import jsonschema

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        _VALIDATOR = jsonschema.Draft7Validator(schema)
    errors = sorted(_VALIDATOR.iter_errors(finding), key=lambda e: e.path)
    if errors:
        raise ValueError(
            f"Finding non conforme au schéma : {errors[0].message} ({finding.get('id')})"
        )


def detect_from_nmap(result: NmapResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for p in result.ports:
        if p.state != "open":
            continue
        banner = " ".join(x for x in [p.product, p.version, p.extra] if x).strip()
        findings.append(
            make_finding(
                target=result.target,
                module="detect",
                ftype="open_port",
                severity="info",
                description=(
                    f"Port {p.port}/{p.protocol} ouvert — service "
                    f"{p.service or 'inconnu'}"
                    + (f" ({banner})" if banner else "")
                ),
                command=result.command,
                output=f"{p.port}/{p.protocol} {p.state} {p.service} {banner}",
                tool="nmap",
                marker=f"port-{p.port}",
            )
        )
        if p.version:
            findings.append(
                make_finding(
                    target=result.target,
                    module="detect",
                    ftype="version_disclosure",
                    severity="low",
                    description=(
                        f"Version logicielle exposée sur {p.port}/{p.protocol} : "
                        f"{p.product} {p.version}. À corréler avec des CVE connues."
                    ),
                    command=result.command,
                    output=banner,
                    tool="nmap",
                    status="unconfirmed",
                    marker=f"version-{p.port}",
                )
            )
    return _validate_all(findings)


def detect_from_whatweb(result: WhatWebResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if result.plugins:
        techs = ", ".join(sorted(result.plugins.keys()))
        findings.append(
            make_finding(
                target=result.target,
                module="detect",
                ftype="tech_stack",
                severity="info",
                description=f"Stack technologique détectée : {techs}",
                command=result.command,
                output=json.dumps(result.plugins)[:2000],
                tool="whatweb",
                marker="techstack",
            )
        )
    return _validate_all(findings)


def detect_from_nikto(result: NiktoResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in result.items:
        desc = item.get("description", "").strip()
        if not desc:
            continue
        ftype = _classify_nikto(desc)
        findings.append(
            make_finding(
                target=result.target,
                module="detect",
                ftype=ftype,
                severity=_severity_for(ftype),
                description=f"[Nikto, à valider] {desc}",
                command=result.command,
                output=f"{item.get('method')} {item.get('uri')} :: {desc}",
                tool="nikto",
                status="unconfirmed",
                marker=f"{item.get('uri')}-{desc[:40]}",
            )
        )
    return _validate_all(findings)


def detect_from_probe(result: ProbeResult) -> list[dict[str, Any]]:
    """Découverte active -> findings déclencheurs (login_form, suspicious_parameter).

    Ces findings alimentent le rapport ET justifient les décisions d'exploitation
    (hydra sur les login, sqlmap sur les paramètres).
    """
    findings: list[dict[str, Any]] = []
    for le in result.login_endpoints:
        findings.append(
            make_finding(
                target=result.target,
                module="detect",
                ftype="login_form",
                severity="info",
                description=(
                    f"Endpoint d'authentification détecté : {le.path} "
                    f"(champs {le.user_field}/{le.pass_field}). "
                    "Candidat au brute-force (hydra)."
                ),
                command=f"probe POST {le.url}",
                output=f"login={le.path} fields={le.user_field}/{le.pass_field} "
                       f"fail_status={le.fail_status} marker={le.fail_marker!r}",
                tool="probe",
                marker=f"login-{le.path}",
            )
        )
    for pe in result.param_endpoints:
        findings.append(
            make_finding(
                target=result.target,
                module="detect",
                ftype="suspicious_parameter",
                severity="low",
                description=(
                    f"Paramètre GET '{pe.param}' sur endpoint de données : {pe.url}. "
                    "Candidat à l'injection SQL (sqlmap)."
                ),
                command=f"probe GET {pe.url}",
                output=pe.url,
                tool="probe",
                status="unconfirmed",
                marker=f"param-{pe.url}",
            )
        )
    return _validate_all(findings)


def _classify_nikto(desc: str) -> str:
    d = desc.lower()
    if "header" in d:
        return "missing_header"
    if "cookie" in d:
        return "cookie_issue"
    if "outdated" in d or "version" in d:
        return "outdated_software"
    return "generic_web_issue"


def _severity_for(ftype: str) -> str:
    return {
        "missing_header": "low",
        "cookie_issue": "low",
        "outdated_software": "medium",
    }.get(ftype, "info")


def _validate_all(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for f in findings:
        validate_finding(f)
    return findings
