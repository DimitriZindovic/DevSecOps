from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.detect import validate_finding

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport de pentest — {{ target }}</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { border-bottom: 3px solid #333; padding-bottom: .3rem; }
  .meta { color: #555; font-size: .9rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { border: 1px solid #ccc; padding: .5rem .7rem; text-align: left;
           vertical-align: top; font-size: .9rem; }
  th { background: #f0f0f0; }
  .critical { background: #ffdede; } .high { background: #ffe9d6; }
  .medium { background: #fff6d6; }  .low { background: #eef6ff; }
  .info { background: #f6f6f6; }
  .badge { font-weight: bold; text-transform: uppercase; font-size: .75rem; }
  pre { white-space: pre-wrap; margin: 0; font-size: .8rem; color: #333; }
  .summary span { display: inline-block; margin-right: 1rem; }
</style>
</head>
<body>
<h1>Rapport de pentest — {{ target }}</h1>
<p class="meta">Généré le {{ generated_at }} · {{ findings|length }} finding(s)
  · étapes : {{ steps }}</p>
<div class="summary">
  {% for sev, count in summary.items() %}
    <span class="badge {{ sev }}">{{ sev }} : {{ count }}</span>
  {% endfor %}
</div>
<table>
  <thead><tr>
    <th>Sévérité</th><th>Type</th><th>Module</th><th>Statut</th>
    <th>Description</th><th>Preuve (commande / sortie)</th>
  </tr></thead>
  <tbody>
  {% for f in findings %}
    <tr class="{{ f.severity }}">
      <td class="badge">{{ f.severity }}</td>
      <td>{{ f.type }}</td>
      <td>{{ f.module }}</td>
      <td>{{ f.status }}</td>
      <td>{{ f.description }}</td>
      <td><pre>$ {{ f.evidence.command }}
{{ f.evidence.output[:800] }}</pre></td>
    </tr>
  {% endfor %}
  </tbody>
</table>
</body>
</html>
"""


def build_report(
    target: str, findings: list[dict[str, Any]], steps: list[str] | None = None
) -> dict[str, Any]:
    for f in findings:
        validate_finding(f)
    ordered = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9)
    )
    summary: dict[str, int] = {}
    for f in ordered:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "steps": steps or [],
        "summary": summary,
        "findings": ordered,
    }


def write_json(report: dict[str, Any], path: str | Path | None = None) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(path) if path else REPORTS_DIR / f"report_{report['target']}.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def write_html(report: dict[str, Any], path: str | Path | None = None) -> Path:
    from jinja2 import Template

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(path) if path else REPORTS_DIR / f"report_{report['target']}.html"
    html = Template(_HTML_TEMPLATE).render(
        target=report["target"],
        generated_at=report["generated_at"],
        steps=", ".join(report.get("steps", [])) or "n/a",
        summary=report.get("summary", {}),
        findings=report["findings"],
    )
    out.write_text(html, encoding="utf-8")
    return out


def write_pdf(report: dict[str, Any], path: str | Path | None = None) -> Path | None:
    try:
        from weasyprint import HTML
    except ImportError:
        print(
            "[report] weasyprint absent : PDF non généré (HTML disponible). "
            "Installez-le pour le PDF : pip install weasyprint"
        )
        return None
    html_path = write_html(report)
    out = Path(path) if path else REPORTS_DIR / f"report_{report['target']}.pdf"
    HTML(filename=str(html_path)).write_pdf(str(out))
    return out


def generate_all(
    target: str, findings: list[dict[str, Any]], steps: list[str] | None = None
) -> dict[str, Path]:
    report = build_report(target, findings, steps)
    produced = {
        "json": write_json(report),
        "html": write_html(report),
    }
    pdf = write_pdf(report)
    if pdf:
        produced["pdf"] = pdf
    return produced
