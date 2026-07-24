from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import detect, exploit, probe, recon, report, scope

st.set_page_config(page_title="Pentest Framework", layout="wide")
st.title("🛡️ Framework d'automatisation de pentest")
st.caption("Cibles restreintes à la whitelist (Juice Shop, VAmPI) — garde-fou de scope actif.")

guard = scope.get_guard()
target_names = list(guard.targets.keys())

with st.sidebar:
    st.header("Configuration du scan")
    target_name = st.selectbox("Cible (whitelist uniquement)", target_names)
    steps = st.multiselect(
        "Étapes",
        options=["recon", "detect", "exploit", "report"],
        default=["recon", "detect", "report"],
    )
    launch = st.button("🚀 Lancer le scan", type="primary")

target = guard.targets[target_name]
st.info(f"Cible sélectionnée : **{target.name}** → {target.base_url()}")


def run_scan(target_name: str, steps: list[str]) -> list[dict]:
    allowed = scope.assert_in_scope(target_name)
    findings: list[dict] = []
    nmap_result = whatweb_result = nikto_result = probe_result = None

    if "recon" in steps:
        with st.status("Recon (nmap / whatweb / nikto / probe)…", expanded=True) as status:
            for tool_name, fn in [
                ("nmap", lambda: recon.run_nmap(allowed.name)),
                ("whatweb", lambda: recon.run_whatweb(allowed.name)),
                ("nikto", lambda: recon.run_nikto(allowed.name)),
                ("probe", lambda: probe.probe_target(allowed.name)),
            ]:
                try:
                    res = fn()
                    st.write(f"✅ {tool_name} OK")
                    if tool_name == "nmap":
                        nmap_result = res
                    elif tool_name == "whatweb":
                        whatweb_result = res
                    elif tool_name == "nikto":
                        nikto_result = res
                    else:
                        probe_result = res
                except recon.ToolNotFoundError as exc:
                    st.warning(f"⚠️ {tool_name} absent : {exc}")
                except Exception as exc:
                    st.error(f"❌ {tool_name} : {exc}")
            status.update(label="Recon terminé", state="complete")

    if "detect" in steps:
        with st.status("Détection (normalisation)…") as status:
            if nmap_result:
                findings += detect.detect_from_nmap(nmap_result)
            if whatweb_result:
                findings += detect.detect_from_whatweb(whatweb_result)
            if nikto_result:
                findings += detect.detect_from_nikto(nikto_result)
            if probe_result:
                findings += detect.detect_from_probe(probe_result)
            st.write(f"{len(findings)} finding(s)")
            status.update(label="Détection terminée", state="complete")

    if "exploit" in steps:
        with st.status("Exploitation réelle (sqlmap / hydra)…") as status:
            if not probe_result:
                st.write("Pas de découverte active : rien à exploiter.")
            else:
                decisions = exploit.plan_exploits(probe_result)
                for d in decisions:
                    st.write(f"→ {d.tool}/{d.kind} : {d.reason}")
                try:
                    findings += exploit.run_plan(allowed.name, decisions)
                except recon.ToolNotFoundError as exc:
                    st.warning(f"⚠️ {exc}")
            status.update(label="Exploitation terminée", state="complete")

    if "report" in steps:
        with st.status("Génération du rapport…") as status:
            produced = report.generate_all(allowed.name, findings, steps)
            st.session_state["produced"] = {k: str(v) for k, v in produced.items()}
            status.update(label="Rapport généré", state="complete")

    return findings


if launch:
    try:
        st.session_state["findings"] = run_scan(target_name, steps)
    except scope.ScopeError as exc:
        st.error(f"Cible hors scope : {exc}")

findings = st.session_state.get("findings", [])
if findings:
    st.subheader(f"Findings ({len(findings)})")
    st.dataframe(
        [
            {
                "sévérité": f["severity"],
                "type": f["type"],
                "module": f["module"],
                "statut": f["status"],
                "description": f["description"],
            }
            for f in findings
        ],
        use_container_width=True,
    )

produced = st.session_state.get("produced", {})
if produced:
    st.subheader("Téléchargement du rapport")
    cols = st.columns(len(produced))
    for col, (kind, path) in zip(cols, produced.items()):
        p = Path(path)
        if p.exists():
            col.download_button(
                f"⬇️ {kind.upper()}",
                data=p.read_bytes(),
                file_name=p.name,
                mime="application/json" if kind == "json" else "text/html",
            )
