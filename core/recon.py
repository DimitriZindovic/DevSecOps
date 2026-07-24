from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core import scope

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_OUTPUT_DIR = PROJECT_ROOT / "raw_output"


class ReconError(Exception):
    """Erreur générique de reconnaissance."""


class ToolNotFoundError(ReconError):
    """Outil Kali requis absent du PATH."""


class ReconTimeoutError(ReconError):
    """Un outil a dépassé le délai imparti."""

@dataclass
class ServicePort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""


@dataclass
class NmapResult:
    target: str
    host: str
    command: str
    ports: list[ServicePort] = field(default_factory=list)
    raw_xml: str = ""


@dataclass
class WhatWebResult:
    target: str
    url: str
    command: str
    plugins: dict = field(default_factory=dict)
    raw: str = ""


@dataclass
class NiktoResult:
    target: str
    url: str
    command: str
    items: list[dict] = field(default_factory=list)
    raw: str = ""


def _require_tool(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise ToolNotFoundError(
            f"Outil '{tool}' introuvable dans le PATH. "
            f"Installez-le sur Kali : sudo apt install -y {tool}"
        )
    return path


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReconTimeoutError(
            f"Délai dépassé ({timeout}s) pour : {' '.join(command)}"
        ) from exc
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"Binaire introuvable : {command[0]}") from exc


def _save_raw(name: str, content: str) -> Path:
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RAW_OUTPUT_DIR / f"{name}_{ts}.txt"
    path.write_text(content, encoding="utf-8")
    return path


def run_nmap(
    target: str,
    ports: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> NmapResult:
    allowed = scope.assert_in_scope(target)
    host = allowed.hosts[0]

    _require_tool("nmap")
    command = ["nmap", "-sV", "-oX", "-"]
    if ports:
        command += ["-p", ports]
    if extra_args:
        command += extra_args
    command.append(host)

    proc = _run(command, timeout=timeout)
    raw_xml = proc.stdout
    _save_raw(f"nmap_{allowed.name}", raw_xml or proc.stderr)

    result = NmapResult(
        target=allowed.name, host=host, command=" ".join(command), raw_xml=raw_xml
    )
    if not raw_xml.strip():
        raise ReconError(
            f"nmap n'a produit aucune sortie XML. stderr: {proc.stderr[:500]}"
        )
    result.ports = parse_nmap_xml(raw_xml)
    return result


def parse_nmap_xml(raw_xml: str) -> list[ServicePort]:
    ports: list[ServicePort] = []
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise ReconError(f"XML nmap invalide : {exc}") from exc

    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        ports.append(
            ServicePort(
                port=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", ""),
                state=state_el.get("state", "") if state_el is not None else "",
                service=service_el.get("name", "") if service_el is not None else "",
                product=service_el.get("product", "") if service_el is not None else "",
                version=service_el.get("version", "") if service_el is not None else "",
                extra=service_el.get("extrainfo", "") if service_el is not None else "",
            )
        )
    return ports


def run_whatweb(target: str, timeout: int = 120) -> WhatWebResult:
    allowed = scope.assert_in_scope(target)
    url = allowed.base_url()

    _require_tool("whatweb")
    command = ["whatweb", "--log-json=-", "--no-errors", url]
    proc = _run(command, timeout=timeout)
    raw = proc.stdout
    _save_raw(f"whatweb_{allowed.name}", raw or proc.stderr)

    plugins: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            plugins.update(entry.get("plugins", {}))
        except json.JSONDecodeError:
            continue
    return WhatWebResult(
        target=allowed.name, url=url, command=" ".join(command), plugins=plugins, raw=raw
    )


def run_nikto(target: str, timeout: int = 600) -> NiktoResult:
    allowed = scope.assert_in_scope(target)
    host = allowed.hosts[0]
    port = allowed.ports[0]

    _require_tool("nikto")
    command = ["nikto", "-h", host, "-p", str(port), "-Format", "csv", "-o", "-"]
    proc = _run(command, timeout=timeout)
    raw = proc.stdout
    _save_raw(f"nikto_{allowed.name}", raw or proc.stderr)

    items = parse_nikto_csv(raw)
    return NiktoResult(
        target=allowed.name,
        url=allowed.base_url(),
        command=" ".join(command),
        items=items,
        raw=raw,
    )


def parse_nikto_csv(raw: str) -> list[dict]:
    import csv
    import io

    items: list[dict] = []
    for row in csv.reader(io.StringIO(raw)):
        if len(row) >= 7:
            items.append(
                {
                    "host": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "osvdb": row[3],
                    "method": row[4],
                    "uri": row[5],
                    "description": row[6],
                }
            )
    return items
