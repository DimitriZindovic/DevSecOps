from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "targets.yaml"


class ScopeError(Exception):
    """Exception bloquante levée quand une cible est hors scope."""


@dataclass(frozen=True)
class Target:

    name: str
    description: str
    hosts: tuple[str, ...]
    ips: tuple[str, ...]
    ports: tuple[int, ...]
    scheme: str = "http"

    def base_url(self, host: str | None = None) -> str:
        chosen_host = host or self.hosts[0]
        return f"{self.scheme}://{chosen_host}:{self.ports[0]}"


@dataclass
class ParsedTarget:

    raw: str
    host: str
    port: int | None
    scheme: str | None


def _default_resolver(host: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return {info[4][0] for info in infos}
    except (socket.gaierror, socket.herror, OSError):
        return set()


def parse_target(raw: str) -> ParsedTarget:
    raw = raw.strip()
    if not raw:
        raise ScopeError("Cible vide fournie.")

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme or None
        if not host:
            raise ScopeError(f"URL invalide, hostname introuvable : {raw!r}")
        return ParsedTarget(raw=raw, host=host, port=port, scheme=scheme)

    if raw.count(":") == 1:
        host, _, port_str = raw.partition(":")
        try:
            port = int(port_str)
        except ValueError:
            raise ScopeError(f"Port invalide dans la cible {raw!r}")
        return ParsedTarget(raw=raw, host=host, port=port, scheme=None)

    return ParsedTarget(raw=raw, host=raw, port=None, scheme=None)


class ScopeGuard:
    def __init__(
        self,
        config_path: str | Path = DEFAULT_CONFIG_PATH,
        resolver: Callable[[str], set[str]] = _default_resolver,
        audit_logger: logging.Logger | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self._resolver = resolver
        self.targets: dict[str, Target] = {}
        self.enforce_ip_resolution: bool = True
        self.audit_log_path: Path = PROJECT_ROOT / "logs" / "audit.log"
        self._load_config()
        self._audit = audit_logger or self._build_audit_logger()

    def _load_config(self) -> None:
        if not self.config_path.exists():
            raise ScopeError(
                f"Fichier de scope introuvable : {self.config_path}. "
                "Impossible de valider les cibles : arrêt par sécurité."
            )
        try:
            data = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ScopeError(f"Config de scope illisible ({self.config_path}) : {exc}")

        raw_targets = data.get("targets") or []
        if not raw_targets:
            raise ScopeError(
                "Aucune cible dans la whitelist : par sécurité, tout est refusé."
            )

        for entry in raw_targets:
            name = entry.get("name")
            if not name:
                raise ScopeError(f"Entrée de cible sans 'name' : {entry!r}")
            self.targets[name] = Target(
                name=name,
                description=entry.get("description", ""),
                hosts=tuple(str(h) for h in entry.get("hosts", [])),
                ips=tuple(str(i) for i in entry.get("ips", [])),
                ports=tuple(int(p) for p in entry.get("ports", [])),
                scheme=entry.get("scheme", "http"),
            )

        settings = data.get("settings") or {}
        self.enforce_ip_resolution = bool(settings.get("enforce_ip_resolution", True))
        audit_rel = settings.get("audit_log", "logs/audit.log")
        self.audit_log_path = (PROJECT_ROOT / audit_rel).resolve()

    def _build_audit_logger(self) -> logging.Logger:
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("pentest.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", "") == str(self.audit_log_path)
            for h in logger.handlers
        ):
            handler = logging.FileHandler(self.audit_log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            logger.addHandler(handler)
        return logger

    @property
    def allowed_hosts(self) -> set[str]:
        hosts: set[str] = set()
        for t in self.targets.values():
            hosts.update(h.lower() for h in t.hosts)
        return hosts

    @property
    def allowed_ips(self) -> set[str]:
        ips: set[str] = set()
        for t in self.targets.values():
            ips.update(t.ips)
        return ips

    def _audit_attempt(self, target: str, allowed: bool, reason: str) -> None:
        verdict = "AUTORISÉ" if allowed else "REFUSÉ"
        self._audit.info(f"scope target={target!r} verdict={verdict} raison={reason}")

    def assert_in_scope(self, target: str) -> Target:
        try:
            parsed = parse_target(target)
        except ScopeError:
            self._audit_attempt(target, allowed=False, reason="parsing impossible")
            raise

        alias = self.targets.get(parsed.host)
        if alias is not None and parsed.port is None:
            self._audit_attempt(target, allowed=True, reason=f"alias={alias.name}")
            return alias

        host_lower = parsed.host.lower()

        candidates = [
            t for t in self.targets.values() if host_lower in {h.lower() for h in t.hosts}
        ]

        resolved_ips: set[str] = set()
        if not candidates and self.enforce_ip_resolution:
            resolved_ips = self._resolver(parsed.host)
            candidates = [
                t
                for t in self.targets.values()
                if resolved_ips & set(t.ips)
            ]

        if not candidates and parsed.host in self.allowed_ips:
            candidates = [t for t in self.targets.values() if parsed.host in t.ips]

        if not candidates:
            reason = (
                f"host {parsed.host!r} absent de la whitelist "
                f"(ips résolues={sorted(resolved_ips) or 'n/a'})"
            )
            self._audit_attempt(target, allowed=False, reason=reason)
            raise ScopeError(
                f"CIBLE HORS SCOPE : {target!r}. "
                f"Autorisées uniquement : {sorted(self.allowed_hosts)}. "
                "Requête réseau BLOQUÉE avant émission."
            )

        if parsed.port is not None:
            port_match = [t for t in candidates if parsed.port in t.ports]
            if not port_match:
                allowed_ports = sorted({p for t in candidates for p in t.ports})
                reason = f"port {parsed.port} non autorisé (ports permis={allowed_ports})"
                self._audit_attempt(target, allowed=False, reason=reason)
                raise ScopeError(
                    f"PORT HORS SCOPE : {parsed.port} pour {parsed.host!r}. "
                    f"Ports autorisés : {allowed_ports}. Requête BLOQUÉE."
                )
            candidates = port_match

        chosen = candidates[0]
        self._audit_attempt(
            target, allowed=True, reason=f"cible={chosen.name} host={parsed.host}"
        )
        return chosen


_default_guard: ScopeGuard | None = None


def get_guard() -> ScopeGuard:
    global _default_guard
    if _default_guard is None:
        _default_guard = ScopeGuard()
    return _default_guard


def assert_in_scope(target: str) -> Target:
    return get_guard().assert_in_scope(target)
