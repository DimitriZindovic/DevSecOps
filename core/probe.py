"""Découverte active (scope-guardée) des surfaces exploitables.

Ce module comble le chaînon manquant entre la reconnaissance passive et
l'exploitation : il sonde activement la cible (requêtes HTTP légères) pour
repérer les CONTEXTES qui justifient de déclencher un outil d'exploitation :

    - endpoints de login          -> déclencheront hydra (brute-force)
    - paramètres injectables (GET) -> déclencheront sqlmap (injection SQL)

RÈGLE DE SÉCURITÉ : ``scope.assert_in_scope`` est appelé EN PREMIER. Aucune
requête n'est émise vers une cible hors whitelist.

La découverte reste GÉNÉRIQUE (liste de chemins candidats communs, pas la vuln
exacte codée en dur) : on sonde des chemins usuels et on infère les champs et
les marqueurs d'échec à partir des réponses réelles.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

from core import scope

# Chemins de login candidats (génériques, communs aux apps web / API REST).
LOGIN_PATHS = [
    "/rest/user/login",       # Juice Shop
    "/users/v1/login",        # VAmPI
    "/login",
    "/api/login",
    "/auth/login",
    "/api/v1/login",
]

# Endpoints à paramètre GET candidats (recherche = surface d'injection typique).
# On exige une réponse JSON pour éviter les faux positifs des SPA (qui renvoient
# index.html en 200 sur n'importe quel chemin).
PARAM_PATHS = [
    ("/rest/products/search", "q"),   # Juice Shop (endpoint de données JSON)
    ("/api/v1/search", "q"),
]

# Jeux de champs d'authentification à tester.
FIELD_SETS = [("username", "password"), ("email", "password")]


@dataclass
class LoginEndpoint:
    url: str
    path: str
    host: str
    port: int
    user_field: str
    pass_field: str
    content_type: str          # application/json | application/x-www-form-urlencoded
    fail_marker: str           # sous-chaîne présente dans une réponse d'ÉCHEC
    fail_status: int           # statut HTTP d'un échec


@dataclass
class ParamEndpoint:
    url: str                   # URL complète avec ?param=valeur
    param: str
    method: str = "GET"


@dataclass
class ProbeResult:
    target: str
    login_endpoints: list[LoginEndpoint] = field(default_factory=list)
    param_endpoints: list[ParamEndpoint] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _looks_like_login(status: int, body: str) -> bool:
    low = body.lower()
    tokens = ("password", "login", "token", "auth", "credential",
              "invalid", "fail", "unauthor", "incorrect")
    return status in (200, 400, 401, 403, 422) and (
        status in (401, 403) or any(t in low for t in tokens)
    )


def _pick_fail_marker(body: str, status: int) -> str:
    """Choisit un marqueur d'échec STABLE à partir d'une réponse d'échec.

    On privilégie les jetons de statut génériques ('fail', 'invalid') plutôt que
    les messages spécifiques ('does not exist'), car le message varie selon le
    mode d'échec (mauvais user vs mauvais mot de passe) alors que le jeton de
    statut est présent dans TOUS les échecs — indispensable pour que hydra ne
    produise pas de faux positif.
    """
    low = body.lower()
    for token in ("fail", "invalid", "unauthor", "denied", "incorrect",
                  "not correct", "does not exist", "error"):
        if token in low:
            return token
    # Corps vide (ex: 401 sans corps) : hydra s'appuiera sur le statut via 1=.
    return ""


def probe_target(target: str, timeout: int = 8) -> ProbeResult:
    """Sonde activement la cible pour découvrir login + paramètres injectables.

    ``scope.assert_in_scope`` est appelé EN PREMIER (garde-fou).
    """
    allowed = scope.assert_in_scope(target)
    base = allowed.base_url()
    host = allowed.hosts[0]
    port = allowed.ports[0]
    result = ProbeResult(target=allowed.name)

    session = requests.Session()

    # ---- Découverte des endpoints de login --------------------------------
    for path in LOGIN_PATHS:
        url = f"{base}{path}"
        best: LoginEndpoint | None = None
        for user_field, pass_field in FIELD_SETS:
            payload = {user_field: "probe_user_x", pass_field: "probe_pass_y"}
            try:
                r = session.post(url, json=payload, timeout=timeout)
            except requests.RequestException:
                continue
            if not _looks_like_login(r.status_code, r.text):
                continue
            marker = _pick_fail_marker(r.text, r.status_code)
            candidate = LoginEndpoint(
                url=url,
                path=path,
                host=host,
                port=port,
                user_field=user_field,
                pass_field=pass_field,
                content_type="application/json",
                fail_marker=marker,
                fail_status=r.status_code,
            )
            # L'app indique souvent le champ attendu dans son message d'erreur
            # (ex: Juice Shop -> "invalid email or password"). On préfère le jeu
            # de champs dont le nom d'utilisateur apparaît dans la réponse.
            mentions_field = user_field in r.text.lower()
            if best is None:
                best = candidate
            elif mentions_field and best.user_field not in r.text.lower():
                best = candidate
            elif marker and not best.fail_marker:
                best = candidate
        if best is not None:
            result.login_endpoints.append(best)
            result.notes.append(
                f"login détecté: {best.path} "
                f"({best.user_field}/{best.pass_field}, échec={best.fail_status})"
            )

    # ---- Découverte de paramètres injectables (GET) -----------------------
    for path, param in PARAM_PATHS:
        url = f"{base}{path}?{param}=probe"
        try:
            r = session.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        ct = r.headers.get("Content-Type", "")
        # On n'accepte que les endpoints de DONNÉES (réponse JSON) en 200, pour
        # écarter les SPA qui renvoient index.html en 200 sur tout chemin.
        if r.status_code == 200 and "application/json" in ct:
            result.param_endpoints.append(ParamEndpoint(url=url, param=param))
            result.notes.append(f"paramètre GET candidat (JSON): {path}?{param}=")

    return result
