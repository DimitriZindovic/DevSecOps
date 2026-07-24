import logging
from pathlib import Path

import pytest

from core.scope import ScopeError, ScopeGuard, parse_target

CONFIG = Path(__file__).resolve().parent.parent / "config" / "targets.yaml"


def _guard(tmp_path, resolver=None):
    audit = logging.getLogger(f"test.audit.{tmp_path.name}")
    audit.handlers.clear()
    audit.setLevel(logging.INFO)
    audit.propagate = False
    handler = logging.FileHandler(tmp_path / "audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    audit.addHandler(handler)
    return ScopeGuard(
        config_path=CONFIG,
        resolver=resolver or (lambda host: set()),
        audit_logger=audit,
    )


def test_parse_alias():
    p = parse_target("juiceshop")
    assert p.host == "juiceshop" and p.port is None


def test_parse_url():
    p = parse_target("http://juiceshop:3000/rest/products")
    assert p.host == "juiceshop" and p.port == 3000 and p.scheme == "http"


def test_parse_host_port():
    p = parse_target("vampi:5000")
    assert p.host == "vampi" and p.port == 5000


def test_parse_empty_raises():
    with pytest.raises(ScopeError):
        parse_target("   ")


def test_alias_juiceshop_allowed(tmp_path):
    g = _guard(tmp_path)
    target = g.assert_in_scope("juiceshop")
    assert target.name == "juiceshop"


def test_alias_vampi_allowed(tmp_path):
    g = _guard(tmp_path)
    assert g.assert_in_scope("vampi").name == "vampi"


def test_url_juiceshop_allowed(tmp_path):
    g = _guard(tmp_path)
    assert g.assert_in_scope("http://juiceshop:3000/rest").name == "juiceshop"


def test_localhost_correct_port_allowed(tmp_path):
    g = _guard(tmp_path)
    assert g.assert_in_scope("localhost:3000").name == "juiceshop"
    assert g.assert_in_scope("localhost:5000").name == "vampi"


def test_ip_resolution_allows_whitelisted_ip(tmp_path):
    g = _guard(tmp_path, resolver=lambda host: {"127.0.0.1"})
    assert g.assert_in_scope("127.0.0.1:5000").name == "vampi"


def test_external_ip_refused(tmp_path):
    g = _guard(tmp_path)
    with pytest.raises(ScopeError):
        g.assert_in_scope("8.8.8.8")


def test_external_host_refused(tmp_path):
    g = _guard(tmp_path)
    with pytest.raises(ScopeError):
        g.assert_in_scope("evil.example.com")


def test_external_url_refused(tmp_path):
    g = _guard(tmp_path)
    with pytest.raises(ScopeError):
        g.assert_in_scope("https://google.com")


def test_allowed_host_wrong_port_refused(tmp_path):
    g = _guard(tmp_path)
    with pytest.raises(ScopeError):
        g.assert_in_scope("localhost:22")


def test_resolved_ip_not_whitelisted_refused(tmp_path):
    g = _guard(tmp_path, resolver=lambda host: {"93.184.216.34"})
    with pytest.raises(ScopeError):
        g.assert_in_scope("sneaky.example.com")


def test_refused_attempt_is_logged(tmp_path):
    g = _guard(tmp_path)
    with pytest.raises(ScopeError):
        g.assert_in_scope("8.8.8.8")
    content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "REFUSÉ" in content and "8.8.8.8" in content


def test_allowed_attempt_is_logged(tmp_path):
    g = _guard(tmp_path)
    g.assert_in_scope("juiceshop")
    content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "AUTORISÉ" in content and "juiceshop" in content


def test_missing_config_raises(tmp_path):
    with pytest.raises(ScopeError):
        ScopeGuard(config_path=tmp_path / "nope.yaml")
