import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "entra_test_cli.py"
spec = importlib.util.spec_from_file_location("entra_test_cli", MODULE_PATH)
cli = importlib.util.module_from_spec(spec)
sys.modules["entra_test_cli"] = cli
assert spec.loader is not None  # for mypy/pylint
spec.loader.exec_module(cli)  # type: ignore[attr-defined]


def test_generate_code_verifier_length_and_charset():
    verifier = cli._generate_code_verifier()
    assert 43 <= len(verifier) <= 128
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(verifier) <= allowed


def test_code_challenge_matches_known_value():
    assert cli._code_challenge("test") == "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"


def test_build_authorization_url_includes_pkce_params():
    url = cli._build_authorization_url(
        tenant_id="tenant",
        client_id="client",
        redirect_uri="https://example.com/cb",
        scope="openid",
        response_mode="query",
        response_type="code",
        state="xyz",
        code_challenge="abc123",
        code_challenge_method="S256",
    )
    parsed = cli.urlparse.urlparse(url)
    query = cli.urlparse.parse_qs(parsed.query)
    assert query["code_challenge"] == ["abc123"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == ["client"]


def test_extract_code_from_redirect_url():
    code = cli._extract_code("https://example.com/cb?code=abc123&state=xyz")
    assert code == "abc123"


def test_extract_code_raises_when_missing():
    with pytest.raises(RuntimeError):
        cli._extract_code("https://example.com/cb?state=xyz")


def test_load_env_defaults_reads_values(tmp_path):
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        'client_id="abc"\nclient_secret="secret"\nredirect_uri="https://example.com/cb"\n'
        'discovery_url="https://login.microsoftonline.com/custom-tenant/v2.0/.well-known/openid-configuration"\n'
    )
    defaults = cli._load_env_defaults(str(env_file))
    assert defaults.client_id == "abc"
    assert defaults.client_secret == "secret"
    assert defaults.redirect_uri == "https://example.com/cb"
    assert defaults.discovery_url.endswith(".well-known/openid-configuration")
    assert defaults.tenant_id == "custom-tenant"


def _make_args(**overrides):
    defaults = dict(
        client_id="client",
        client_secret="secret",
        redirect_uri="https://example.com/cb",
        env_file=".env",
        discovery_url="https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration",
        tenant_id="tenant",
        timeout=5,
        client_credentials_scope=None,
        authorization_code=None,
        non_interactive=True,
        open_browser=False,
        state="none",
        scope="openid offline_access",
        response_mode="query",
        response_type="code",
        refresh_token=None,
        access_token=None,
        disable_pkce=False,
        code_verifier=None,
        public_client=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _stub_http(monkeypatch, post_callback=None):
    def fake_get(url, headers=None, timeout=0):
        payload = {"issuer": "https://issuer", "token_endpoint": "https://issuer/token"}
        return cli.HttpResponse(200, "application/json", json.dumps(payload))

    def fake_post_form(url, data, timeout=0):
        if post_callback is not None:
            post_callback(url, data)
        grant = data.get("grant_type")
        if grant == "client_credentials":
            payload = {"access_token": "app-token", "expires_in": 1200}
        elif grant == "refresh_token":
            payload = {"access_token": "refreshed", "expires_in": 1800}
        else:
            payload = {"access_token": "token", "refresh_token": "refresh", "expires_in": 3600}
        return cli.HttpResponse(200, "application/json", json.dumps(payload))

    monkeypatch.setattr(cli, "_get", fake_get)
    monkeypatch.setattr(cli, "_post_form", fake_post_form)


def test_handle_report_requires_pkce_verifier(monkeypatch):
    _stub_http(monkeypatch)
    args = _make_args(authorization_code="https://example.com/cb?code=abc123")
    with pytest.raises(SystemExit):
        cli.handle_report(args)


def test_handle_report_succeeds_with_code_and_verifier(monkeypatch):
    _stub_http(monkeypatch)
    args = _make_args(
        authorization_code="https://example.com/cb?code=abc123",
        code_verifier="verifier",
        client_credentials_scope="api://app/.default",
    )
    cli.handle_report(args)


def test_handle_report_public_client_skips_secret(monkeypatch):
    captured = []

    def capture(url, data):
        if data.get("grant_type") == "authorization_code":
            captured.append(data.copy())

    _stub_http(monkeypatch, post_callback=capture)
    args = _make_args(
        authorization_code="https://example.com/cb?code=abc123",
        code_verifier="verifier",
        client_secret=None,
    )
    cli.handle_report(args)
    assert captured
    assert "client_secret" not in captured[0]
