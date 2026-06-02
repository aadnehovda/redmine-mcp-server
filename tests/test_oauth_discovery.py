"""Tests for OAuth discovery endpoints after the FastMCP v3 auth migration.

These build a parallel FastMCP instance in OAuth mode and exercise its HTTP
surface so the global `mcp` singleton (legacy mode in the test process) is
not disturbed.
"""

import importlib

import httpx
import pytest
from fastmcp import FastMCP


@pytest.fixture
def oauth_app(monkeypatch):
    """Construct a fresh OAuth-mode FastMCP app for discovery tests.

    Returns the Starlette ASGI app. The fixture mirrors the production
    wiring in ``main.py`` and ``server.py`` but uses a local FastMCP
    instance so the global ``mcp`` singleton (carrying tool registrations)
    is not perturbed.
    """
    monkeypatch.setenv("REDMINE_URL", "https://r.example.com")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "http://localhost:3040")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
    monkeypatch.setenv("REDMINE_AUTH_MODE", "oauth")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "cid")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "csec")
    monkeypatch.delenv("REDMINE_MCP_READ_ONLY", raising=False)

    from redmine_mcp_server import _auth, oauth_scopes
    from redmine_mcp_server import main as main_mod

    importlib.reload(oauth_scopes)
    importlib.reload(_auth)

    auth_provider = _auth.build_remote_auth()
    local_mcp = FastMCP("redmine_mcp_tools_test", auth=auth_provider)

    return main_mod.build_authenticated_app(local_mcp, auth_provider)


@pytest.mark.asyncio
async def test_protected_resource_suffix_path_returns_200(oauth_app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oauth_app), base_url="http://test"
    ) as client:
        r = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    body = r.json()
    assert "authorization_servers" in body
    assert any("r.example.com" in str(u) for u in body["authorization_servers"])
    assert "scopes_supported" in body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/.well-known/oauth-protected-resource",
        "/mcp/.well-known/oauth-protected-resource",
        "/mcp/.well-known/oauth-authorization-server",
    ],
)
async def test_dropped_discovery_paths_return_404(oauth_app, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oauth_app), base_url="http://test"
    ) as client:
        r = await client.get(path)
    assert (
        r.status_code == 404
    ), f"Expected 404 for dropped path {path}, got {r.status_code}"


@pytest.mark.asyncio
async def test_authorization_server_root_path_returns_200(oauth_app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oauth_app), base_url="http://test"
    ) as client:
        r = await client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    body = r.json()
    assert body["authorization_endpoint"] == "https://r.example.com/oauth/authorize"
    assert body["token_endpoint"] == "https://r.example.com/oauth/token"
    assert body["revocation_endpoint"] == "https://r.example.com/oauth/revoke"


@pytest.mark.asyncio
async def test_scope_sources_match(oauth_app):
    """Both discovery endpoints must return identical scopes_supported."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oauth_app), base_url="http://test"
    ) as client:
        pr = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
        asm = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert pr["scopes_supported"] == asm["scopes_supported"]


@pytest.mark.asyncio
async def test_scope_sources_filtered_consistently_in_read_only_mode(monkeypatch):
    """Read-only mode must filter write scopes from BOTH discovery endpoints."""
    monkeypatch.setenv("REDMINE_URL", "https://r.example.com")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "http://localhost:3040")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "cid")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "csec")
    monkeypatch.setenv("REDMINE_MCP_READ_ONLY", "true")

    from redmine_mcp_server import _auth, oauth_scopes
    from redmine_mcp_server import main as main_mod

    importlib.reload(oauth_scopes)
    importlib.reload(_auth)

    auth_provider = _auth.build_remote_auth()
    local_mcp = FastMCP("ro_test", auth=auth_provider)
    app = main_mod.build_authenticated_app(local_mcp, auth_provider)

    from redmine_mcp_server.oauth_scopes import WRITE_SCOPES

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        pr = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
        asm = (await client.get("/.well-known/oauth-authorization-server")).json()

    for write_scope in WRITE_SCOPES:
        assert write_scope not in pr["scopes_supported"]
        assert write_scope not in asm["scopes_supported"]


@pytest.mark.asyncio
async def test_authenticated_app_mounts_remote_auth_under_mcp(monkeypatch):
    monkeypatch.setenv("REDMINE_URL", "https://r.example.com")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "cid")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "csec")
    monkeypatch.delenv("REDMINE_MCP_READ_ONLY", raising=False)

    from redmine_mcp_server import _auth, oauth_scopes
    from redmine_mcp_server import main as main_mod

    importlib.reload(oauth_scopes)
    importlib.reload(_auth)

    auth_provider = _auth.build_remote_auth()
    local_mcp = FastMCP("remote_auth_mount_test", auth=auth_provider)
    app = main_mod.build_authenticated_app(local_mcp, auth_provider)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        root_prm = await client.get("/.well-known/oauth-protected-resource")
        prm = await client.get("/.well-known/oauth-protected-resource/mcp")
        mounted_prm = await client.get("/mcp/.well-known/oauth-protected-resource")
        asm = await client.get("/.well-known/oauth-authorization-server")
        mcp_get = await client.get("/mcp")

    assert root_prm.status_code == 404
    assert prm.status_code == 200
    assert mounted_prm.status_code == 404
    assert asm.status_code == 200
    assert mcp_get.status_code == 405
