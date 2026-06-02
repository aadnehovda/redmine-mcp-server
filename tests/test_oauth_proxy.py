import pytest
import httpx
from fastmcp import FastMCP
from fastmcp import settings
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier

from redmine_mcp_server._oauth_proxy import build_oauth_proxy


def test_build_oauth_proxy_uses_introspection_verifier(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    proxy = build_oauth_proxy()

    assert isinstance(proxy, OAuthProxy)
    assert isinstance(proxy._token_validator, IntrospectionTokenVerifier)
    assert proxy._require_authorization_consent == "external"
    assert proxy._token_validator.introspection_url == (
        "https://redmine.example/oauth/introspect"
    )


@pytest.mark.asyncio
async def test_authenticated_app_mounts_oauth_proxy_under_mcp(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(FastMCP("oauth_proxy_test", auth=auth), auth)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        root_as = await client.get("/.well-known/oauth-authorization-server")
        resource_as = await client.get("/.well-known/oauth-authorization-server/mcp")
        prm = await client.get("/.well-known/oauth-protected-resource/mcp")
        mounted_prm = await client.get("/mcp/.well-known/oauth-protected-resource")
        authorize = await client.get("/authorize")
        mcp_get = await client.get("/mcp")
        mcp_post = await client.post("/mcp", json={})

    assert root_as.status_code == 200
    assert resource_as.status_code == 200
    assert prm.status_code == 200
    assert mounted_prm.status_code == 404
    assert authorize.status_code != 404
    assert mcp_get.status_code == 405
    assert mcp_post.status_code == 401

    as_body = root_as.json()
    resource_as_body = resource_as.json()
    prm_body = prm.json()
    assert as_body["issuer"] == "https://mcp.example/"
    assert resource_as_body == as_body
    assert as_body["authorization_endpoint"] == "https://mcp.example/authorize"
    assert as_body["token_endpoint"] == "https://mcp.example/token"
    assert as_body["registration_endpoint"] == "https://mcp.example/register"
    assert prm_body["authorization_servers"] == ["https://mcp.example/"]
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp'
        in mcp_post.headers["www-authenticate"]
    )


@pytest.mark.asyncio
async def test_authenticated_app_derives_mount_prefix_from_base_url(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example/somepath")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(FastMCP("oauth_proxy_test", auth=auth), auth)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        scoped_as = await client.get("/.well-known/oauth-authorization-server/somepath")
        resource_scoped_as = await client.get(
            "/.well-known/oauth-authorization-server/somepath/mcp"
        )
        prm = await client.get("/.well-known/oauth-protected-resource/somepath/mcp")
        authorize = await client.get("/somepath/authorize")
        mcp_post = await client.post("/somepath/mcp", json={})

    assert scoped_as.status_code == 200
    assert resource_scoped_as.status_code == 200
    assert prm.status_code == 200
    assert authorize.status_code != 404
    assert mcp_post.status_code == 401
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/somepath/mcp'
        in mcp_post.headers["www-authenticate"]
    )
    assert resource_scoped_as.json() == scoped_as.json()


@pytest.mark.asyncio
async def test_authenticated_app_respects_fastmcp_streamable_path(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("FASTMCP_STREAMABLE_HTTP_PATH", "/redmine")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(FastMCP("oauth_proxy_test", auth=auth), auth)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        prm = await client.get("/.well-known/oauth-protected-resource/redmine")
        mcp_post = await client.post("/redmine", json={})

    assert prm.status_code == 200
    assert mcp_post.status_code == 401
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/redmine'
        in mcp_post.headers["www-authenticate"]
    )
