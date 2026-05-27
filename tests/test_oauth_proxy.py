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
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    proxy = build_oauth_proxy()

    assert isinstance(proxy, OAuthProxy)
    assert isinstance(proxy._token_validator, IntrospectionTokenVerifier)
    assert proxy._token_validator.introspection_url == (
        "https://redmine.example/oauth/introspect"
    )


@pytest.mark.asyncio
async def test_authenticated_app_mounts_oauth_proxy_under_mcp(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(
        FastMCP("oauth_proxy_test", auth=auth), auth, "oauth-proxy"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        root_as = await client.get("/.well-known/oauth-authorization-server")
        prm = await client.get("/.well-known/oauth-protected-resource/mcp")
        mounted_prm = await client.get("/mcp/.well-known/oauth-protected-resource")
        authorize = await client.get("/authorize")
        mcp_get = await client.get("/mcp")
        mcp_post = await client.post("/mcp", json={})

    assert root_as.status_code == 200
    assert prm.status_code == 200
    assert mounted_prm.status_code == 404
    assert authorize.status_code != 404
    assert mcp_get.status_code == 405
    assert mcp_post.status_code == 401

    as_body = root_as.json()
    prm_body = prm.json()
    assert as_body["issuer"] == "https://mcp.example/"
    assert as_body["authorization_endpoint"] == "https://mcp.example/authorize"
    assert as_body["token_endpoint"] == "https://mcp.example/token"
    assert as_body["registration_endpoint"] == "https://mcp.example/register"
    assert prm_body["authorization_servers"] == ["https://mcp.example/"]
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp'
        in mcp_post.headers["www-authenticate"]
    )


@pytest.mark.asyncio
async def test_authenticated_app_respects_mount_prefix(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example/somepath")
    monkeypatch.setenv("REDMINE_MCP_MOUNT_PREFIX", "/somepath")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(
        FastMCP("oauth_proxy_test", auth=auth), auth, "oauth-proxy"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        scoped_as = await client.get(
            "/.well-known/oauth-authorization-server/somepath"
        )
        prm = await client.get(
            "/.well-known/oauth-protected-resource/somepath/mcp"
        )
        authorize = await client.get("/somepath/authorize")
        mcp_post = await client.post("/somepath/mcp", json={})

    assert scoped_as.status_code == 200
    assert prm.status_code == 200
    assert authorize.status_code != 404
    assert mcp_post.status_code == 401
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/somepath/mcp'
        in mcp_post.headers["www-authenticate"]
    )


@pytest.mark.asyncio
async def test_authenticated_app_respects_custom_mcp_path(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example")
    monkeypatch.setenv("REDMINE_MCP_PATH", "/redmine")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(
        FastMCP("oauth_proxy_test", auth=auth), auth, "oauth-proxy"
    )

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


@pytest.mark.asyncio
async def test_authenticated_app_supports_mcp_path_none(monkeypatch, tmp_path):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://mcp.example/mcp")
    monkeypatch.setenv("REDMINE_MCP_MOUNT_PREFIX", "/mcp")
    monkeypatch.setenv("REDMINE_MCP_PATH", "none")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(
        FastMCP("oauth_proxy_test", auth=auth), auth, "oauth-proxy"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://mcp.example",
        follow_redirects=False,
    ) as client:
        scoped_as = await client.get("/.well-known/oauth-authorization-server/mcp")
        prm = await client.get("/.well-known/oauth-protected-resource/mcp")
        authorize = await client.get("/mcp/authorize")
        mcp_post = await client.post("/mcp", json={})
        mcp_post_slash = await client.post("/mcp/", json={})

    assert scoped_as.status_code == 200
    assert prm.status_code == 200
    assert authorize.status_code != 404
    assert mcp_post.status_code == 307
    assert mcp_post_slash.status_code == 401
    assert (
        'resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp'
        in mcp_post_slash.headers["www-authenticate"]
    )


@pytest.mark.asyncio
async def test_authenticated_app_rewrites_metadata_from_proxy_headers(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("REDMINE_URL", "https://redmine.example")
    monkeypatch.setenv("REDMINE_MCP_BASE_URL", "https://internal.example")
    monkeypatch.setenv("REDMINE_MCP_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_ID", "upstream-client")
    monkeypatch.setenv("REDMINE_OAUTH_CLIENT_SECRET", "upstream-secret")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_ID", "introspect-client")
    monkeypatch.setenv("REDMINE_INTROSPECT_CLIENT_SECRET", "introspect-secret")
    monkeypatch.setenv("REDMINE_MCP_JWT_SIGNING_KEY", "stable-test-signing-key")
    monkeypatch.setattr(settings, "home", tmp_path)

    from redmine_mcp_server.main import build_authenticated_app

    auth = build_oauth_proxy()
    app = build_authenticated_app(
        FastMCP("oauth_proxy_test", auth=auth), auth, "oauth-proxy"
    )
    headers = {
        "x-forwarded-proto": "https",
        "x-forwarded-host": "public.example",
        "x-forwarded-prefix": "/somepath",
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://internal.example"
    ) as client:
        root_as = await client.get(
            "/.well-known/oauth-authorization-server", headers=headers
        )
        prm = await client.get(
            "/.well-known/oauth-protected-resource/mcp", headers=headers
        )
        mcp_post = await client.post("/mcp", json={}, headers=headers)

    as_body = root_as.json()
    prm_body = prm.json()
    assert as_body["issuer"] == "https://public.example/somepath/"
    assert (
        as_body["authorization_endpoint"]
        == "https://public.example/somepath/authorize"
    )
    assert prm_body["authorization_servers"] == [
        "https://public.example/somepath/"
    ]
    assert (
        'resource_metadata="https://public.example/.well-known/oauth-protected-resource/somepath/mcp"'
        in mcp_post.headers["www-authenticate"]
    )
