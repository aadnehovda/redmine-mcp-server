"""FastMCP OAuthProxy factory for Redmine OAuth."""

from __future__ import annotations

import os

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier

from ._env import get_secret_env, require_introspection_credentials
from ._mount import mcp_base_url
from .oauth_scopes import advertised_scopes


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace(",", " ")
    return [item for item in normalized.split() if item]


def build_oauth_proxy() -> OAuthProxy:
    """Construct FastMCP OAuthProxy for Redmine-backed OAuth."""
    redmine_url = os.getenv("REDMINE_URL", "").rstrip("/")
    public_base_url = mcp_base_url()

    upstream_client_id = os.getenv("REDMINE_OAUTH_CLIENT_ID")
    upstream_client_secret = get_secret_env("REDMINE_OAUTH_CLIENT_SECRET")
    jwt_signing_key = get_secret_env("REDMINE_MCP_JWT_SIGNING_KEY")

    missing = [
        name
        for name, value in (
            ("REDMINE_URL", redmine_url),
            ("REDMINE_MCP_BASE_URL", public_base_url),
            ("REDMINE_OAUTH_CLIENT_ID", upstream_client_id),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing required FastMCP OAuthProxy configuration: " + ", ".join(missing)
        )

    if not jwt_signing_key:
        raise RuntimeError(
            "Set REDMINE_MCP_JWT_SIGNING_KEY[_FILE] for FastMCP OAuthProxy. "
            "FastMCP uses it to sign proxy tokens and derive encrypted storage."
        )

    introspect_client_id, introspect_client_secret = require_introspection_credentials()
    verifier = IntrospectionTokenVerifier(
        introspection_url=f"{redmine_url}/oauth/introspect",
        client_id=introspect_client_id,
        client_secret=introspect_client_secret,
    )

    return OAuthProxy(
        upstream_authorization_endpoint=f"{redmine_url}/oauth/authorize",
        upstream_token_endpoint=f"{redmine_url}/oauth/token",
        upstream_client_id=upstream_client_id or "",
        upstream_client_secret=upstream_client_secret,
        upstream_revocation_endpoint=f"{redmine_url}/oauth/revoke",
        token_verifier=verifier,
        base_url=public_base_url,
        allowed_client_redirect_uris=_split_values(
            os.getenv("REDMINE_MCP_ALLOWED_CLIENT_REDIRECT_URIS")
        )
        or None,
        valid_scopes=advertised_scopes(),
        forward_pkce=os.getenv("REDMINE_MCP_FORWARD_PKCE", "true").lower() == "true",
        forward_resource=(
            os.getenv("REDMINE_MCP_FORWARD_RESOURCE", "false").lower() == "true"
        ),
        token_endpoint_auth_method=os.getenv(
            "REDMINE_OAUTH_TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post"
        ),
        require_authorization_consent=os.getenv(
            "REDMINE_MCP_PROXY_CONSENT", "external"
        ),
        jwt_signing_key=jwt_signing_key,
        fallback_access_token_expiry_seconds=int(
            os.getenv("REDMINE_MCP_ACCESS_TOKEN_TTL", "3600")
        ),
        enable_cimd=os.getenv("REDMINE_MCP_ENABLE_CIMD", "true").lower() == "true",
    )
