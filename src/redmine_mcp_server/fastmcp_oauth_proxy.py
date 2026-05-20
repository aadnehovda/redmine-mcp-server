"""FastMCP OAuthProxy integration for Redmine OAuth.

This is an experimental adapter around FastMCP's built-in OAuth proxy. Redmine
acts as the upstream OAuth server and the MCP server presents the DCR-capable
surface that MCP clients expect.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.redis import RedisStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from .oauth_scopes import advertised_scopes


def _read_secret(env_name: str, file_env_name: str) -> str | None:
    value = os.getenv(env_name)
    if value:
        return value

    file_name = os.getenv(file_env_name)
    if not file_name:
        return None

    return Path(file_name).read_text(encoding="utf-8").strip()


def _split_scopes(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace(",", " ")
    return [scope for scope in normalized.split() if scope]


def _build_client_storage(
    *, client_secret: str | None, jwt_signing_key: str | None
) -> AsyncKeyValue | None:
    redis_url = os.getenv("REDMINE_MCP_REDIS_URL")
    if not redis_url:
        return None

    source_material = jwt_signing_key or client_secret
    if not source_material:
        raise RuntimeError(
            "REDMINE_MCP_REDIS_URL requires REDMINE_MCP_JWT_SIGNING_KEY[_FILE] "
            "or REDMINE_OAUTH_CLIENT_SECRET[_FILE] for encrypted OAuth storage."
        )

    return FernetEncryptionWrapper(
        key_value=RedisStore(url=redis_url),
        source_material=source_material,
        salt="redmine-mcp-oauth-proxy-storage",
        raise_on_decryption_error=False,
    )


class RedmineTokenVerifier(TokenVerifier):
    """Validate opaque Redmine OAuth access tokens via the Redmine REST API.

    Scope authorization stays in Redmine. The proxy advertises the scopes this
    MCP server can use, Redmine grants the user's selected subset, and Redmine's
    API enforces those permissions on each tool call.
    """

    def __init__(self, redmine_url: str):
        super().__init__(required_scopes=[])
        self.redmine_url = redmine_url.rstrip("/")

    async def verify_token(self, token: str) -> AccessToken | None:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.redmine_url}/users/current.json",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
            except httpx.RequestError:
                return None

        if response.status_code != 200:
            return None

        user = response.json().get("user", {})
        client_id = str(user.get("id") or user.get("login") or "redmine-user")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=self.required_scopes,
            expires_at=int(time.time()) + 300,
        )


def build_redmine_oauth_proxy() -> OAuthProxy:
    redmine_url = os.getenv("REDMINE_URL", "").rstrip("/")
    base_url = os.getenv("REDMINE_MCP_BASE_URL", "http://localhost:3040").rstrip("/")

    client_id = os.getenv("REDMINE_OAUTH_CLIENT_ID")
    client_secret = _read_secret(
        "REDMINE_OAUTH_CLIENT_SECRET",
        "REDMINE_OAUTH_CLIENT_SECRET_FILE",
    )
    jwt_signing_key = _read_secret(
        "REDMINE_MCP_JWT_SIGNING_KEY",
        "REDMINE_MCP_JWT_SIGNING_KEY_FILE",
    )

    missing = [
        name
        for name, value in (
            ("REDMINE_URL", redmine_url),
            ("REDMINE_MCP_BASE_URL", base_url),
            ("REDMINE_OAUTH_CLIENT_ID", client_id),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing required FastMCP OAuthProxy configuration: " + ", ".join(missing)
        )

    if not client_secret and not jwt_signing_key:
        raise RuntimeError(
            "Set REDMINE_OAUTH_CLIENT_SECRET[_FILE] or "
            "REDMINE_MCP_JWT_SIGNING_KEY[_FILE] for FastMCP OAuthProxy."
        )

    verifier = RedmineTokenVerifier(redmine_url)

    return OAuthProxy(
        upstream_authorization_endpoint=f"{redmine_url}/oauth/authorize",
        upstream_token_endpoint=f"{redmine_url}/oauth/token",
        upstream_client_id=client_id or "",
        upstream_client_secret=client_secret,
        upstream_revocation_endpoint=f"{redmine_url}/oauth/revoke",
        token_verifier=verifier,
        base_url=base_url,
        allowed_client_redirect_uris=_split_scopes(
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
        client_storage=_build_client_storage(
            client_secret=client_secret,
            jwt_signing_key=jwt_signing_key,
        ),
        require_authorization_consent=os.getenv(
            "REDMINE_MCP_PROXY_CONSENT", "external"
        ),
        jwt_signing_key=jwt_signing_key,
        fallback_access_token_expiry_seconds=int(
            os.getenv("REDMINE_MCP_ACCESS_TOKEN_TTL", "3600")
        ),
        enable_cimd=os.getenv("REDMINE_MCP_ENABLE_CIMD", "false").lower() == "true",
    )
