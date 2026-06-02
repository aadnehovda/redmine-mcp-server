"""FastMCP v3 native auth provider factory for the Redmine MCP server.

Builds a RemoteAuthProvider that:
  - Validates opaque OAuth tokens via Doorkeeper RFC 7662 introspection
    (POST {REDMINE_URL}/oauth/introspect).
  - Mounts RFC 9728 protected-resource metadata under the configured
    public base URL path plus FASTMCP_STREAMABLE_HTTP_PATH.
  - Advertises scopes_supported from oauth_scopes.advertised_scopes()
    (filtered when REDMINE_MCP_READ_ONLY=true).

The MCP server's introspection client_id/secret are read from
REDMINE_INTROSPECT_CLIENT_ID / REDMINE_INTROSPECT_CLIENT_SECRET. The
client must be registered in Doorkeeper as a confidential client, and
Doorkeeper's ``allow_token_introspection`` block must permit it to
introspect tokens issued to user-flow OAuth apps (stock Redmine sets
this to ``false`` and must be patched). See docs/oauth-setup.md Step 2.
"""

from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import cors_middleware
from mcp.shared.auth import OAuthMetadata
from pydantic import AnyHttpUrl
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse
import httpx
from urllib.parse import urlparse

from ._env import get_required, get_required_secret
from .oauth_scopes import advertised_scopes
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

INTROSPECTION_GUIDANCE = (
    "Register a confidential OAuth client in Redmine and configure "
    "Doorkeeper's allow_token_introspection block to accept it "
    "(see docs/oauth-setup.md Step 2 for the walkthrough)."
)


class RedmineAuthProvider(RemoteAuthProvider):

    redmine_url: AnyHttpUrl

    def __init__(
        self,
        redmine_url: AnyHttpUrl,
        base_url: AnyHttpUrl | str,
        introspect_client_id: str,
        introspect_client_secret: str,
        scopes_supported: list[str],
    ):
        self.redmine_url = redmine_url
        verifier = IntrospectionTokenVerifier(
            introspection_url=str(self.redmine_endpoint("/oauth/introspect")),
            client_id=introspect_client_id,
            client_secret=introspect_client_secret,
            # required_scopes is intentionally unset: today we advertise scopes
            # but do not gate tool calls on them. Per-tool scope enforcement is
            # a follow-up roadmap item.
        )

        super().__init__(
            token_verifier=verifier,
            authorization_servers=[self.redmine_url],
            base_url=base_url,
            scopes_supported=scopes_supported,
            resource_name="Redmine",
        )

    def redmine_endpoint(self, path: str) -> AnyHttpUrl:
        """Build a Redmine OAuth endpoint URL from the configured issuer URL."""
        return AnyHttpUrl(
            f"{str(AnyHttpUrl(self.redmine_url)).rstrip('/')}/{path.lstrip('/')}"
        )

    async def oauth_authorization_server(self, request: Request):
        """RFC 8414 — Authorization Server Metadata.

        Redmine uses Doorkeeper but does not serve this discovery document itself.
        We serve it manually, pointing to Redmine's real Doorkeeper endpoints.

        Env vars are read at request time (rather than module-import time) so
        that the handler responds to runtime configuration changes and is
        cleanly testable without module reloads.
        """
        asm = OAuthMetadata(
            issuer=self.redmine_url,
            authorization_endpoint=self.redmine_endpoint("/oauth/authorize"),
            token_endpoint=self.redmine_endpoint("/oauth/token"),
            revocation_endpoint=self.redmine_endpoint("/oauth/revoke"),
            scopes_supported=self._scopes_supported,
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
            ],
            revocation_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
            ],
            code_challenge_methods_supported=["S256"],
        )

        return await MetadataHandler(asm).handle(request)

    async def revoke_token(self, request: Request):
        """RFC 7009 — Revoke an OAuth2 access or refresh token.

        Proxies token revocation to Redmine's Doorkeeper /oauth/revoke endpoint.

        Accepts token via:
        - Authorization header: Bearer <token>
        - POST body: {"token": "<token>"} or form-encoded token=<token>

        Returns:
            200 OK on success (per RFC 7009, even if token was already invalid)
            400 Bad Request if no token provided
            502 Bad Gateway if Redmine is unreachable
        """
        token = None

        # Try Authorization header first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()

        # Fall back to request body
        if not token:
            content_type = request.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    body = await request.json()
                    token = body.get("token")
                except Exception:
                    pass
            else:
                # form-encoded
                try:
                    form = await request.form()
                    token = form.get("token")
                except Exception:
                    pass

        if not token:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "No token provided",
                },
            )

        # Forward revocation to Redmine's Doorkeeper endpoint.
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    str(self.redmine_endpoint("/oauth/revoke")),
                    data={"token": token},
                    timeout=10,
                )
            except httpx.RequestError:
                logger.error(
                    "Failed to reach Redmine for token revocation.",
                    exc_info=True,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "upstream_unavailable"},
                )

        if response.status_code not in (200, 204):
            # If Redmine returns an error, log but still return success per RFC 7009
            logger.warning(
                'Redmine revocation returned %s: "%s"',
                response.status_code,
                response.text,
            )

        # RFC 7009: return 200 regardless of whether token was valid
        # (to prevent token scanning attacks)
        return JSONResponse(status_code=200, content={"success": True})

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)

        issuer = (self.base_url.path or "").rstrip("/")
        routes.append(
            Route(
                f"/.well-known/oauth-authorization-server{issuer}",
                endpoint=cors_middleware(
                    self.oauth_authorization_server, ["GET", "OPTIONS"]
                ),
                methods=["GET", "OPTIONS"],
            )
        )
        routes.append(Route("/revoke", self.revoke_token, methods=["POST"]))

        for i, route in enumerate(routes):
            logger.debug("Route %d: %s", i, route)

        return routes


def build_remote_auth() -> RedmineAuthProvider:
    """Construct the RemoteAuthProvider for OAuth-mode startup.

    Raises RuntimeError if required env vars are missing — let the server
    fail fast at boot rather than 401 every request.
    """
    redmine_url = get_required(
        "REDMINE_URL",
        context="OAuth mode",
        guidance="See docs/oauth-setup.md.",
    )
    base_url = get_required(
        "REDMINE_MCP_BASE_URL",
        context="OAuth mode",
        guidance="Set it to the public MCP base URL.",
    )
    introspect_client_id = get_required(
        "REDMINE_INTROSPECT_CLIENT_ID",
        context="OAuth mode",
        guidance=INTROSPECTION_GUIDANCE,
    )
    introspect_client_secret = get_required_secret(
        "REDMINE_INTROSPECT_CLIENT_SECRET",
        context="OAuth mode",
        guidance=INTROSPECTION_GUIDANCE,
    )

    return RedmineAuthProvider(
        redmine_url=AnyHttpUrl(redmine_url),
        base_url=base_url,
        introspect_client_id=introspect_client_id,
        introspect_client_secret=introspect_client_secret,
        scopes_supported=advertised_scopes(),
    )
