"""
Main entry point for the MCP Redmine server.

This module uses FastMCP's native HTTP transport for MCP protocol communication.
The server runs with built-in HTTP endpoints and handles MCP requests natively.

Endpoints:
    - /mcp: Handles MCP requests via streamable HTTP transport.

Modules:
    - .tools: Per-resource MCP tool registrations (issues, projects, ...).
    - .server: Shared FastMCP instance.
"""

import logging
import os
import uvicorn
import httpx
from importlib.metadata import version, PackageNotFoundError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

# Configure basic logging before importing modules that log during init
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from . import tools  # noqa: E402,F401  -- triggers @mcp.tool registration
from . import _http_routes  # noqa: E402,F401  -- registers HTTP custom routes
from .server import AUTH_PROVIDER, mcp  # noqa: E402
from ._mount import (  # noqa: E402
    authorization_server_metadata_path,
    mcp_base_url,
    mcp_mount_prefix,
    mcp_path_for_http_app,
    mcp_path_for_metadata,
)
from .oauth_scopes import advertised_scopes  # noqa: E402

logger = logging.getLogger(__name__)

REDMINE_URL = os.environ.get("REDMINE_URL", "").rstrip("/")
REDMINE_MCP_BASE_URL = mcp_base_url()
REDMINE_AUTH_MODE = os.environ.get("REDMINE_AUTH_MODE", "legacy").lower()
AUTHENTICATED_AUTH_MODES = {"oauth", "oauth-proxy"}


def get_version() -> str:
    """Get package version from metadata."""
    try:
        return version("redmine-mcp-server")
    except PackageNotFoundError:
        return "dev"


# --- OAuth2 route handlers (registered conditionally) ---


async def oauth_authorization_server(request: Request):
    """RFC 8414 — Authorization Server Metadata.

    Redmine uses Doorkeeper but does not serve this discovery document itself.
    We serve it manually, pointing to Redmine's real Doorkeeper endpoints.

    Env vars are read at request time (rather than module-import time) so
    that the handler responds to runtime configuration changes and is
    cleanly testable without module reloads.
    """
    redmine_url = (os.environ.get("REDMINE_URL", "") or "").rstrip("/")
    base_url = mcp_base_url()
    return JSONResponse(
        {
            "issuer": base_url,
            "authorization_endpoint": f"{redmine_url}/oauth/authorize",
            "token_endpoint": f"{redmine_url}/oauth/token",
            "revocation_endpoint": f"{redmine_url}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "scopes_supported": advertised_scopes(),
        }
    )


async def revoke_token(request: Request):
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

    # Forward revocation to Redmine's Doorkeeper endpoint. Env vars are read
    # at request time so runtime overrides (and tests) are honoured.
    redmine_url = (os.environ.get("REDMINE_URL", "") or "").rstrip("/")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{redmine_url}/oauth/revoke",
                data={"token": token},
                timeout=10,
            )
        except httpx.RequestError as e:
            logger.error(f"Failed to reach Redmine for token revocation: {e}")
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_unavailable"},
            )

    # RFC 7009: return 200 regardless of whether token was valid
    # (to prevent token scanning attacks)
    if response.status_code in (200, 204):
        return JSONResponse(status_code=200, content={"success": True})

    # If Redmine returns an error, log but still return success per RFC 7009
    logger.warning(
        f"Redmine revocation returned {response.status_code}: " f"{response.text}"
    )
    return JSONResponse(status_code=200, content={"success": True})


def build_authenticated_app(mcp_instance, auth_provider, auth_mode: str):
    """Build a mounted ASGI app for authenticated modes."""
    metadata_path = mcp_path_for_metadata()
    mcp_app = mcp_instance.http_app(
        path=mcp_path_for_http_app(), stateless_http=True
    )

    routes = list(auth_provider.get_well_known_routes(mcp_path=metadata_path))
    if auth_mode == "oauth":
        routes.append(
            Route(
                authorization_server_metadata_path(),
                oauth_authorization_server,
                methods=["GET"],
            )
        )
        routes.append(Route("/revoke", revoke_token, methods=["POST"]))

    routes.extend(
        [
            Route("/health", _http_routes.health_check, methods=["GET"]),
            Route(
                "/files/{file_id}",
                _http_routes.serve_attachment,
                methods=["GET"],
            ),
            Route(
                "/cleanup/status",
                _http_routes.cleanup_status,
                methods=["GET"],
            ),
            Mount(mcp_mount_prefix(), app=mcp_app),
        ]
    )
    return Starlette(routes=routes, lifespan=mcp_app.lifespan)


def build_app():
    """Build the ASGI app.

    Authenticated modes use FastMCP's documented mounted-server layout:
    MCP and OAuth endpoints live under /mcp, while .well-known discovery and
    operational HTTP routes remain at the root application.
    """
    if REDMINE_AUTH_MODE in AUTHENTICATED_AUTH_MODES and AUTH_PROVIDER is not None:
        return build_authenticated_app(mcp, AUTH_PROVIDER, REDMINE_AUTH_MODE)

    return mcp.http_app(stateless_http=True)


# Export the Starlette app for testing and external use
app = build_app()

# Log version at module load time so it appears regardless of how the server is started
logger.info("Redmine MCP Server v%s", get_version())
logger.info("Auth mode: %s", REDMINE_AUTH_MODE)


def main():
    """Main entry point for the console script."""
    # Note: .env is already loaded during _client import
    # Note: version/auth mode are logged at module level
    # (works for both direct and uvicorn invocation)

    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8000"))

    # Run with our app directly so custom routes (well-known endpoints) are served
    uvicorn.run(app, host=host, port=port, log_config=None)


if __name__ == "__main__":
    main()
