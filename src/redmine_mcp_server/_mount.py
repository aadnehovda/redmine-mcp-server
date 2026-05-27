"""HTTP mount configuration for authenticated MCP deployments."""

from __future__ import annotations

import os
from urllib.parse import urlparse

DEFAULT_BASE_URL = "http://localhost:3040"
DEFAULT_MCP_PATH = "/mcp"
NONE_VALUES = {"", "none", "null"}


def _clean_url(value: str) -> str:
    return value.rstrip("/")


def _clean_path(value: str, *, allow_root: bool = True) -> str:
    path = value.strip()
    if not path:
        return "/"
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/") or "/"
    if path == "/" and not allow_root:
        raise RuntimeError("REDMINE_MCP_PATH must not be /")
    return path


def mcp_base_url() -> str:
    """Public base URL of the mounted OAuth/MCP app."""
    return _clean_url(os.getenv("REDMINE_MCP_BASE_URL", DEFAULT_BASE_URL))


def mcp_path() -> str:
    """MCP transport path inside the mounted app."""
    return _clean_path(
        os.getenv("REDMINE_MCP_PATH", DEFAULT_MCP_PATH), allow_root=False
    )


def mcp_path_for_metadata() -> str | None:
    """MCP path for OAuth metadata; None means the mounted app root."""
    raw = os.getenv("REDMINE_MCP_PATH")
    if raw is not None and raw.strip().lower() in NONE_VALUES:
        return None
    return mcp_path()


def mcp_path_for_http_app() -> str:
    """MCP path passed to FastMCP's ASGI app."""
    return mcp_path_for_metadata() or "/"


def mcp_mount_prefix() -> str:
    """Internal ASGI mount prefix; / means no preserved proxy prefix."""
    raw = os.getenv("REDMINE_MCP_MOUNT_PREFIX")
    return "/" if raw is None else _clean_path(raw)


def authorization_server_metadata_path(base_url: str | None = None) -> str:
    """RFC 8414 metadata route for the configured public base URL."""
    configured_base_url = base_url or mcp_base_url()
    issuer_path = urlparse(configured_base_url).path.rstrip("/")
    return f"/.well-known/oauth-authorization-server{issuer_path}"
