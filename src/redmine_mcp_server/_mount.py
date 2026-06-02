"""HTTP mount configuration for authenticated MCP deployments."""

from __future__ import annotations

import os
from urllib.parse import urlparse

DEFAULT_BASE_URL = "http://localhost:3040"
DEFAULT_MCP_PATH = "/mcp"


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
        raise RuntimeError("FASTMCP_STREAMABLE_HTTP_PATH must not be /")
    return path


def mcp_base_url() -> str:
    """Public base URL of the mounted OAuth/MCP app."""
    return _clean_url(os.getenv("REDMINE_MCP_BASE_URL", DEFAULT_BASE_URL))


def mcp_path_for_http_app() -> str:
    """MCP transport path inside the mounted app."""
    return _clean_path(
        os.getenv("FASTMCP_STREAMABLE_HTTP_PATH", DEFAULT_MCP_PATH),
        allow_root=True,
    )


def mcp_path_for_metadata() -> str | None:
    """MCP path for OAuth metadata; None means the mounted app root."""
    path = mcp_path_for_http_app()
    if path == "/":
        return None
    return path


def mcp_mount_prefix() -> str:
    """Internal ASGI mount prefix derived from the public base URL path."""
    path = urlparse(mcp_base_url()).path.rstrip("/")
    return path or "/"
