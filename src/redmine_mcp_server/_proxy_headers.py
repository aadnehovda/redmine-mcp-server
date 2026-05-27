"""Optional forwarded-header rewriting for OAuth discovery responses."""

from __future__ import annotations

import json
import os
import re

from mcp.server.auth.routes import build_resource_metadata_url
from pydantic import AnyHttpUrl
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ._mount import mcp_base_url, mcp_path


def trust_proxy_headers() -> bool:
    return os.getenv("REDMINE_MCP_TRUST_PROXY_HEADERS", "false").lower() == "true"


def _first_header_value(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(",", 1)[0].strip() or None


def _forwarded_param(value: str | None, name: str) -> str | None:
    forwarded = _first_header_value(value)
    if not forwarded:
        return None
    for part in forwarded.split(";"):
        key, _, raw = part.strip().partition("=")
        if key.lower() == name:
            return raw.strip().strip('"') or None
    return None


def _clean_prefix(value: str | None) -> str:
    if not value:
        return ""
    prefix = _first_header_value(value) or ""
    if not prefix:
        return ""
    if not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return prefix.rstrip("/")


def forwarded_base_url(request: Request) -> str:
    """Return the public base URL from trusted proxy headers."""
    forwarded = request.headers.get("forwarded")
    proto = (
        _first_header_value(request.headers.get("x-forwarded-proto"))
        or _forwarded_param(forwarded, "proto")
        or request.url.scheme
    )
    host = (
        _first_header_value(request.headers.get("x-forwarded-host"))
        or _forwarded_param(forwarded, "host")
        or request.headers.get("host")
        or request.url.netloc
    )
    prefix = _clean_prefix(request.headers.get("x-forwarded-prefix"))
    return f"{proto}://{host}{prefix}".rstrip("/")


def _replace_base_url(value: str, old_base_url: str, new_base_url: str) -> str:
    old_base = old_base_url.rstrip("/")
    new_base = new_base_url.rstrip("/")
    for old in (f"{old_base}/", old_base):
        if value == old:
            return f"{new_base}/" if old.endswith("/") else new_base
        if value.startswith(old):
            return f"{new_base}{value[len(old_base):]}"
    return value


def _rewrite_json(value, old_base_url: str, new_base_url: str):
    if isinstance(value, str):
        return _replace_base_url(value, old_base_url, new_base_url)
    if isinstance(value, list):
        return [_rewrite_json(item, old_base_url, new_base_url) for item in value]
    if isinstance(value, dict):
        return {
            key: _rewrite_json(item, old_base_url, new_base_url)
            for key, item in value.items()
        }
    return value


def _copy_headers(response) -> dict[str, str]:
    return {
        key: value
        for key, value in response.headers.items()
        if key.lower() != "content-length"
    }


class ForwardedOAuthMetadataMiddleware(BaseHTTPMiddleware):
    """Rewrite OAuth metadata URLs using trusted forwarded headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        external_base_url = forwarded_base_url(request)
        fallback_base_url = mcp_base_url()
        if external_base_url == fallback_base_url:
            return response

        headers = _copy_headers(response)
        authenticate = headers.get("www-authenticate")
        if authenticate:
            resource_url = f"{external_base_url}/{mcp_path().lstrip('/')}"
            metadata_url = str(build_resource_metadata_url(AnyHttpUrl(resource_url)))
            headers["www-authenticate"] = re.sub(
                r'resource_metadata="[^"]+"',
                f'resource_metadata="{metadata_url}"',
                authenticate,
            )

        content_type = response.headers.get("content-type", "")
        should_rewrite_json = (
            request.url.path.startswith("/.well-known/")
            and "application/json" in content_type
        )
        if should_rewrite_json or authenticate:
            body = b"".join([chunk async for chunk in response.body_iterator])
            if not should_rewrite_json:
                return Response(
                    body,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                    background=response.background,
                )
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return Response(
                    body,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                )
            return JSONResponse(
                _rewrite_json(data, fallback_base_url, external_base_url),
                status_code=response.status_code,
                headers=headers,
            )

        return response
