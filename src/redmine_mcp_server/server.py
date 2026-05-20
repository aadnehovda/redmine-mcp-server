"""FastMCP server instance.

The single source of truth for the `mcp` object that all `@mcp.tool()`
decorators register against. Tool modules import `mcp` from here.

Importing this module does NOT register any tools -- only `tools/__init__.py`
(via `from . import tools` in `main.py`) triggers tool registration.
"""

import os

from fastmcp import FastMCP

from ._tool_error_middleware import CleanValidationErrorMiddleware
from .fastmcp_oauth_proxy import build_redmine_oauth_proxy

auth = None
if os.getenv("REDMINE_AUTH_MODE", "legacy").lower() == "fastmcp-oauth-proxy":
    auth = build_redmine_oauth_proxy()

mcp = FastMCP("redmine_mcp_tools", auth=auth)
mcp.add_middleware(CleanValidationErrorMiddleware())
