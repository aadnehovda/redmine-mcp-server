"""Environment-variable accessor helpers."""

import os
from pathlib import Path


def _is_true_env(var_name: str, default: str = "false") -> bool:
    """Parse common truthy env-var values."""
    return os.getenv(var_name, default).strip().lower() in {"1", "true", "yes", "on"}


def _is_read_only_mode() -> bool:
    """Check if the server is in read-only mode."""
    return _is_true_env("REDMINE_MCP_READ_ONLY", "false")


def _is_agile_enabled() -> bool:
    """Check if RedmineUP Agile plugin support is enabled."""
    return _is_true_env("REDMINE_AGILE_ENABLED", "false")


def _is_checklists_enabled() -> bool:
    """Check if RedmineUP Checklists plugin support is enabled."""
    return _is_true_env("REDMINE_CHECKLISTS_ENABLED", "false")


def _is_products_enabled() -> bool:
    """Check if RedmineUP Products plugin support is enabled."""
    return _is_true_env("REDMINE_PRODUCTS_ENABLED", "false")


def _is_crm_enabled() -> bool:
    """Check if RedmineUP CRM (Contacts) plugin support is enabled."""
    return _is_true_env("REDMINE_CRM_ENABLED", "false")


def _is_dmsf_enabled() -> bool:
    """Check if DMSF (document management) plugin support is enabled."""
    return _is_true_env("REDMINE_DMSF_ENABLED", "false")


def _admin_tools_enabled() -> bool:
    """Check if operator-facing admin tools are exposed on the MCP surface.

    Default ``False``. When unset, admin/cron-style tools
    (``cleanup_attachment_files`` and any future maintenance helpers)
    are not registered at import time and do not appear in
    ``tools/list``. Operators who want to drive cleanup through the
    MCP surface set ``REDMINE_MCP_EXPOSE_ADMIN_TOOLS=true`` to opt in;
    the underlying background cleanup task runs regardless of this flag.
    """
    return _is_true_env("REDMINE_MCP_EXPOSE_ADMIN_TOOLS", "false")


def _get_int_env(var_name: str, default: int) -> int:
    """Parse an integer environment variable, falling back to default."""
    try:
        return int(os.getenv(var_name, str(default)))
    except (ValueError, TypeError):
        return default


def get(var_name: str, default: str | None = None) -> str | None:
    """Return an environment variable value."""
    return os.getenv(var_name, default)


def get_secret(var_name: str, file_var_name: str | None = None) -> str | None:
    """Return a secret from an env var or a Docker/Kubernetes-style file env var."""
    value = os.getenv(var_name)
    if value:
        return value

    file_name = os.getenv(file_var_name or f"{var_name}_FILE")
    if not file_name:
        return None

    return Path(file_name).read_text(encoding="utf-8").strip()


def get_required(
    var_name: str,
    *,
    context: str | None = None,
    guidance: str | None = None,
) -> str:
    """Return a required environment variable or raise a clear RuntimeError."""
    value = get(var_name)
    if value:
        return value

    parts = []
    if context:
        parts.append(f"{context} requires {var_name}.")
    else:
        parts.append(f"Missing required env var: {var_name}.")
    if guidance:
        parts.append(guidance)
    raise RuntimeError(" ".join(parts))


def get_required_secret(
    var_name: str,
    *,
    file_var_name: str | None = None,
    context: str | None = None,
    guidance: str | None = None,
) -> str:
    """Return a required secret from env or a file env var."""
    value = get_secret(var_name, file_var_name)
    if value:
        return value

    names = (
        f"{var_name}[_FILE]" if file_var_name is None else f"{var_name}/{file_var_name}"
    )
    parts = []
    if context:
        parts.append(f"{context} requires {names}.")
    else:
        parts.append(f"Missing required secret env var: {names}.")
    if guidance:
        parts.append(guidance)
    raise RuntimeError(" ".join(parts))


def get_health_introspection_ttl_seconds() -> int:
    """How long /health caches the Doorkeeper introspection probe result."""
    return _get_int_env("HEALTH_INTROSPECTION_TTL_SECONDS", 30)
