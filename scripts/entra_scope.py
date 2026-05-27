#!/usr/bin/env python3
"""
Shared Entra naming and scope resolution helpers.

This module lets legacy environments keep their current tenant-wide Entra
object names while making new environments default to env-scoped names.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Callable

from entra_provisioning import get_azd_env, set_azd_env

SCOPE_MODE_LEGACY = "legacy"
SCOPE_MODE_SCOPED = "scoped"
VALID_SCOPE_MODES = {SCOPE_MODE_LEGACY, SCOPE_MODE_SCOPED}

LEGACY_BLUEPRINT_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Budget Backend Agents"
LEGACY_PORTAL_MANAGEMENT_APP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Portal - Management"
LEGACY_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Portal - Security Portal Mock"
LEGACY_PORTAL_ADMIN_GROUP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Administrators"
LEGACY_PORTAL_VIEWER_GROUP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Viewers"
LEGACY_PORTAL_ADMIN_GROUP_MAIL_NICKNAME = "isp-administrators"
LEGACY_PORTAL_VIEWER_GROUP_MAIL_NICKNAME = "isp-viewers"

SCOPE_MODE_SENTINEL_KEYS = (
    "ENTRA_BLUEPRINT_OBJECT_ID",
    "PORTAL_AUTH_CLIENT_ID",
)


class ScopeResolutionError(RuntimeError):
    """Raised when the current azd environment cannot be scoped safely."""


@dataclass(frozen=True)
class EntraScope:
    mode: str
    env_name: str
    scope_key: str
    mode_source: str
    key_source: str


def _normalize_mode(raw_mode: str | None) -> str | None:
    if not raw_mode:
        return None
    mode = raw_mode.strip().lower()
    if mode not in VALID_SCOPE_MODES:
        raise ScopeResolutionError(
            f"Unsupported ISP_ENV_SCOPE_MODE '{raw_mode}'. Expected one of: "
            f"{', '.join(sorted(VALID_SCOPE_MODES))}."
        )
    return mode


def sanitize_scope_key(env_name: str, max_length: int = 32) -> str:
    if not env_name:
        return ""
    key = env_name.lower()
    key = re.sub(r"[^a-z0-9-]+", "-", key)
    key = re.sub(r"-{2,}", "-", key).strip("-")
    return key[:max_length].strip("-")


def _build_getter(
    env_get: Callable[[str], str | None] | None = None,
    environ: dict[str, str] | None = None,
) -> Callable[[str], str | None]:
    env = os.environ if environ is None else environ

    def getter(key: str) -> str | None:
        value = env.get(key)
        if value:
            return value
        if env_get:
            return env_get(key)
        return None

    return getter


def _persist_value(
    key: str,
    value: str,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> None:
    env = os.environ if environ is None else environ
    env[key] = value
    if env_set:
        env_set(key, value)


def resolve_scope_mode(
    env_get: Callable[[str], str | None] | None = None,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> str:
    mode, _ = resolve_scope_mode_with_source(env_get=env_get, env_set=env_set, environ=environ)
    return mode


def resolve_scope_mode_with_source(
    env_get: Callable[[str], str | None] | None = None,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[str, str]:
    getter = _build_getter(env_get=env_get, environ=environ)
    explicit = _normalize_mode(getter("ISP_ENV_SCOPE_MODE"))
    if explicit:
        return explicit, "explicit"

    mode = SCOPE_MODE_SCOPED
    source = "auto-scoped"
    for key in SCOPE_MODE_SENTINEL_KEYS:
        if getter(key):
            mode = SCOPE_MODE_LEGACY
            source = "auto-legacy"
            break

    _persist_value("ISP_ENV_SCOPE_MODE", mode, env_set=env_set, environ=environ)
    return mode, source


def resolve_scope_key(
    env_name: str | None = None,
    env_get: Callable[[str], str | None] | None = None,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> str:
    key, _ = resolve_scope_key_with_source(
        env_name=env_name,
        env_get=env_get,
        env_set=env_set,
        environ=environ,
    )
    return key


def resolve_scope_key_with_source(
    env_name: str | None = None,
    env_get: Callable[[str], str | None] | None = None,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[str, str]:
    getter = _build_getter(env_get=env_get, environ=environ)
    raw_key = getter("ISP_ENV_SCOPE_KEY")
    if raw_key:
        scope_key = sanitize_scope_key(raw_key)
        if not scope_key:
            raise ScopeResolutionError(
                f"ISP_ENV_SCOPE_KEY '{raw_key}' does not produce a valid scope key."
            )
        if scope_key != raw_key:
            _persist_value("ISP_ENV_SCOPE_KEY", scope_key, env_set=env_set, environ=environ)
        return scope_key, "explicit"

    resolved_env_name = env_name or getter("AZURE_ENV_NAME")
    if not resolved_env_name:
        raise ScopeResolutionError(
            "AZURE_ENV_NAME is required to resolve ISP_ENV_SCOPE_KEY."
        )

    scope_key = sanitize_scope_key(resolved_env_name)
    if not scope_key:
        raise ScopeResolutionError(
            f"AZURE_ENV_NAME '{resolved_env_name}' does not produce a valid scope key."
        )
    _persist_value("ISP_ENV_SCOPE_KEY", scope_key, env_set=env_set, environ=environ)
    return scope_key, "derived"


def resolve_scope(
    env_get: Callable[[str], str | None] | None = None,
    env_set: Callable[[str, str], None] | None = None,
    environ: dict[str, str] | None = None,
) -> EntraScope:
    getter = _build_getter(env_get=env_get, environ=environ)
    mode, mode_source = resolve_scope_mode_with_source(
        env_get=env_get,
        env_set=env_set,
        environ=environ,
    )
    env_name = getter("AZURE_ENV_NAME") or ""
    if mode == SCOPE_MODE_SCOPED and not env_name:
        raise ScopeResolutionError(
            "Scoped Entra naming requires AZURE_ENV_NAME to be set in the current azd environment."
        )
    scope_key, key_source = resolve_scope_key_with_source(
        env_name=env_name,
        env_get=env_get,
        env_set=env_set,
        environ=environ,
    )
    return EntraScope(
        mode=mode,
        env_name=env_name,
        scope_key=scope_key,
        mode_source=mode_source,
        key_source=key_source,
    )


def blueprint_display_name(scope: EntraScope) -> str:
    if scope.mode == SCOPE_MODE_LEGACY:
        return LEGACY_BLUEPRINT_DISPLAY_NAME
    return f"{LEGACY_BLUEPRINT_DISPLAY_NAME} [{scope.env_name}]"


def agent_identity_display_name(agent_name: str, scope: EntraScope) -> str:
    if scope.mode == SCOPE_MODE_LEGACY:
        return f"isp-{agent_name}"
    # Avoid isp-isp-* when scope_key already starts with isp-
    key = scope.scope_key
    if key.startswith("isp-"):
        return f"{key}-{agent_name}"
    return f"isp-{key}-{agent_name}"


def fic_name(agent_name: str, scope: EntraScope) -> str:
    if scope.mode == SCOPE_MODE_LEGACY:
        return f"isp-fic-{agent_name}"
    key = scope.scope_key
    if key.startswith("isp-"):
        return f"isp-fic-{key[4:]}-{agent_name}"
    return f"isp-fic-{key}-{agent_name}"


def portal_management_app_display_name(scope: EntraScope) -> str:
    if scope.mode == SCOPE_MODE_LEGACY:
        return LEGACY_PORTAL_MANAGEMENT_APP_DISPLAY_NAME
    return f"{LEGACY_PORTAL_MANAGEMENT_APP_DISPLAY_NAME} [{scope.env_name}]"


def portal_securityportal_app_display_name(scope: EntraScope) -> str:
    if scope.mode == SCOPE_MODE_LEGACY:
        return LEGACY_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME
    return f"{LEGACY_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME} [{scope.env_name}]"


def portal_admin_group_display_name(scope: EntraScope) -> str:
    return LEGACY_PORTAL_ADMIN_GROUP_DISPLAY_NAME


def portal_viewer_group_display_name(scope: EntraScope) -> str:
    return LEGACY_PORTAL_VIEWER_GROUP_DISPLAY_NAME


def portal_admin_group_mail_nickname(scope: EntraScope) -> str:
    return LEGACY_PORTAL_ADMIN_GROUP_MAIL_NICKNAME


def portal_viewer_group_mail_nickname(scope: EntraScope) -> str:
    return LEGACY_PORTAL_VIEWER_GROUP_MAIL_NICKNAME


def validate_group_mail_nickname(mail_nickname: str) -> None:
    if len(mail_nickname) > 64:
        raise ScopeResolutionError(
            f"Generated mail nickname '{mail_nickname}' exceeds the 64 character limit."
        )


def summary_values(scope: EntraScope) -> dict[str, str]:
    values = {
        "ISP_ENV_SCOPE_MODE": scope.mode,
        "ISP_ENV_SCOPE_MODE_SOURCE": scope.mode_source,
        "ISP_ENV_SCOPE_KEY": scope.scope_key,
        "ISP_ENV_SCOPE_KEY_SOURCE": scope.key_source,
        "ISP_ENV_SCOPE_ENV_NAME": scope.env_name,
        "ENTRA_SCOPE_BLUEPRINT_DISPLAY_NAME": blueprint_display_name(scope),
        "ENTRA_SCOPE_PORTAL_MANAGEMENT_APP_DISPLAY_NAME": portal_management_app_display_name(scope),
        "ENTRA_SCOPE_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME": portal_securityportal_app_display_name(scope),
        "ENTRA_SCOPE_PORTAL_ADMIN_GROUP_DISPLAY_NAME": portal_admin_group_display_name(scope),
        "ENTRA_SCOPE_PORTAL_VIEWER_GROUP_DISPLAY_NAME": portal_viewer_group_display_name(scope),
        "ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME": portal_admin_group_mail_nickname(scope),
        "ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME": portal_viewer_group_mail_nickname(scope),
    }
    validate_group_mail_nickname(values["ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME"])
    validate_group_mail_nickname(values["ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME"])
    return values


def _emit_shell_exports(scope: EntraScope) -> int:
    for key, value in summary_values(scope).items():
        print(f"export {key}={shlex.quote(value)}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve env-scoped Entra naming")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("shell-exports", help="Print shell export statements")

    name_parser = subparsers.add_parser("name", help="Resolve one generated name")
    name_parser.add_argument(
        "kind",
        choices=(
            "blueprint",
            "agent",
            "fic",
            "portal-management-app",
            "portal-securityportal-app",
            "portal-admin-group",
            "portal-viewer-group",
            "portal-admin-mail",
            "portal-viewer-mail",
        ),
    )
    name_parser.add_argument("agent_name", nargs="?")
    return parser.parse_args()


def _emit_name(scope: EntraScope, kind: str, agent_name: str | None) -> int:
    if kind == "blueprint":
        print(blueprint_display_name(scope))
        return 0
    if kind == "agent":
        if not agent_name:
            raise ScopeResolutionError("agent name is required for kind=agent")
        print(agent_identity_display_name(agent_name, scope))
        return 0
    if kind == "fic":
        if not agent_name:
            raise ScopeResolutionError("agent name is required for kind=fic")
        print(fic_name(agent_name, scope))
        return 0
    if kind == "portal-management-app":
        print(portal_management_app_display_name(scope))
        return 0
    if kind == "portal-securityportal-app":
        print(portal_securityportal_app_display_name(scope))
        return 0
    if kind == "portal-admin-group":
        print(portal_admin_group_display_name(scope))
        return 0
    if kind == "portal-viewer-group":
        print(portal_viewer_group_display_name(scope))
        return 0
    if kind == "portal-admin-mail":
        print(portal_admin_group_mail_nickname(scope))
        return 0
    if kind == "portal-viewer-mail":
        print(portal_viewer_group_mail_nickname(scope))
        return 0
    raise ScopeResolutionError(f"Unsupported name kind '{kind}'")


def main() -> int:
    args = _parse_args()
    try:
        scope = resolve_scope(env_get=get_azd_env, env_set=set_azd_env)
        if args.command == "shell-exports":
            return _emit_shell_exports(scope)
        if args.command == "name":
            return _emit_name(scope, args.kind, args.agent_name)
        raise ScopeResolutionError(f"Unsupported command '{args.command}'")
    except ScopeResolutionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
