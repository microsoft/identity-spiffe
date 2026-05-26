#!/usr/bin/env python3
"""
cleanup-entra-agent-ids.py
==========================
Deletes Entra Agent Identity objects for the current azd environment by default.
Use --all-envs for the old tenant-wide cleanup behavior.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from entra_provisioning import (  # noqa: E402
    ProvisionerBootstrapError,
    build_required_permission_values,
    get_azd_env,
    get_graph_token as get_provisioner_graph_token,
    set_azd_env,
)
from entra_scope import (  # noqa: E402
    ScopeResolutionError,
    agent_identity_display_name,
    blueprint_display_name,
    fic_name,
    resolve_scope,
)

GRAPH_BASE = "https://graph.microsoft.com/beta"
BLUEPRINT_PREFIX = "AIM Prototype Platform Budget Backend Agents"

AGENTS = [
    "budget-report",
    "budget-backend",
    "employee-menus",
    "budget-approval",
    "admin-control-plane",
]

STATIC_ENV_KEYS = [
    "ENTRA_BLUEPRINT_APP_ID",
    "ENTRA_BLUEPRINT_OBJECT_ID",
    "ENTRA_OAUTH2_APP_ROLES_READY",
    "ENTRA_OAUTH2_AUDIENCE",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Clean up Entra Agent IDs")
    parser.add_argument(
        "--all-envs",
        action="store_true",
        help="Delete all AIM Entra Agent Identities across environments in the tenant",
    )
    return parser.parse_args()


def odata_escape(value: str) -> str:
    return value.replace("'", "''")


def graph_request(method, path, token, retry=True):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    url = f"{GRAPH_BASE}{path}"
    resp = requests.request(method, url, headers=headers)
    if retry and resp.status_code in (429, 500, 502, 503, 504):
        wait = int(resp.headers.get("Retry-After", "10"))
        print(f"  Retrying in {wait}s (got {resp.status_code})...")
        time.sleep(wait)
        resp = requests.request(method, url, headers=headers)
    return resp


def load_azd_env_values():
    result = subprocess.run(
        ["azd", "env", "get-values"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return {}
    values = {}
    for line in result.stdout.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key] = value.strip().strip('"')
    return values


def find_blueprint_applications(token, scope, all_envs=False):
    apps = []
    if all_envs:
        resp = graph_request(
            "GET",
            f"/applications?$filter=startswith(displayName,'{odata_escape(BLUEPRINT_PREFIX)}')",
            token,
        )
        if resp.status_code == 200:
            apps.extend(resp.json().get("value", []))
        return apps

    stored_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")
    if stored_obj_id:
        resp = graph_request("GET", f"/applications/{stored_obj_id}", token, retry=False)
        if resp.status_code == 200:
            return [resp.json()]

    stored_app_id = get_azd_env("ENTRA_BLUEPRINT_APP_ID")
    if stored_app_id:
        resp = graph_request(
            "GET",
            f"/applications?$filter=appId eq '{odata_escape(stored_app_id)}'",
            token,
        )
        if resp.status_code == 200 and resp.json().get("value"):
            return [resp.json()["value"][0]]

    current_name = blueprint_display_name(scope)
    resp = graph_request(
        "GET",
        f"/applications?$filter=displayName eq '{odata_escape(current_name)}'",
        token,
    )
    if resp.status_code == 200:
        return [
            app for app in resp.json().get("value", [])
            if app.get("displayName") == current_name
        ]
    return []


def derive_sp_name_from_fic_name(fic_display_name, scope):
    if scope.mode == "scoped":
        prefix = f"aim-fic-{scope.scope_key}-"
        if fic_display_name.startswith(prefix):
            return f"aim-{scope.scope_key}-{fic_display_name[len(prefix):]}"
    else:
        prefix = "aim-fic-"
        if fic_display_name.startswith(prefix):
            return f"aim-{fic_display_name[len(prefix):]}"
    return None


def collect_current_env_sp_targets(token, scope, blueprint_apps):
    app_ids = set()
    display_names = set(agent_identity_display_name(agent, scope) for agent in AGENTS)
    azd_values = load_azd_env_values()

    for key, value in azd_values.items():
        if key.startswith("ENTRA_AGENT_ID_") and value:
            app_ids.add(value)

    for app in blueprint_apps:
        obj_id = app.get("id")
        if not obj_id:
            continue
        fic_resp = graph_request(
            "GET",
            f"/applications/{obj_id}/federatedIdentityCredentials",
            token,
        )
        if fic_resp.status_code != 200:
            continue
        for fic in fic_resp.json().get("value", []):
            derived_name = derive_sp_name_from_fic_name(fic.get("name", ""), scope)
            if derived_name:
                display_names.add(derived_name)

    return app_ids, display_names


def find_target_service_principals(token, scope, all_envs=False, blueprint_apps=None):
    targets = {}
    if all_envs:
        resp = graph_request(
            "GET",
            "/servicePrincipals?$filter=startswith(displayName,'aim-')",
            token,
        )
        if resp.status_code == 200:
            for sp in resp.json().get("value", []):
                targets[sp["id"]] = sp
        return list(targets.values())

    if scope.mode == "scoped":
        prefix = f"aim-{scope.scope_key}-"
        resp = graph_request(
            "GET",
            f"/servicePrincipals?$filter=startswith(displayName,'{odata_escape(prefix)}')",
            token,
        )
        if resp.status_code == 200:
            for sp in resp.json().get("value", []):
                targets[sp["id"]] = sp
        return list(targets.values())

    blueprint_apps = blueprint_apps or []
    app_ids, display_names = collect_current_env_sp_targets(token, scope, blueprint_apps)
    for app_id in app_ids:
        resp = graph_request(
            "GET",
            f"/servicePrincipals?$filter=appId eq '{odata_escape(app_id)}'",
            token,
        )
        if resp.status_code == 200:
            for sp in resp.json().get("value", []):
                targets[sp["id"]] = sp
    for display_name in display_names:
        resp = graph_request(
            "GET",
            f"/servicePrincipals?$filter=displayName eq '{odata_escape(display_name)}'",
            token,
        )
        if resp.status_code == 200:
            for sp in resp.json().get("value", []):
                if sp.get("displayName") == display_name:
                    targets[sp["id"]] = sp
    return list(targets.values())


def delete_service_principals(token, service_principals):
    print("\n--- Deleting Agent Identity Service Principals ---\n")
    deleted = 0
    if not service_principals:
        print("  No matching Agent Identity service principals found")
        return deleted
    for sp in service_principals:
        display_name = sp.get("displayName", "<unknown>")
        sp_id = sp["id"]
        print(f"  [{display_name}] Deleting SP {sp_id}...")
        resp = graph_request("DELETE", f"/servicePrincipals/{sp_id}", token)
        if resp.status_code in (200, 204):
            print(f"  [{display_name}] Deleted OK")
            deleted += 1
        else:
            print(f"  [{display_name}] DELETE failed: {resp.status_code} {resp.text[:200]}")
    return deleted


def delete_blueprints(token, blueprint_apps):
    print("\n--- Deleting Agent Identity Blueprints ---\n")
    if not blueprint_apps:
        print("  No matching blueprint applications found")
        return True

    ok = True
    for app in blueprint_apps:
        app_id = app["appId"]
        obj_id = app["id"]
        display_name = app.get("displayName", "<unknown>")
        print(f"  Found blueprint: {display_name} (appId={app_id}, objectId={obj_id})")

        sp_resp = graph_request(
            "GET",
            f"/servicePrincipals?$filter=appId eq '{odata_escape(app_id)}'",
            token,
        )
        if sp_resp.status_code == 200:
            for sp in sp_resp.json().get("value", []):
                sp_id = sp["id"]
                print(f"  Deleting blueprint SP {sp_id}...")
                del_sp = graph_request("DELETE", f"/servicePrincipals/{sp_id}", token)
                if del_sp.status_code in (200, 204):
                    print("  Blueprint SP deleted OK")
                else:
                    print(f"  Blueprint SP delete failed: {del_sp.status_code} {del_sp.text[:200]}")
                    ok = False

        print(f"  Deleting blueprint application {obj_id}...")
        del_resp = graph_request("DELETE", f"/applications/{obj_id}", token)
        if del_resp.status_code in (200, 204):
            print("  Blueprint application deleted OK")
        else:
            print(f"  Blueprint delete failed: {del_resp.status_code} {del_resp.text[:200]}")
            ok = False
    return ok


def clear_azd_env_vars():
    print("\n--- Clearing current azd env variables ---\n")
    azd_values = load_azd_env_values()
    for key in sorted(azd_values):
        if (
            key in STATIC_ENV_KEYS
            or key.startswith("ENTRA_AGENT_ID_")
            or key.startswith("MI_CLIENT_ID_")
            or key.startswith("ENTRA_FIC_CREATED_")
        ):
            set_azd_env(key, "")
            print(f"  Cleared: {key}")


def verify_cleanup(token, scope, all_envs=False):
    print("\n--- Verifying Cleanup ---\n")
    issues = []

    if all_envs:
        resp = graph_request(
            "GET",
            "/servicePrincipals?$filter=startswith(displayName,'aim-')",
            token,
        )
        if resp.status_code == 200 and resp.json().get("value"):
            for sp in resp.json()["value"]:
                issues.append(f"  ORPHANED SP: {sp['displayName']} (id={sp['id']})")

        resp = graph_request(
            "GET",
            f"/applications?$filter=startswith(displayName,'{odata_escape(BLUEPRINT_PREFIX)}')",
            token,
        )
        if resp.status_code == 200 and resp.json().get("value"):
            for app in resp.json()["value"]:
                issues.append(f"  ORPHANED BLUEPRINT: {app['displayName']} (id={app['id']})")
    else:
        blueprint_apps = find_blueprint_applications(token, scope, all_envs=False)
        if blueprint_apps:
            for app in blueprint_apps:
                issues.append(f"  ORPHANED BLUEPRINT: {app['displayName']} (id={app['id']})")

        service_principals = find_target_service_principals(
            token,
            scope,
            all_envs=False,
            blueprint_apps=blueprint_apps,
        )
        if service_principals:
            for sp in service_principals:
                issues.append(f"  ORPHANED SP: {sp['displayName']} (id={sp['id']})")

    if issues:
        print("\n  ISSUES FOUND:")
        for issue in issues:
            print(issue)
        return False

    print("  No matching Agent Identity objects remain")
    return True


def print_preflight(scope, all_envs=False):
    print("\nScope preflight:")
    print(f"  AIM_ENV_SCOPE_MODE: {scope.mode} ({scope.mode_source})")
    print(f"  AIM_ENV_SCOPE_KEY:  {scope.scope_key} ({scope.key_source})")
    if all_envs:
        print("  Target: ALL AIM Agent Identity objects across all environments")
        print(f"  Blueprints: displayName startswith '{BLUEPRINT_PREFIX}'")
        print("  Service principals: displayName startswith 'aim-'")
        return

    print(f"  Blueprint:          {blueprint_display_name(scope)}")
    for agent in AGENTS:
        print(f"  Agent Identity [{agent}]: {agent_identity_display_name(agent, scope)}")
    for agent in ("budget-report", "budget-approval", "employee-menus"):
        print(f"  FIC [{agent}]: {fic_name(agent, scope)}")


def main():
    args = parse_args()

    print("=" * 50)
    print("  Entra Agent Identity Cleanup")
    print("=" * 50)

    try:
        scope = resolve_scope(env_get=get_azd_env, env_set=set_azd_env)
    except ScopeResolutionError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    print_preflight(scope, all_envs=args.all_envs)

    try:
        print("\nGetting provisioner token...")
        token = get_provisioner_graph_token(
            build_required_permission_values(include_ca=True)
        )
        print("  Token acquired")
    except ProvisionerBootstrapError as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)

    blueprint_apps = find_blueprint_applications(token, scope, all_envs=args.all_envs)
    service_principals = find_target_service_principals(
        token,
        scope,
        all_envs=args.all_envs,
        blueprint_apps=blueprint_apps,
    )

    delete_service_principals(token, service_principals)
    delete_blueprints(token, blueprint_apps)
    clear_azd_env_vars()

    print("\nWaiting 10s for Graph propagation...")
    time.sleep(10)

    clean = verify_cleanup(token, scope, all_envs=args.all_envs)
    if not clean:
        print("\nWARNING: Some matching resources remain!")
        sys.exit(1)

    print("\nCleanup complete!")


if __name__ == "__main__":
    main()
