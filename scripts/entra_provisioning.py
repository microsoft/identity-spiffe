#!/usr/bin/env python3
"""
Shared helpers for Entra Graph provisioning.

This module centralizes the dedicated provisioner app registration used for:
  - Agent Blueprint and Agent ID creation
  - custom security attribute definition and assignment
  - Conditional Access policy provisioning
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

MS_GRAPH_API_ID = "00000003-0000-0000-c000-000000000000"
PROVISIONER_APP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Agent ID Provisioner"

BASE_PERMISSION_VALUES = [
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
]

AGENT_ID_PERMISSION_MATCHERS = [
    "AgentIdentity",
]

CA_PERMISSION_VALUES = [
    "Application.Read.All",
    "CustomSecAttributeAssignment.ReadWrite.All",
    "CustomSecAttributeDefinition.ReadWrite.All",
    "IdentityRiskyAgent.Read.All",
    "IdentityRiskyAgent.ReadWrite.All",
    "Organization.Read.All",
    "Policy.Read.All",
    "Policy.ReadWrite.ConditionalAccess",
]

REQUIRED_DIRECTORY_ROLE_NAMES = [
    "Attribute Definition Reader",
]


class ProvisionerBootstrapError(RuntimeError):
    """Raised when the provisioner app cannot be created or consented."""


def _client_secret_credential():
    try:
        from azure.identity import ClientSecretCredential
    except ImportError as exc:
        raise ProvisionerBootstrapError(
            "azure-identity is required. Install with 'pip install azure-identity'."
        ) from exc
    return ClientSecretCredential


def run_az(args, capture=True):
    result = subprocess.run(["az"] + args, capture_output=capture, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def load_azd_env():
    env_dir = Path(".azure")
    if not env_dir.exists():
        return None

    config = env_dir / "config.json"
    if not config.exists():
        return None

    try:
        with open(config, encoding="utf-8") as f:
            env_name = json.load(f).get("defaultEnvironment", "")
    except (OSError, json.JSONDecodeError):
        return None

    env_file = env_dir / env_name / ".env"
    if not env_file.exists():
        return env_name

    with open(env_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip('"').strip("'"))
    return env_name


def get_azd_env(key):
    result = subprocess.run(["azd", "env", "get-values"], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip('"')
    return None


def set_azd_env(key, value):
    result = subprocess.run(["azd", "env", "set", key, value], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  WARNING: Failed to store {key} in azd env: {result.stderr.strip()}")


def get_signed_in_user_id():
    rc, out, _ = run_az(["ad", "signed-in-user", "show", "--query", "id", "-o", "tsv"])
    if rc == 0 and out:
        return out
    return None


def build_sponsors_bind():
    user_id = get_signed_in_user_id()
    if user_id:
        return [f"https://graph.microsoft.com/beta/users/{user_id}"]
    return []


def print_admin_required(action, err=""):
    print(f"  ERROR: The signed-in operator could not {action}.")
    print("  This bootstrap step requires an Entra administrator with permission to")
    print("  create/update app registrations and grant Microsoft Graph admin consent.")
    print("  Ask an administrator to complete the setup, then rerun deploy.")
    if err:
        print(f"  Details: {err}")


def application_exists(client_id):
    rc, _, _ = run_az(["ad", "app", "show", "--id", client_id], capture=True)
    return rc == 0


def ensure_service_principal(client_id):
    rc, _, _ = run_az(["ad", "sp", "show", "--id", client_id], capture=True)
    if rc == 0:
        return
    rc, _, err = run_az(["ad", "sp", "create", "--id", client_id])
    if rc != 0 and "already exists" not in err.lower():
        raise ProvisionerBootstrapError(err or "service principal creation failed")


def _load_graph_app_roles():
    rc, out, err = run_az([
        "ad", "sp", "show", "--id", MS_GRAPH_API_ID,
        "--query", "appRoles[].{id:id,value:value}",
        "-o", "json",
    ])
    if rc != 0 or not out:
        raise ProvisionerBootstrapError(err or "could not query Microsoft Graph app roles")
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise ProvisionerBootstrapError(f"failed to parse Graph role list: {exc}") from exc


def resolve_graph_permissions():
    roles = _load_graph_app_roles()
    permission_map = {}
    for role in roles:
        value = role.get("value")
        role_id = role.get("id")
        if value and role_id:
            permission_map[value] = role_id
    return permission_map


def graph_rest(method, url, json_body=None):
    args = [
        "rest",
        "--method", method,
        "--url", url,
        "--headers", "Content-Type=application/json",
    ]
    if json_body is not None:
        args += ["--body", json.dumps(json_body)]
    return run_az(args)


def get_service_principal_object_id(client_id):
    rc, out, err = run_az(["ad", "sp", "show", "--id", client_id, "--query", "id", "-o", "tsv"])
    if rc != 0 or not out:
        raise ProvisionerBootstrapError(err or f"could not resolve service principal for app {client_id}")
    return out


def resolve_directory_role_ids(required_names):
    rc, out, err = graph_rest(
        "GET",
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName",
    )
    if rc != 0 or not out:
        raise ProvisionerBootstrapError(err or "could not query Entra directory roles")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ProvisionerBootstrapError(f"failed to parse directory role definitions: {exc}") from exc

    role_map = {
        item.get("displayName"): item.get("id")
        for item in data.get("value", [])
        if item.get("displayName") and item.get("id")
    }
    missing = [name for name in required_names if name not in role_map]
    if missing:
        raise ProvisionerBootstrapError(
            "missing Entra directory roles in tenant: " + ", ".join(sorted(missing))
        )
    return {name: role_map[name] for name in required_names}


def get_existing_directory_role_assignments(principal_id):
    rc, out, err = graph_rest(
        "GET",
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        "?$select=id,principalId,roleDefinitionId,directoryScopeId",
    )
    if rc != 0 or not out:
        raise ProvisionerBootstrapError(err or "could not query Entra directory role assignments")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ProvisionerBootstrapError(f"failed to parse directory role assignments: {exc}") from exc
    return {
        item.get("roleDefinitionId")
        for item in data.get("value", [])
        if item.get("principalId") == principal_id and item.get("directoryScopeId") == "/"
    }


def ensure_directory_roles(client_id, role_names):
    if not role_names:
        return

    principal_id = get_service_principal_object_id(client_id)
    role_ids = resolve_directory_role_ids(role_names)
    existing_role_ids = get_existing_directory_role_assignments(principal_id)

    missing_role_names = [name for name, role_id in role_ids.items() if role_id not in existing_role_ids]
    if not missing_role_names:
        print("  Provisioner service principal already has the required Entra directory roles")
        return

    print(f"  Ensuring {len(missing_role_names)} Entra directory role assignments on provisioner service principal...")
    for role_name in missing_role_names:
        body = {
            "principalId": principal_id,
            "roleDefinitionId": role_ids[role_name],
            "directoryScopeId": "/",
        }
        rc, _, err = graph_rest(
            "POST",
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
            json_body=body,
        )
        if rc != 0:
            lowered = (err or "").lower()
            if "already exists" in lowered or "conflict" in lowered:
                continue
            if any(term in lowered for term in ["insufficient", "authorization", "privilege", "denied", "admin"]):
                print_admin_required(
                    f"assign the '{role_name}' Entra directory role to the provisioner service principal",
                    err,
                )
            raise ProvisionerBootstrapError(err or f"failed to assign directory role {role_name}")
        print(f"  Assigned Entra directory role: {role_name}")


def build_required_permission_values(include_ca=True):
    required = list(BASE_PERMISSION_VALUES)
    graph_permissions = resolve_graph_permissions()
    for value in sorted(graph_permissions):
        if any(matcher in value for matcher in AGENT_ID_PERMISSION_MATCHERS):
            required.append(value)
    if include_ca:
        required.extend(CA_PERMISSION_VALUES)
    deduped = []
    for value in required:
        if value not in deduped:
            deduped.append(value)
    return deduped


def resolve_permission_specs(required_values):
    permission_map = resolve_graph_permissions()
    specs = []
    missing = []
    for value in required_values:
        role_id = permission_map.get(value)
        if role_id:
            specs.append((value, f"{role_id}=Role"))
        else:
            missing.append(value)
    if missing:
        raise ProvisionerBootstrapError(
            "missing Microsoft Graph application permissions in tenant: " + ", ".join(sorted(missing))
        )
    return specs


def get_existing_graph_permission_role_ids(client_id):
    rc, out, err = run_az([
        "ad", "app", "show",
        "--id", client_id,
        "--query", "requiredResourceAccess[?resourceAppId=='00000003-0000-0000-c000-000000000000'].resourceAccess[].id",
        "-o", "json",
    ])
    if rc != 0 or not out:
        if err:
            raise ProvisionerBootstrapError(err)
        return set()
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ProvisionerBootstrapError(f"failed to parse existing app permissions: {exc}") from exc
    return {item for item in data if item}


def ensure_permissions_and_consent(client_id, required_values):
    ensure_service_principal(client_id)

    permission_specs = resolve_permission_specs(required_values)
    existing_role_ids = get_existing_graph_permission_role_ids(client_id)
    missing_specs = [spec for _, spec in permission_specs if spec.split("=", 1)[0] not in existing_role_ids]
    print(f"  Ensuring {len(permission_specs)} Graph application permissions on provisioner app...")

    if missing_specs:
        cmd = [
            "ad", "app", "permission", "add",
            "--id", client_id,
            "--api", MS_GRAPH_API_ID,
            "--api-permissions",
        ] + missing_specs
        rc, _, err = run_az(cmd)
        if rc != 0 and "already exists" not in err.lower():
            if "insufficient" in err.lower() or "authorization" in err.lower() or "privilege" in err.lower():
                print_admin_required("add the required Microsoft Graph application permissions", err)
            raise ProvisionerBootstrapError(err or "permission add failed")
    else:
        print("  Provisioner app already has the required Graph permissions")

    print("  Granting admin consent for provisioner app...")
    consent_error = ""
    for attempt in range(4):
        if attempt:
            wait = 10 * (attempt + 1)
            print(f"  Retrying admin consent in {wait}s (attempt {attempt + 1}/4)...")
            time.sleep(wait)
        rc, _, err = run_az(["ad", "app", "permission", "admin-consent", "--id", client_id])
        if rc == 0:
            print("  Admin consent granted")
            return
        consent_error = err

    lowered = consent_error.lower()
    if any(term in lowered for term in ["insufficient", "authorization", "privilege", "admin"]):
        print_admin_required("grant admin consent for the provisioner app", consent_error)
    raise ProvisionerBootstrapError(consent_error or "admin consent failed")


def ensure_app_registration(required_values, wait_for_propagation=True):
    load_azd_env()

    client_id = os.environ.get("ENTRA_AGENTID_CLIENT_ID") or get_azd_env("ENTRA_AGENTID_CLIENT_ID")
    client_secret = os.environ.get("ENTRA_AGENTID_CLIENT_SECRET") or get_azd_env("ENTRA_AGENTID_CLIENT_SECRET")
    tenant_id = os.environ.get("AZURE_TENANT_ID") or get_azd_env("AZURE_TENANT_ID")

    if not tenant_id:
        rc, out, err = run_az(["account", "show", "--query", "tenantId", "-o", "tsv"])
        if rc != 0 or not out:
            raise ProvisionerBootstrapError(err or "cannot determine tenant ID; run 'az login' first")
        tenant_id = out
        set_azd_env("AZURE_TENANT_ID", tenant_id)

    if client_id and not application_exists(client_id):
        print(f"  Cached provisioner app is stale: {client_id}")
        client_id = None
        client_secret = None
        set_azd_env("ENTRA_AGENTID_CLIENT_ID", "")
        set_azd_env("ENTRA_AGENTID_CLIENT_SECRET", "")

    if not client_id:
        rc, out, err = run_az([
            "ad", "app", "list",
            "--display-name", PROVISIONER_APP_DISPLAY_NAME,
            "--query", "[0].appId",
            "-o", "tsv",
        ])
        if rc == 0 and out:
            client_id = out
            print(f"  Found existing provisioner app: {client_id}")
            set_azd_env("ENTRA_AGENTID_CLIENT_ID", client_id)
        else:
            print("  Creating dedicated Entra provisioner app registration...")
            rc, out, err = run_az([
                "ad", "app", "create",
                "--display-name", PROVISIONER_APP_DISPLAY_NAME,
                "--sign-in-audience", "AzureADMyOrg",
                "--query", "appId",
                "-o", "tsv",
            ])
            if rc != 0 or not out:
                if any(term in (err or "").lower() for term in ["insufficient", "authorization", "privilege", "permission"]):
                    print_admin_required("create the dedicated provisioner app registration", err)
                raise ProvisionerBootstrapError(err or "app registration creation failed")
            client_id = out
            print(f"  Created provisioner app: {client_id}")
            set_azd_env("ENTRA_AGENTID_CLIENT_ID", client_id)

    ensure_permissions_and_consent(client_id, required_values)
    ensure_directory_roles(client_id, REQUIRED_DIRECTORY_ROLE_NAMES)

    if not client_secret:
        print("  Creating provisioner app client secret...")
        rc, out, err = run_az([
            "ad", "app", "credential", "reset",
            "--id", client_id,
            "--append",
            "--years", "1",
            "--query", "password",
            "-o", "tsv",
        ])
        if rc != 0 or not out:
            if any(term in (err or "").lower() for term in ["insufficient", "authorization", "privilege", "permission"]):
                print_admin_required("create a client secret on the provisioner app", err)
            raise ProvisionerBootstrapError(err or "client secret creation failed")
        client_secret = out
        set_azd_env("ENTRA_AGENTID_CLIENT_SECRET", client_secret)
        print("  Stored provisioner app secret in azd env")

    if wait_for_propagation:
        print("  Waiting 30s for Graph permission propagation...")
        time.sleep(30)
    return client_id, client_secret, tenant_id


def get_graph_token(required_values=None, wait_for_propagation=True):
    if required_values is None:
        required_values = build_required_permission_values(include_ca=True)
    client_id, client_secret, tenant_id = ensure_app_registration(
        required_values,
        wait_for_propagation=wait_for_propagation,
    )
    credential_cls = _client_secret_credential()
    credential = credential_cls(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    return credential.get_token("https://graph.microsoft.com/.default").token


def verify_graph_preflight(token, checks):
    import requests

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    failures = []
    for name, method, url in checks:
        resp = requests.request(method, url, headers=headers)
        if resp.status_code in (200, 204):
            continue
        failures.append((name, resp.status_code, resp.text[:300]))
    return failures


def bootstrap_cli():
    try:
        required_values = build_required_permission_values(include_ca=True)
        client_id, _, tenant_id = ensure_app_registration(required_values)
        print("")
        print("Provisioner bootstrap complete")
        print(f"  Tenant:      {tenant_id}")
        print(f"  Client ID:   {client_id}")
        print(f"  Permissions: {', '.join(required_values)}")
        return 0
    except ProvisionerBootstrapError as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(bootstrap_cli())
