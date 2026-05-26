#!/usr/bin/env python3
"""
create-custom-attributes.py
============================
Provisions Custom Security Attributes on Entra Agent Identity service
principals and creates a Conditional Access policy that blocks high-risk agents.

This makes Layer 4 (admin governance) REAL — the enforcement tags come
from Entra's directory, not hardcoded YAML values.

What it does:
  1. Creates attribute set "AgentIdentity" (if not exists)
  2. Creates attribute "Department" with allowed values (Finance, HR, etc.)
  3. Assigns "Department = Finance" to BudgetReport + BudgetApproval SPs
  4. Leaves EmployeeMenus untagged (blocked by tag mismatch)
  5. Creates a CA policy blocking high-risk agents (state: enabled)
  6. Stores attribute metadata in azd env for deploy.sh

Usage:
    python3 scripts/create-custom-attributes.py

Prerequisites:
    - az login with Attribute Definition Administrator + Attribute Assignment
      Administrator roles
    - CustomSecAttributeDefinition.ReadWrite.All permission
    - CustomSecAttributeAssignment.ReadWrite.All permission
    - Application.Read.All permission
    - Policy.ReadWrite.ConditionalAccess permission (for CA policy creation)
    - Organization.Read.All permission (for licensing/SKU detection)
"""
import json
import os
import subprocess
import sys
import time

from entra_provisioning import (
    CA_PERMISSION_VALUES,
    ProvisionerBootstrapError,
    build_required_permission_values,
    get_azd_env,
    get_graph_token as get_provisioner_graph_token,
    set_azd_env,
    verify_graph_preflight,
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

ATTRIBUTE_SET_ID = "AgentIdentity"
ATTRIBUTE_SET_DESCRIPTION = "Custom security attributes for Identity Research for Agent Management Using SPIFFE agent identity governance"
ATTRIBUTE_NAME = "Department"
ATTRIBUTE_DESCRIPTION = "Department the agent is authorized for"
ALLOWED_VALUES = ["Finance", "HR", "IT", "Operations"]

# Agent → tag mapping. Agents not listed get no tag (blocked by tag mismatch).
AGENT_TAGS = {
    "budget-report":        "Finance",
    "budget-approval":      "Finance",
    "budget-backend":       "Finance",
    "employee-menus":       "HR",
    "admin-control-plane":  "Operations",
}

# The CA schema/policy stays shared tenant-wide. Parallel environment isolation
# comes from env-scoped Agent Identity service principals, not per-env CA names.
CA_POLICY_NAME = "Identity Research for Agent Management Using SPIFFE: Block agents based on risk"
OLD_CA_POLICY_NAME = "Identity Research for Agent Management Using SPIFFE: Block non-Finance agents from Budget Backend"
ATTRIBUTE_DEFINITION_ID = f"{ATTRIBUTE_SET_ID}_{ATTRIBUTE_NAME}"


def run_az(args):
    """Run az CLI command, return (rc, stdout, stderr)."""
    result = subprocess.run(["az"] + args, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def get_graph_token():
    """Get a Graph API token via the dedicated provisioner app."""
    try:
        return get_provisioner_graph_token(build_required_permission_values(include_ca=True))
    except ProvisionerBootstrapError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)


def graph_request(method, url, token, json_body=None, expect_404=False):
    """Make a Graph API request using az rest."""
    args = ["rest", "--method", method, "--url", url,
            "--headers", f"Authorization=Bearer {token}",
            "Content-Type=application/json",
            "ConsistencyLevel=eventual"]
    if json_body:
        args += ["--body", json.dumps(json_body)]
    rc, out, err = run_az(args)
    if rc != 0:
        err_lower = err.lower()
        if expect_404 and ("404" in err or "not found" in err_lower or "request_resourcenotfound" in err_lower):
            return None
        if "already exists" in err_lower or "conflict" in err_lower:
            return {"already_exists": True}
        print(f"  Graph API error ({method} {url}): {err}")
        return None
    if out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"raw": out}
    return {}


def get_sp_object_id(entra_agent_id, token):
    """Look up the service principal object ID from the Entra Agent ID.

    The agent identity might be registered as a service principal or
    accessible via the agentIdentityBlueprintPrincipals endpoint.
    """
    # Try direct SP lookup first
    resp = graph_request("GET",
        f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{entra_agent_id}'&$select=id,displayName",
        token, expect_404=True)
    if resp and resp.get("value"):
        return resp["value"][0]["id"]

    # Try by object ID directly (Entra Agent IDs are often object IDs)
    resp = graph_request("GET",
        f"{GRAPH_BASE}/servicePrincipals/{entra_agent_id}?$select=id,displayName",
        token, expect_404=True)
    if resp and resp.get("id"):
        return resp["id"]

    return None


# ─────────────────────────────────────────────────────────────────────
# Step 1: Create Attribute Set
# ─────────────────────────────────────────────────────────────────────

def create_attribute_set(token):
    """Create the AgentIdentity attribute set if it doesn't exist."""
    print("\n─── Step 1: Create Attribute Set ───")

    # Check if it already exists
    resp = graph_request("GET",
        f"{GRAPH_BASE}/directory/attributeSets/{ATTRIBUTE_SET_ID}",
        token, expect_404=True)
    if resp and resp.get("id"):
        print(f"  ✓ Attribute set '{ATTRIBUTE_SET_ID}' already exists")
        return True

    resp = graph_request("POST",
        f"{GRAPH_BASE}/directory/attributeSets",
        token,
        json_body={
            "id": ATTRIBUTE_SET_ID,
            "description": ATTRIBUTE_SET_DESCRIPTION,
            "maxAttributesPerSet": 25,
        })
    if resp and (resp.get("id") or resp.get("already_exists")):
        print(f"  ✓ Created attribute set '{ATTRIBUTE_SET_ID}'")
        return True
    else:
        print(f"  ✗ Failed to create attribute set")
        return False


# ─────────────────────────────────────────────────────────────────────
# Step 2: Create Attribute Definition
# ─────────────────────────────────────────────────────────────────────

def create_attribute_definition(token):
    """Create the Department attribute with predefined allowed values."""
    print("\n─── Step 2: Create Attribute Definition ───")

    resp = graph_request("GET",
        f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions/{ATTRIBUTE_DEFINITION_ID}",
        token, expect_404=True)
    if resp and resp.get("id"):
        print(f"  ✓ Attribute '{ATTRIBUTE_DEFINITION_ID}' already exists")
        return True

    request_body = {
        "attributeSet": ATTRIBUTE_SET_ID,
        "description": ATTRIBUTE_DESCRIPTION,
        "isCollection": False,
        "isSearchable": True,
        "name": ATTRIBUTE_NAME,
        "status": "Available",
        "type": "String",
        "usePreDefinedValuesOnly": True,
    }
    resp = None
    for attempt in range(5):
        resp = graph_request(
            "POST",
            f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions",
            token,
            json_body=request_body,
        )
        if resp is not None:
            break
        if attempt < 4:
            wait = 3 * (attempt + 1)
            print(f"  Attribute set not visible yet, retrying definition create in {wait}s...")
            time.sleep(wait)
    if resp is None:
        print(f"  ✗ Failed to create attribute definition")
        return False

    print(f"  ✓ Created attribute '{ATTRIBUTE_SET_ID}.{ATTRIBUTE_NAME}'")
    return True


def wait_for_attribute_definition(token):
    """Wait for the attribute definition to become readable by ID."""
    for attempt in range(6):
        check = graph_request(
            "GET",
            f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions/{ATTRIBUTE_DEFINITION_ID}",
            token,
            expect_404=True,
        )
        if check and check.get("id"):
            return True
        if attempt < 5:
            wait = 2 * (attempt + 1)
            print(f"  Waiting {wait}s for attribute definition propagation...")
            time.sleep(wait)
    return False


def get_allowed_values(token):
    """Return current allowed values as {value_id: isActive}."""
    resp = graph_request(
        "GET",
        f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions/{ATTRIBUTE_DEFINITION_ID}/allowedValues",
        token,
        expect_404=True,
    )
    if not resp or "value" not in resp:
        return {}
    values = {}
    for item in resp.get("value", []):
        val_id = item.get("id")
        if val_id:
            values[val_id] = bool(item.get("isActive"))
    return values


def ensure_allowed_values(token):
    """Create and verify all required predefined values."""
    print("\n─── Step 2.5: Ensure Allowed Values ───")

    if not wait_for_attribute_definition(token):
        print("  ✗ Attribute definition did not become readable after creation")
        return False

    for val in ALLOWED_VALUES:
        current_values = get_allowed_values(token)
        if current_values.get(val):
            print(f"     Allowed value present: {val}")
            continue

        created = False
        for attempt in range(5):
            resp = graph_request(
                "POST",
                f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions/{ATTRIBUTE_DEFINITION_ID}/allowedValues",
                token,
                json_body={"id": val, "isActive": True},
            )
            current_values = get_allowed_values(token)
            if resp is not None and current_values.get(val):
                print(f"     Added allowed value: {val}")
                created = True
                break
            if current_values.get(val):
                print(f"     Allowed value became visible: {val}")
                created = True
                break
            if attempt < 4:
                wait = 3 * (attempt + 1)
                print(f"     Allowed value '{val}' not ready yet, retrying in {wait}s...")
                time.sleep(wait)
        if not created:
            print(f"     ✗ Required allowed value missing: {val}")
            return False

    final_values = get_allowed_values(token)
    missing = [val for val in ALLOWED_VALUES if not final_values.get(val)]
    if missing:
        print(f"  ✗ Missing required allowed values after repair: {', '.join(missing)}")
        return False

    print("  ✓ All required allowed values are active")
    return True


# ─────────────────────────────────────────────────────────────────────
# Step 3: Assign Attributes to Service Principals
# ─────────────────────────────────────────────────────────────────────

def assign_attributes(token):
    """Assign Department tag to each agent's service principal."""
    print("\n─── Step 3: Assign Custom Security Attributes to Agents ───")

    agents = {
        "budget-report":   "ENTRA_AGENT_ID_BUDGET_REPORT",
        "budget-backend":  "ENTRA_AGENT_ID_BUDGET_BACKEND",
        "employee-menus":  "ENTRA_AGENT_ID_EMPLOYEE_MENUS",
        "budget-approval": "ENTRA_AGENT_ID_BUDGET_APPROVAL",
    }

    results = {}
    for agent_name, env_key in agents.items():
        entra_id = get_azd_env(env_key)
        if not entra_id:
            print(f"  ⚠ {agent_name}: No Entra Agent ID found ({env_key}), skipping")
            continue

        sp_id = get_sp_object_id(entra_id, token)
        if not sp_id:
            print(f"  ⚠ {agent_name}: Could not find service principal for {entra_id}")
            # Use the entra_id directly as it might be the SP object ID
            sp_id = entra_id

        tag = AGENT_TAGS.get(agent_name)
        if tag:
            # Assign the tag
            resp = None
            for attempt in range(5):
                resp = graph_request("PATCH",
                    f"{GRAPH_BASE}/servicePrincipals/{sp_id}",
                    token,
                    json_body={
                        "customSecurityAttributes": {
                            ATTRIBUTE_SET_ID: {
                                "@odata.type": "#Microsoft.DirectoryServices.CustomSecurityAttributeValue",
                                ATTRIBUTE_NAME: tag,
                            }
                        }
                    })
                if resp is not None:
                    break
                if attempt < 4:
                    wait = 3 * (attempt + 1)
                    print(f"  … {agent_name}: attribute assignment not ready yet, retrying in {wait}s")
                    time.sleep(wait)
            if resp is not None:
                print(f"  ✓ {agent_name}: {ATTRIBUTE_SET_ID}.{ATTRIBUTE_NAME} = {tag}")
                results[agent_name] = tag
            else:
                print(f"  ✗ {agent_name}: Failed to assign attribute")
        else:
            print(f"  ○ {agent_name}: Intentionally untagged (will be blocked by tag mismatch)")
            results[agent_name] = None

    return results


# ─────────────────────────────────────────────────────────────────────
# Step 4: Read Back and Verify Attributes
# ─────────────────────────────────────────────────────────────────────

def verify_attributes(token):
    """Read custom security attributes back from each SP to confirm."""
    print("\n─── Step 4: Verify Attributes ───")

    agents = {
        "budget-report":        "ENTRA_AGENT_ID_BUDGET_REPORT",
        "budget-backend":       "ENTRA_AGENT_ID_BUDGET_BACKEND",
        "employee-menus":       "ENTRA_AGENT_ID_EMPLOYEE_MENUS",
        "budget-approval":      "ENTRA_AGENT_ID_BUDGET_APPROVAL",
        "admin-control-plane":  "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE",
    }

    verified = {}
    for agent_name, env_key in agents.items():
        entra_id = get_azd_env(env_key)
        if not entra_id:
            continue

        sp_id = get_sp_object_id(entra_id, token)
        if not sp_id:
            sp_id = entra_id

        resp = graph_request("GET",
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}?$select=id,displayName,customSecurityAttributes",
            token, expect_404=True)
        if resp and resp.get("customSecurityAttributes"):
            attrs = resp["customSecurityAttributes"]
            agent_attrs = attrs.get(ATTRIBUTE_SET_ID, {})
            dept = agent_attrs.get(ATTRIBUTE_NAME, "(not set)")
            print(f"  ✓ {agent_name}: {ATTRIBUTE_SET_ID}.{ATTRIBUTE_NAME} = {dept}")
            verified[agent_name] = dept
        elif resp and not resp.get("customSecurityAttributes"):
            print(f"  ○ {agent_name}: No custom security attributes (expected for EmployeeMenus)")
            verified[agent_name] = None
        else:
            print(f"  ⚠ {agent_name}: Could not read attributes")

    return verified


# ─────────────────────────────────────────────────────────────────────
# Step 5: Create Conditional Access Policy
# ─────────────────────────────────────────────────────────────────────

def check_ca_licensing(token):
    """Check if the tenant has a SKU that supports CA risk-based policies.

    Queries subscribedSkus and looks for Entra ID P2, Workload Identities
    Premium, or M365 Copilot + Frontier enrollment.  Prints a warning if
    no qualifying SKU is found.  Returns True if a qualifying SKU was
    detected, False otherwise.  Never blocks — the POST may still succeed
    under preview programmes.
    """
    qualifying_plan_keywords = [
        "aad_premium_p2",
        "workload_identities_premium",
        "microsoft_365_copilot",
        "m365_copilot",
        "entra_id_governance",
    ]

    resp = graph_request("GET",
        f"{GRAPH_BASE}/subscribedSkus?$select=skuPartNumber,servicePlans",
        token, expect_404=True)
    if not resp or "value" not in resp:
        print("  ⚠ Could not query tenant SKUs (Organization.Read.All may be missing).")
        print("    Risk-based CA policies require Entra ID P2, Workload Identities Premium")
        print("    ($3/workload/month), or M365 Copilot + Frontier enrolment.")
        return False

    for sku in resp.get("value", []):
        sku_part = (sku.get("skuPartNumber") or "").lower()
        for kw in qualifying_plan_keywords:
            if kw in sku_part:
                print(f"  ✓ Qualifying SKU detected: {sku.get('skuPartNumber')}")
                return True
        for plan in sku.get("servicePlans", []):
            plan_name = (plan.get("servicePlanName") or "").lower()
            for kw in qualifying_plan_keywords:
                if kw in plan_name:
                    print(f"  ✓ Qualifying service plan detected: {plan.get('servicePlanName')}")
                    return True

    print("  ⚠ No qualifying SKU found for CA risk-based policies.")
    print("    Risk-based CA policies require Entra ID P2, Workload Identities Premium")
    print("    ($3/workload/month), or M365 Copilot + Frontier enrolment.")
    print("    Policy creation will be attempted but may fail.")
    return False


def _cleanup_old_ca_policy(token):
    """Delete the old Finance-scoped CA policy if it exists."""
    resp = graph_request("GET",
        f"{GRAPH_BETA}/identity/conditionalAccess/policies"
        f"?$filter=displayName eq '{OLD_CA_POLICY_NAME}'",
        token)
    if resp and resp.get("value"):
        for old_policy in resp["value"]:
            old_id = old_policy.get("id")
            if old_id:
                del_resp = graph_request("DELETE",
                    f"{GRAPH_BETA}/identity/conditionalAccess/policies/{old_id}",
                    token)
                if del_resp is not None:
                    print(f"  ✓ Deleted old CA policy '{OLD_CA_POLICY_NAME}' (ID: {old_id})")
                else:
                    print(f"  ⚠ Could not delete old CA policy (ID: {old_id}), may need manual cleanup")


def create_ca_policy(token):
    """Create a CA policy that blocks all high-risk agent identities.

    This policy targets ALL agent identities (no applicationFilter) and
    blocks token issuance when the agent's risk level is high.  It replaces
    the earlier Finance-scoped policy.
    """
    print("\n─── Step 5: Create Conditional Access Policy ───")

    # Check licensing first (warn only, do not block)
    check_ca_licensing(token)

    # Clean up the old Finance-scoped policy if it exists
    _cleanup_old_ca_policy(token)

    # Check if the new policy already exists
    resp = graph_request("GET",
        f"{GRAPH_BETA}/identity/conditionalAccess/policies"
        f"?$filter=displayName eq '{CA_POLICY_NAME}'",
        token)
    if resp and resp.get("value"):
        existing = resp["value"]
        if len(existing) > 0:
            policy_id = existing[0]["id"]
            print(f"  ✓ CA policy already exists (ID: {policy_id})")
            set_azd_env("CA_POLICY_ID", policy_id)
            return policy_id

    # Risk-only policy: block ALL high-risk agent identities.
    # No applicationFilter — scopes to all agents, not just Finance-tagged ones.
    # Uses beta endpoint for agentIdRiskLevels + clientApplications.
    # Schema matches the documented "Block all high risk agents" sample from
    # docs/platform-learnings/Conditional-Access-Learnings.md — only fields
    # that the agent identity CA surface recognises are included.
    policy_body = {
        "displayName": CA_POLICY_NAME,
        "state": "enabled",
        "conditions": {
            "clientAppTypes": ["all"],
            "agentIdRiskLevels": "high",
            "applications": {
                "includeApplications": ["All"],
            },
            "users": {
                "includeUsers": ["None"],
            },
            "clientApplications": {
                "includeAgentIdServicePrincipals": ["All"],
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    }

    resp = graph_request("POST",
        f"{GRAPH_BETA}/identity/conditionalAccess/policies",
        token, json_body=policy_body)
    if resp and resp.get("id"):
        policy_id = resp["id"]
        print(f"  ✓ Created CA policy (ID: {policy_id})")
        print(f"    Name:  {CA_POLICY_NAME}")
        print(f"    State: enabled (On)")
        print(f"    Risk:  blocks high-risk agents")
        set_azd_env("CA_POLICY_ID", policy_id)
        return policy_id
    else:
        print(f"  ✗ Failed to create CA policy")
        print(f"    This usually means the tenant lacks the required licensing.")
        print(f"    Risk-based CA policies require Entra ID P2, Workload Identities")
        print(f"    Premium ($3/workload/month), or M365 Copilot + Frontier enrolment.")
        return None


def require_real_ca():
    value = os.environ.get("REQUIRE_REAL_CA", "true").strip().lower()
    return value not in ("0", "false", "no")


def mark_ca_mode(mode):
    set_azd_env("CA_PROVISIONING_MODE", mode)
    set_azd_env("CA_ATTRIBUTE_SET", ATTRIBUTE_SET_ID)
    set_azd_env("CA_ATTRIBUTE_NAME", ATTRIBUTE_NAME)
    set_azd_env("CA_ATTRIBUTE_DEFINITION_ID", ATTRIBUTE_DEFINITION_ID)


def run_preflight_checks(token):
    print("\n─── Preflight: Verify Graph access for real CA provisioning ───")
    checks = [
        ("attribute_sets", "GET", f"{GRAPH_BASE}/directory/attributeSets"),
        ("attribute_definition", "GET", f"{GRAPH_BASE}/directory/customSecurityAttributeDefinitions?$top=1"),
        ("conditional_access", "GET", f"{GRAPH_BASE}/identity/conditionalAccess/policies?$top=1"),
    ]
    failures = verify_graph_preflight(token, checks)
    if not failures:
        print("  ✓ Graph access checks passed")
        return True
    for name, status, detail in failures:
        print(f"  ✗ {name}: HTTP {status}")
        if detail:
            print(f"    {detail}")
    return False


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 66)
    print("  Identity Research for Agent Management Using SPIFFE — Custom Security Attribute Provisioning")
    print("  Real Entra attributes for Layer 4 (CA) enforcement")
    print("=" * 66)
    strict_real_ca = require_real_ca()
    print(f"\n  REQUIRE_REAL_CA={'true' if strict_real_ca else 'false'}")

    token = get_graph_token()
    print(f"\n  Graph API token acquired")

    if not run_preflight_checks(token):
        mark_ca_mode("fallback")
        if strict_real_ca:
            print("\nERROR: Real CA provisioning is required, but Graph preflight failed.")
            print("  If the signed-in operator cannot grant the needed rights, ask an Entra")
            print("  administrator to grant the provisioner app access before rerunning deploy.")
            return 1
        print("\nWARNING: Graph preflight failed. Continuing in fallback mode because REQUIRE_REAL_CA=false.")
        return 0

    # Step 1: Create attribute set
    if not create_attribute_set(token):
        mark_ca_mode("fallback")
        print("\nERROR: Cannot proceed without attribute set.")
        print("  Ensure you have the Attribute Definition Administrator role.")
        return 1 if strict_real_ca else 0

    # Step 2: Create attribute definition
    if not create_attribute_definition(token):
        mark_ca_mode("fallback")
        print("\nERROR: Cannot proceed without attribute definition.")
        return 1 if strict_real_ca else 0

    if not ensure_allowed_values(token):
        mark_ca_mode("fallback")
        print("\nERROR: Cannot proceed without the required allowed values.")
        return 1 if strict_real_ca else 0

    # Small delay for propagation
    print("\n  Waiting 3s for attribute propagation...")
    time.sleep(3)

    # Step 3: Assign attributes to SPs
    results = assign_attributes(token)

    # Step 4: Verify
    time.sleep(2)
    verified = verify_attributes(token)

    # Step 5: Create CA policy
    ca_policy_id = create_ca_policy(token)
    if strict_real_ca and not ca_policy_id:
        mark_ca_mode("fallback")
        print("\nERROR: Real CA provisioning is required, but CA policy creation failed.")
        print("  This usually means the tenant is missing licensing or the provisioner app")
        print("  still lacks Conditional Access permissions.")
        return 1

    mark_ca_mode("real" if ca_policy_id else "fallback")

    # Summary
    print("\n" + "=" * 66)
    print("  Summary")
    print("=" * 66)
    tag_counts = {}
    untagged = 0
    for v in verified.values():
        if v and v != "(not set)":
            tag_counts[v] = tag_counts.get(v, 0) + 1
        elif v is None:
            untagged += 1
    tagged = sum(tag_counts.values())
    tag_breakdown = ", ".join(f"{count} {tag}" for tag, count in sorted(tag_counts.items()))
    print(f"  Attribute set:   {ATTRIBUTE_SET_ID}")
    print(f"  Attribute name:  {ATTRIBUTE_NAME}")
    print(f"  Agents tagged:   {tagged} ({tag_breakdown})")
    print(f"  Agents untagged: {untagged} (blocked by tag mismatch)")
    if ca_policy_id:
        print(f"  CA policy:       {CA_POLICY_NAME}")
        print(f"  CA policy ID:    {ca_policy_id}")
        print(f"  CA state:        enabled (On)")
        print(f"  CA risk level:   high (blocked)")
    else:
        print(f"  CA policy:       Not created")
    print(f"\n  These are REAL Entra custom security attributes.")
    print(f"  The sidecar reads them from Graph API at startup.")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
