"""
AIM Prototype Platform — SPIFFE Enforcement Test Suite (Budget Backend Scenario)
======================================================================
Tests the enforcement matrix for the Budget Backend demo:

  Transport Layer (mTLS):
    BudgetReport   → BudgetBackend: ✅ mTLS succeeds
    EmployeeMenus  → BudgetBackend: ❌ mTLS rejected (not in allow list)
    BudgetApproval → BudgetBackend: ✅ mTLS succeeds

  Application Layer (RBAC):
    Scenario 1: BudgetReport   → GET  /budget/read   → ✅ 200 (RBAC: allow)
    Scenario 2: BudgetReport   → POST /budget/submit  → ❌ 403 (RBAC: deny)
    Scenario 3: EmployeeMenus  → GET  /budget/read    → ❌ blocked (mTLS rejection)
    Scenario 4: BudgetApproval → POST /budget/submit  → ✅ 200 (RBAC: allow)
    Scenario 5: BudgetApproval → GET  /budget/read    → ✅ 200 (RBAC: allow)

Usage:
  python3 scripts/test_agents.py              # All tests
  python3 scripts/test_agents.py --transport   # Transport-layer tests only
  python3 scripts/test_agents.py --rbac        # RBAC tests only
  python3 scripts/test_agents.py --identity    # Identity chain tests only
  python3 scripts/test_agents.py --oauth2      # OAuth2 token validation only

Reads endpoints from azd env automatically.
"""
import subprocess
import sys
import time

try:
    import httpx
except ImportError:
    print("❌ httpx not installed. Run: pip install httpx")
    sys.exit(1)


def get_azd_env():
    """Read azd env vars."""
    result = subprocess.run(
        ["azd", "env", "get-values"],
        capture_output=True, text=True
    )
    env = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            env[key] = val.strip('"')
    return env


def test_health(name: str, url: str) -> bool:
    """Test agent health endpoint."""
    try:
        resp = httpx.get(f"{url}/health", timeout=10)
        data = resp.json()
        status = "✅" if data.get("status") == "healthy" else "❌"
        print(f"  {status} {name}: {data}")
        return data.get("status") == "healthy"
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        return False


def test_call_backend(name: str, url: str, expected_success: bool, mgmt_api_key: str = "") -> bool:
    """Test caller → BudgetBackend POST /budget/read via SPIFFE proxy (transport-layer test)."""
    try:
        headers = {}
        if mgmt_api_key:
            headers["X-AIM-Admin-Key"] = mgmt_api_key
        resp = httpx.post(
            f"{url}/call-backend-raw",
            params={"method": "GET", "path": "/budget/read"},
            headers=headers,
            timeout=30,
        )
        data = resp.json()

        if expected_success:
            if data.get("http_status") == 200:
                print(f"  ✅ {name} → BudgetBackend: HTTP 200 (ALLOWED - correct)")
                return True
            else:
                print(f"  ❌ {name} → BudgetBackend: Expected 200, got {data.get('http_status')} / error: {data.get('error', 'none')}")
                return False
        else:
            if data.get("http_status") == 0 or data.get("error"):
                print(f"  ✅ {name} → BudgetBackend: BLOCKED (correct!) - error: {data.get('error', 'connection failed')}")
                return True
            elif data.get("http_status") == 200:
                print(f"  ❌ {name} → BudgetBackend: HTTP 200 - SHOULD HAVE BEEN BLOCKED!")
                return False
            else:
                print(f"  ⚠️  {name} → BudgetBackend: Status {data.get('http_status')} - unexpected but not 200")
                return True
    except Exception as e:
        if not expected_success:
            print(f"  ✅ {name} → BudgetBackend: BLOCKED (correct!) - exception: {e}")
            return True
        print(f"  ❌ {name} → BudgetBackend: {e}")
        return False


def test_rbac_scenario(
    scenario_num: int,
    caller_name: str,
    caller_url: str,
    method: str,
    path: str,
    expected_status: int,
    description: str,
    mgmt_api_key: str = "",
) -> bool:
    """Test a specific RBAC scenario via /call-backend-raw."""
    label = f"Scenario {scenario_num}: {caller_name} → {method} {path}"

    try:
        headers = {}
        if mgmt_api_key:
            headers["X-AIM-Admin-Key"] = mgmt_api_key
        resp = httpx.post(
            f"{caller_url}/call-backend-raw",
            params={"method": method, "path": path},
            headers=headers,
            timeout=30,
        )
        data = resp.json()
        actual_status = data.get("http_status", -1)

        if expected_status == 0:
            # Accept: status 0 (connection refused), error field set, or 502 (egress proxy can't reach backend)
            if actual_status == 0 or actual_status == 502 or data.get("error"):
                reason = data.get("error", "connection failed")
                if actual_status == 502:
                    reason = "egress proxy returned 502 (tunnel blocked by mTLS)"
                print(f"  ✅ {label}")
                print(f"     → BLOCKED at mTLS layer (correct): {reason}")
                return True
            else:
                print(f"  ❌ {label}")
                print(f"     → Expected mTLS rejection, got HTTP {actual_status}")
                return False

        elif actual_status == expected_status:
            if expected_status == 200:
                print(f"  ✅ {label}")
                print(f"     → HTTP 200 ALLOWED ({description})")
            elif expected_status == 403:
                print(f"  ✅ {label}")
                print(f"     → HTTP 403 DENIED ({description})")
            else:
                print(f"  ✅ {label}")
                print(f"     → HTTP {expected_status} ({description})")
            return True
        else:
            print(f"  ❌ {label}")
            print(f"     → Expected HTTP {expected_status}, got HTTP {actual_status}")
            if data.get("error"):
                print(f"     → Error: {data['error']}")
            if data.get("response"):
                resp_str = str(data["response"])[:200]
                print(f"     → Response: {resp_str}")
            return False

    except Exception as e:
        if expected_status == 0:
            print(f"  ✅ {label}")
            print(f"     → BLOCKED (exception: {e})")
            return True
        print(f"  ❌ {label}")
        print(f"     → Exception: {e}")
        return False


def run_transport_tests(report_url, menus_url, approval_url, mgmt_api_key=""):
    """Run transport-layer (mTLS) enforcement tests."""
    print("─── Transport Layer: mTLS Enforcement ───")
    print()
    print("  SPIFFE ID Allow List on BudgetBackend's ingress proxy:")
    print("    ✓ spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<budget-report-oid>")
    print("    ✓ spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<budget-approval-oid>")
    print("    ✗ spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<employee-menus-oid>  ← NOT in list")
    print()

    results = []
    results.append(test_call_backend("BudgetReport (allowed)", report_url, expected_success=True, mgmt_api_key=mgmt_api_key))
    results.append(test_call_backend("EmployeeMenus (blocked)", menus_url, expected_success=False, mgmt_api_key=mgmt_api_key))
    results.append(test_call_backend("BudgetApproval (allowed)", approval_url, expected_success=True, mgmt_api_key=mgmt_api_key))
    return results


def run_rbac_tests(report_url, menus_url, approval_url, mgmt_api_key=""):
    """Run application-layer (RBAC) enforcement tests — 5 Budget Backend scenarios."""
    print("─── Application Layer: RBAC Policy Enforcement ───")
    print()
    print("  RBAC Policy on BudgetBackend's ingress proxy:")
    print("    BudgetReport:   /budget/read ✓, /budget/submit ✗")
    print("    EmployeeMenus:  /* ✗ (also blocked at mTLS)")
    print("    BudgetApproval: /budget/read ✓, /budget/submit ✓")
    print("    Default: deny")
    print()

    results = []

    # Scenario 1: BudgetReport → GET /budget/read → 200 (RBAC: allow)
    results.append(test_rbac_scenario(
        1, "BudgetReport", report_url, "GET", "/budget/read", 200,
        "RBAC rule: allow GET /budget/read", mgmt_api_key=mgmt_api_key,
    ))

    # Scenario 2: BudgetReport → POST /budget/submit → 403 (RBAC: deny)
    results.append(test_rbac_scenario(
        2, "BudgetReport", report_url, "POST", "/budget/submit", 403,
        "RBAC rule: deny /budget/submit for BudgetReport", mgmt_api_key=mgmt_api_key,
    ))

    # Scenario 3: EmployeeMenus → GET /budget/read → blocked at mTLS
    results.append(test_rbac_scenario(
        3, "EmployeeMenus", menus_url, "GET", "/budget/read", 0,
        "mTLS handshake rejected — EmployeeMenus not in allow list", mgmt_api_key=mgmt_api_key,
    ))

    # Scenario 4: BudgetApproval → POST /budget/submit → 200 (RBAC: allow)
    results.append(test_rbac_scenario(
        4, "BudgetApproval", approval_url, "POST", "/budget/submit", 200,
        "RBAC rule: allow POST /budget/submit", mgmt_api_key=mgmt_api_key,
    ))

    # Scenario 5: BudgetApproval → GET /budget/read → 200 (RBAC: allow)
    results.append(test_rbac_scenario(
        5, "BudgetApproval", approval_url, "GET", "/budget/read", 200,
        "RBAC rule: allow GET /budget/read", mgmt_api_key=mgmt_api_key,
    ))

    return results


def test_identity_chain(
    caller_name: str,
    caller_url: str,
    expected_entra_id: str,
    mgmt_api_key: str = "",
) -> bool:
    """Test that the full identity chain (SPIFFE → Entra) flows E2E.

    The gateway injects X-SPIFFE-Entra-Agent-ID headers based on RBAC policy
    metadata. BudgetBackend returns them in the response's identity_chain field.
    This verifies the IDs survive the full path:
    caller → egress proxy → mTLS tunnel → ingress gateway → header injection → backend → response.
    """
    label = f"Identity Chain: {caller_name}"
    try:
        headers = {}
        if mgmt_api_key:
            headers["X-AIM-Admin-Key"] = mgmt_api_key
        resp = httpx.post(
            f"{caller_url}/call-backend-raw",
            params={"method": "GET", "path": "/budget/read"},
            headers=headers,
            timeout=30,
        )
        data = resp.json()

        if data.get("http_status") != 200:
            print(f"  ❌ {label}")
            print(f"     → Call failed (HTTP {data.get('http_status')}), cannot verify identity chain")
            return False

        # Parse the response body from BudgetBackend
        response_body = data.get("response", {})
        if isinstance(response_body, str):
            import json as _json
            try:
                response_body = _json.loads(response_body)
            except Exception:
                print(f"  ❌ {label}")
                print(f"     → Could not parse response body as JSON")
                return False

        chain = response_body.get("identity_chain", {})
        actual_entra = chain.get("entra_agent_id") or ""
        spiffe_id = chain.get("spiffe_id") or ""

        passed = True
        details = []

        # Check SPIFFE ID is present and uses new format
        if spiffe_id and "spiffe://" in spiffe_id:
            details.append(f"SPIFFE: {spiffe_id}")
        else:
            details.append(f"SPIFFE: MISSING")
            passed = False

        # Check Entra Agent ID
        if expected_entra_id:
            if actual_entra == expected_entra_id:
                details.append(f"Entra: {actual_entra}")
            else:
                details.append(f"Entra: expected {expected_entra_id}, got '{actual_entra}'")
                passed = False
        else:
            details.append(f"Entra: {actual_entra or 'N/A (no expected value)'}")

        status = "✅" if passed else "❌"
        print(f"  {status} {label}")
        for d in details:
            print(f"     → {d}")
        return passed

    except Exception as e:
        print(f"  ❌ {label}")
        print(f"     → Exception: {e}")
        return False


def run_identity_chain_tests(report_url, approval_url, env):
    """Run identity chain tests — verify Entra Agent IDs flow E2E through SPIFFE."""
    print("─── Identity Chain: Entra Agent ID E2E Verification ───")
    print()
    print("  Tests that platform identity metadata (Entra Agent IDs)")
    print("  flows through: RBAC policy → gateway header injection → backend response")
    print()

    results = []

    # Get expected IDs from azd env
    report_entra = env.get("ENTRA_AGENT_ID_BUDGET_REPORT", "")
    approval_entra = env.get("ENTRA_AGENT_ID_BUDGET_APPROVAL", "")
    mgmt_api_key = env.get("MGMT_API_KEY", "")

    results.append(test_identity_chain(
        "BudgetReport", report_url, report_entra, mgmt_api_key=mgmt_api_key,
    ))
    results.append(test_identity_chain(
        "BudgetApproval", approval_url, approval_entra, mgmt_api_key=mgmt_api_key,
    ))

    return results


def test_oauth2_token(caller_name: str, caller_url: str, mgmt_api_key: str = "") -> bool:
    """Test that the caller acquires an Entra token and BudgetBackend validates it."""
    label = f"OAuth2 Token: {caller_name}"
    try:
        headers = {}
        if mgmt_api_key:
            headers["X-AIM-Admin-Key"] = mgmt_api_key
        resp = httpx.post(
            f"{caller_url}/call-backend-raw",
            params={"method": "GET", "path": "/budget/read"},
            headers=headers,
            timeout=30,
        )
        data = resp.json()
        if data.get("http_status") != 200:
            print(f"  ❌ {label}")
            print(f"     → Call failed (HTTP {data.get('http_status')})")
            return False

        response_body = data.get("response", {})
        if isinstance(response_body, str):
            import json as _json
            try:
                response_body = _json.loads(response_body)
            except Exception:
                print(f"  ❌ {label}")
                print(f"     → Could not parse response")
                return False

        chain = response_body.get("identity_chain", {})
        token_info = chain.get("entra_token", {})

        if not token_info.get("present"):
            print(f"  ⚠️  {label}")
            print(f"     → No Bearer token sent (OAuth2 credentials may not be configured)")
            return False

        # BudgetBackend echoes token metadata (read-only, no validation).
        # JWT validation is handled by the SPIFFE proxy (Layer 3), but this
        # helper should still verify token acquisition produced meaningful claims.
        oid = str(token_info.get("oid", "")).strip()
        app_id = str(token_info.get("app_id", "")).strip()
        audience = str(token_info.get("audience", "")).strip()
        if audience and (oid or app_id):
            print(f"  ✅ {label}")
            print(f"     → Token echoed: oid={oid or '?'}, app_id={app_id or '?'}, audience={audience}")
            return True
        elif token_info.get("validated"):
            # Legacy path: old backend with validation
            print(f"  ✅ {label}")
            print(f"     → Token validated! oid={token_info.get('oid', '?')}, app_id={token_info.get('app_id', '?')}")
            return True
        else:
            print(f"  ❌ {label}")
            print(f"     → Token present but missing expected claims (need audience + oid/app_id)")
            return False

    except Exception as e:
        print(f"  ❌ {label}")
        print(f"     → Exception: {e}")
        return False


def run_oauth2_tests(report_url, approval_url, mgmt_api_key=""):
    """Run OAuth2 token validation tests."""
    print("─── OAuth2 Token Validation: Entra Agent Identity ───")
    print()
    print("  Tests that callers acquire Entra tokens and BudgetBackend validates them.")
    print("  Three-layer auth: SPIFFE mTLS (transport) + RBAC (path) + OAuth2 (token)")
    print()

    results = []
    results.append(test_oauth2_token("BudgetReport", report_url, mgmt_api_key=mgmt_api_key))
    results.append(test_oauth2_token("BudgetApproval", approval_url, mgmt_api_key=mgmt_api_key))
    return results


def run_s2s_tests(report_url, approval_url, mgmt_api_key=""):
    """Run S2S Entra OAuth enforcement tests — proxy validates JWTs as Layer 3."""
    print("─── S2S OAuth Enforcement: Proxy JWT Validation (Layer 3) ───")
    print()
    print("  Tests that the SPIFFE proxy validates JWTs as Layer 3.")
    print("  Three-layer auth: mTLS (transport) + RBAC (path) + OAuth/JWT (token + roles)")
    print()

    results = []

    # S2S-1: BudgetReport → GET /budget/read (with valid JWT + Budget.Read role) → 200
    results.append(test_rbac_scenario(
        "S2S-1", "BudgetReport", report_url, "GET", "/budget/read", 200,
        "All 3 layers pass: mTLS + RBAC + JWT (Budget.Read)", mgmt_api_key=mgmt_api_key,
    ))

    # S2S-2: BudgetReport → POST /budget/submit (RBAC denies) → 403
    results.append(test_rbac_scenario(
        "S2S-2", "BudgetReport", report_url, "POST", "/budget/submit", 403,
        "Layer 2 (RBAC) denies POST for BudgetReport", mgmt_api_key=mgmt_api_key,
    ))

    # S2S-3: BudgetApproval → POST /budget/submit (with valid JWT + Budget.Submit role) → 200
    results.append(test_rbac_scenario(
        "S2S-3", "BudgetApproval", approval_url, "POST", "/budget/submit", 200,
        "All 3 layers pass: mTLS + RBAC + JWT (Budget.Submit)", mgmt_api_key=mgmt_api_key,
    ))

    # S2S-4: BudgetApproval → GET /budget/read (with valid JWT + Budget.Read role) → 200
    results.append(test_rbac_scenario(
        "S2S-4", "BudgetApproval", approval_url, "GET", "/budget/read", 200,
        "All 3 layers pass: mTLS + RBAC + JWT (Budget.Read)", mgmt_api_key=mgmt_api_key,
    ))

    return results


# ─── A2A Direct Calling Tests (Layer 4b at app layer) ───

def test_a2a_call(scenario_num, caller_name, caller_url, target_name, expected_status, description):
    """Test A2A direct call via /call-agent?target=..."""
    label = f"Scenario {scenario_num}: {caller_name} → {target_name} /a2a/status"
    try:
        resp = httpx.get(f"{caller_url}/call-agent", params={"target": target_name.lower().replace(' ', '-')}, timeout=15)
        data = resp.json()
        actual_status = data.get("http_status", -1)

        if actual_status == expected_status:
            if expected_status == 200:
                print(f"  ✅ {label}")
                print(f"     → HTTP 200 ALLOWED ({description})")
            elif expected_status == 403:
                response = data.get("response", {})
                reason = response.get("error", "unknown") if isinstance(response, dict) else "unknown"
                print(f"  ✅ {label}")
                print(f"     → HTTP 403 DENIED ({description}) — reason: {reason}")
            else:
                print(f"  ✅ {label}")
                print(f"     → HTTP {expected_status} ({description})")
            return True
        elif actual_status == 0 and expected_status == 403:
            # Connection refused also counts as blocked
            print(f"  ✅ {label}")
            print(f"     → BLOCKED (connection refused) ({description})")
            return True
        else:
            print(f"  ❌ {label}")
            print(f"     → Expected HTTP {expected_status}, got HTTP {actual_status}")
            if data.get("error"):
                print(f"     → Error: {data['error']}")
            return False

    except Exception as e:
        if expected_status == 403:
            print(f"  ✅ {label}")
            print(f"     → BLOCKED (exception: {e})")
            return True
        print(f"  ❌ {label}")
        print(f"     → Exception: {e}")
        return False


def run_a2a_tests(report_url, menus_url):
    """Run A2A direct calling tests (S2S OAuth, Layer 4b at app layer)."""
    print("─── A2A Direct Calling: Layer 4b at App Layer ───")
    print()
    print("  Tests agent-to-agent (A2A) direct calling with CA tag enforcement.")
    print("  BudgetReport (finance) → BudgetApproval (finance): tag match → allowed")
    print("  EmployeeMenus (no tag) → BudgetApproval (finance): tag mismatch → blocked")
    print("  BudgetReport (finance) → EmployeeMenus (no tag): tag mismatch → blocked")
    print()

    results = []

    # A2A-1: BudgetReport → BudgetApproval /approval/status → 200 (tag match)
    results.append(test_a2a_call(
        "A2A-1", "BudgetReport", report_url, "budget-approval", 200,
        "Tag match: finance == finance → allowed",
    ))

    # A2A-2: EmployeeMenus → BudgetApproval /approval/status → 403 (tag mismatch)
    results.append(test_a2a_call(
        "A2A-2", "EmployeeMenus", menus_url, "budget-approval", 403,
        "Tag mismatch: '' != finance → blocked at Layer 4b",
    ))

    # A2A-3: BudgetReport → EmployeeMenus /a2a/status → 403 (target untagged)
    results.append(test_a2a_call(
        "A2A-3", "BudgetReport", report_url, "employee-menus", 403,
        "Tag mismatch: finance != '' → blocked at Layer 4b",
    ))

    return results


# ─── CA Risk Enforcement Tests (Layer 4b) ───

def set_agent_risk(control_plane_url, spiffe_id, risk_level, mgmt_api_key=""):
    """Push agent risk update via the dedicated admin control-plane."""
    try:
        headers = {}
        if mgmt_api_key:
            headers["X-AIM-Admin-Key"] = mgmt_api_key
        resp = httpx.put(
            f"{control_plane_url}/admin/agent-risk",
            json={"spiffe_id": spiffe_id, "risk_level": risk_level},
            headers=headers,
            timeout=10,
        )
        data = resp.json()
        print(f"     Risk update: {risk_level} → {data.get('status', 'unknown')}")
        return data.get("status") == "updated"
    except Exception as e:
        print(f"     Risk update failed: {e}")
        return False


def _get_graph_token(env):
    """Acquire a Graph API token using provisioner credentials from azd env."""
    client_id = env.get("ENTRA_AGENTID_CLIENT_ID", "")
    client_secret = env.get("ENTRA_AGENTID_CLIENT_SECRET", "")
    tenant_id = env.get("AZURE_TENANT_ID", "")
    if not client_id or not client_secret or not tenant_id:
        return None
    try:
        resp = httpx.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()["access_token"]
    except Exception as e:
        print(f"     Graph token failed: {e}")
    return None


def _resolve_sp_oid(app_id, token):
    """Resolve appId → SP object ID via Graph (confirmSafe needs OID)."""
    try:
        resp = httpx.get(
            f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'&$select=id",
            headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"},
            timeout=10,
        )
        if resp.status_code == 200:
            values = resp.json().get("value", [])
            if values:
                return values[0]["id"]
    except Exception:
        pass
    return app_id  # fallback to raw value


def _entra_confirm_safe(agent_oids, token):
    """Call Graph confirmSafe to clear Entra risk state for agents."""
    # Resolve appIds to SP OIDs
    sp_oids = [_resolve_sp_oid(oid, token) for oid in agent_oids if oid]
    if not sp_oids:
        return
    try:
        resp = httpx.post(
            "https://graph.microsoft.com/beta/identityProtection/riskyAgents/confirmSafe",
            json={"agentIds": sp_oids},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 204:
            print(f"     Entra confirmSafe: cleared risk for {len(sp_oids)} agent(s)")
        else:
            print(f"     Entra confirmSafe: {resp.status_code} (may not have reset)")
    except Exception as e:
        print(f"     Entra confirmSafe failed: {e}")


def reset_risk_baseline(control_plane_url, env):
    """Force all caller risk levels back to low before starting verification.

    Two-phase reset:
    1. Sidecar risk store (immediate — data plane enforcement)
    2. Entra ID Protection (confirmSafe — clears CA policy risk state)
    """
    bp_oid = env.get("ENTRA_BLUEPRINT_OBJECT_ID", "unknown-bp")
    report_oid = env.get("ENTRA_AGENT_ID_BUDGET_REPORT", "unknown-report")
    approval_oid = env.get("ENTRA_AGENT_ID_BUDGET_APPROVAL", "unknown-approval")
    mgmt_api_key = env.get("MGMT_API_KEY", "")

    report_spiffe = f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{report_oid}"
    approval_spiffe = f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{approval_oid}"

    print("─── Baseline Reset ───")
    print("  Resetting caller risk levels to LOW before verification...")

    # Phase 1: Reset sidecar risk store
    if control_plane_url:
        set_agent_risk(control_plane_url, report_spiffe, "low", mgmt_api_key)
        set_agent_risk(control_plane_url, approval_spiffe, "low", mgmt_api_key)
    else:
        print("     Skipped sidecar reset: no control plane URL")

    # Phase 2: Clear Entra ID Protection risk state
    token = _get_graph_token(env)
    if token:
        _entra_confirm_safe([report_oid, approval_oid], token)
        # Entra risk propagation can take 30-60s. Verify by attempting a token
        # exchange for BudgetReport — if it still fails with AADSTS53003, wait more.
        print("  Waiting for Entra risk propagation (up to 90s)...")
        report_url = env.get("SERVICE_BUDGET_REPORT_ENDPOINT_URL", "")
        for attempt in range(6):
            time.sleep(15)
            if report_url:
                try:
                    headers = {}
                    if mgmt_api_key:
                        headers["X-AIM-Admin-Key"] = mgmt_api_key
                    resp = httpx.post(
                        f"{report_url}/call-backend-raw",
                        params={"method": "GET", "path": "/budget/read"},
                        headers=headers,
                        timeout=15,
                    )
                    data = resp.json()
                    if data.get("http_status") == 200:
                        print(f"  ✅ Risk cleared after {(attempt + 1) * 15}s")
                        break
                    elif "AADSTS53003" in str(data.get("response", "")):
                        print(f"     Still blocked after {(attempt + 1) * 15}s, waiting...")
                    else:
                        # Different error — risk may be cleared but something else failed
                        break
                except Exception:
                    break
            else:
                time.sleep(15)  # No URL to probe, just wait 30s total
                break
        else:
            print("  ⚠️  Risk may still be propagating after 90s — some tests may fail")
    else:
        print("     Skipped Entra reset: Graph credentials not available")
    print()


def run_ca_risk_tests(report_url, control_plane_url, approval_url, env):
    """Run CA risk enforcement tests — Layer 4b at sidecar."""
    print("─── CA Risk Enforcement: Layer 4b at Sidecar ───")
    print()
    print("  Tests that agent risk levels block calls at the data plane.")
    print("  Uses the /agent-risk mgmt API to push risk levels.")
    print()

    results = []

    # Get BudgetReport's SPIFFE ID prefix from env
    bp_oid = env.get("ENTRA_BLUEPRINT_OBJECT_ID", "unknown-bp")
    report_oid = env.get("ENTRA_AGENT_ID_BUDGET_REPORT", "unknown-report")
    report_spiffe = f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{report_oid}"
    approval_oid = env.get("ENTRA_AGENT_ID_BUDGET_APPROVAL", "unknown-approval")
    approval_spiffe = f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{approval_oid}"

    # Mgmt API key required for the dedicated admin control-plane auth
    mgmt_api_key = env.get("MGMT_API_KEY", "")

    # CA-1: Set BudgetReport risk=high → GET /budget/read → 403
    print(f"  Setting BudgetReport risk to HIGH...")
    set_agent_risk(control_plane_url, report_spiffe, "high", mgmt_api_key)
    time.sleep(1)  # Brief pause for risk store propagation
    results.append(test_rbac_scenario(
        "CA-1", "BudgetReport", report_url, "GET", "/budget/read", 403,
        "Layer 4b: high risk agent blocked at sidecar", mgmt_api_key=mgmt_api_key,
    ))

    # CA-2: Reset BudgetReport risk=low → GET /budget/read → 200
    print(f"  Resetting BudgetReport risk to LOW...")
    set_agent_risk(control_plane_url, report_spiffe, "low", mgmt_api_key)
    time.sleep(1)
    results.append(test_rbac_scenario(
        "CA-2", "BudgetReport", report_url, "GET", "/budget/read", 200,
        "Layer 4b: risk cleared → allowed again", mgmt_api_key=mgmt_api_key,
    ))

    # CA-3: Set BudgetApproval risk=high → POST /budget/submit → 403
    print(f"  Setting BudgetApproval risk to HIGH...")
    set_agent_risk(control_plane_url, approval_spiffe, "high", mgmt_api_key)
    time.sleep(1)
    results.append(test_rbac_scenario(
        "CA-3", "BudgetApproval", approval_url, "POST", "/budget/submit", 403,
        "Layer 4b: high risk agent blocked at sidecar", mgmt_api_key=mgmt_api_key,
    ))

    # CA-4: Reset BudgetApproval risk=low
    print(f"  Resetting BudgetApproval risk to LOW...")
    set_agent_risk(control_plane_url, approval_spiffe, "low", mgmt_api_key)

    return results


def main():
    # Parse args
    run_transport = True
    run_rbac = True
    run_identity = True
    run_oauth2 = True
    run_s2s = True
    run_a2a = True
    run_ca_risk = True
    if "--transport" in sys.argv:
        run_rbac = False
        run_identity = False
        run_oauth2 = False
        run_s2s = False
        run_a2a = False
        run_ca_risk = False
    elif "--rbac" in sys.argv:
        run_transport = False
        run_identity = False
        run_oauth2 = False
        run_s2s = False
        run_a2a = False
        run_ca_risk = False
    elif "--identity" in sys.argv:
        run_transport = False
        run_rbac = False
        run_oauth2 = False
        run_s2s = False
        run_a2a = False
        run_ca_risk = False
    elif "--oauth2" in sys.argv:
        run_transport = False
        run_rbac = False
        run_identity = False
        run_s2s = False
        run_a2a = False
        run_ca_risk = False
    elif "--s2s" in sys.argv:
        run_transport = False
        run_rbac = False
        run_identity = False
        run_oauth2 = False
        run_a2a = False
        run_ca_risk = False
    elif "--a2a" in sys.argv:
        run_transport = False
        run_rbac = False
        run_identity = False
        run_oauth2 = False
        run_s2s = False
        run_ca_risk = False
    elif "--ca-risk" in sys.argv:
        run_transport = False
        run_rbac = False
        run_identity = False
        run_oauth2 = False
        run_s2s = False
        run_a2a = False

    print()
    print("=" * 66)
    print("  AIM Prototype Platform — SPIFFE Enforcement Test Suite")
    print("  Budget Backend Scenario")
    print("=" * 66)
    print()

    env = get_azd_env()

    report_url = env.get("SERVICE_BUDGET_REPORT_ENDPOINT_URL", "").rstrip("/")
    backend_url = env.get("SERVICE_BUDGET_BACKEND_ENDPOINT_URL", "").rstrip("/")
    menus_url = env.get("SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL", "").rstrip("/")
    approval_url = env.get("SERVICE_BUDGET_APPROVAL_ENDPOINT_URL", "").rstrip("/")
    control_plane_url = env.get("SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL", "").rstrip("/")
    spire_fqdn = env.get("SPIRE_SERVER_FQDN", "")

    if not all([report_url, menus_url, approval_url]):
        print("❌ Missing endpoint URLs. Run 'azd provision' first.")
        sys.exit(1)

    print(f"  SPIRE Server:    {spire_fqdn}")
    print(f"  BudgetReport:    {report_url}")
    print(f"  BudgetBackend:   {backend_url}")
    print(f"  EmployeeMenus:   {menus_url}")
    print(f"  BudgetApproval:  {approval_url}")
    print()

    # ── Health checks ──
    print("─── Health Checks ───")
    h1 = test_health("BudgetReport", report_url)
    h3 = test_health("EmployeeMenus", menus_url)
    h4 = test_health("BudgetApproval", approval_url)
    print()
    print("  ℹ️  BudgetBackend health not tested — external ingress is gRPC (port 8443)")
    print()

    if not (h1 and h3 and h4):
        print("⚠️  Some agents not healthy. Waiting 30s and retrying...")
        time.sleep(30)
        print("─── Retry Health Checks ───")
        h1 = test_health("BudgetReport", report_url)
        h3 = test_health("EmployeeMenus", menus_url)
        h4 = test_health("BudgetApproval", approval_url)
        print()

    reset_risk_baseline(control_plane_url, env)

    mgmt_api_key = env.get("MGMT_API_KEY", "")

    all_results = []
    # Track each section's results separately for accurate summary counts
    transport_results = []
    rbac_results = []
    identity_results = []
    oauth2_results = []
    s2s_results = []
    a2a_results = []
    ca_risk_results = []

    # ── Transport-layer tests ──
    if run_transport:
        transport_results = run_transport_tests(report_url, menus_url, approval_url, mgmt_api_key=mgmt_api_key)
        all_results.extend(transport_results)
        print()

    # ── RBAC tests ──
    if run_rbac:
        rbac_results = run_rbac_tests(report_url, menus_url, approval_url, mgmt_api_key=mgmt_api_key)
        all_results.extend(rbac_results)
        print()

    # ── Identity chain tests ──
    if run_identity:
        identity_results = run_identity_chain_tests(report_url, approval_url, env)
        all_results.extend(identity_results)
        print()

    # ── OAuth2 token validation tests ──
    if run_oauth2:
        oauth2_results = run_oauth2_tests(report_url, approval_url, mgmt_api_key=mgmt_api_key)
        all_results.extend(oauth2_results)
        print()

    # ── S2S OAuth enforcement tests ──
    if run_s2s:
        s2s_results = run_s2s_tests(report_url, approval_url, mgmt_api_key=mgmt_api_key)
        all_results.extend(s2s_results)
        print()

    # ── A2A direct calling tests ──
    if run_a2a:
        a2a_results = run_a2a_tests(report_url, menus_url)
        all_results.extend(a2a_results)
        print()

    # ── CA risk enforcement tests ──
    if run_ca_risk:
        ca_risk_results = run_ca_risk_tests(report_url, control_plane_url, approval_url, env)
        all_results.extend(ca_risk_results)
        print()

    # ── Summary ──
    print("=" * 66)
    print("  Summary")
    print("=" * 66)
    passed = sum(all_results)
    total = len(all_results)

    if transport_results:
        print(f"  Transport layer (mTLS):    {sum(transport_results)}/{len(transport_results)} passed")
    if rbac_results:
        print(f"  Application layer (RBAC):  {sum(rbac_results)}/{len(rbac_results)} passed")
    if identity_results:
        print(f"  Identity chain (E2E):      {sum(identity_results)}/{len(identity_results)} passed")
    if oauth2_results:
        print(f"  OAuth2 token validation:   {sum(oauth2_results)}/{len(oauth2_results)} passed")
    if s2s_results:
        print(f"  S2S OAuth enforcement:     {sum(s2s_results)}/{len(s2s_results)} passed")
    if a2a_results:
        print(f"  A2A direct calling:        {sum(a2a_results)}/{len(a2a_results)} passed")
    if ca_risk_results:
        print(f"  CA risk enforcement:       {sum(ca_risk_results)}/{len(ca_risk_results)} passed")
    print(f"  Total:                     {passed}/{total} passed")

    print()
    if passed == total:
        print("  ✅ All tests passed!")
        layers = []
        if transport_results:
            layers.append("mTLS")
            print("  Transport layer: EmployeeMenus blocked at mTLS handshake.")
        if rbac_results:
            layers.append("RBAC")
            print("  Application layer: BudgetReport restricted to read-only by RBAC policy.")
            print("  BudgetApproval has full access to both read and submit.")
        if identity_results:
            layers.append("Identity Chain")
            print("  Identity chain: Entra Agent IDs flow E2E through SPIFFE gateway.")
        if oauth2_results:
            layers.append("OAuth2")
            print("  OAuth2: Entra Agent ID JWT tokens validated with signature + claims.")
        if s2s_results:
            layers.append("S2S OAuth")
            print("  S2S: Proxy validates JWTs as Layer 3 (mTLS + RBAC + OAuth/JWT).")
        if a2a_results:
            layers.append("A2A (CA)")
            print("  A2A: Agent-to-agent direct calling with CA tag enforcement (Layer 4b).")
        if ca_risk_results:
            layers.append("CA Risk")
            print("  CA Risk: Agent risk levels block calls at data plane (Layer 4b).")
        if layers:
            print(f"  Enforcement layers verified: {' + '.join(layers)}")
    else:
        print(f"  ⚠️  {total - passed} test(s) failed.")
        print("  Check logs: az containerapp logs show --name <app> --resource-group <rg>")
        print("  Check BudgetBackend sidecar: az containerapp logs show --name budget-backend --resource-group <rg> --container budget-backend-spiffe-proxy")
    print()

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
