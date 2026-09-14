"""Closed expectations for connected browser-to-backend journeys."""


SCENARIOS = {
    "allowed": (200, "oauth", "ALLOWED", "Valid identity, JWT and policy reach the backend"),
    "rbac_deny": (403, "rbac", "RBAC DENY", "Disallowed submit never reaches the backend"),
    "jwt_missing": (401, "authentication", "OAuth UNAUTHORIZED", "Caller token acquisition failure stops dispatch"),
    "jwt_expired": (401, "oauth", "OAuth DENY", "Expired signed JWT is rejected by the actual gateway"),
    "jwt_wrong_audience": (401, "oauth", "OAuth DENY", "Wrong-audience JWT is rejected by the actual gateway"),
    "jwt_wrong_signature": (401, "oauth", "OAuth DENY", "Bad-signature JWT is rejected by the actual gateway"),
    "jwt_no_expiry": (401, "oauth", "OAuth DENY", "Expiration-less JWT must not reach the backend"),
    "ca_disabled": (403, "conditional_access", "CA DENY", "Disabled caller cannot reach the backend"),
    "ca_tag_mismatch": (403, "conditional_access", "CA DENY", "Mismatched caller tag cannot reach the backend"),
    "ca_high_risk": (403, "conditional_access", "CA DENY", "High-risk caller cannot reach the backend"),
    "ca_missing_risk": (403, "conditional_access", "CA DENY", "Missing risk evidence must fail closed"),
    "ca_policy_outage": (403, "conditional_access", "CA DENY", "Initial policy outage must fail closed"),
    "ca_graph_tag_absent": (403, "conditional_access", "CA DENY", "Missing Graph tag must not fall back to allowing YAML"),
    "mtls_denied": (0, "mtls", "ERROR", "Closed raw tunnel is proven rejected by TLS audit and never reaches the backend"),
}


def specification(name):
    status, layer, label, description = SCENARIOS[name]
    return {
        "name": name, "status": status, "layer": layer, "label": label,
        "description": description,
        "method": "POST" if name == "rbac_deny" else "GET",
        "path": "/budget/submit" if name == "rbac_deny" else "/budget/read",
    }


def inventory():
    cases = [{
        "id": "e2e." + name, "suite": "e2e", "layer": layer,
        "profiles": ["local"], "description": description,
        "expected": description + "; browser, caller, audit and backend observations agree",
        "mutation": name.startswith("ca_") or name == "mtls_denied",
    } for name, (_status, layer, _label, description) in SCENARIOS.items()]
    cases.append({
        "id": "e2e.security_risk_roundtrip", "suite": "e2e", "layer": "cross-portal-governance",
        "profiles": ["local"], "mutation": True,
        "description": "Apply high risk in Security Portal, verify denial in Management Portal, restore low",
        "expected": "Real sidecar risk changes, backend dispatch stops, then recovers; restoration verified",
    })
    return cases


def verify(case, observed, caller_id):
    if (observed.get("scenario") != case["name"]
            or observed.get("status") != case["status"]
            or observed.get("badge") != f"{case['status']} {case['label']}"
            or observed.get("caller_requests") != 1
            or observed.get("blocked_browser_requests") != 0):
        return False
    allowed = case["status"] == 200
    if observed.get("backend_requests") != (1 if allowed else 0):
        return False
    if allowed and observed.get("backend_caller") != caller_id:
        return False
    audit = observed.get("audit")
    if not isinstance(audit, list):
        return False
    if case["layer"] == "mtls":
        return not audit and observed.get("mtls_rejections", 0) > 0
    if case["layer"] == "authentication":
        return not audit and observed.get("response_layer") == "authentication"
    if len(audit) != 1 or not isinstance(audit[0], dict):
        return False
    entry = audit[0]
    if (entry.get("caller_spiffe_id") != caller_id
            or entry.get("method") != case["method"] or entry.get("path") != case["path"]
            or entry.get("decision") != ("allow" if allowed else "deny")
            or entry.get("enforcement_layer") != case["layer"]
            or not isinstance(entry.get("request_id"), str) or not entry["request_id"]):
        return False
    if case["layer"] == "oauth":
        if entry.get("jwt_present") is not True:
            return False
        if allowed != (entry.get("jwt_valid") is True):
            return False
    return True
