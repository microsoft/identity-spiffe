"""Exercise a real Security Portal risk change and its data-plane consequences."""
from pathlib import Path
import sys
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "browser"))
from browser_guards import allowed_write


def risk_guard(identity):
    permitted = {
        "/set-risk?spiffe_id=" + quote(identity, safe="") + "&risk_level=" + level
        for level in ("high", "low")
    }

    def guarded(path, method, body, *, role, **kwargs):
        if path in permitted and method == "PUT" and body is None and role == "admin":
            return True
        return allowed_write(path, method, body, role=role, **kwargs)

    return guarded


def run_roundtrip(browser, page, client, topology, caller, backend, security, config):
    from unittest.mock import patch
    from browser_engine import assert_access, route_boundary
    from evidence import specification, verify
    from journeys import json_request, observe

    caller_id = topology["caller_spiffe_id"]
    management = topology["management_url"] + "/admin/agent-risk"
    headers = {"X-Spiffe-Admin-Key": config["admin_key"]}
    original = json_request(client, "GET", management, params={"spiffe_id": caller_id}, headers=headers)
    if original.get("risk_level") != "low":
        raise ValueError("Governance fixture does not start explicitly low")
    facts = {}
    restored = False
    try:
        with browser.new_context(service_workers="block", accept_downloads=False) as context:
            context.set_default_timeout(12000)
            security_page = context.new_page()
            with patch("browser_engine.allowed_write", risk_guard(caller_id)):
                blocked = route_boundary(context, security, "admin", True)
                security_page.goto(security, wait_until="domcontentloaded")
                assert_access(security_page, "security", "admin", live=False)

                def apply(level):
                    select = security_page.locator("#risk-budget-report")
                    select.select_option(level)
                    with security_page.expect_response(
                            lambda r: r.request.method == "PUT" and "/set-risk?" in r.url) as response:
                        select.locator("xpath=ancestor::div[contains(@class,'agent-card')]").get_by_role(
                            "button", name="Apply", exact=True).click()
                    if response.value.status != 200:
                        return False
                    body = response.value.json()
                    if not isinstance(body.get("sidecar"), dict) or body["sidecar"].get("error"):
                        return False
                    current = json_request(client, "GET", management,
                        params={"spiffe_id": caller_id}, headers=headers)
                    return current.get("risk_level") == level

                facts["ui_risk_update_verified"] = apply("high")
                denied = observe(client, page, specification("ca_high_risk"),
                                 topology, caller, backend, [])
                deny_spec = dict(specification("ca_high_risk"), name="allowed")
                facts["denial_verified"] = verify(deny_spec, denied, caller_id)
                previous = {entry["request_id"] for entry in denied["audit"]}
                facts["ui_risk_restore_verified"] = apply("low")
                for target in (caller, backend):
                    json_request(client, "POST", target + "/__test/reset")
                recovered = observe(client, page, specification("allowed"),
                                    topology, caller, backend, [])
                recovered["audit"] = [entry for entry in recovered["audit"]
                                       if entry["request_id"] not in previous]
                facts["recovery_verified"] = verify(specification("allowed"), recovered, caller_id)
                facts["child_browser_containment_verified"] = not blocked
                restored = facts["ui_risk_restore_verified"]
    finally:
        if not restored:
            json_request(client, "PUT", management, headers=headers,
                         json={"spiffe_id": caller_id, "risk_level": "low"})
        current = json_request(client, "GET", management, params={"spiffe_id": caller_id}, headers=headers)
        if current.get("risk_level") != original["risk_level"]:
            raise RuntimeError("Risk fixture restoration failed")
        facts["cleanup_verified"] = True
    return facts
