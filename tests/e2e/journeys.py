"""Cross-layer journeys: a real browser request must match real server evidence."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import urlsplit

import httpx
from playwright.sync_api import Error as BrowserError, expect, sync_playwright

from bootstrap import application
from evidence import specification, verify

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "browser"))
sys.path.insert(0, str(HERE.parent / "stack"))
from browser_engine import CaseProblem, assert_access, route_boundary
from browser_guards import validate_debug_environment
from runtime import running_stack, StackUnavailable, StackFailure


def json_request(client, method, url, **kwargs):
    response = client.request(method, url, **kwargs)
    response.raise_for_status()
    if response.is_redirect:
        raise ValueError("Fixture redirect refused")
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Invalid fixture object")
    return data


def prepare(client, topology, caller, backend, name):
    result = json_request(client, "POST", topology["control_url"] + "/scenario", json={"name": name})
    if result.get("scenario", result.get("name")) != name:
        raise ValueError("Scenario did not acknowledge requested state")
    for target in (caller, backend):
        if json_request(client, "POST", target + "/__test/reset").get("reset") is not True:
            raise ValueError("Observation reset failed")
    for target in (caller, backend):
        if json_request(client, "GET", target + "/__test/evidence").get("requests") != 0:
            raise ValueError("Observation reset not established")


def click_execute(page, case):
    page.locator('.nav-btn[data-tab="execute"]').click()
    caller = page.locator(".caller-card").filter(
        has=page.locator(".c-name", has_text="BudgetReport"))
    if "selected" not in (caller.get_attribute("class") or "").split():
        caller.click()
    page.locator(".ep-btn").filter(
        has=page.locator(".ep-path", has_text=case["path"])).click()
    with page.expect_response(lambda r: urlsplit(r.url).path == "/api/execute"
                              and r.request.method == "POST", timeout=45000) as response:
        page.locator(".send-btn").click()
    if response.value.status != 200:
        raise ValueError("Portal execute envelope did not succeed")
    result = response.value.json()
    status = result.get("status")
    if type(status) is not int:
        raise ValueError("Portal status missing")
    badge = page.locator(".result-header .badge")
    expect(badge).to_contain_text(str(status))
    body = result.get("body", {})
    inner = body.get("response", {}) if isinstance(body, dict) else {}
    return {
        "status": status, "badge": badge.inner_text(),
        "response_layer": inner.get("enforcement_layer", "") if isinstance(inner, dict) else "",
    }


def observe(client, page, case, topology, caller, backend, blocked):
    observed = click_execute(page, case)
    sidecar = json_request(client, "GET", topology["control_url"] + "/evidence")
    received = json_request(client, "GET", backend + "/__test/evidence")
    invoked = json_request(client, "GET", caller + "/__test/evidence")
    audit = sidecar.get("audit")
    if not isinstance(audit, list) or any(not isinstance(row, dict) for row in audit):
        raise ValueError("Actual audit evidence missing")
    observed.update(
        scenario=sidecar.get("scenario"), audit=[r for r in audit if r.get("enforcement_layer") != "mtls"],
        caller_requests=invoked.get("requests"), backend_requests=received.get("requests"),
        backend_caller=received.get("caller"), mtls_rejections=sidecar.get("mtls_rejections"),
        blocked_browser_requests=len(blocked),
    )
    return observed


def report_row(case, status, message, seconds, facts=None):
    row = dict(case, status=status, observed=message, duration_seconds=round(seconds, 4))
    if facts is not None:
        row["evidence"] = facts
    return row


def run_cases(cases):
    rows = []
    try:
        validate_debug_environment(os.environ)
    except ValueError:
        return [report_row(c, "BLOCKED", "Disable browser debug and remote-connection settings before execution", 0) for c in cases]
    try:
        with ExitStack() as resources:
            backend = resources.enter_context(application("backend", {}))
            topology = resources.enter_context(running_stack(backend))
            config = dict(topology)
            config.setdefault("admin_key", secrets.token_urlsafe(32))
            caller = resources.enter_context(application("caller", config))
            config["caller_url"] = caller
            portal = resources.enter_context(application("portal", config))
            security = resources.enter_context(application("security", config))
            client = resources.enter_context(httpx.Client(trust_env=False, timeout=15, follow_redirects=False))
            playwright = resources.enter_context(sync_playwright())
            browser = playwright.chromium.launch(headless=True)
            resources.callback(browser.close)
            for descriptor in cases:
                name = descriptor["id"].removeprefix("e2e.")
                governance = name == "security_risk_roundtrip"
                case = specification("allowed" if governance else name)
                started = time.monotonic()
                facts = {
                    "real_browser": True, "real_portal_backend": True, "real_caller": True,
                    "real_backend": True, "real_tunnel_client": True, "real_tunnel_server": True,
                    "mocked_identity_issuance": True, "mocked_operator_identity": True,
                    "cloud_platform_verified": False,
                    "production_source_sha256": topology["source_sha256"],
                }
                try:
                    with browser.new_context(service_workers="block", accept_downloads=False) as context:
                        context.set_default_timeout(12000)
                        page = context.new_page()
                        permitted = {"caller": "budget-report", "method": "GET", "path": "/budget/read"}
                        blocked = route_boundary(context, portal, "admin", True, execute_payload=permitted)
                        page.goto(portal, wait_until="domcontentloaded")
                        assert_access(page, "management", "admin", live=False)
                        prepare(client, topology, caller, backend, "allowed")
                        control = observe(client, page, specification("allowed"), topology, caller, backend, blocked)
                        facts["positive_control_verified"] = verify(
                            specification("allowed"), control, topology["caller_spiffe_id"])
                        if not facts["positive_control_verified"]:
                            rows.append(report_row(descriptor, "FAIL",
                                "Healthy connected browser-to-backend control failed; denial not established",
                                time.monotonic() - started, facts))
                            continue
                        prepare(client, topology, caller, backend, "allowed" if governance else name)
                        if governance:
                            from governance import run_roundtrip
                            result = run_roundtrip(browser, page, client, topology, caller, backend, security, config)
                            result["management_browser_containment_verified"] = not blocked
                            facts.update(result)
                            rows.append(report_row(descriptor, "PASS" if all(result.values()) else "FAIL",
                                "Cross-portal risk update, data-plane denial and recovery verified"
                                if all(result.values()) else "Cross-portal risk change or enforcement/recovery disagreed",
                                time.monotonic() - started, facts))
                            continue
                        permitted.update(method=case["method"], path=case["path"])
                        observed = observe(client, page, case, topology, caller, backend, blocked)
                        matched = verify(case, observed, topology["caller_spiffe_id"])
                        facts.update(
                            http_status=observed["status"], backend_requests=observed["backend_requests"],
                            caller_requests=observed["caller_requests"],
                            audit_entries=len(observed["audit"]),
                            mtls_rejections=observed["mtls_rejections"],
                            surfaces_agree=matched,
                        )
                        message = ("Browser, real caller, actual gateway audit and backend dispatch agree"
                                   if matched else "Connected outcome disagrees with required browser/enforcement/backend behavior")
                        rows.append(report_row(descriptor, "PASS" if matched else "FAIL", message,
                                               time.monotonic() - started, facts))
                except (BrowserError, AssertionError, CaseProblem, ValueError, httpx.HTTPError):
                    rows.append(report_row(descriptor, "FAIL",
                        "Connected journey failed; no raw responses or credentials retained",
                        time.monotonic() - started, facts))
    except StackUnavailable:
        return [report_row(c, "BLOCKED", "Prepared local Go/protobuf stack prerequisite unavailable", 0) for c in cases]
    except (StackFailure, RuntimeError, OSError, BrowserError, httpx.HTTPError):
        return [report_row(c, "FAIL", "Connected topology startup or cleanup failed", 0) for c in cases]
    return rows
