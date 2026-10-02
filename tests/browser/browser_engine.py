"""Real Chromium interaction with existing app code, not a replacement UI."""
from contextlib import contextmanager, ExitStack
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

import httpx
from playwright.sync_api import Error as PlaywrightError, expect, sync_playwright

from browser_guards import allowed_write, case_result, describe_block, live_origin, read_private_json, validate_session

HERE = Path(__file__).resolve().parent
AUTH_DIR = HERE / ".auth"
PORTALS = {
    "management": {
        "token": "_accessToken", "user": "currentUser", "splash": "#auth-splash",
        "error": "#auth-error", "read": "/api/config",
    },
    "security": {
        "token": "_securityPortalToken", "user": "_securityPortalUser",
        "splash": "#sp-auth-splash", "error": "#sp-auth-error", "read": "/api/agents",
    },
}
TABS = {
    "overview": ("Security Overview", "/api/config"),
    "execute": ("Test Calls", "/api/audit"),
    "logs": ("Logs", "/api/audit"),
    "mtls": ("Network Access", "/api/mtls-policy"),
    "policy": ("Policy Editor", "/api/policy"),
    "health": ("System Health", "/api/health"),
    "oauth": ("Enforcement Layers", "/api/oauth-status"),
    "settings": ("Settings", "/api/settings/risk"),
}


class CaseProblem(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def require(value):
    if not value:
        raise CaseProblem("FAIL", "assertion_failed")


def target_config(config, portal):
    entry = config.get(portal)
    if not isinstance(entry, dict):
        raise CaseProblem("BLOCKED", "config_missing")
    try:
        origin = live_origin(entry.get("url"))
    except ValueError:
        raise CaseProblem("BLOCKED", "config_missing") from None
    return entry, origin


def session_path(entry, portal, role):
    sessions = entry.get("sessions", {})
    if not isinstance(sessions, dict) or not isinstance(sessions.get(role), str):
        raise CaseProblem("BLOCKED", "session_missing")
    path = Path(sessions[role])
    if not path.is_absolute():
        path = HERE.parents[1] / path
    # Credential files may only live in this suite's ignored auth directory.
    if not path.absolute().is_relative_to(AUTH_DIR) or ".." in path.parts:
        raise CaseProblem("BLOCKED", "session_invalid")
    return path


def load_session(entry, portal, role, origin):
    try:
        data = read_private_json(session_path(entry, portal, role))
        return validate_session(data, portal=portal, role=role, origin=origin)
    except FileNotFoundError:
        raise CaseProblem("BLOCKED", "session_missing") from None
    except (OSError, ValueError, TypeError):
        raise CaseProblem("BLOCKED", "session_invalid") from None


def restore_session(context, session):
    encoded = json.dumps({"origin": session["origin"], "entries": session["session_storage"]})
    context.add_init_script(
        f"""(() => {{
          const saved = {encoded};
          if (window.location.origin === saved.origin &&
              !window.sessionStorage.getItem('__browser_harness_restored')) {{
            for (const [key, value] of Object.entries(saved.entries)) {{
              window.sessionStorage.setItem(key, value);
            }}
            window.sessionStorage.setItem('__browser_harness_restored', 'true');
          }}
        }})();""")


def fixture_msal(role):
    account = {
        "name": "Browser Fixture", "username": "fixture@example.invalid",
        "idTokenClaims": {"groups": [f"fixture-{role}-group"] if role != "unassigned" else []},
    }
    return """window.msal = {PublicClientApplication: class {
        constructor() { this.activeAccount = null; }
        handleRedirectPromise() { return Promise.resolve(null); }
        getAllAccounts() { return ACCOUNTS; }
        getActiveAccount() { return this.activeAccount; }
        setActiveAccount(account) { this.activeAccount = account; }
        acquireTokenSilent() { return Promise.resolve({account: ACCOUNT, idToken: TOKEN}); }
        acquireTokenRedirect() { return Promise.reject(new Error('fixture cannot authenticate')); }
    }};""".replace("ACCOUNTS", json.dumps([] if role == "anonymous" else [account])).replace(
        "ACCOUNT", json.dumps(account)).replace("TOKEN", json.dumps(f"fixture-{role}"))


def request_summary(page, portal, path, *, method="GET", payload=None):
    # Token stays in the browser realm. Only allowlisted scalar facts leave it.
    return page.evaluate("""async args => {
        const token = window[args.token];
        const headers = {};
        if (token) headers.Authorization = 'Bearer ' + token;
        if (args.payload !== null) headers['Content-Type'] = 'application/json';
        const response = await fetch(args.path, {method: args.method, headers,
            body: args.payload === null ? undefined : JSON.stringify(args.payload),
            redirect: 'error'});
        return {status: response.status};
    }""", {"token": PORTALS[portal]["token"], "path": path, "method": method, "payload": payload})


def assert_required_auth(page):
    summary = page.evaluate("""async () => {
        const r = await fetch('/api/auth-config', {redirect:'error'});
        const c = await r.json();
        return {status:r.status, required:c.auth_required === true,
            configured:typeof c.client_id === 'string' && c.client_id.length > 0};
    }""")
    if summary["status"] != 200 or not summary["required"] or not summary["configured"]:
        raise CaseProblem("FAIL", "auth_disabled")


def assert_access(page, portal, role, live):
    ui = PORTALS[portal]
    assert_required_auth(page)
    if role == "anonymous":
        expect(page.locator(ui["splash"])).to_be_visible()
        require(request_summary(page, portal, ui["read"])["status"] == 401)
        return
    try:
        page.wait_for_function(
            "(name) => typeof window[name] === 'string' && window[name].length > 0",
            arg=ui["token"], timeout=10000)
    except PlaywrightError:
        if live:
            raise CaseProblem("BLOCKED", "session_rejected") from None
        raise
    status = request_summary(page, portal, ui["read"])["status"]
    if status == 401 and live:
        raise CaseProblem("BLOCKED", "session_rejected")
    if role == "unassigned":
        expect(page.locator(ui["splash"])).to_be_visible()
        expect(page.locator(ui["error"])).to_contain_text("Access Denied")
        require(status == 403)
    else:
        expect(page.locator(ui["splash"])).to_be_hidden()
        require(page.evaluate("(name) => window[name] && window[name].role", ui["user"]) == role)
        require(status == 200)
        # Empty input lacks required schema fields; no handler can mutate state.
        path, method = ("/api/execute", "POST") if portal == "management" else ("/set-risk", "PUT")
        probe_status = request_summary(page, portal, path, method=method, payload={})["status"]
        require(probe_status == 403 if role == "viewer" else probe_status in (400, 422))


def management_navigation(page):
    for tab, (title, endpoint) in TABS.items():
        require(request_summary(page, "management", endpoint)["status"] == 200)
        page.locator(f'.nav-btn[data-tab="{tab}"]').click()
        expect(page.locator(".main-title")).to_have_text(title)
        expect(page.locator("#content")).not_to_be_empty()
        if tab == "policy":
            expect(page.locator("#policy-editor")).to_be_visible()
            expect(page.locator("#policy-editor")).not_to_have_value("")
        if tab == "execute":
            expect(page.locator(".caller-card").first).to_be_visible()
            expect(page.locator(".send-btn")).to_be_disabled()
        if tab == "mtls":
            expect(page.locator("#add-mtls-input")).to_be_visible()
            page.locator("#add-mtls-input").fill("spiffe://browser.test/not-submitted")
        if tab == "logs":
            page.locator('.logs-toolbar input[type="text"]').fill("browser-no-match")
        if tab == "settings":
            switches = page.get_by_role("switch")
            expect(switches).to_have_count(2)
            role = page.evaluate("currentUser.role")
            for index in range(2):
                if role == "viewer":
                    expect(switches.nth(index)).to_be_disabled()
                else:
                    expect(switches.nth(index)).to_be_enabled()
            cache = page.get_by_label("Entra risk cache lifetime (seconds)", exact=True)
            if role == "viewer":
                expect(cache).to_be_disabled()
            else:
                expect(cache).to_be_enabled()
            for endpoint in ("/api/settings/risk-signal", "/api/settings/risk-enforcement", "/api/settings/risk-cache"):
                require(request_summary(page, "management", endpoint, method="PUT", payload={})["status"]
                        == (403 if role == "viewer" else 422))
    # Navigate via the app's own resource card, then browser Back.
    page.locator('.nav-btn[data-tab="overview"]').click()
    card = page.locator('.agent-id-card[role="button"]').first
    expect(card).to_be_visible()
    card.click()
    page.wait_for_function("location.hash.startsWith('#/agent/')")
    expect(page.locator("#content")).not_to_be_empty()
    page.go_back()
    return {"pages_checked": len(TABS) + 1}


def security_navigation(page):
    inventory = page.evaluate("""async () => {
        const response = await fetch('/api/agents', {
            headers: {Authorization: 'Bearer ' + window._securityPortalToken},
            redirect: 'error'
        });
        const body = await response.json();
        return {status: response.status, count: Array.isArray(body.agents) ? body.agents.length : null};
    }""")
    require(inventory["status"] == 200 and type(inventory["count"]) is int)
    if inventory["count"] == 0:
        raise CaseProblem("FAIL", "inventory_empty")
    require(request_summary(page, "security", "/agents")["status"] == 200)
    expect(page.locator(".agent-card").first).to_be_visible()
    selector = page.locator('.agent-card select').first
    if selector.count():
        selector.select_option("medium")
        expect(selector).to_have_value("medium")
        # Form-only change; deliberately do not click Apply.
    button = page.locator(".agent-card .btn-isolate, .agent-card .btn-restore").first
    button.click()
    expect(page.locator(".confirm-card")).to_be_visible()
    page.locator("#confirm-cancel").click()
    expect(page.locator(".confirm-card")).to_have_count(0)
    return {"pages_checked": 2}


def execute_read(page, caller_name, denied=False):
    page.locator('.nav-btn[data-tab="execute"]').click()
    page.locator(".caller-card").filter(
        has=page.locator(".c-name", has_text=re.compile("^" + re.escape(caller_name) + "$"))).click()
    endpoint = "/budget/submit" if denied else "/budget/read"
    page.locator(".ep-btn").filter(has=page.locator(".ep-path", has_text=endpoint)).click()
    with page.expect_response(lambda r: urlsplit(r.url).path == "/api/execute" and r.request.method == "POST") as response:
        page.locator(".send-btn").click()
    require(response.value.status == 200)
    expected = 403 if denied else 200
    # Examine only the result status in memory; never retain response bodies.
    require(response.value.json().get("status") == expected)
    expect(page.locator(".result-header .badge")).to_have_text(
        "403 RBAC DENY" if denied else "200 ALLOWED")
    return {"http_status": expected}


def risk_settings_roundtrip(page):
    def preferences():
        result = page.evaluate("""async () => {
            const response = await fetch('/api/settings/risk', {
                headers: {Authorization: 'Bearer ' + window._accessToken}, redirect: 'error'
            });
            const data = await response.json();
            return {status: response.status, signal: data.signal && data.signal.enabled,
                    enforcement: data.risk_enforcement_enabled, cache: data.risk_cache_seconds};
        }""")
        require(result["status"] == 200 and type(result.get("signal")) is bool
                and type(result.get("enforcement")) is bool and type(result.get("cache")) is int)
        return {"signal": result["signal"], "enforcement": result["enforcement"], "cache": result["cache"]}

    original = preferences()
    current = dict(original)
    controls = (
        ("signal", "Show Entra risk in the portal", "/api/settings/risk-signal"),
        ("enforcement", "Enforce Entra risk at the gateway", "/api/settings/risk-enforcement"),
    )
    try:
        for key, name, endpoint in controls:
            page.locator('.nav-btn[data-tab="settings"]').click()
            toggle = page.get_by_role("switch", name=name, exact=True)
            expect(toggle).to_be_enabled()
            desired = not original[key]
            if not desired:
                page.once("dialog", lambda dialog: dialog.accept())
            with page.expect_response(lambda response: urlsplit(response.url).path == endpoint
                                      and response.request.method == "PUT") as response:
                toggle.set_checked(desired)
            require(response.value.status == 200)
            current[key] = desired
            page.wait_for_function(
                "(expected) => state.riskSettings && state.riskSettings.signal.enabled === expected.signal"
                " && state.riskSettings.risk_enforcement_enabled === expected.enforcement",
                arg=current,
            )
            require(preferences() == current)
            page.reload(wait_until="domcontentloaded")
            assert_access(page, "management", "admin", live=False)
            page.locator('.nav-btn[data-tab="settings"]').click()
            if desired:
                expect(page.get_by_role("switch", name=name, exact=True)).to_be_checked()
            else:
                expect(page.get_by_role("switch", name=name, exact=True)).not_to_be_checked()
            require(preferences() == current)
            expect(page.locator(".policy-msg.err")).to_have_count(0)
        for seconds in (0, 120):
            page.get_by_label("Entra risk cache lifetime (seconds)", exact=True).fill(str(seconds))
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/settings/risk-cache"
                                      and response.request.method == "PUT") as response:
                page.get_by_role("button", name="Save cache lifetime", exact=True).click()
            require(response.value.status == 200)
            current["cache"] = seconds
            page.wait_for_function("(seconds) => state.riskSettings.risk_cache_seconds === seconds", arg=seconds)
            require(preferences() == current)
            page.reload(wait_until="domcontentloaded")
            assert_access(page, "management", "admin", live=False)
            page.locator('.nav-btn[data-tab="settings"]').click()
            expect(page.locator("#risk-cache-seconds")).to_have_value(str(seconds))
            require(preferences() == current)
        info = page.get_by_role("button", name="About Entra risk cache lifetime", exact=True)
        info.hover()
        expect(page.locator("#risk-cache-help")).to_be_visible()
        expect(page.locator("#risk-cache-help")).to_contain_text("Set 0 to check Entra on every call")
        page.mouse.move(0, 0)
        info.focus()
        expect(page.locator("#risk-cache-help")).to_be_visible()
    finally:
        for key, _name, endpoint in controls:
            require(request_summary(page, "management", endpoint, method="PUT",
                                    payload={"enabled": original[key]})["status"] == 200)
        require(request_summary(page, "management", "/api/settings/risk-cache", method="PUT",
                                payload={"seconds": original["cache"]})["status"] == 200)
        if preferences() != original:
            raise CaseProblem("FAIL", "cleanup_failed")
    return {"http_status": 200, "cleanup_verified": True}


def saved_policy(page, name):
    page.locator('.nav-btn[data-tab="policy"]').click()
    page.wait_for_function(
        "() => state.policyData && state.caGovData && state.mtlsData && state.auditData")
    expect(page.locator("#policy-editor")).not_to_have_value("")
    page.locator("#save-config-name").fill(name)
    created = False
    try:
        with page.expect_response(lambda r: urlsplit(r.url).path == "/api/policy-configs"
                                  and r.request.method == "POST") as response:
            page.locator(".save-btn").click()
        created = response.value.status == 200
        require(created)
        expect(page.locator(f'#config-select option[value="{name}"]')).to_have_count(1)
        page.locator("#config-select").select_option(name)
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_response(lambda r: urlsplit(r.url).path == f"/api/policy-configs/{name}"
                                  and r.request.method == "DELETE") as deleted:
            page.locator(".delete-cfg-btn").click()
        require(deleted.value.status == 200)
        expect(page.locator(f'#config-select option[value="{name}"]')).to_have_count(0)
    finally:
        if created:
            # Idempotent local cleanup, even when a UI assertion fails.
            cleanup_status = request_summary(page, "management", f"/api/policy-configs/{name}",
                                             method="DELETE")["status"]
            if cleanup_status not in (200, 404):
                raise CaseProblem("FAIL", "cleanup_failed")
            absent = page.evaluate("""async name => {
                const r = await fetch('/api/policy-configs', {
                    headers: {Authorization:'Bearer ' + window._accessToken}, redirect:'error'});
                const rows = await r.json();
                return r.status === 200 && Array.isArray(rows) && !rows.some(c => c.name === name);
            }""", name)
            if not absent:
                raise CaseProblem("FAIL", "cleanup_failed")
    return {"cleanup_verified": True}


@contextmanager
def local_target(portal):
    with tempfile.TemporaryDirectory(prefix="browser-", dir=HERE / "artifacts") as directory:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            # No inherited cloud, auth, proxy or telemetry settings.
            env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG") if k in os.environ}
            env.update({"PYTHONNOUSERSITE": "1", "AZURE_TENANT_ID": "fixture-tenant"})
            process = subprocess.Popen(
                [sys.executable, str(HERE / "browser_fixture.py"), "--portal", portal,
                 "--socket-fd", str(listener.fileno()), "--directory", directory],
                pass_fds=(listener.fileno(),), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        try:
            origin = f"http://127.0.0.1:{port}"
            with httpx.Client(trust_env=False, timeout=0.5, follow_redirects=False) as client:
                deadline = time.monotonic() + 20
                ready = False
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        ready = client.get(origin + "/api/auth-config").status_code == 200
                    except httpx.RequestError:
                        ready = False
                    if ready:
                        break
                    time.sleep(0.1)
                if not ready:
                    raise CaseProblem("BLOCKED", "startup_failed")
            yield origin
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def route_boundary(context, origin, role, local, execute_payload=None, saved_name=None,
                   human_login=False, on_block=None, settings_mutation=False):
    if len(context.pages) != 1:
        raise ValueError("Create exactly one blank page before installing its network boundary")
    blocked_writes = []
    owned_page = context.pages[0]

    def deny_child_targets(route):
        try:
            frame = route.request.frame
        except PlaywrightError:
            frame = None
        if frame != owned_page.main_frame:
            blocked_writes.append(True)
            if on_block:
                on_block(describe_block(route.request.url, "child_target"))
            route.abort()
        else:
            route.continue_()
    identity_origins = {"https://alcdn.msauth.net", "https://login.microsoftonline.com"}
    if human_login:
        identity_origins.update({
            "https://login.microsoft.com",
            "https://login.live.com", "https://browser.events.data.microsoft.com",
            "https://aadcdn.msauth.net", "https://aadcdn.msftauth.net",
            "https://logincdn.msauth.net", "https://aadcdn.msauthimages.net",
            "https://aadcdn.msftauthimages.net",
        })

    def attach(page):
        session = context.new_cdp_session(page)

        def intercept(event):
            request = event["request"]
            parsed = urlsplit(request["url"])
            request_origin = f"{parsed.scheme}://{parsed.netloc}"
            command = {"requestId": event["requestId"]}
            if (local and request_origin == "https://alcdn.msauth.net" and
                    parsed.path == "/browser/2.38.0/js/msal-browser.min.js" and
                    request["method"] == "GET"):
                session.send("Fetch.fulfillRequest", dict(command, responseCode=200,
                    responseHeaders=[{"name": "Content-Type", "value": "application/javascript"}],
                    body=base64.b64encode(fixture_msal(role).encode()).decode()))
                return
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            permitted = request_origin == origin and (
                request["method"] in ("GET", "HEAD") or
                allowed_write(path, request["method"], request.get("postData"), role=role,
                              execute_payload=execute_payload, saved_name=saved_name,
                              settings_mutation=local and settings_mutation))
            if not local and request_origin in identity_origins:
                permitted = True
            if not permitted:
                blocked_writes.append(True)
                if on_block:
                    on_block(describe_block(request["url"], "destination_or_write"))
                session.send("Fetch.failRequest", dict(command, errorReason="BlockedByClient"))
            else:
                session.send("Fetch.continueRequest", command)

        # Playwright routes skip redirect hops. CDP pauses every HTTP hop before
        # dispatch, preserving streaming responses and normal browser redirects.
        session.on("Fetch.requestPaused", intercept)
        session.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})

    for page in context.pages:
        attach(page)
    # Context routes intercept the first popup/iframe request before dispatch.
    # Deny all child targets: a page CDP session cannot police OOPIFs or popups.
    # The owned page's CDP guard still validates every subsequent redirect hop.
    context.route("**/*", deny_child_targets)
    return blocked_writes


def run_cases(cases, profile, config):
    rows = []
    with ExitStack() as stack:
        local = profile == "local"
        targets = {}
        if local:
            (HERE / "artifacts").mkdir(mode=0o700, exist_ok=True)
            try:
                for portal in PORTALS:
                    targets[portal] = stack.enter_context(local_target(portal))
            except CaseProblem as exc:
                return [case_result(c, exc.status, exc.code, 0) for c in cases]
        try:
            playwright = stack.enter_context(sync_playwright())
            browser = playwright.chromium.launch(headless=True)
            stack.callback(browser.close)
        except PlaywrightError:
            return [case_result(c, "BLOCKED", "browser_missing", 0) for c in cases]
        for case in cases:
            started = time.monotonic()
            portal = case["id"].split(".")[1]
            role = case["id"].split(".")[2]
            if role in {"local", "live"}:
                role = "admin"
            status, code = "PASS", "verified"
            evidence = {"real_browser": True, "real_portal_backend": True,
                        "mocked_identity": local, "mocked_control_plane": local,
                        "mocked_workload": local}
            try:
                entry, origin = ({}, targets[portal]) if local else target_config(config, portal)
                execute = ".execute-" in case["id"]
                saved = case["id"].endswith(".saved-policy")
                settings_case = case["id"].endswith(".risk-settings")
                permit = {}
                if case["mutation"] and not local:
                    permit = entry.get("execute_read", {})
                    if (not isinstance(permit, dict) or permit.get("enabled") is not True or
                            permit.get("dedicated_test_environment") is not True or
                            not isinstance(permit.get("caller_name"), str) or
                            not isinstance(permit.get("caller_key"), str) or
                            not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", permit["caller_key"]) or
                            not re.fullmatch(r"[A-Za-z0-9 _-]{1,64}", permit["caller_name"])):
                        raise CaseProblem("SKIPPED", "mutation_disabled")
                denied = case["id"].endswith("-deny")
                execute_payload = {
                    "caller": "budget-report" if local else permit.get("caller_key"),
                    "method": "POST" if denied else "GET",
                    "path": "/budget/submit" if denied else "/budget/read",
                } if execute else None
                saved_name = "browser-" + uuid.uuid4().hex[:12] if saved else None
                session = None if local or role == "anonymous" else load_session(entry, portal, role, origin)
                with browser.new_context(
                    storage_state=session["storage_state"] if session else None,
                    service_workers="block", accept_downloads=False,
                ) as context:
                    context.set_default_timeout(12000)
                    if session:
                        restore_session(context, session)
                    page = context.new_page()
                    blocked_writes = route_boundary(context, origin, role, local,
                                                    execute_payload=execute_payload, saved_name=saved_name,
                                                    settings_mutation=settings_case)
                    errors = []
                    page.on("pageerror", lambda _error: errors.append(True))
                    page.goto(origin + "/", wait_until="domcontentloaded")
                    assert_access(page, portal, role, live=not local)
                    if case["id"].endswith(".navigation"):
                        evidence.update(management_navigation(page) if portal == "management"
                                        else security_navigation(page))
                    elif execute:
                        name = "BudgetReport" if local else entry["execute_read"]["caller_name"]
                        evidence.update(execute_read(page, name, denied=denied))
                    elif saved:
                        evidence.update(saved_policy(page, saved_name))
                    elif settings_case:
                        evidence.update(risk_settings_roundtrip(page))
                    require(not errors and not blocked_writes)
            except CaseProblem as exc:
                status, code = exc.status, exc.code
            except AssertionError:
                status, code = "FAIL", "assertion_failed"
            except PlaywrightError:
                status, code = "FAIL", "browser_error"
            except Exception:
                # Reporting boundary: never serialize browser errors, URLs, claims or tokens.
                status, code = "FAIL", "unexpected_error"
            rows.append(case_result(case, status, code, time.monotonic() - started,
                                    evidence if status == "PASS" else None))
    return rows
