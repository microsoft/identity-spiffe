"""Actual Chromium security regressions, run separately from dependency-free tests."""
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import time
import io
import json
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@contextmanager
def redirect_server(destination=None, script_target=None):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            received.append((self.command, self.path))
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            if self.path in {"/redirect", "/api/execute"}:
                self.send_response(307)
                self.send_header("Location", destination or "/forbidden-write")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<!doctype html><title>Redirect regression</title>")
                if script_target:
                    self.wfile.write((
                        "<script>fetch(" + json.dumps(script_target) +
                        ", {method:'POST',body:'{}'}).catch(()=>{});</script>").encode())

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class BrowserBoundaryRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import browser_engine
            from playwright.sync_api import Error, sync_playwright
        except ImportError:
            raise unittest.SkipTest("Browser/runtime dependencies unavailable") from None
        cls.engine = browser_engine
        cls.browser_error = Error
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True, timeout=15000)
        except Error:
            raise unittest.SkipTest("Matching Chromium unavailable") from None
        cls.addClassCleanup(cls.browser.close)

    def test_cross_origin_get_redirect_never_reaches_destination(self):
        with redirect_server() as (other, received):
            with redirect_server(other + "/escaped") as (origin, _):
                with self.browser.new_context(service_workers="block") as context:
                    page = context.new_page()
                    blocked = self.engine.route_boundary(context, origin, "admin", True)
                    try:
                        page.goto(origin + "/redirect", timeout=5000)
                    except self.browser_error:
                        pass
                    self.assertEqual(received, [])
                    self.assertTrue(blocked)

    def test_execute_307_never_dispatches_forbidden_post(self):
        with redirect_server() as (origin, received):
            with self.browser.new_context(service_workers="block") as context:
                payload = {"caller": "budget-report", "method": "GET", "path": "/budget/read"}
                page = context.new_page()
                blocked = self.engine.route_boundary(
                    context, origin, "admin", True, execute_payload=payload)
                page.goto(origin, timeout=5000)
                page.evaluate("""async body => {
                    try { await fetch('/api/execute', {method:'POST',
                        headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); }
                    catch (_) {}
                }""", payload)
                self.assertIn(("POST", "/api/execute"), received)
                self.assertNotIn(("POST", "/forbidden-write"), received)
                self.assertTrue(blocked)

    def test_api_probe_does_not_follow_redirect(self):
        with redirect_server() as (other, received):
            with redirect_server(other + "/escaped") as (origin, _):
                with self.browser.new_context(service_workers="block") as context:
                    page = context.new_page()
                    self.engine.route_boundary(context, origin, "admin", True)
                    page.goto(origin, timeout=5000)
                    with self.assertRaises(self.browser_error):
                        self.engine.request_summary(page, "management", "/redirect")
                    self.assertEqual(received, [])

    def test_allowed_navigation_redirect_remains_functional(self):
        with redirect_server("/landing") as (origin, received):
            with self.browser.new_context(service_workers="block") as context:
                page = context.new_page()
                blocked = self.engine.route_boundary(
                    context, origin, "admin", False, human_login=True)
                page.goto(origin + "/redirect", timeout=5000)
                self.assertEqual(page.url, origin + "/landing")
                self.assertIn(("GET", "/landing"), received)
                self.assertEqual(blocked, [])

    def test_fido_bridge_is_allowed_only_during_human_sign_in(self):
        for host, human_login, allowed in (
            ("login.microsoft.com", True, True),
            ("login.microsoft.com", False, False),
            ("login.microsoft.com.example.invalid", True, False),
            ("login.live.com", True, True),
            ("login.live.com", False, False),
            ("browser.events.data.microsoft.com", True, True),
            ("browser.events.data.microsoft.com", False, False),
            ("browser.events.data.microsoft.com.example.invalid", True, False),
        ):
            with self.subTest(host=host, human_login=human_login):
                with redirect_server() as (identity_server, received):
                    destination = identity_server + "/fixture-tenant/bridge/fido"
                    with redirect_server(destination) as (origin, _):
                        split = self.engine.urlsplit

                        def mapped_url(value):
                            parsed = split(value)
                            if parsed.netloc == split(identity_server).netloc:
                                return parsed._replace(scheme="https", netloc=host)
                            return parsed

                        with self.browser.new_context(service_workers="block") as context:
                            page = context.new_page()
                            with patch.object(self.engine, "urlsplit", side_effect=mapped_url):
                                blocked = self.engine.route_boundary(
                                    context, origin, "admin", False, human_login=human_login)
                                try:
                                    page.goto(origin + "/redirect", timeout=5000)
                                except self.browser_error:
                                    pass
                            reached = ("GET", "/fixture-tenant/bridge/fido") in received
                            self.assertEqual(reached, allowed)
                            self.assertEqual(bool(blocked), not allowed)

    def test_frontend_admin_backend_viewer_is_rejected(self):
        original = self.engine.fixture_msal
        # Keep the real frontend's admin group, but present a backend viewer token.
        def disagreeing_msal(role):
            return original(role).replace('"fixture-admin"', '"fixture-viewer"')

        for portal in ("management", "security"):
            with self.subTest(portal=portal):
                with self.engine.local_target(portal) as origin:
                    with self.browser.new_context(service_workers="block") as context:
                        with patch.object(self.engine, "fixture_msal", disagreeing_msal):
                            page = context.new_page()
                            self.engine.route_boundary(context, origin, "admin", True)
                            page.goto(origin, timeout=10000)
                            with self.assertRaises(self.engine.CaseProblem) as rejected:
                                self.engine.assert_access(page, portal, "admin", False)
                            self.assertEqual(rejected.exception.status, "FAIL")

    def test_auto_capture_saves_only_after_real_app_role_validation(self):
        import auth_setup
        with tempfile.TemporaryDirectory() as temporary, self.engine.local_target("management") as origin:
            directory = Path(temporary).resolve()
            browser = self.playwright.chromium.launch(headless=True)
            context = browser.new_context(service_workers="block")
            context.add_init_script("sessionStorage.setItem('msal.fixture', 'fixture-only')")
            boundary = self.engine.route_boundary
            output = io.StringIO()

            def local_boundary(ctx, url, role, _local, **kwargs):
                return boundary(ctx, url, role, True, on_block=kwargs.get("on_block"))

            with (
                patch("playwright.sync_api.sync_playwright", return_value=nullcontext(self.playwright)),
                patch.object(type(self.playwright.chromium), "launch", return_value=browser),
                patch.object(type(browser), "new_context", return_value=context),
                patch.object(auth_setup.sys.stdin, "isatty", return_value=False),
                patch("builtins.input", side_effect=AssertionError("No terminal confirmation")),
                patch.object(auth_setup.Path, "read_text", return_value='{"browser":{}}'),
                patch.object(self.engine, "target_config", return_value=({}, origin)),
                patch.object(self.engine, "route_boundary", side_effect=local_boundary),
                patch.object(self.engine, "AUTH_DIR", directory / "auth"),
                redirect_stdout(output),
            ):
                result = auth_setup.main([
                    "--config", "unused", "--portal", "management", "--role", "admin",
                    "--auto-capture", "--status-output", str(directory / "status.json"),
                ])
            self.assertEqual(result, 0)
            self.assertIn("DO NOT CLOSE THIS TERMINAL", output.getvalue())
            self.assertIn("stop authentication", output.getvalue())
            self.assertLess(output.getvalue().index("DO NOT CLOSE THIS TERMINAL"),
                            output.getvalue().index("Captured private"))
            self.assertEqual(json.loads((directory / "status.json").read_text())["status"], "CAPTURED")
            session = directory / "auth" / "management-admin.json"
            self.assertTrue(session.exists())
            self.assertEqual(session.stat().st_mode & 0o777, 0o600)

    def test_empty_security_inventory_reports_api_failure_not_missing_deployment(self):
        from playwright.sync_api import expect
        from browser_guards import OBSERVATIONS

        with self.engine.local_target("security") as origin:
            with self.browser.new_context(service_workers="block") as context:
                page = context.new_page()
                page.set_default_timeout(500)
                self.engine.route_boundary(context, origin, "admin", True)
                page.goto(origin)
                self.engine.assert_access(page, "security", "admin", False)
                expect(page.locator(".agent-card").first).to_be_visible()
                # Reproduce the empty API boundary without changing production code.
                page.route("**/api/agents", lambda route: route.fulfill(
                    status=200, content_type="application/json", body='{"agents":[]}'))
                try:
                    self.engine.security_navigation(page)
                except self.engine.CaseProblem as exc:
                    self.assertEqual(exc.code, "inventory_empty")
                    self.assertIn("/api/agents", OBSERVATIONS[exc.code])
                else:
                    self.fail("An empty inventory must be reported even when rendered cards are stale")

    def test_capture_assertion_failure_is_terminal_and_sanitized(self):
        import auth_setup
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            origin = "https://portal.example.test"
            output = io.StringIO()
            with (
                patch("playwright.sync_api.sync_playwright") as start,
                patch.object(auth_setup.Path, "read_text", return_value='{"browser":{}}'),
                patch.object(self.engine, "target_config", return_value=({}, origin)),
                patch.object(self.engine, "route_boundary", return_value=[]),
                patch.object(self.engine, "assert_access",
                             side_effect=AssertionError("private-assertion-actual-value")),
                patch.object(self.engine, "AUTH_DIR", directory / "auth"),
                redirect_stdout(output), redirect_stderr(output),
            ):
                page = start.return_value.__enter__.return_value.chromium.launch.return_value \
                    .new_context.return_value.__enter__.return_value.new_page.return_value
                page.url = origin
                try:
                    result = auth_setup.main([
                        "--config", "unused", "--portal", "management", "--role", "admin",
                        "--auto-capture", "--status-output", str(directory / "status.json"),
                    ])
                except AssertionError:
                    result = None
            status = json.loads((directory / "status.json").read_text())
            self.assertEqual(result, 1, "Capture must handle assertion failures, not escape")
            self.assertEqual((status["status"], status["reason"]), ("FAIL", "assertion_failed"))
            self.assertNotIn("private-assertion-actual-value", output.getvalue())
            self.assertNotIn("private-assertion-actual-value", json.dumps(status))
            self.assertFalse((directory / "auth" / "management-admin.json").exists())

    def test_auth_capture_pumps_network_before_human_presses_enter(self):
        import auth_setup
        with redirect_server() as (origin, received):
            browser = self.playwright.chromium.launch(headless=True, timeout=15000)
            context = browser.new_context(service_workers="block")
            context.add_init_script(
                "setTimeout(() => fetch('/human-progress').catch(() => {}), 300)")
            before_enter = []

            def human_input(_prompt):
                deadline = time.monotonic() + 2
                while ("GET", "/human-progress") not in received and time.monotonic() < deadline:
                    time.sleep(0.01)
                before_enter.append(("GET", "/human-progress") in received)
                return ""

            with (
                patch("playwright.sync_api.sync_playwright", return_value=nullcontext(self.playwright)),
                patch.object(type(self.playwright.chromium), "launch", return_value=browser),
                patch.object(type(browser), "new_context", return_value=context),
                patch.object(auth_setup.sys.stdin, "isatty", return_value=True),
                patch.object(auth_setup.Path, "read_text", return_value='{"browser":{}}'),
                patch.object(self.engine, "target_config", return_value=({}, origin)),
                patch.object(self.engine, "assert_access",
                             side_effect=self.engine.CaseProblem("BLOCKED", "session_rejected")),
                patch("builtins.input", side_effect=human_input),
                redirect_stdout(io.StringIO()),
            ):
                status = auth_setup.main([
                    "--config", "not-read.json", "--portal", "management", "--role", "admin"])
            self.assertEqual(status, 2)
            self.assertEqual(before_enter, [True], "Login HTTP must progress before Enter")

    def test_popup_is_denied_before_initial_request(self):
        with redirect_server() as (other, received), redirect_server() as (origin, _):
            with self.browser.new_context(service_workers="block") as context:
                page = context.new_page()
                blocked = self.engine.route_boundary(context, origin, "admin", True)
                page.goto(origin, timeout=5000)
                with page.expect_popup(timeout=5000) as opened:
                    page.evaluate("(url) => window.open(url)", other + "/escaped")
                try:
                    opened.value.wait_for_load_state("domcontentloaded", timeout=2000)
                except self.browser_error:
                    pass
                self.assertEqual(received, [])
                self.assertTrue(blocked)

    def test_cross_site_iframe_cannot_dispatch_unconfigured_post(self):
        with (
            redirect_server() as (other, received),
            redirect_server(script_target=other + "/escaped") as (child, _),
            redirect_server() as (origin, _),
            self.playwright.chromium.launch(headless=True, args=["--site-per-process"]) as browser,
            browser.new_context(service_workers="block") as context,
        ):
            child = child.replace("127.0.0.1", "localhost")
            original_split = self.engine.urlsplit

            def fixture_identity_origin(url):
                parsed = original_split(url)
                if url.startswith(child + "/"):
                    return parsed._replace(scheme="https", netloc="login.microsoftonline.com")
                return parsed

            page = context.new_page()
            # Only the in-memory allowlist comparison changes; HTTP stays loopback.
            with patch.object(self.engine, "urlsplit", fixture_identity_origin):
                blocked = self.engine.route_boundary(context, origin, "admin", False, human_login=True)
                page.goto(origin, timeout=5000)
                page.evaluate("""url => {
                    const frame = document.createElement('iframe');
                    frame.src = url;
                    document.body.appendChild(frame);
                }""", child + "/")
                page.wait_for_timeout(500)
                self.assertEqual(received, [])
                self.assertTrue(blocked)


if __name__ == "__main__":
    unittest.main()
