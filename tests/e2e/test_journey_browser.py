"""Actual Chromium regressions for repeatable connected-journey interactions."""
from pathlib import Path
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "browser"))


class JourneyBrowserTests(unittest.TestCase):
    def test_inherited_selenium_settings_never_contact_remote_service(self):
        import journeys
        from evidence import inventory
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.path)
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"value":{"error":"session not created","message":"fixture refusal"}}')

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        topology = {
            "egress_url": origin, "management_url": origin, "control_url": origin,
            "caller_spiffe_id": "spiffe://fixture/caller", "audience": "fixture", "source_sha256": "a" * 64,
        }
        try:
            with patch.dict(os.environ, {
                "SELENIUM_REMOTE_URL": origin, "SELENIUM_REMOTE_HEADERS": '{"Authorization":"fixture-only"}',
            }), patch.object(journeys, "application", side_effect=lambda *_: nullcontext(origin)), \
                    patch.object(journeys, "running_stack", return_value=nullcontext(topology)):
                rows = journeys.run_cases(inventory()[:1])
            self.assertEqual(requests, [], "Local E2E must not create any remote Selenium session")
            self.assertEqual(rows[0]["status"], "BLOCKED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_repeating_read_does_not_toggle_selected_caller_off(self):
        from playwright.sync_api import Error, sync_playwright
        from browser_engine import assert_access, local_target, route_boundary
        from journeys import click_execute
        from evidence import specification

        with local_target("management") as origin, sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                with browser.new_context(service_workers="block") as context:
                    context.set_default_timeout(1000)
                    page = context.new_page()
                    route_boundary(context, origin, "admin", True, execute_payload={
                        "caller": "budget-report", "method": "GET", "path": "/budget/read"})
                    page.goto(origin)
                    assert_access(page, "management", "admin", False)
                    outcomes = []
                    try:
                        for _ in range(2):
                            outcomes.append(click_execute(page, specification("allowed"))["status"])
                    except Error:
                        pass
                    self.assertEqual(outcomes, [200, 200],
                                     "Repeated execute must not deselect the current caller")
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
