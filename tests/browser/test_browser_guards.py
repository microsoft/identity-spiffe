"""Dependency-free regression tests for browser credential/report boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


class BrowserGuardTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("browser_guards.py")
        self.assertTrue(path.exists(), "browser session/report guards must be implemented")
        spec = importlib.util.spec_from_file_location("identity_browser_guards_test", path)
        self.guards = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guards)
        self.session = {
            "version": 1, "portal": "management", "role": "viewer",
            "origin": "https://portal.example.test",
            "created_at": time.time() - 10, "expires_at": time.time() + 600,
            "storage_state": {"cookies": [], "origins": []},
            "session_storage": {"msal.account.keys": '["fixture"]'},
        }

    def validate(self, value=None, **kwargs):
        return self.guards.validate_session(
            self.session if value is None else value,
            portal=kwargs.get("portal", "management"),
            role=kwargs.get("role", "viewer"),
            origin=kwargs.get("origin", "https://portal.example.test"),
        )

    def test_valid_session(self):
        self.assertEqual(self.validate(), self.session)

    def test_remote_browser_environment_is_rejected(self):
        for name in ("SELENIUM_REMOTE_URL", "SELENIUM_REMOTE_HEADERS", "SELENIUM_REMOTE_CAPABILITIES"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.guards.validate_debug_environment({name: "fixture-value"})

    def test_block_diagnostic_never_contains_url_credentials_or_query(self):
        self.assertTrue(hasattr(self.guards, "describe_block"), "Safe blocked-request diagnostics missing")
        result = self.guards.describe_block(
            "https://user:private-password@login.microsoft.com/tenant/bridge/fido?code=private-code#private-state",
            "destination_or_write")
        self.assertEqual(result, {"hostname": "login.microsoft.com", "reason": "destination_or_write"})
        self.assertNotIn("private", json.dumps(result))

    def test_rejects_wrong_role_portal_origin_and_expired_state(self):
        for key, value in [
            ("role", "admin"), ("portal", "security"),
            ("origin", "https://other.example.test"), ("expires_at", time.time() - 1),
            ("created_at", time.time() + 100), ("version", 2),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(dict(self.session, **{key: value}))

    def test_rejects_storage_state_without_msal_session_storage(self):
        for value in ({}, {"unrelated": "value"}, {"msal.key": 123}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(dict(self.session, session_storage=value))

    def test_rejects_cross_origin_storage_and_identity_provider_cookies(self):
        for state in [
            {"cookies": [], "origins": [{"origin": "https://login.example.test", "localStorage": []}]},
            {"cookies": [{"domain": ".example.test"}], "origins": []},
            {"cookies": [], "origins": "invalid"},
        ]:
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.validate(dict(self.session, storage_state=state))

    def test_rejects_nonfinite_times_and_unbounded_lifetime(self):
        for expiry in (float("nan"), float("inf"), time.time() + 100000):
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                self.validate(dict(self.session, expires_at=expiry))

    def test_live_origin_rejects_credentials_http_paths_queries_fragments(self):
        for url in [
            "http://localhost:8000", "https://user:secret@example.test",
            "https://example.test/path", "https://example.test?token=secret",
            "https://example.test#fragment", "https://127.0.0.1", "not a URL",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.guards.live_origin(url)
        self.assertEqual(self.guards.live_origin("https://portal.example.test/"),
                         "https://portal.example.test")

    def test_private_session_file_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "viewer.json"
            self.guards.write_private_json(path, self.session)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), self.session)
            link = Path(directory).resolve() / "link.json"
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                self.guards.write_private_json(link, {})
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                self.guards.read_private_json(path)

    def test_reports_only_allowlisted_observations_and_evidence(self):
        descriptor = {"id": "browser.example", "suite": "browser", "layer": "operator",
                      "profiles": ["live"], "description": "Example",
                      "expected": "Example", "mutation": False}
        row = self.guards.case_result(descriptor, "BLOCKED", "session_missing", 0.1)
        self.assertEqual(row["status"], "BLOCKED")
        self.assertEqual(row["observed"], "Session missing; run human-assisted auth setup.")
        for status, code, seconds in [
            ("PASS", "Bearer secret", 0), ("MAYBE", "verified", 0),
            ("PASS", "verified", float("nan")), ("PASS", "verified", -1),
        ]:
            with self.assertRaises(ValueError):
                self.guards.case_result(descriptor, status, code, seconds)
        with self.assertRaises(ValueError):
            self.guards.case_result(descriptor, "PASS", "verified", 1,
                                    {"token": "secret"})

    def test_write_scope_matches_exact_method_path_and_payload(self):
        expected = {"caller": "budget-report", "method": "GET", "path": "/budget/read"}
        self.assertTrue(hasattr(self.guards, "allowed_write"), "exact write guard is required")
        allowed = self.guards.allowed_write
        self.assertTrue(allowed("/api/execute", "POST", "{}", role="viewer"))
        self.assertTrue(allowed("/set-risk", "PUT", "{}", role="viewer"))
        self.assertFalse(allowed("/set-risk?risk_level=high", "PUT", "{}", role="viewer"))
        self.assertFalse(allowed("/api/execute", "POST", json.dumps(expected), role="viewer"))
        self.assertTrue(allowed("/api/execute", "POST", json.dumps(expected),
                                role="admin", execute_payload=expected))
        for payload in [
            dict(expected, caller="other"), dict(expected, method="DELETE"),
            dict(expected, path="/budget/admin"), dict(expected, extra=True),
        ]:
            self.assertFalse(allowed("/api/execute", "POST", json.dumps(payload),
                                     role="admin", execute_payload=expected))
        self.assertFalse(allowed("/api/policy", "PUT", "{}", role="admin"))
        self.assertFalse(allowed("/api/policy-configs/anything", "DELETE", None,
                                 role="admin", saved_name="browser-scoped"))
        self.assertTrue(allowed("/api/policy-configs/browser-scoped", "DELETE", None,
                                role="admin", saved_name="browser-scoped"))

    def test_unsafe_inherited_browser_debugging_is_rejected(self):
        self.assertTrue(hasattr(self.guards, "validate_debug_environment"))
        self.guards.validate_debug_environment({})
        self.guards.validate_debug_environment({"DEBUG": ""})
        for name in ("DEBUG", "PWDEBUG", "DEBUG_FILE", "NODE_OPTIONS"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.guards.validate_debug_environment({name: "enabled"})

    def test_admin_probe_only_permits_empty_schema_invalid_requests(self):
        for path, method in (("/api/execute", "POST"), ("/set-risk", "PUT")):
            self.assertTrue(self.guards.allowed_write(path, method, "{}", role="admin"))
            self.assertFalse(self.guards.allowed_write(
                path + "?spiffe_id=test&risk_level=low", method, "{}", role="admin"))
            self.assertFalse(self.guards.allowed_write(
                path, method, '{"caller":"budget-report"}', role="admin"))
            self.assertFalse(self.guards.allowed_write(path, method, "{}", role="unassigned"))


if __name__ == "__main__":
    unittest.main()
