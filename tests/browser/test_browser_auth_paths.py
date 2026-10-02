"""Capture file safety with synthetic browser state and no network access."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import auth_setup


class CaptureProblem(Exception):
    pass


class BrowserError(Exception):
    pass


class AuthPathTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.auth_dir = self.root / ".auth"
        self.auth_dir.mkdir()
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({
            "browser": {"management": {"url": "https://portal.example.test"}}
        }))
        self.session = self.auth_dir / "management-admin.json"
        self.session.write_text("previous-private-session")
        self.status = self.root / "status.json"
        self.output = io.StringIO()
        self.playwright = MagicMock()
        browser = self.playwright.return_value.__enter__.return_value.chromium.launch.return_value
        context = browser.new_context.return_value.__enter__.return_value
        context.storage_state.return_value = {"cookies": [], "origins": []}
        page = context.new_page.return_value
        page.url = "https://portal.example.test/"
        page.evaluate.return_value = {"msal.fixture": "synthetic-session"}
        engine = SimpleNamespace(
            AUTH_DIR=self.auth_dir, CaseProblem=CaptureProblem, assert_access=MagicMock(),
            route_boundary=MagicMock(return_value=[]),
            target_config=lambda config, portal: (config[portal], config[portal]["url"]),
        )
        modules = {
            "browser_engine": engine,
            "playwright.sync_api": SimpleNamespace(
                Error=BrowserError, sync_playwright=self.playwright),
        }
        for mocked in (
                patch.dict(sys.modules, modules),
                patch.dict(os.environ, {}, clear=True),
                patch.object(auth_setup, "wait_for_sign_in")):
            mocked.start()
            self.addCleanup(mocked.stop)

    def capture(self, status_path):
        with redirect_stdout(self.output):
            return auth_setup.main([
                "--config", str(self.config), "--portal", "management",
                "--role", "admin", "--auto-capture", "--status-output", str(status_path),
            ])

    def assert_collision_blocked(self, status_path):
        before_config = self.config.read_bytes()
        before_session = self.session.read_bytes() if self.session.exists() else None
        with patch.object(auth_setup, "write_private_json",
                          wraps=auth_setup.write_private_json) as write:
            result = self.capture(status_path)
        self.assertEqual(self.config.read_bytes(), before_config)
        if before_session is None:
            self.assertFalse(self.session.exists())
        else:
            self.assertEqual(self.session.read_bytes(), before_session)
        self.assertEqual(result, 2)
        self.assertIn("BLOCKED:", self.output.getvalue())
        self.assertNotIn("Captured private", self.output.getvalue())
        write.assert_not_called()
        self.playwright.assert_not_called()

    def test_status_cannot_replace_config(self):
        self.assert_collision_blocked(self.config)

    def test_status_cannot_replace_existing_session(self):
        self.assert_collision_blocked(self.session)

    def test_status_cannot_replace_future_session(self):
        self.session.unlink()
        self.assert_collision_blocked(self.session)

    def test_normalized_config_alias_is_rejected(self):
        nested = self.root / "nested"
        nested.mkdir()
        self.assert_collision_blocked(nested / ".." / self.config.name)

    def test_normalized_session_alias_is_rejected(self):
        self.assert_collision_blocked(self.auth_dir / ".." / ".auth" / self.session.name)

    def test_relative_config_alias_is_rejected(self):
        self.assert_collision_blocked(Path(os.path.relpath(self.config)))

    def test_hard_link_to_config_is_rejected(self):
        self.status.hardlink_to(self.config)
        self.assert_collision_blocked(self.status)

    def test_hard_link_to_session_is_rejected(self):
        self.status.hardlink_to(self.session)
        self.assert_collision_blocked(self.status)

    def test_symlink_to_config_is_rejected_before_status_write(self):
        self.status.symlink_to(self.config)
        self.assert_collision_blocked(self.status)

    def test_symlink_to_session_is_rejected_before_status_write(self):
        self.status.symlink_to(self.session)
        self.assert_collision_blocked(self.status)

    def test_distinct_output_preserves_config_and_captures_session(self):
        before = self.config.read_bytes()
        self.assertEqual(self.capture(self.status), 0)
        self.assertEqual(self.config.read_bytes(), before)
        session = json.loads(self.session.read_text())
        self.assertEqual(session["session_storage"], {"msal.fixture": "synthetic-session"})
        self.assertNotIn("status", session)
        status = json.loads(self.status.read_text())
        self.assertEqual(status["status"], "CAPTURED")
        self.assertNotIn("session_storage", status)
        self.assertEqual(self.session.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.status.stat().st_mode & 0o777, 0o600)
        self.assertIn("Captured private", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
