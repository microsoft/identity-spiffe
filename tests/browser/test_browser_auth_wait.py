"""Dependency-free terminal confirmation and error propagation checks."""
import threading
import unittest
from unittest.mock import patch

import auth_setup


class AuthWaitTests(unittest.TestCase):
    def test_automatic_capture_waits_for_portal_token_without_terminal_input(self):
        self.assertTrue(hasattr(auth_setup, "wait_for_sign_in"), "Automatic capture is missing")
        from unittest.mock import Mock
        page = Mock()
        with patch("builtins.input", side_effect=AssertionError("Terminal input must not be required")):
            auth_setup.wait_for_sign_in(page, "https://portal.example.test", "management", 60)
        page.wait_for_function.assert_called_once()
        args = page.wait_for_function.call_args.kwargs
        self.assertEqual(args["arg"], {"origin": "https://portal.example.test", "token": "_accessToken"})
        self.assertEqual(args["timeout"], 60000)

    def test_confirmation_returns(self):
        with patch("builtins.input", return_value=""):
            auth_setup.wait_for_human(self)

    def test_terminal_failures_are_propagated(self):
        for error in (EOFError(), OSError(), ValueError(), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with patch("builtins.input", side_effect=error):
                    with self.assertRaises(type(error)):
                        auth_setup.wait_for_human(self)

    def test_confirmation_wait_has_a_deadline(self):
        release = threading.Event()
        with patch("builtins.input", side_effect=lambda _prompt: release.wait(1)):
            with patch.object(auth_setup.time, "monotonic", side_effect=[0, 2]):
                try:
                    with self.assertRaises(TimeoutError):
                        auth_setup.wait_for_human(self, timeout_seconds=1)
                finally:
                    release.set()

    def wait_for_timeout(self, _milliseconds):
        threading.Event().wait(0.001)


if __name__ == "__main__":
    unittest.main()
