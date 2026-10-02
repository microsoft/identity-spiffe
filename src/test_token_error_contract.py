"""Regression tests for safe token-error handling in deployable agents."""

import ast
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent
TOKEN_MODULE_DIRS = (
    "admin-control-plane",
    "budget-approval",
    "budget-backend",
    "budget-report",
    "demo-agent",
    "employee-menus",
)


class TestTokenExchangeCopies(unittest.TestCase):
    def test_service_copies_match_shared_module(self):
        shared = (SRC_DIR / "shared" / "entra_token_exchange.py").read_bytes()

        for service in TOKEN_MODULE_DIRS:
            with self.subTest(service=service):
                service_copy = (
                    SRC_DIR / service / "entra_token_exchange.py"
                ).read_bytes()
                self.assertEqual(
                    service_copy,
                    shared,
                    f"{service} token exchange module drifted from src/shared",
                )


class TestTokenErrorResponses(unittest.TestCase):
    def test_apps_do_not_return_raw_token_errors(self):
        unsafe_locations = []

        for app_path in SRC_DIR.glob("*/app.py"):
            tree = ast.parse(app_path.read_text(), filename=str(app_path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                for key, value in zip(node.keys, node.values):
                    if not (
                        isinstance(key, ast.Constant)
                        and key.value == "detail"
                    ):
                        continue
                    if any(
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Name)
                        and child.func.id == "get_last_token_error"
                        for child in ast.walk(value)
                    ):
                        unsafe_locations.append(f"{app_path}:{node.lineno}")

        self.assertEqual(
            unsafe_locations,
            [],
            "raw token errors are returned in client-facing detail fields",
        )


if __name__ == "__main__":
    unittest.main()
