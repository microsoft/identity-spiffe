#!/usr/bin/env python3
"""
CI tests for all Python agent apps.

Validates that each agent:
  1. Imports without errors
  2. Creates a valid FastAPI application
  3. Responds to GET /health with status 200 and expected fields
  4. Rejects disallowed methods/paths via /call-backend-raw (where applicable)
  5. Enforces admin key on sensitive endpoints (where applicable)
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

# Ensure src/ is importable
SRC_DIR = Path(__file__).resolve().parent

# Ensure shared modules (ca_evaluator.py) are importable by agent apps
_shared_dir = str(SRC_DIR / "shared")
if _shared_dir not in sys.path:
    sys.path.insert(0, _shared_dir)


def _load_app(agent_dir: str):
    """Load an agent's app.py module and return its FastAPI app."""
    app_path = SRC_DIR / agent_dir / "app.py"
    if not app_path.exists():
        raise FileNotFoundError(f"{app_path} not found")
    spec = importlib.util.spec_from_file_location(f"{agent_dir}_app", app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {app_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


# ---------------------------------------------------------------------------
# Lazy import — httpx is needed for TestClient but may not be installed yet
# when the module is first parsed.
# ---------------------------------------------------------------------------
_TestClient = None


def _get_test_client():
    global _TestClient
    if _TestClient is None:
        from starlette.testclient import TestClient
        _TestClient = TestClient
    return _TestClient


# ---------------------------------------------------------------------------
# Per-agent test suites
# ---------------------------------------------------------------------------

class TestBudgetReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_app("budget-report")
        cls.client = _get_test_client()(cls.app)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("agent", data)
        self.assertIn("role", data)

    def test_call_backend_raw_rejects_bad_method(self):
        """call-backend-raw requires admin key; with key set, bad method → 400."""
        os.environ["MGMT_API_KEY"] = "test-raw-key"
        import importlib
        app_path = SRC_DIR / "budget-report" / "app.py"
        spec = importlib.util.spec_from_file_location("br_raw_method", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        resp = client.post(
            "/call-backend-raw",
            params={"method": "TRACE", "path": "/budget/read"},
            headers={"X-AIM-Admin-Key": "test-raw-key"},
        )
        data = resp.json()
        self.assertEqual(data.get("http_status"), 400)
        self.assertIn("not allowed", data.get("error", "").lower())
        os.environ.pop("MGMT_API_KEY", None)

    def test_call_backend_raw_rejects_bad_path(self):
        """call-backend-raw requires admin key; with key set, bad path → 400."""
        os.environ["MGMT_API_KEY"] = "test-raw-key"
        import importlib
        app_path = SRC_DIR / "budget-report" / "app.py"
        spec = importlib.util.spec_from_file_location("br_raw_path", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        resp = client.post(
            "/call-backend-raw",
            params={"method": "GET", "path": "/mgmt/policy"},
            headers={"X-AIM-Admin-Key": "test-raw-key"},
        )
        data = resp.json()
        self.assertEqual(data.get("http_status"), 400)
        self.assertIn("not allowed", data.get("error", "").lower())
        os.environ.pop("MGMT_API_KEY", None)

    def test_flush_token_requires_admin_key(self):
        os.environ["MGMT_API_KEY"] = "test-key-123"
        # Reload to pick up the env var — but ADMIN_KEY is read at import time,
        # so we patch it directly.
        import importlib
        app_path = SRC_DIR / "budget-report" / "app.py"
        spec = importlib.util.spec_from_file_location("br_reload", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        # No key → 401
        resp = client.post("/flush-token")
        self.assertEqual(resp.status_code, 401)
        # Wrong key → 401
        resp = client.post("/flush-token", headers={"X-AIM-Admin-Key": "wrong"})
        self.assertEqual(resp.status_code, 401)
        # Correct key → 200
        resp = client.post("/flush-token", headers={"X-AIM-Admin-Key": "test-key-123"})
        self.assertEqual(resp.status_code, 200)
        os.environ.pop("MGMT_API_KEY", None)


class TestBudgetBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["ALLOW_REMOTE_ACCESS"] = "true"
        cls.app = _load_app("budget-backend")
        cls.client = _get_test_client()(cls.app)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("ALLOW_REMOTE_ACCESS", None)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")

    def test_budget_read(self):
        resp = self.client.get("/budget/read")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("data", data)

    def test_budget_submit(self):
        resp = self.client.post("/budget/submit", json={"amount": 1000, "description": "test"})
        self.assertEqual(resp.status_code, 200)


class TestBudgetApproval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_app("budget-approval")
        cls.client = _get_test_client()(cls.app)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")

    def test_call_backend_raw_rejects_bad_path(self):
        """call-backend-raw requires admin key; with key set, bad path → 400."""
        os.environ["MGMT_API_KEY"] = "test-raw-key"
        import importlib
        app_path = SRC_DIR / "budget-approval" / "app.py"
        spec = importlib.util.spec_from_file_location("ba_raw_path", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        resp = client.post(
            "/call-backend-raw",
            params={"method": "GET", "path": "/mgmt/policy"},
            headers={"X-AIM-Admin-Key": "test-raw-key"},
        )
        data = resp.json()
        self.assertEqual(data.get("http_status"), 400)
        os.environ.pop("MGMT_API_KEY", None)

    def test_flush_token_requires_admin_key(self):
        os.environ["MGMT_API_KEY"] = "test-key-456"
        import importlib
        app_path = SRC_DIR / "budget-approval" / "app.py"
        spec = importlib.util.spec_from_file_location("ba_reload", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        resp = client.post("/flush-token")
        self.assertEqual(resp.status_code, 401)
        resp = client.post("/flush-token", headers={"X-AIM-Admin-Key": "test-key-456"})
        self.assertEqual(resp.status_code, 200)
        os.environ.pop("MGMT_API_KEY", None)

    def test_approval_status_rejects_no_jwt(self):
        """Layer 3: /approval/status must reject calls without a Bearer token."""
        resp = self.client.get("/approval/status")
        self.assertEqual(resp.status_code, 401)
        data = resp.json()
        self.assertEqual(data["error"], "missing_token")
        self.assertEqual(data["enforcement_layer"], "jwt")

    def test_approval_status_rejects_invalid_jwt(self):
        """Layer 3: /approval/status must reject invalid JWTs."""
        resp = self.client.get(
            "/approval/status",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.json()
        self.assertEqual(data["error"], "invalid_token")

    def test_approval_status_rejects_spoofed_header(self):
        """X-Caller-Agent header alone must NOT grant access when DEV_MODE is off."""
        resp = self.client.get(
            "/approval/status",
            headers={"X-Caller-Agent": "budget-report"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_approval_status_dev_mode_allows_header(self):
        """DEV_MODE=true should allow X-Caller-Agent fallback."""
        import importlib
        os.environ["DEV_MODE"] = "true"
        app_path = SRC_DIR / "budget-approval" / "app.py"
        spec = importlib.util.spec_from_file_location("ba_devmode", app_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = _get_test_client()(mod.app)
        resp = client.get(
            "/approval/status",
            headers={"X-Caller-Agent": "budget-report"},
        )
        # Should not be 401 — dev mode allows it (may be 403 from CA layer, that's ok)
        self.assertNotEqual(resp.status_code, 401)
        os.environ.pop("DEV_MODE", None)


class TestEmployeeMenus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_app("employee-menus")
        cls.client = _get_test_client()(cls.app)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")


class TestDemoAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _load_app("demo-agent")
        cls.client = _get_test_client()(cls.app)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
