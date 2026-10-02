"""Check instrumentation observes real handlers without replacing their results."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


class ApplicationFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import httpx
        self.httpx = httpx
        path = Path(__file__).with_name("apps.py")
        self.assertTrue(path.exists(), "Connected real-app bootstrap is missing")
        spec = importlib.util.spec_from_file_location("connected_apps", path)
        self.apps = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.apps
        spec.loader.exec_module(self.apps)

    async def test_backend_preserves_business_handler_and_counts_dispatch(self):
        app = self.apps.backend_app()
        async with self.httpx.AsyncClient(
                transport=self.httpx.ASGITransport(app=app, client=("127.0.0.1", 9999)),
                base_url="http://127.0.0.1") as client:
            response = await client.get("/budget/read", headers={"X-SPIFFE-Caller-ID": "fixture-caller"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["data"]["total_budget"], 2500000)
            self.assertEqual(response.json()["identity_chain"]["spiffe_id"], "fixture-caller")
            evidence = (await client.get("/__test/evidence")).json()
            self.assertEqual(evidence, {"requests": 1, "caller": "fixture-caller"})
            await client.post("/__test/reset")
            self.assertEqual((await client.get("/__test/evidence")).json()["requests"], 0)

    async def test_backend_localhost_enforcement_is_not_disabled(self):
        app = self.apps.backend_app()
        async with self.httpx.AsyncClient(
                transport=self.httpx.ASGITransport(app=app, client=("192.0.2.7", 9999)),
                base_url="http://127.0.0.1") as client:
            response = await client.get("/budget/read")
            self.assertEqual(response.status_code, 403)

    async def test_backend_instrumentation_is_not_remotely_readable(self):
        app = self.apps.backend_app()
        async with self.httpx.AsyncClient(
                transport=self.httpx.ASGITransport(app=app, client=("192.0.2.7", 9999)),
                base_url="http://127.0.0.1") as client:
            response = await client.get("/__test/evidence")
            self.assertEqual(response.status_code, 403)

    async def test_network_guard_rejects_remote_urls_and_redirects(self):
        guard = self.apps.LocalHTTP(["http://127.0.0.1:12345"])
        for target in ("https://graph.microsoft.com/", "http://localhost:12345/",
                       "http://127.0.0.1:9999/", "http://user:pass@127.0.0.1:12345/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                await guard.check(self.httpx.Request("GET", target))
        await guard.check(self.httpx.Request("GET", "http://127.0.0.1:12345/budget/read"))
        async with guard.AsyncClient() as client:
            self.assertFalse(client.follow_redirects)

    async def test_portal_startup_requires_explicit_loopback_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.apps.portal_app({
                    "caller_url": "https://production.invalid", "management_url": "http://127.0.0.1:1",
                    "caller_spiffe_id": "spiffe://connected.test/report",
                }, Path(directory))

    async def test_security_portal_requires_backend_admin_for_risk_write(self):
        self.assertTrue(hasattr(self.apps, "security_app"), "Real connected Security Portal missing")
        app = self.apps.security_app({
            "caller_url": "http://127.0.0.1:12345", "management_url": "http://127.0.0.1:12346",
            "caller_spiffe_id": "spiffe://connected.test/report", "admin_key": "fixture-only",
        })
        async with self.httpx.AsyncClient(
                transport=self.httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
            for token, expected in (("fixture-viewer", 403), ("fixture-admin", 422)):
                response = await client.put("/set-risk", headers={"Authorization": "Bearer " + token}, json={})
                self.assertEqual(response.status_code, expected)


if __name__ == "__main__":
    unittest.main()
