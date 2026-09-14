"""Prepared-toolchain integration test of launcher, actual tunnel and cleanup."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler, Request


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("connected_runtime_test", HERE / "runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class ConnectedLauncherTests(unittest.TestCase):
    def test_actual_go_topology_self_test(self):
        try:
            result = runtime.self_test()
        except runtime.StackUnavailable as error:
            self.skipTest(str(error))
        self.assertEqual(result["status"], "PASS")
        self.assertIn("TestConnectedProductionClientAndServer", result["tests"])
        self.assertIn("TestRejectNonLoopbackBackend", result["tests"])

    def test_context_serves_real_stack_and_removes_ephemeral_process_state(self):
        dispatched = []

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                dispatched.append((self.path, self.headers.get("X-Spiffe-Caller-Id")))
                data = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        before = set(HERE.glob(".work-*"))
        client = build_opener(ProxyHandler({}))
        ready = None
        try:
            with runtime.running_stack(f"http://127.0.0.1:{server.server_port}") as ready:
                self.assertEqual(set(ready), {"egress_url", "management_url", "control_url",
                                             "caller_spiffe_id", "audience", "source_sha256"})
                self.assertRegex(ready["source_sha256"], r"^[a-f0-9]{64}$")
                with client.open(ready["control_url"] + "/token", timeout=3) as response:
                    token = json.load(response)["access_token"]
                request = Request(ready["egress_url"] + "/budget/read",
                                  headers={"Authorization": "Bearer " + token})
                with client.open(request, timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.load(response), {"ok": True})
                self.assertEqual(dispatched, [("/budget/read", ready["caller_spiffe_id"])])
                request = Request(ready["control_url"] + "/scenario",
                                  data=b'{"name":"jwt_missing"}',
                                  headers={"Content-Type": "application/json"})
                with client.open(request, timeout=10) as response:
                    self.assertEqual(json.load(response), {"scenario": "jwt_missing"})
                with self.assertRaises(HTTPError) as denial:
                    client.open(ready["egress_url"] + "/budget/read", timeout=10)
                self.assertEqual(denial.exception.code, 401)
                denial.exception.close()
                self.assertEqual(len(dispatched), 1)
                with client.open(ready["control_url"] + "/evidence", timeout=3) as response:
                    evidence = json.load(response)
                self.assertEqual(set(evidence), {"scenario", "audit", "mtls_rejections"})
                self.assertEqual(len(evidence["audit"]), 1)
                self.assertEqual(evidence["audit"][0]["enforcement_layer"], "oauth")
                self.assertEqual(evidence["audit"][0]["decision"], "deny")
        except runtime.StackUnavailable as error:
            self.skipTest(str(error))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        self.assertEqual(set(HERE.glob(".work-*")), before)
        with self.assertRaises(OSError):
            client.open(ready["control_url"] + "/health", timeout=1)


if __name__ == "__main__":
    unittest.main()
