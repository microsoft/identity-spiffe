"""The browser result alone must never establish connected enforcement."""
import importlib.util
from pathlib import Path
import unittest


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("evidence.py")
        cls.oracle = None
        if path.exists():
            spec = importlib.util.spec_from_file_location("connected_evidence", path)
            cls.oracle = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.oracle)

    def oracle_ready(self):
        self.assertIsNotNone(self.oracle, "Connected browser/backend evidence oracle is missing")
        return self.oracle

    def observed(self, **updates):
        value = {
            "scenario": "allowed", "status": 200, "badge": "200 ALLOWED",
            "caller_requests": 1, "backend_requests": 1,
            "backend_caller": "spiffe://connected.test/report",
            "audit": [{"caller_spiffe_id": "spiffe://connected.test/report",
                       "method": "GET", "path": "/budget/read", "decision": "allow",
                       "enforcement_layer": "oauth", "jwt_valid": True,
                       "jwt_present": True, "request_id": "unique-request"}],
            "mtls_rejections": 0, "blocked_browser_requests": 0,
        }
        value.update(updates)
        return value

    def test_all_three_surfaces_required_for_allowance(self):
        oracle = self.oracle_ready()
        case = oracle.specification("allowed")
        self.assertTrue(oracle.verify(case, self.observed(), "spiffe://connected.test/report"))
        for update in ({"caller_requests": 0}, {"backend_requests": 0}, {"audit": []},
                       {"backend_caller": "forged"}, {"badge": "403 RBAC DENY"},
                       {"blocked_browser_requests": 1}, {"scenario": "stale"}):
            with self.subTest(update=update):
                self.assertFalse(oracle.verify(case, self.observed(**update), "spiffe://connected.test/report"))

    def test_denial_requires_correct_layer_and_zero_backend_dispatch(self):
        oracle = self.oracle_ready()
        case = oracle.specification("jwt_expired")
        row = self.observed(scenario="jwt_expired", status=401, badge="401 OAuth DENY",
                            backend_requests=0)
        row["audit"][0].update(decision="deny", jwt_valid=False, reason="jwt_invalid")
        self.assertTrue(oracle.verify(case, row, "spiffe://connected.test/report"))
        for field, value in (("backend_requests", 1), ("audit", []), ("status", 502)):
            with self.subTest(field=field):
                self.assertFalse(oracle.verify(case, dict(row, **{field: value}),
                                               "spiffe://connected.test/report"))
        row["audit"][0]["enforcement_layer"] = "rbac"
        self.assertFalse(oracle.verify(case, row, "spiffe://connected.test/report"))

    def test_generic_transport_failure_is_not_mtls_denial(self):
        oracle = self.oracle_ready()
        case = oracle.specification("mtls_denied")
        row = self.observed(scenario="mtls_denied", status=0, badge="0 ERROR",
                            backend_requests=0, audit=[], mtls_rejections=0)
        self.assertFalse(oracle.verify(case, row, "spiffe://connected.test/report"))
        row["mtls_rejections"] = 1
        self.assertTrue(oracle.verify(case, row, "spiffe://connected.test/report"))

    def test_extra_or_stale_audit_cannot_pass(self):
        oracle = self.oracle_ready()
        row = self.observed()
        row["audit"] *= 2
        self.assertFalse(oracle.verify(oracle.specification("allowed"), row,
                                       "spiffe://connected.test/report"))

    def test_missing_risk_is_not_redefined_as_allowance(self):
        oracle = self.oracle_ready()
        case = oracle.specification("ca_missing_risk")
        self.assertFalse(oracle.verify(case, self.observed(scenario="ca_missing_risk"),
                                       "spiffe://connected.test/report"))


if __name__ == "__main__":
    unittest.main()
