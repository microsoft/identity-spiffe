import importlib.util
from pathlib import Path
import unittest
from urllib.parse import quote


class GovernanceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("governance.py")
        cls.module = None
        if path.exists():
            spec = importlib.util.spec_from_file_location("connected_governance", path)
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)

    def test_risk_write_guard_is_exactly_scoped(self):
        self.assertIsNotNone(self.module, "Connected governance journey missing")
        identity = "spiffe://connected.test/report"
        guard = self.module.risk_guard(identity)
        path = "/set-risk?spiffe_id=" + quote(identity, safe="") + "&risk_level=high"
        self.assertTrue(guard(path, "PUT", None, role="admin"))
        for update in (
            (path, "POST", None, "admin"), (path, "PUT", "{}", "admin"),
            (path, "PUT", None, "viewer"), (path + "&scope=all", "PUT", None, "admin"),
            (path.replace("report", "other"), "PUT", None, "admin"),
            (path.replace("high", "unknown"), "PUT", None, "admin"),
        ):
            with self.subTest(update=update):
                self.assertFalse(guard(*update[:3], role=update[3]))


if __name__ == "__main__":
    unittest.main()
