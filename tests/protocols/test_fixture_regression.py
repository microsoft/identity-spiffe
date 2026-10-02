"""Go-backed harness regression: metadata outages cannot prove JWT rejection.

Requires the same offline Go/protobuf prerequisites as the protocol matrix.
Fault injection changes only the adapter's temporary copy of a test fixture.
"""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
JWT_CASES = (
    "jwt_malformed", "jwt_bad_signature", "jwt_wrong_audience", "jwt_wrong_issuer",
    "jwt_expired", "jwt_future", "jwt_no_expiry",
)


class FixtureRegressionTests(unittest.TestCase):
    def test_metadata_outage_cannot_satisfy_negative_jwt_case(self):
        spec = importlib.util.spec_from_file_location("protocol_adapter", HERE / "run.py")
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        original_invoke = adapter.invoke
        for route in ("/fixture-tenant/v2.0/.well-known/openid-configuration", "/fixture-jwks"):
            with self.subTest(route=route):
                completions = []

                def inject_outage(command, cwd, env, timeout=180):
                    if len(command) > 1 and command[1] == "test":
                        fixture = Path(cwd) / "fixtures_test.go"
                        self.assertNotEqual(fixture.resolve(), (HERE / "fixtures_test.go").resolve())
                        source = fixture.read_text(encoding="utf-8")
                        anchor = '\t\tw.Header().Set("Content-Type", "application/json")'
                        self.assertEqual(source.count(anchor), 1, "Fixture injection anchor changed")
                        replacement = (
                            f'\t\tif req.URL.Path == "{route}" {{\n'
                            '\t\t\tw.WriteHeader(http.StatusServiceUnavailable)\n'
                            '\t\t\treturn\n\t\t}\n' + anchor
                        )
                        fixture.write_text(source.replace(anchor, replacement), encoding="utf-8")
                        pattern = "^TestEnforcement$/^(" + "|".join(JWT_CASES) + ")$"
                        command = command[:-1] + ["-run", pattern, command[-1]]
                        completed = original_invoke(command, cwd, env, timeout)
                        completions.append(completed)
                        return completed
                    return original_invoke(command, cwd, env, timeout)

                with patch.object(adapter, "invoke", side_effect=inject_outage):
                    results = adapter.run_cases("local")
                self.assertEqual(len(completions), 1, "Go/protobuf prerequisites must be prepared")
                completed = completions[0]
                events = [json.loads(line) for line in completed.stdout.splitlines()]
                actions = {}
                for event in events:
                    if event.get("Package") == adapter.TEST_PACKAGE and event.get("Test"):
                        actions.setdefault(event["Test"], []).append(event["Action"])
                by_id = {case["id"]: case for case in results}
                for name in JWT_CASES:
                    test_name = "TestEnforcement/" + name
                    self.assertIn("run", actions.get(test_name, []), "Actual Go subtest must execute")
                    self.assertIn(
                        "fail", actions.get(test_name, []),
                        f"{test_name} falsely passed with unavailable token-validation metadata",
                    )
                    result = by_id["protocols.enforcement." + name]
                    self.assertEqual(result["status"], "FAIL")
                    self.assertTrue(result["observed"].startswith("Actual Go assertion failed"))
                self.assertEqual(completed.returncode, 1)


if __name__ == "__main__":
    unittest.main()
