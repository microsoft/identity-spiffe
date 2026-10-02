"""Offline regressions for healthy controls; no deployed enforcement claims."""
import copy
import os
import unittest
from unittest.mock import patch

from test_live import (
    adapter, ANCHOR, audit_event, allowed, a2a_allowed, CONFIG, IDENTITY,
    OBSERVATION_START, OBSERVATION_END, SID,
)


def tag_denied(oid):
    return {"error": "agent_tag_mismatch", "enforcement_layer": "conditional_access",
            "caller_tag": "engineering", "target_tag": "finance",
            "enforcement": {"jwt_validated": True, "jwt_oid": oid, "tag_match": False}}


class LiveControlTests(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(CONFIG)
        live = self.config["live"]
        live["timeout_seconds"] = 3
        live["exclusive_observation"] = True
        live["a2a_controls"] = {}
        credentials = {"LIVE_KEY": "offline-admin", "LIVE_TOKEN": "offline-report"}
        for short, target in adapter.ALIASES.items():
            live["identities"][target] = dict(
                IDENTITY, oid=short + "-oid", token_env="NEGATIVE_" + short.upper(),
                invalid_token_env="INVALID_" + short.upper())
            fixture = "control-" + short
            live["a2a_controls"][target] = fixture
            live["identities"][fixture] = dict(
                IDENTITY, oid=fixture + "-oid", token_env="CONTROL_" + short.upper())
            credentials["CONTROL_" + short.upper()] = "offline-control-" + short
            credentials["NEGATIVE_" + short.upper()] = "offline-caller-" + short
            credentials["INVALID_" + short.upper()] = "offline-invalid-" + short
        self.env = patch.dict(os.environ, credentials, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def execute(self, case_id, sequence, config=None):
        with patch.object(adapter, "request", side_effect=sequence) as request, \
                patch.object(adapter.time, "time", side_effect=[OBSERVATION_START, OBSERVATION_END]):
            result = adapter.run_case(case_id, config if config is not None else self.config, "live")
        return result, request

    def test_original_single_401_without_control_is_blocked_without_network(self):
        result, request = self.execute("live.a2a.approval.missing-token", [
            (401, {"error": "missing_token", "enforcement_layer": "jwt"})], CONFIG)
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_a2a_absent_control_fixtures_block_all_negative_cases(self):
        for case in adapter.descriptors():
            if not case["id"].startswith("live.a2a.") or case["id"].endswith(".allow"):
                continue
            for missing in ("mapping", "identity", "credential"):
                config = copy.deepcopy(self.config)
                if missing == "mapping":
                    config["live"]["a2a_controls"] = {}
                elif missing == "identity":
                    for fixture in config["live"]["a2a_controls"].values():
                        del config["live"]["identities"][fixture]
                else:
                    for fixture in config["live"]["a2a_controls"].values():
                        config["live"]["identities"][fixture]["token_env"] = "ABSENT"
                with self.subTest(case=case["id"], missing=missing):
                    result, request = self.execute(case["id"], [], config)
                    self.assertEqual(result["status"], "BLOCKED")
                    request.assert_not_called()

    def test_a2a_control_mapping_requires_identity_names_not_urls(self):
        for mapping in ([], "budget-report", {"budget-approval": []},
                        {"budget-approval": "https://unconfigured.example"}):
            config = copy.deepcopy(self.config)
            config["live"]["a2a_controls"] = mapping
            with self.subTest(mapping=mapping):
                result, request = self.execute("live.a2a.approval.missing-token", [], config)
                self.assertEqual(result["status"], "BLOCKED")
                request.assert_not_called()

    def test_a2a_negative_fixtures_preflight_before_control(self):
        for case_id, fixture, key in [
                ("live.a2a.approval.invalid-token", "budget-approval", "invalid_token_env"),
                ("live.a2a.menus-to-approval.deny", "employee-menus", "token_env")]:
            config = copy.deepcopy(self.config)
            config["live"]["identities"][fixture][key] = "ABSENT"
            with self.subTest(case=case_id):
                result, request = self.execute(case_id, [], config)
                self.assertEqual(result["status"], "BLOCKED")
                request.assert_not_called()

    def test_a2a_all_token_negatives_require_bounded_same_target_control_first(self):
        for short, target in adapter.ALIASES.items():
            for outcome in ("missing-token", "invalid-token"):
                control = (200, a2a_allowed("control-" + short + "-oid"))
                deny = (401, {"error": outcome.replace("-", "_"), "enforcement_layer": "jwt"})
                with self.subTest(target=target, outcome=outcome):
                    result, request = self.execute(f"live.a2a.{short}.{outcome}", [control, deny])
                    self.assertEqual(result["status"], "PASS")
                    self.assertTrue(result["evidence"]["healthy_control_verified"])
                    self.assertEqual(request.call_count, 2)
                    first, second = request.call_args_list
                    for exchange in (first, second):
                        self.assertEqual(exchange.args[:2], (
                            "GET", self.config["live"]["endpoints"][target] + "/a2a/status"))
                        self.assertEqual(exchange.kwargs["timeout"], 3)
                    self.assertEqual(first.args[2]["Authorization"], "Bearer offline-control-" + short)
                    expected = {} if outcome == "missing-token" else {
                        "Authorization": "Bearer offline-invalid-" + short}
                    self.assertEqual(second.args[2], expected)
                    self.assertNotIn("offline", str(result))

    def test_a2a_failed_controls_fail_without_dispatching_negative(self):
        bad_identity = a2a_allowed("wrong-oid")
        bad_jwt = a2a_allowed("control-approval-oid")
        bad_jwt["enforcement"]["jwt_validated"] = False
        bad_tags = a2a_allowed("control-approval-oid")
        bad_tags["enforcement"]["caller_tag"] = ""
        for case_id in ("live.a2a.approval.missing-token", "live.a2a.approval.invalid-token",
                        "live.a2a.menus-to-approval.deny"):
            for control in [(401, {"error": "invalid_token", "enforcement_layer": "jwt"}),
                            (403, tag_denied("control-approval-oid")), (503, {}),
                            (200, bad_identity), (200, bad_jwt), (200, bad_tags),
                            adapter.NetworkFailure("offline-secret")]:
                with self.subTest(case=case_id, control=control):
                    result, request = self.execute(case_id, [control])
                    self.assertEqual(result["status"], "FAIL")
                    self.assertEqual(request.call_count, 1)
                    self.assertNotIn("healthy_control_verified", result["evidence"])
                    self.assertNotIn("offline", str(result))

    def test_a2a_tag_denials_use_control_then_correct_negative_identity_on_same_target(self):
        for pair, caller, target, control_oid in [
                ("menus-to-approval", "menus", "budget-approval", "control-approval-oid"),
                ("report-to-menus", "report", "employee-menus", "control-menus-oid")]:
            with self.subTest(pair=pair):
                result, request = self.execute(f"live.a2a.{pair}.deny", [
                    (200, a2a_allowed(control_oid)), (403, tag_denied(caller + "-oid"))])
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["evidence"]["healthy_control_verified"])
                first, second = request.call_args_list
                self.assertEqual(first.args[1], second.args[1])
                self.assertEqual(second.args[1], self.config["live"]["endpoints"][target] + "/a2a/status")
                self.assertEqual(second.args[2]["Authorization"], "Bearer offline-caller-" + caller)

    def test_a2a_bad_negative_stays_fail_after_healthy_control(self):
        for case_id, bad_negative in [
                ("live.a2a.approval.missing-token", (401, {})),
                ("live.a2a.approval.invalid-token", (200, a2a_allowed("control-approval-oid"))),
                ("live.a2a.menus-to-approval.deny", (403, tag_denied("control-approval-oid")))]:
            with self.subTest(case=case_id):
                result, request = self.execute(case_id, [
                    (200, a2a_allowed("control-approval-oid")), bad_negative])
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(request.call_count, 2)

    def test_a2a_different_target_control_cannot_satisfy_missing_target_fixture(self):
        del self.config["live"]["a2a_controls"]["employee-menus"]
        result, request = self.execute("live.a2a.report-to-menus.deny", [])
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_a2a_control_is_fresh_for_each_case_not_cached_from_prior_allowance(self):
        self.config["live"]["a2a_controls"]["budget-approval"] = "budget-report"
        sequence = [(200, a2a_allowed("report-oid")),
                    (503, {}),
                    (200, a2a_allowed("report-oid")),
                    (401, {"error": "invalid_token", "enforcement_layer": "jwt"})]
        with patch.object(adapter, "request", side_effect=sequence) as request:
            allowance = adapter.run_case("live.a2a.report-to-approval.allow", self.config, "live")
            missing = adapter.run_case("live.a2a.approval.missing-token", self.config, "live")
            invalid = adapter.run_case("live.a2a.approval.invalid-token", self.config, "live")
        self.assertEqual([r["status"] for r in (allowance, missing, invalid)], ["PASS", "FAIL", "PASS"])
        self.assertEqual(request.call_count, 4)

    def rbac_sequence(self):
        deny = {"http_status": 403, "response": {"error": "forbidden", "request_id": "r1"}}
        event = {"request_id": "r1", "caller_spiffe_id": SID, "method": "GET",
                 "path": "/budget/submit", "decision": "deny", "enforcement_layer": "rbac"}
        return [(200, {"entries": [ANCHOR]}), (200, allowed()),
                (200, {"entries": [ANCHOR, audit_event()]}),
                (200, deny), (200, {"entries": [event]})]

    def test_rbac_control_proves_same_caller_target_stack_before_readonly_negative(self):
        result, request = self.execute("live.rbac.report.get-submit.deny", self.rbac_sequence())
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["evidence"]["healthy_control_verified"])
        self.assertEqual(request.call_count, 5)
        control, negative = request.call_args_list[1], request.call_args_list[3]
        self.assertEqual(control.args[1],
                         "https://report.example/call-backend-raw?method=GET&path=%2Fbudget%2Fread")
        self.assertEqual(negative.args[1],
                         "https://report.example/call-backend-raw?method=GET&path=%2Fbudget%2Fsubmit")
        self.assertEqual(control.args[2], negative.args[2])
        self.assertTrue(all(c.kwargs["timeout"] == 3 for c in request.call_args_list))

    def test_rbac_missing_control_prerequisites_block_without_network(self):
        for missing in ("exclusive_observation", "identity", "admin", "caller", "management"):
            config = copy.deepcopy(self.config)
            if missing == "exclusive_observation":
                config["live"]["exclusive_observation"] = False
            elif missing == "identity":
                config["live"]["identities"] = {}
            elif missing == "admin":
                config["live"]["admin_key_env"] = "ABSENT"
            else:
                del config["live"]["endpoints"]["budget-report" if missing == "caller" else "management"]
            with self.subTest(missing=missing):
                result, request = self.execute("live.rbac.report.get-submit.deny", [], config)
                self.assertEqual(result["status"], "BLOCKED")
                request.assert_not_called()

    def test_rbac_failed_control_never_dispatches_negative(self):
        for control in [(200, {"http_status": 401, "response": {}}),
                        (200, {"http_status": 503, "response": {}}),
                        adapter.NetworkFailure("offline-secret")]:
            with self.subTest(control=control):
                result, request = self.execute("live.rbac.report.get-submit.deny", [
                    (200, {"entries": [ANCHOR]}), control])
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(request.call_count, 2)

    def test_rbac_control_requires_current_authenticated_identity_audit(self):
        for bad in ("identity", "jwt", "audit-path", "stale"):
            sequence = self.rbac_sequence()
            if bad == "identity":
                data = allowed()
                data["response"]["identity_chain"]["spiffe_id"] = "spiffe://other/agent"
                sequence[1] = (200, data)
            else:
                event = audit_event()
                if bad == "jwt":
                    event["jwt_valid"] = False
                elif bad == "audit-path":
                    event["path"] = "/another/path"
                else:
                    event["timestamp"] = "2000-01-01T00:00:00Z"
                sequence[2] = (200, {"entries": [ANCHOR, event]})
            with self.subTest(bad=bad):
                result, request = self.execute("live.rbac.report.get-submit.deny", sequence)
                self.assertNotEqual(result["status"], "PASS")
                self.assertLessEqual(request.call_count, 3)


if __name__ == "__main__":
    unittest.main()
