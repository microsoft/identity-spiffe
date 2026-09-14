"""Harness self-tests only: mocked network is not live enforcement evidence."""
import copy
import importlib.util
import json
import os
import multiprocessing
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone


ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("live_adapter", ROOT / "run.py")
adapter = importlib.util.module_from_spec(SPEC)
if (ROOT / "run.py").exists():
    SPEC.loader.exec_module(adapter)

SID = "spiffe://test.example/ests/bp/blueprint/aid/report"
IDENTITY = {"spiffe_id": SID, "oid": "report-oid", "audience": "api://backend",
            "token_env": "LIVE_TOKEN"}
CONFIG = {"live": {
    "endpoints": {"budget-report": "https://report.example",
                  "budget-approval": "https://approval.example",
                  "employee-menus": "https://menus.example",
                  "management": "https://admin.example/admin"},
    "identities": {"budget-report": IDENTITY},
    "admin_key_env": "LIVE_KEY",
}}


def slow_http_worker(connection, payload):
    """Simulated stuck network worker; never makes a request."""
    time.sleep(5)


def successful_http_worker(connection, payload):
    """Simulated IPC return, not live evidence."""
    connection.send((200, {"ok": True}))
    connection.close()


def allowed():
    return {"http_status": 200, "response": {"status": "success", "identity_chain": {
        "spiffe_id": SID, "entra_agent_id": "report-oid",
        "entra_token": {"present": True, "oid": "report-oid", "audience": "api://backend"}}}}


OBSERVATION_START = 1_789_164_000.0
OBSERVATION_END = OBSERVATION_START + 10


def audit_event(request_id="new", timestamp=None):
    if timestamp is None:
        timestamp = datetime.fromtimestamp(OBSERVATION_START + 5, timezone.utc).isoformat()
    return {"request_id": request_id, "timestamp": timestamp, "caller_spiffe_id": SID,
            "method": "GET", "path": "/budget/read", "decision": "allow", "jwt_valid": True,
            "jwt_present": True, "jwt_audience": "api://backend", "enforcement_layer": "oauth"}


ANCHOR = audit_event("retained-anchor", "2000-01-01T00:00:00Z")


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(adapter, "run_case"), "live adapter must implement run_case")
        self.env = patch.dict(os.environ, {"LIVE_KEY": "sensitive-key", "LIVE_TOKEN": "sensitive-token"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_case(self, case_id, response=None, config=None):
        with patch.object(adapter, "request", return_value=response or (200, allowed())) as request:
            result = adapter.run_case(case_id, config or CONFIG, "live")
        return result, request

    def test_inventory_contract(self):
        cases = adapter.descriptors()
        self.assertGreaterEqual(len(cases), 20)
        self.assertEqual(len(cases), len({c["id"] for c in cases}))
        for case in cases:
            self.assertEqual(case["suite"], "live")
            self.assertEqual(case["profiles"], ["live"])
            self.assertIsInstance(case["mutation"], bool)

    def test_missing_targets_block_no_network(self):
        result, request = self.run_case("live.transport.report.allow", config={"live": {}})
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_local_profile_never_calls_network(self):
        with patch.object(adapter, "request") as request:
            results = adapter.run(CONFIG, "local")
        self.assertEqual(results, [])
        request.assert_not_called()

    def test_url_validation(self):
        for url in ["http://public.example", "https://user:password@example.test",
                    "https://example.test/?token=secret", "https://example.test/#fragment",
                    "file:///etc/passwd", "https://example.test/../admin",
                    "https://example.test/%2e%2e", "http://127.0.0.1.evil",
                    "https://example.test\\@evil", "https://example.test/\n",
                    "http://169.254.169.254", "https://graph.microsoft.com"]:
            with self.subTest(url=url), self.assertRaises(adapter.Requirement):
                adapter.validate_url(url)
        for url in ["https://app.example", "http://127.0.0.1:9443", "http://[::1]:9443"]:
            adapter.validate_url(url)

    def test_inline_credentials_rejected(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["admin_key"] = "secret"
        result, request = self.run_case("live.transport.report.allow", config=config)
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_missing_env_key_blocks(self):
        with patch.dict(os.environ, {"LIVE_KEY": ""}):
            result, request = self.run_case("live.transport.report.allow")
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_transport_outages_never_prove_denial(self):
        for error in [adapter.NetworkFailure("timeout"), adapter.NetworkFailure("tls")]:
            with patch.object(adapter, "request", side_effect=error):
                result = adapter.run_case("live.transport.menus.deny", CONFIG, "live")
            self.assertEqual(result["status"], "FAIL")
        for response in [(502, {}), (200, {"http_status": 0, "error": "request_failed"}),
                         (200, {"http_status": 502}), (403, {"error": "forbidden"})]:
            result, _ = self.run_case("live.transport.menus.deny", response)
            self.assertNotEqual(result["status"], "PASS")

    def test_transport_allow_requires_expected_identity(self):
        result, _ = self.run_case("live.transport.report.allow")
        self.assertEqual(result["status"], "PASS")
        data = allowed()
        data["response"]["identity_chain"]["spiffe_id"] = "spiffe://wrong"
        result, _ = self.run_case("live.transport.report.allow", (200, data))
        self.assertEqual(result["status"], "FAIL")

    def test_identity_chain_exact_comparisons(self):
        result, _ = self.run_case("live.identity.report")
        self.assertEqual(result["status"], "PASS")
        for field in ["oid", "audience", "present"]:
            data = allowed()
            data["response"]["identity_chain"]["entra_token"][field] = "wrong"
            result, _ = self.run_case("live.identity.report", (200, data))
            self.assertEqual(result["status"], "FAIL")

    def test_rbac_requires_correlated_audit_not_generic_403(self):
        deny = {"http_status": 403, "response": {"error": "forbidden", "request_id": "r1"}}
        event = {"request_id": "r1", "caller_spiffe_id": SID, "method": "GET",
                 "path": "/budget/submit", "decision": "deny", "enforcement_layer": "rbac"}
        with patch.object(adapter, "request", side_effect=[(200, deny), (200, {"entries": [event]})]):
            result = adapter.run_case("live.rbac.report.get-submit.deny", CONFIG, "live")
        self.assertEqual(result["status"], "PASS")
        event["enforcement_layer"] = "conditional_access"
        with patch.object(adapter, "request", side_effect=[(200, deny), (200, {"entries": [event]})]):
            result = adapter.run_case("live.rbac.report.get-submit.deny", CONFIG, "live")
        self.assertNotEqual(result["status"], "PASS")

    def test_oauth_echo_alone_not_validation(self):
        result, _ = self.run_case("live.oauth.report.valid")
        self.assertNotEqual(result["status"], "PASS")

    def test_a2a_missing_token_safe_target_only(self):
        result, request = self.run_case("live.a2a.approval.missing-token",
                                       (401, {"error": "missing_token", "enforcement_layer": "jwt"}))
        self.assertEqual(result["status"], "PASS")
        args = request.call_args.args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/a2a/status"))
        self.assertNotIn("Authorization", args[2])

    def test_a2a_generic_401_not_denial_proof(self):
        result, _ = self.run_case("live.a2a.approval.missing-token", (401, {}))
        self.assertEqual(result["status"], "FAIL")

    def test_a2a_valid_requires_jwt_identity_and_tag(self):
        data = {"status": "ok", "enforcement": {"jwt_validated": True,
                "jwt_oid": "report-oid", "tag_match": True,
                "caller_tag": "Finance", "target_tag": "finance"}}
        result, request = self.run_case("live.a2a.report-to-approval.allow", (200, data))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(request.call_args.args[2]["Authorization"], "Bearer sensitive-token")
        data["enforcement"]["jwt_validated"] = False
        result, _ = self.run_case("live.a2a.report-to-approval.allow", (200, data))
        self.assertEqual(result["status"], "FAIL")

    def test_a2a_claimed_match_requires_real_nonempty_matching_tags(self):
        for caller, target in [("", ""), (None, None), ([], []), (3, 3),
                               ("finance", "engineering"), ("finance", ""),
                               ("", "finance"), ("finance", None),
                               (" ", " "), ("finance", {})]:
            with self.subTest(caller=caller, target=target):
                data = {"status": "ok", "enforcement": {"jwt_validated": True,
                        "jwt_oid": "report-oid", "tag_match": True,
                        "caller_tag": caller, "target_tag": target}}
                result, _ = self.run_case("live.a2a.report-to-approval.allow", (200, data))
                self.assertEqual(result["status"], "FAIL")
        for missing in ("caller_tag", "target_tag"):
            data = {"status": "ok", "enforcement": {"jwt_validated": True,
                    "jwt_oid": "report-oid", "tag_match": True,
                    "caller_tag": "finance", "target_tag": "finance"}}
            del data["enforcement"][missing]
            result, _ = self.run_case("live.a2a.report-to-approval.allow", (200, data))
            self.assertEqual(result["status"], "FAIL")

    def test_reports_never_echo_response_or_exception(self):
        result, _ = self.run_case("live.transport.report.allow",
                                 (500, {"error": "sensitive-key sensitive-token"}))
        self.assertNotIn("sensitive", json.dumps(result))
        with patch.object(adapter, "request", side_effect=adapter.NetworkFailure("sensitive-token")):
            result = adapter.run_case("live.transport.report.allow", CONFIG, "live")
        self.assertNotIn("sensitive", json.dumps(result))

    def test_mutations_disabled_no_requests(self):
        for case in ["live.ca.local-risk", "live.ca.local-tag",
                     "live.rbac.approval.submit.allow", "live.rbac.report.submit.deny"]:
            result, request = self.run_case(case)
            self.assertEqual(result["status"], "BLOCKED")
            request.assert_not_called()

    def mutation_config(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["endpoints"]["sidecar"] = "http://127.0.0.1:9443"
        config["live"]["mutations"] = {"enabled": True, "environment": "dedicated-test",
            "marker_env": "LIVE_DEDICATED", "scope_ids": [SID], "exclusive": True}
        return config

    def test_mutation_authorization_gates(self):
        for key, value in [("enabled", False), ("environment", "production"),
                           ("scope_ids", []), ("exclusive", False)]:
            config = self.mutation_config()
            config["live"]["mutations"][key] = value
            with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}):
                result, request = self.run_case("live.ca.local-risk", config=config)
            self.assertEqual(result["status"], "BLOCKED")
            request.assert_not_called()

    def test_remote_sidecar_mutation_blocked(self):
        config = self.mutation_config()
        config["live"]["endpoints"]["sidecar"] = "https://remote.example"
        with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}):
            result, request = self.run_case("live.ca.local-risk", config=config)
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_risk_absent_snapshot_cannot_be_restored(self):
        config = self.mutation_config()
        with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}):
            result, request = self.run_case("live.ca.local-risk", (200, {"risks": {}}), config)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(all(c.args[0] == "GET" for c in request.call_args_list))

    def test_unacknowledged_mutation_requires_operator_recovery_after_restore(self):
        for kind, collection, field, original in [
                ("risk", "risks", "risk_level", "low"), ("tag", "tags", "tag", "finance")]:
            for response in [adapter.NetworkFailure("timeout"), (202, {}), (500, {})]:
                snapshot = (200, {collection: {SID: original}})
                sequence = [snapshot, (200, allowed()), response, (200, {}), snapshot]
                with self.subTest(kind=kind, response=response), \
                        patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                        patch.object(adapter, "request", side_effect=sequence) as request:
                    result = adapter.run_case(f"live.ca.local-{kind}", self.mutation_config(), "live")
                    self.assertEqual(result["status"], "FAIL")
                    self.assertFalse(result["evidence"]["cleanup_verified"])
                    self.assertIn("operator recovery required", result["observed"])
                    self.assertNotIn("post_restore_allowed", result["evidence"])
                    puts = [c for c in request.call_args_list if c.args[0] == "PUT"]
                    self.assertEqual(len(puts), 2)
                    self.assertEqual(puts[-1].args[3], {"spiffe_id": SID, field: original})

    def test_late_mutation_cannot_be_certified_by_an_earlier_restore_readback(self):
        for kind, collection, field, original, changed in [
                ("risk", "risks", "risk_level", "low", "high"),
                ("tag", "tags", "tag", "finance", "live-harness-deny")]:
            store = {SID: original}
            pending = []

            def exchange(method, url, headers, body=None, timeout=20):
                if "/call-backend-raw?" in url:
                    return 200, allowed()
                if method == "PUT":
                    if body[field] == changed:
                        pending.append(changed)
                        raise adapter.NetworkFailure("timeout")
                    store[SID] = body[field]
                    return 200, {}
                snapshot = {collection: dict(store)}
                if pending:
                    # The timed-out server write completes after the cleanup read.
                    store[SID] = pending.pop()
                return 200, snapshot

            with self.subTest(kind=kind), \
                    patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                    patch.object(adapter, "request", side_effect=exchange):
                result = adapter.run_case(f"live.ca.local-{kind}", self.mutation_config(), "live")
                self.assertEqual(store[SID], changed)
                self.assertEqual(result["status"], "FAIL")
                self.assertFalse(result["evidence"]["cleanup_verified"])
                self.assertIn("operator recovery required", result["observed"])

    def test_acknowledged_mutation_can_verify_cleanup_after_readback_timeout(self):
        for kind, collection, original in [
                ("risk", "risks", "low"), ("tag", "tags", "finance")]:
            snapshot = (200, {collection: {SID: original}})
            sequence = [snapshot, (200, allowed()), (200, {}), adapter.NetworkFailure("timeout"),
                        (200, {}), snapshot]
            with self.subTest(kind=kind), \
                    patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                    patch.object(adapter, "request", side_effect=sequence):
                result = adapter.run_case(f"live.ca.local-{kind}", self.mutation_config(), "live")
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(result["evidence"]["cleanup_verified"])

    def test_cleanup_failure_overrides_success(self):
        config = self.mutation_config()
        snapshot = (200, {"risks": {SID: "low"}})
        deny = (200, {"http_status": 403, "response": {
            "error": "high_risk_agent_blocked", "layer": "conditional_access",
            "caller": SID}})
        sequence = [snapshot, (200, allowed()), (200, {}), (200, {"risks": {SID: "high"}}),
                    deny, (200, {}), (200, {"risks": {SID: "high"}})]
        with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                patch.object(adapter, "request", side_effect=sequence):
            result = adapter.run_case("live.ca.local-risk", config, "live")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["evidence"]["cleanup_verified"])

    def test_exit_codes(self):
        self.assertEqual(adapter.exit_code([{"status": "PASS"}]), 0)
        self.assertEqual(adapter.exit_code([{"status": "BLOCKED"}]), 2)
        self.assertEqual(adapter.exit_code([{"status": "SKIPPED"}]), 2)
        self.assertEqual(adapter.exit_code([{"status": "FAIL"}, {"status": "BLOCKED"}]), 1)

    def test_invalid_config_shapes_report_every_case(self):
        for config in [None, [], {"live": []}, {"live": {"endpoints": [], "identities": {}}}]:
            results = adapter.run(config, "live")
            self.assertEqual(len(results), len(adapter.descriptors()))
            self.assertTrue(all(result["status"] == "BLOCKED" for result in results))

    def test_timeout_bounds(self):
        for timeout in [0, 61, float("nan"), float("inf"), True, "20", []]:
            config = copy.deepcopy(CONFIG)
            config["live"]["timeout_seconds"] = timeout
            result, request = self.run_case("live.transport.report.allow", config=config)
            self.assertEqual(result["status"], "BLOCKED")
            request.assert_not_called()

    def test_invalid_spiffe_id_blocks_instead_of_crash(self):
        for sid in ["spiffe://[invalid", "spiffe://user@host/id", "spiffe://test/id?q=x",
                    "spiffe://test/../id", "spiffe://test/id\n"]:
            config = copy.deepcopy(CONFIG)
            config["live"]["identities"]["budget-report"]["spiffe_id"] = sid
            result, request = self.run_case("live.identity.report", config=config)
            self.assertEqual(result["status"], "BLOCKED")
            request.assert_not_called()

    def test_oauth_real_audit_validation_path(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["exclusive_observation"] = True
        event = audit_event()
        sequence = [(200, {"entries": [ANCHOR]}), (200, allowed()),
                    (200, {"entries": [ANCHOR, event]})]
        with patch.object(adapter, "request", side_effect=sequence), \
                patch.object(adapter.time, "time", side_effect=[OBSERVATION_START, OBSERVATION_END]):
            result = adapter.run_case("live.oauth.report.valid", config, "live")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["evidence"]["jwt_audit_validated"])

    def test_oauth_audit_wrong_layer_not_pass(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["exclusive_observation"] = True
        event = audit_event()
        event["enforcement_layer"] = "rbac"
        sequence = [(200, {"entries": [ANCHOR]}), (200, allowed()),
                    (200, {"entries": [ANCHOR, event]})]
        with patch.object(adapter, "request", side_effect=sequence), \
                patch.object(adapter.time, "time", side_effect=[OBSERVATION_START, OBSERVATION_END]):
            result = adapter.run_case("live.oauth.report.valid", config, "live")
        self.assertEqual(result["status"], "FAIL")

    def test_oauth_unseen_old_or_untrustworthy_timestamp_blocks(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["exclusive_observation"] = True
        for timestamp in ["2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z",
                          None, "", "invalid", [], 0, "2026-09-11T17:00:00"]:
            event = audit_event()
            event["timestamp"] = timestamp
            sequence = [(200, {"entries": [ANCHOR]}), (200, allowed()),
                        (200, {"entries": [ANCHOR, event]})]
            with self.subTest(timestamp=timestamp), \
                    patch.object(adapter, "request", side_effect=sequence), \
                    patch.object(adapter.time, "time", side_effect=[OBSERVATION_START, OBSERVATION_END]):
                result = adapter.run_case("live.oauth.report.valid", config, "live")
            self.assertEqual(result["status"], "BLOCKED")

    def test_oauth_requires_immutable_retained_audit_source_anchor(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["exclusive_observation"] = True
        changed_anchor = dict(ANCHOR, decision="deny")
        for before, after in [([], [audit_event()]), ([ANCHOR], [audit_event()]),
                              ([ANCHOR], [changed_anchor, audit_event()])]:
            with self.subTest(before=before, after=after), \
                    patch.object(adapter, "request", side_effect=[
                        (200, {"entries": before}), (200, allowed()), (200, {"entries": after})]), \
                    patch.object(adapter.time, "time", side_effect=[OBSERVATION_START, OBSERVATION_END]):
                result = adapter.run_case("live.oauth.report.valid", config, "live")
            self.assertEqual(result["status"], "BLOCKED")

    def test_oauth_stale_ambiguous_and_malformed_audit_never_pass(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["exclusive_observation"] = True
        event = {"request_id": "new", "caller_spiffe_id": SID, "method": "GET",
                 "path": "/budget/read", "decision": "allow", "jwt_valid": True,
                 "jwt_present": True, "jwt_audience": "api://backend"}
        for before, after in [([event], [event]), ([], [event, event]), ([{"request_id": []}], [])]:
            sequence = [(200, {"entries": before}), (200, allowed()), (200, {"entries": after})]
            with patch.object(adapter, "request", side_effect=sequence):
                result = adapter.run_case("live.oauth.report.valid", config, "live")
            self.assertNotEqual(result["status"], "PASS")

    def test_a2a_missing_graph_tag_not_denial_proof(self):
        config = copy.deepcopy(CONFIG)
        config["live"]["identities"]["employee-menus"] = dict(IDENTITY)
        for missing in ["", None]:
            body = {"error": "agent_tag_mismatch", "enforcement_layer": "conditional_access",
                    "caller_tag": missing, "target_tag": "finance",
                    "enforcement": {"jwt_validated": True, "jwt_oid": "report-oid",
                                    "tag_match": False}}
            result, _ = self.run_case("live.a2a.menus-to-approval.deny", (403, body), config)
            self.assertEqual(result["status"], "FAIL")

    def test_dynamic_and_federated_explicit_fixture_identity(self):
        for kind in ["dynamic", "federated"]:
            config = copy.deepcopy(CONFIG)
            config["live"]["endpoints"][kind] = "https://fixture.example"
            config["live"]["identities"][kind] = dict(IDENTITY)
            result, request = self.run_case(f"live.{kind}.identity", config=config)
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(request.call_args.args[1].startswith("https://fixture.example/call-backend-raw"))

    def test_credential_name_and_header_injection_rejected(self):
        for name in ["Bearer abc.def.ghi", "../key", "KEY\n"]:
            with self.assertRaises(adapter.Requirement):
                adapter.credential(name)
        with patch.dict(os.environ, {"LIVE_KEY": "secret\r\nInjected: value"}):
            result, request = self.run_case("live.transport.report.allow")
        self.assertEqual(result["status"], "BLOCKED")
        request.assert_not_called()

    def test_redirect_handler_never_forwards_credentials(self):
        req = adapter.urllib_request.Request("https://original.example",
                                             headers={"Authorization": "Bearer secret"})
        with self.assertRaises(adapter.NetworkFailure):
            adapter.NoRedirect().redirect_request(req, None, 302, "Found", {},
                                                  "https://attacker.example")

    def test_request_parses_http_denial_without_logging_body(self):
        response = MagicMock()
        response.code = 401
        response.read.return_value = b'{"error":"missing_token","enforcement_layer":"jwt"}'
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(adapter.urllib_request, "build_opener", return_value=opener):
            status, body = adapter.exchange("GET", "https://target.example/a2a/status", {})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "missing_token")
        response.__exit__.assert_called_once()

    def test_request_failures_are_sanitized(self):
        for failure in [URLError("secret"), TimeoutError("secret"), IncompleteRead(b"secret")]:
            opener = MagicMock()
            opener.open.side_effect = failure
            with patch.object(adapter.urllib_request, "build_opener", return_value=opener):
                with self.assertRaises(adapter.NetworkFailure) as caught:
                    adapter.exchange("GET", "https://target.example", {})
            self.assertNotIn("secret", str(caught.exception))

    def test_request_rejects_redirect_non_json_oversize_and_scalar(self):
        for code, raw in [(302, b'{}'), (200, b'<html>secret</html>'),
                          (200, b'x' * 1_048_577), (200, b'[]')]:
            response = MagicMock()
            response.code = code
            response.read.return_value = raw
            opener = MagicMock()
            opener.open.return_value = response
            with patch.object(adapter.urllib_request, "build_opener", return_value=opener):
                with self.assertRaises(adapter.NetworkFailure):
                    adapter.exchange("GET", "https://target.example", {})

    def test_mutation_success_requires_restored_read_path(self):
        for kind, collection, original, changed, error in [
                ("risk", "risks", "low", "high", "high_risk_agent_blocked"),
                ("tag", "tags", "finance", "live-harness-deny", "agent_tag_mismatch")]:
            config = self.mutation_config()
            snapshot = (200, {collection: {SID: original}})
            deny = (200, {"http_status": 403, "response": {
                "error": error, "layer": "conditional_access", "caller": SID}})
            sequence = [snapshot, (200, allowed()), (200, {}), (200, {collection: {SID: changed}}),
                        deny, (200, {}), snapshot, (200, allowed())]
            with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                    patch.object(adapter, "request", side_effect=sequence):
                result = adapter.run_case(f"live.ca.local-{kind}", config, "live")
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["evidence"]["cleanup_verified"])
            self.assertTrue(result["evidence"]["post_restore_allowed"])

    def test_mutation_preflight_denial_performs_no_write(self):
        config = self.mutation_config()
        with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                patch.object(adapter, "request", side_effect=[
                    (200, {"risks": {SID: "low"}}), (200, {"http_status": 403, "response": {}})]) as req:
            result = adapter.run_case("live.ca.local-risk", config, "live")
        self.assertEqual(result["status"], "FAIL")
        self.assertNotIn("PUT", [c.args[0] for c in req.call_args_list])

    def test_snapshot_restore_compares_other_entries_too(self):
        config = self.mutation_config()
        snapshot = (200, {"risks": {SID: "low", "other": "medium"}})
        sequence = [snapshot, (200, allowed()), adapter.NetworkFailure(),
                    (200, {}), (200, {"risks": {SID: "low", "other": "high"}})]
        with patch.dict(os.environ, {"LIVE_DEDICATED": "dedicated-test"}), \
                patch.object(adapter, "request", side_effect=sequence):
            result = adapter.run_case("live.ca.local-risk", config, "live")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["evidence"]["cleanup_verified"])
        self.assertIn("Cleanup", result["observed"])

    def test_cli_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.json"
            output.write_text("original")
            proc = subprocess.run([sys.executable, str(ROOT / "run.py"), "--profile", "local",
                                   "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(output.read_text(), "original")

    def test_output_creation_failure_prevents_all_live_requests(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.json"
            output.write_text("original")
            with patch.object(sys, "argv", ["run.py", "--profile", "live", "--output", str(output)]), \
                    patch.object(sys, "stderr"), \
                    patch.object(adapter, "run", return_value=[]) as run:
                self.assertEqual(adapter.main(), 1)
            run.assert_not_called()

    def test_wall_deadline_terminates_stuck_worker(self):
        self.assertTrue(hasattr(adapter, "HTTP_WORKER"), "HTTP needs a killable wall-clock worker")
        before = {p.pid for p in multiprocessing.active_children()}
        start = time.monotonic()
        with patch.object(adapter, "HTTP_WORKER", slow_http_worker):
            with self.assertRaises(adapter.NetworkFailure):
                adapter.request("GET", "https://unused.example", {}, timeout=0.1)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_wall_deadline_worker_returns_structured_result(self):
        self.assertTrue(hasattr(adapter, "HTTP_WORKER"), "HTTP needs a killable wall-clock worker")
        with patch.object(adapter, "HTTP_WORKER", successful_http_worker):
            self.assertEqual(adapter.request("GET", "https://unused.example", {}, timeout=2),
                             (200, {"ok": True}))

    def test_cli_list_and_missing_config_reports_all(self):
        listed = subprocess.run([sys.executable, str(ROOT / "run.py"), "--list"],
                                capture_output=True, text=True, check=True)
        descriptors = json.loads(listed.stdout)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.json"
            proc = subprocess.run([sys.executable, str(ROOT / "run.py"), "--profile", "live",
                                   "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            results = json.loads(output.read_text())["cases"]
        self.assertEqual({r["id"] for r in results}, {d["id"] for d in descriptors})
        self.assertTrue(all(r["status"] == "BLOCKED" for r in results))


if __name__ == "__main__":
    unittest.main()
