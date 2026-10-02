import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

MODULE_PATH = Path(__file__).with_name("ca_evaluator.py")


def load_evaluator(risk_provider):
    env = {
        "CA_RISK_PROVIDER": risk_provider,
        "GRAPH_CLIENT_ID": "client-id",
        "GRAPH_CLIENT_SECRET": "client-secret",
        "AZURE_TENANT_ID": "tenant-id",
    }
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(
            "ca_evaluator_under_test",
            MODULE_PATH,
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class CARiskProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_sidecar_provider_allows_explicit_low_risk(self):
        module = load_evaluator("sidecar")
        evaluator = module.CAEvaluator()
        evaluator.fetch_ca_policies = AsyncMock(
            return_value=[
                {
                    "id": "policy-id",
                    "state": "enabled",
                    "conditions": {"agentIdRiskLevels": ["high"]},
                    "grantControls": {"builtInControls": ["block"]},
                }
            ]
        )
        evaluator.fetch_agent_risk = AsyncMock()

        blocked, details = await evaluator.should_block_caller(
            "caller-id",
            fallback_risk="low",
        )

        self.assertFalse(blocked)
        self.assertEqual(details["risk_source"], "sidecar")
        evaluator.fetch_agent_risk.assert_not_awaited()

    async def test_sidecar_provider_blocks_high_and_missing_risk(self):
        module = load_evaluator("sidecar")
        evaluator = module.CAEvaluator()
        evaluator.fetch_ca_policies = AsyncMock(
            return_value=[
                {
                    "id": "policy-id",
                    "state": "enabled",
                    "conditions": {"agentIdRiskLevels": ["high"]},
                    "grantControls": {"builtInControls": ["block"]},
                }
            ]
        )

        high_blocked, high_details = await evaluator.should_block_caller(
            "caller-id",
            fallback_risk="high",
        )
        missing_blocked, missing_details = await evaluator.should_block_caller(
            "caller-id",
            fallback_risk=None,
        )

        self.assertTrue(high_blocked)
        self.assertEqual(high_details["risk_source"], "sidecar")
        self.assertTrue(missing_blocked)
        self.assertEqual(missing_details["enforcement_source"], "fail_closed")

    async def test_entra_provider_ignores_sidecar_fallback(self):
        module = load_evaluator("entra")
        evaluator = module.CAEvaluator()
        evaluator.fetch_ca_policies = AsyncMock(
            return_value=[
                {
                    "id": "policy-id",
                    "state": "enabled",
                    "conditions": {"agentIdRiskLevels": ["high"]},
                    "grantControls": {"builtInControls": ["block"]},
                }
            ]
        )
        evaluator.fetch_agent_risk = AsyncMock(return_value=None)

        blocked, details = await evaluator.should_block_caller(
            "caller-id",
            fallback_risk="low",
        )

        self.assertTrue(blocked)
        self.assertEqual(details["risk_source"], "unavailable")
        evaluator.fetch_agent_risk.assert_awaited_once_with("caller-id")

    async def test_entra_provider_rejects_unrecognized_risk(self):
        for risk in ("", "unknown", "unknownFutureValue"):
            with self.subTest(risk=risk):
                module = load_evaluator("entra")
                evaluator = module.CAEvaluator()
                evaluator.fetch_ca_policies = AsyncMock(return_value=[risk_policy()])
                evaluator.fetch_agent_risk = AsyncMock(return_value=risk)
                blocked, details = await evaluator.should_block_caller("caller-id", fallback_risk="low")
                self.assertTrue(blocked)
                self.assertEqual(details["enforcement_source"], "fail_closed")


def risk_policy(state="enabled"):
    return {
        "id": "policy-id",
        "state": state,
        "conditions": {"agentIdRiskLevels": ["high"]},
        "grantControls": {"builtInControls": ["block"]},
    }


class CAGraphEvidenceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.module = load_evaluator("entra")
        self.evaluator = self.module.CAEvaluator()
        self.evaluator._get_graph_token = AsyncMock(return_value="synthetic-token")
        self.evaluator._resolve_sp_object_id = AsyncMock(return_value="resolved-sp")
        self.evaluator.fetch_agent_risk = AsyncMock(return_value="low")
        self.response = httpx.Response(200, json={"value": [risk_policy()]})
        self.async_client = httpx.AsyncClient

    def client(self, *args, **kwargs):
        def respond(request):
            if isinstance(self.response, Exception):
                raise self.response
            return self.response
        return self.async_client(transport=httpx.MockTransport(respond), **kwargs)

    async def test_initial_policy_errors_deny_and_recover(self):
        for response in (
            httpx.Response(503),
            httpx.ReadTimeout("fixture timeout"),
            httpx.Response(200, content="{"),
            httpx.Response(200, json={}),
            httpx.Response(200, json={"value": None}),
        ):
            with self.subTest(response=type(response).__name__):
                self.evaluator._policy_cache = {"policies": None, "fetched_at": 0}
                self.response = response
                with patch.object(self.module.httpx, "AsyncClient", self.client):
                    policies = await self.evaluator.fetch_ca_policies()
                    self.assertIsNone(policies)
                    blocked, details = await self.evaluator.should_block_caller("caller-id")
                    self.assertTrue(blocked)
                    self.assertEqual(details["enforcement_source"], "fail_closed")
                    self.response = httpx.Response(200, json={"value": [risk_policy()]})
                    blocked, details = await self.evaluator.should_block_caller("caller-id")
                    self.assertFalse(blocked)
                    self.assertEqual(details["agent_risk"], "low")

    async def test_trustworthy_no_applicable_policy_allows_without_risk(self):
        for policies in ([], [risk_policy("disabled")], [risk_policy("enabledForReportingButNotEnforced")]):
            with self.subTest(policies=policies):
                self.evaluator._policy_cache = {"policies": None, "fetched_at": 0}
                self.response = httpx.Response(200, json={"value": policies})
                with patch.object(self.module.httpx, "AsyncClient", self.client):
                    blocked, details = await self.evaluator.should_block_caller("caller-id")
                    self.assertFalse(blocked)
                    self.assertEqual(details["blocked_risk_levels"], [])
                    self.evaluator.fetch_agent_risk.assert_not_awaited()

    async def test_last_known_good_policy_survives_refresh_errors(self):
        for policies in ([], [risk_policy()]):
            for failure in (httpx.Response(503), httpx.ReadTimeout("fixture timeout"),
                            httpx.Response(200, json={})):
                with self.subTest(policies=policies, failure=type(failure).__name__):
                    self.evaluator._policy_cache = {"policies": None, "fetched_at": 0}
                    self.response = httpx.Response(200, json={"value": policies})
                    with patch.object(self.module.httpx, "AsyncClient", self.client):
                        self.assertEqual(await self.evaluator.fetch_ca_policies(), policies)
                        self.evaluator._policy_cache["fetched_at"] = 0
                        self.response = failure
                        self.assertEqual(await self.evaluator.fetch_ca_policies(), policies)
                        self.assertEqual(self.evaluator._policy_cache["fetched_at"], 0)
                        self.evaluator.fetch_agent_risk = AsyncMock(return_value="high")
                        blocked, _ = await self.evaluator.should_block_caller("caller-id")
                        self.assertEqual(blocked, bool(policies))

    async def test_initial_token_unavailable_is_not_empty_policy(self):
        self.evaluator._get_graph_token = AsyncMock(return_value=None)
        self.assertIsNone(await self.evaluator.fetch_ca_policies())
        blocked, details = await self.evaluator.should_block_caller("caller-id")
        self.assertTrue(blocked)
        self.assertEqual(details["enforcement_source"], "fail_closed")

    async def test_policy_token_errors_preserve_availability_and_last_good(self):
        del self.evaluator._get_graph_token
        for failure in (httpx.ReadTimeout("fixture token timeout"), httpx.Response(200, json={})):
            for policies in (None, [], [risk_policy()]):
                with self.subTest(policies=policies, failure=type(failure).__name__):
                    self.evaluator._token_cache = {"token": None, "expires_at": 0}
                    self.evaluator._policy_cache = {"policies": policies, "fetched_at": 0}
                    self.response = failure
                    with patch.object(self.module.httpx, "AsyncClient", self.client):
                        self.assertEqual(await self.evaluator.fetch_ca_policies(), policies)
                        blocked, _ = await self.evaluator.should_block_caller("caller-id")
                        self.assertEqual(blocked, policies is None)

    async def test_graph_risk_requires_observed_recognized_level(self):
        del self.evaluator.fetch_agent_risk
        for level in ("missing", None, "", "unknown", "unknownFutureValue", "none", "low", "medium", "high"):
            for state in ("atRisk", "confirmedSafe"):
                with self.subTest(level=level, state=state):
                    data = {"riskState": state}
                    if level != "missing":
                        data["riskLevel"] = level
                    self.response = httpx.Response(200, json=data)
                    self.evaluator._risk_cache = {}
                    with patch.object(self.module.httpx, "AsyncClient", self.client):
                        risk = await self.evaluator.fetch_agent_risk("caller-id")
                        if level not in ("none", "low", "medium", "high"):
                            self.assertIsNone(risk)
                            self.assertEqual(self.evaluator._risk_cache, {})
                        else:
                            self.assertEqual(risk, "none" if state == "confirmedSafe" else level)

    async def test_graph_risk_transport_errors_deny_after_cache_ttl(self):
        del self.evaluator.fetch_agent_risk
        self.response = httpx.Response(200, json={"riskLevel": "low", "riskState": "atRisk"})
        with patch.object(self.module.httpx, "AsyncClient", self.client):
            self.assertEqual(await self.evaluator.fetch_agent_risk("caller-id"), "low")
            self.response = httpx.Response(503)
            self.assertEqual(await self.evaluator.fetch_agent_risk("caller-id"), "low")
            self.evaluator._risk_cache["resolved-sp"]["fetched_at"] = 0
            self.assertIsNone(await self.evaluator.fetch_agent_risk("caller-id"))

    async def test_resolved_graph_risk_404_retains_documented_no_risk(self):
        del self.evaluator.fetch_agent_risk
        self.response = httpx.Response(404)
        with patch.object(self.module.httpx, "AsyncClient", self.client):
            self.assertEqual(await self.evaluator.fetch_agent_risk("caller-id"), "none")
            self.evaluator._resolve_sp_object_id = AsyncMock(return_value=None)
            self.assertIsNone(await self.evaluator.fetch_agent_risk("unresolved"))


if __name__ == "__main__":
    unittest.main()
