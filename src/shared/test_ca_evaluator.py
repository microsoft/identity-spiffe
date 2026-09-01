import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


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


if __name__ == "__main__":
    unittest.main()
