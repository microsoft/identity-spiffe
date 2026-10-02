"""Risk signal preferences and explicit enforcement controls."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

import yaml

from portal.app.errors import PortalError
from portal.app.services.risk_settings import RiskSettingsService


class TestRiskSettings(unittest.IsolatedAsyncioTestCase):
    def make_service(self, entries=None):
        store = SimpleNamespace(
            list_configs=AsyncMock(return_value=entries or []),
            write_configs=AsyncMock(),
        )
        graph = SimpleNamespace(fetch_risky_agents=AsyncMock(return_value={}))
        policy = SimpleNamespace(
            get_policy=AsyncMock(return_value={
                "version": "5.0", "admin_governance": {"enabled": True, "risk_enforcement": "sts"},
                "policies": [{"name": "budget-report", "rules": []}], "loaded_at": "runtime-only",
            }),
            put_policy=AsyncMock(return_value={"status": "updated"}),
            admin_client=SimpleNamespace(get_json=AsyncMock(
                return_value={"risk_enforcement_control_supported": True},
            )),
        )
        return RiskSettingsService(store, graph, policy)

    async def test_default_reads_entra_and_empty_records_do_not_supply_safe_ratings(self):
        service = self.make_service()
        result = await service.signal_status()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["status"], "on")
        self.assertEqual(result["risks"], {})
        service.graph_client.fetch_risky_agents.assert_awaited_once()

    async def test_disabled_does_not_call_graph(self):
        service = self.make_service([{"entra_signal_enabled": False}])
        result = await service.signal_status()
        self.assertEqual(result["status"], "off")
        service.graph_client.fetch_risky_agents.assert_not_awaited()

    async def test_license_failure_is_unavailable_not_off_or_safe(self):
        service = self.make_service()
        service.graph_client.fetch_risky_agents.side_effect = PortalError(
            502, "graph_risky_agents_failed", "Risk API failed",
            {"body": "Your tenant is not licensed for this feature."},
        )
        result = await service.signal_status()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("not licensed", result["detail"])
        self.assertEqual(result["risks"], {})

    async def test_graph_payload_is_replaced_with_customer_facing_license_message(self):
        service = self.make_service()
        service.graph_client.fetch_risky_agents.side_effect = PortalError(
            502, "graph_risky_agents_failed", "Failed to fetch risky agents from Microsoft Graph",
            {"status_code": 403, "body": '{"error":{"code":"Forbidden","message":"Your tenant is not licensed for this feature.","innerError":{"request-id":"internal-request-id"}}}'},
        )
        result = await service.signal_status()
        self.assertEqual(result["detail"], "Your tenant is not licensed for this feature.")
        self.assertNotIn("internal-request-id", result["detail"])

    async def test_unexpected_provider_errors_do_not_expose_internal_details(self):
        service = self.make_service()
        service.graph_client.fetch_risky_agents.side_effect = PortalError(
            502, "graph_risky_agents_failed", "Internal connection failure",
            {"status_code": 503, "body": "<html>Internal upstream diagnostics</html>"},
        )
        result = await service.signal_status()
        self.assertEqual(result["detail"], "Entra agent risk signals are temporarily unavailable. Try again later.")
        self.assertEqual(result["status"], "unavailable")

    async def test_signal_read_is_cached_and_toggle_invalidates(self):
        service = self.make_service()
        await service.signal_status()
        await service.signal_status()
        service.graph_client.fetch_risky_agents.assert_awaited_once()
        await service.set_signal_enabled(True)
        self.assertEqual(service.graph_client.fetch_risky_agents.await_count, 2)
        service.store.write_configs.assert_awaited_once_with([{"entra_signal_enabled": True}])

    async def test_invalid_stored_setting_is_rejected(self):
        service = self.make_service([{"entra_signal_enabled": "false"}])
        with self.assertRaises(PortalError):
            await service.signal_status()
        service.graph_client.fetch_risky_agents.assert_not_awaited()

    async def test_storage_outage_is_not_a_disabled_default(self):
        service = self.make_service()
        service.store.list_configs.side_effect = OSError("store unreachable")
        with self.assertRaises(PortalError) as ctx:
            await service.signal_status()
        self.assertEqual(ctx.exception.error_code, "risk_settings_unavailable")

    async def test_enforcement_off_changes_only_risk_mode(self):
        service = self.make_service()
        await service.set_enforcement_enabled(False, "request-id")
        text, request_id = service.policy_service.put_policy.await_args.args
        updated = yaml.safe_load(text)
        self.assertEqual(updated["admin_governance"], {"enabled": True, "risk_enforcement": "off"})
        self.assertEqual(updated["policies"], [{"name": "budget-report", "rules": []}])
        self.assertNotIn("loaded_at", updated)
        self.assertEqual(request_id, "request-id")

    async def test_old_sidecar_is_rejected_before_mutation(self):
        service = self.make_service()
        service.policy_service.admin_client.get_json.return_value = {"status": "healthy"}
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(False, "request-id")
        self.assertEqual(ctx.exception.error_code, "sidecar_upgrade_required")
        service.policy_service.put_policy.assert_not_awaited()

    async def test_unavailable_signal_does_not_disable_enforcement(self):
        service = self.make_service()
        service.graph_client.fetch_risky_agents.side_effect = PortalError(
            502, "graph_risky_agents_failed", "Risk API unavailable",
        )
        result = await service.get_settings("request-id")
        self.assertEqual(result["signal"]["status"], "unavailable")
        self.assertTrue(result["risk_enforcement_enabled"])
        service.policy_service.put_policy.assert_not_awaited()

    async def test_enabling_local_enforcement_requires_enabled_governance(self):
        service = self.make_service()
        service.policy_service.get_policy.return_value["admin_governance"]["enabled"] = False
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(True, "request-id")
        self.assertEqual(ctx.exception.error_code, "governance_disabled")
        service.policy_service.put_policy.assert_not_awaited()

    async def test_preferences_survive_service_recreation_and_reconcile_sidecar(self):
        service = self.make_service([{
            "entra_signal_enabled": False, "risk_enforcement_enabled": False,
        }])
        recreated = RiskSettingsService(service.store, service.graph_client, service.policy_service)
        result = await recreated.get_settings("request-id")
        self.assertEqual(result["signal"]["status"], "off")
        self.assertFalse(result["risk_enforcement_enabled"])
        text, _ = recreated.policy_service.put_policy.await_args.args
        self.assertEqual(yaml.safe_load(text)["admin_governance"]["risk_enforcement"], "off")

    async def test_signal_toggle_preserves_enforcement_preference(self):
        service = self.make_service([{
            "entra_signal_enabled": True, "risk_enforcement_enabled": True,
        }])
        await service.set_signal_enabled(False)
        service.store.write_configs.assert_awaited_once_with([{
            "entra_signal_enabled": False, "risk_enforcement_enabled": True,
        }])

    async def test_failed_sidecar_update_restores_saved_setting(self):
        service = self.make_service([{
            "entra_signal_enabled": True, "risk_enforcement_enabled": True,
        }])
        service.policy_service.put_policy.side_effect = PortalError(502, "update_failed", "sidecar unavailable")
        with self.assertRaises(PortalError):
            await service.set_enforcement_enabled(False, "request-id")
        self.assertEqual(service.store.write_configs.await_count, 2)
        service.store.write_configs.assert_awaited_with([{
            "entra_signal_enabled": True, "risk_enforcement_enabled": True,
        }])

    async def test_write_failure_does_not_change_live_enforcement(self):
        service = self.make_service()
        service.store.write_configs.side_effect = OSError("storage unavailable")
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(False, "request-id")
        self.assertEqual(ctx.exception.error_code, "risk_settings_write_failed")
        service.policy_service.put_policy.assert_not_awaited()

    async def test_failed_rollback_reports_partial_update(self):
        service = self.make_service()
        service.policy_service.put_policy.side_effect = PortalError(502, "update_failed", "sidecar unavailable")
        service.store.write_configs.side_effect = [None, OSError("storage unavailable")]
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(False, "request-id")
        self.assertEqual(ctx.exception.error_code, "risk_settings_partial_update")

    async def test_enforcement_toggle_preserves_signal_preference(self):
        service = self.make_service([{"entra_signal_enabled": False}])
        await service.set_enforcement_enabled(False, "request-id")
        service.store.write_configs.assert_awaited_once_with([{
            "entra_signal_enabled": False, "risk_enforcement_enabled": False,
        }])

    async def test_enabling_without_control_plane_evidence_does_not_lock_out_management(self):
        service = self.make_service()
        service.policy_service.get_control_plane_spiffe_id = lambda: "spiffe://test/admin"
        service.policy_service.admin_client.get_json.return_value["entra_risk_enforcement_supported"] = True
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(True, "request-id")
        self.assertEqual(ctx.exception.error_code, "risk_enforcement_not_ready")
        service.store.write_configs.assert_not_awaited()
        service.policy_service.put_policy.assert_not_awaited()

    async def test_enabling_with_ready_cache_and_permitted_control_plane_evidence(self):
        service = self.make_service()
        service.policy_service.get_control_plane_spiffe_id = lambda: "spiffe://test/admin"

        async def get_json(path, request_id):
            return {
                "health": {"risk_enforcement_control_supported": True, "entra_risk_enforcement_supported": True},
                "entra-risk?spiffe_id=spiffe%3A%2F%2Ftest%2Fadmin": {"risks": {"spiffe://test/admin": "low"}},
                "ca-policy-effective": {"ready": True, "blocked_risk_levels": ["high"]},
            }[path]

        service.policy_service.admin_client.get_json.side_effect = get_json
        result = await service.set_enforcement_enabled(True, "request-id")
        self.assertTrue(result["risk_enforcement_enabled"])
        text, _ = service.policy_service.put_policy.await_args.args
        self.assertEqual(yaml.safe_load(text)["admin_governance"]["risk_enforcement"], "data_plane")

    async def test_cache_default_is_90_and_zero_is_persisted_and_applied(self):
        service = self.make_service([{"entra_signal_enabled": False, "risk_enforcement_enabled": False}])
        service.policy_service.admin_client.get_json.return_value["entra_risk_enforcement_supported"] = True
        self.assertEqual((await service.get_settings("request-id"))["risk_cache_seconds"], 90)
        await service.set_cache_seconds(0, "request-id")
        service.store.write_configs.assert_awaited_once_with([{
            "entra_signal_enabled": False, "risk_enforcement_enabled": False, "risk_cache_seconds": 0,
        }])
        text, _ = service.policy_service.put_policy.await_args.args
        governance = yaml.safe_load(text)["admin_governance"]
        self.assertEqual(governance["risk_cache_seconds"], 0)
        self.assertEqual(governance["risk_enforcement"], "off")

    async def test_cache_update_failure_restores_preferences(self):
        previous = {"entra_signal_enabled": False, "risk_enforcement_enabled": False, "risk_cache_seconds": 90}
        service = self.make_service([previous])
        service.policy_service.admin_client.get_json.return_value["entra_risk_enforcement_supported"] = True
        service.policy_service.put_policy.side_effect = PortalError(502, "failed", "Gateway unavailable")
        with self.assertRaises(PortalError):
            await service.set_cache_seconds(0, "request-id")
        service.store.write_configs.assert_awaited_with([previous])

    async def test_cache_reconciles_after_service_recreation(self):
        service = self.make_service([{"entra_signal_enabled": False, "risk_cache_seconds": 0}])
        service.policy_service.admin_client.get_json.return_value["entra_risk_enforcement_supported"] = True
        await service.get_settings("request-id")
        text, _ = service.policy_service.put_policy.await_args.args
        self.assertEqual(yaml.safe_load(text)["admin_governance"]["risk_cache_seconds"], 0)

    async def test_cache_rejects_invalid_values_and_old_gateways(self):
        service = self.make_service()
        for value in (-1, True, 0.5, "90", 9223372037):
            with self.assertRaises(PortalError):
                await service.set_cache_seconds(value, "request-id")
        with self.assertRaises(PortalError) as ctx:
            await service.set_cache_seconds(90, "request-id")
        self.assertEqual(ctx.exception.error_code, "sidecar_upgrade_required")
        service.store.write_configs.assert_not_awaited()

    async def test_enabling_does_not_accept_manual_risk_on_old_gateway(self):
        service = self.make_service()
        with self.assertRaises(PortalError) as ctx:
            await service.set_enforcement_enabled(True, "request-id")
        self.assertEqual(ctx.exception.error_code, "sidecar_upgrade_required")
        service.store.write_configs.assert_not_awaited()
