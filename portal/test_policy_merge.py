#!/usr/bin/env python3
"""Unit tests for additive RBAC quick-fix policy merge behavior."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

import yaml

from portal.app.services.policy import PolicyService
from portal.app.services.scan import ScanService
from portal.app.settings import AgentConfig, ControlPlaneConfig, PortalSettings


def _make_service():
    return PolicyService(
        settings=PortalSettings(
            mode="live",
            runtime_environment="local",
            trust_domain="aim.microsoft.com",
            control_plane=ControlPlaneConfig(
                name="AdminControlPlane",
                url="https://admin-control-plane.example",
                spiffe_id="spiffe://aim.microsoft.com/ests/bp/x/aid/admin",
                entra_agent_id="admin-app-id",
            ),
        ),
        admin_client=None,
        policy_store=None,
    )


class TestPolicyMerge(unittest.TestCase):
    def test_build_permissive_rbac_yaml_disables_jwt_for_budget_routes(self):
        service = _make_service()

        policy = yaml.safe_load(service.build_permissive_rbac_yaml())
        report = next(entry for entry in policy["policies"] if entry.get("name") == "budget-report")
        submit_rule = next(rule for rule in report["rules"] if rule.get("path") == "/budget/submit")
        read_rule = next(rule for rule in report["rules"] if rule.get("path") == "/budget/read")

        self.assertEqual(submit_rule.get("action"), "allow")
        self.assertNotIn("require_jwt", submit_rule)
        self.assertNotIn("required_roles", submit_rule)
        self.assertNotIn("require_jwt", read_rule)
        self.assertNotIn("required_roles", read_rule)

    def test_enable_jwt_validation_preserves_permissive_rbac(self):
        service = _make_service()
        permissive = yaml.safe_load(service.build_permissive_rbac_yaml())

        fixed = service.enable_jwt_validation(permissive)
        report = next(entry for entry in fixed["policies"] if entry.get("name") == "budget-report")
        read_rule = next(rule for rule in report["rules"] if rule.get("path") == "/budget/read")
        submit_rule = next(rule for rule in report["rules"] if rule.get("path") == "/budget/submit")

        self.assertEqual(fixed["default_action"], "allow")
        self.assertTrue(read_rule["require_jwt"])
        self.assertEqual(read_rule["required_roles"], ["Budget.Read"])
        self.assertTrue(submit_rule["require_jwt"])
        self.assertEqual(submit_rule["required_roles"], ["Budget.Submit"])

    def test_demo_presets_do_not_require_risk_evidence(self):
        service = _make_service()
        for build in (service.build_hardened_rbac_yaml, service.build_permissive_rbac_yaml):
            policy = yaml.safe_load(build())
            self.assertEqual(policy["admin_governance"]["risk_enforcement"], "off")
            self.assertTrue(policy["admin_governance"]["enabled"])
            for entry in policy["policies"]:
                self.assertNotIn("blocked_risk_levels", entry.get("ca", {}))

    def test_presets_put_foreign_agents_in_federated_policies(self):
        service = _make_service()
        service.settings.agents["google-budget-reader"] = AgentConfig(
            key="google-budget-reader",
            name="GoogleBudgetReader",
            role="federated-caller",
            url="",
            spiffe_id="spiffe://gcp.aim.microsoft.com/ests/bp/google/aid/reader",
            entra_agent_id="reader",
            hosting_platform="gcp",
        )

        for yaml_text in (
            service.build_hardened_rbac_yaml(),
            service.build_permissive_rbac_yaml(),
        ):
            policy = yaml.safe_load(yaml_text)
            self.assertFalse(
                any(entry.get("name") == "google-budget-reader" for entry in policy["policies"])
            )
            google = next(
                entry
                for entry in policy["federated_policies"]
                if entry.get("name") == "google-budget-reader"
            )
            self.assertEqual(google["trust_domain"], "gcp.aim.microsoft.com")
            self.assertEqual(
                google["spiffe_id"],
                "spiffe://gcp.aim.microsoft.com/ests/bp/google/aid/reader",
            )
            self.assertNotIn("spiffe_id_prefix", google)

    def test_permissive_preset_adds_employee_menus_to_mtls(self):
        service = _make_service()
        service.settings.agents.update(
            {
                key: AgentConfig(
                    key=key,
                    name=key,
                    role="caller",
                    url="",
                    spiffe_id="spiffe://aim.microsoft.com/ests/bp/x/aid/{0}".format(key),
                    entra_agent_id=key,
                )
                for key in ("budget-report", "budget-approval", "employee-menus")
            }
        )

        permissive = service.preset_mtls_ids("permissive")
        hardened = service.preset_mtls_ids("hardened")

        self.assertIn(service.get_agent_spiffe_id("employee-menus"), permissive)
        self.assertNotIn(service.get_agent_spiffe_id("employee-menus"), hardened)
        self.assertIn(service.get_control_plane_spiffe_id(), permissive)
        self.assertIn(service.get_control_plane_spiffe_id(), hardened)

    def test_merge_rules_drops_overlapping_broad_allow(self):
        service = _make_service()
        existing_rules = [
            {
                "path": "/budget/*",
                "methods": ["*"],
                "action": "allow",
                "require_jwt": True,
                "required_roles": ["Legacy.All"],
            },
            {
                "path": "/healthz",
                "methods": ["GET"],
                "action": "allow",
            },
        ]

        desired_rules = [
            {
                "path": "/budget/read",
                "methods": ["GET"],
                "action": "allow",
                "require_jwt": True,
                "required_roles": ["Budget.Read"],
            },
            {
                "path": "/budget/*",
                "methods": ["POST", "PUT", "DELETE"],
                "action": "deny",
            },
        ]

        merged = service.merge_rules(existing_rules, desired_rules)

        self.assertFalse(any(r.get("path") == "/budget/*" and r.get("methods") == ["*"] for r in merged))
        self.assertTrue(any(r.get("path") == "/healthz" for r in merged))

    def test_merge_rules_preserves_jwt_fields_on_exact_match(self):
        service = _make_service()
        existing_rules = [
            {
                "path": "/budget/read",
                "methods": ["GET"],
                "action": "allow",
                "require_jwt": True,
                "required_roles": ["Budget.Read"],
                "custom_meta": "keep-me",
            }
        ]

        desired_rules = [
            {
                "path": "/budget/read",
                "methods": ["GET"],
                "action": "allow",
                "require_jwt": True,
                "required_roles": ["Budget.Read"],
            }
        ]

        merged = service.merge_rules(existing_rules, desired_rules)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].get("custom_meta"), "keep-me")
        self.assertTrue(merged[0].get("require_jwt"))
        self.assertEqual(merged[0].get("required_roles"), ["Budget.Read"])

    def test_harden_policy_additive_sets_default_deny_and_enforces_report_scope(self):
        service = _make_service()
        current_policy = {
            "version": "4.0",
            "trust_domain": "aim.microsoft.com",
            "default_action": "allow",
            "policies": [
                {
                    "name": "budget-report",
                    "spiffe_id": "spiffe://aim.microsoft.com/ests/bp/x/aid/report",
                    "rules": [
                        {
                            "path": "/budget/*",
                            "methods": ["*"],
                            "action": "allow",
                            "require_jwt": True,
                            "required_roles": ["Legacy.All"],
                        }
                    ],
                },
                {
                    "name": "budget-approval",
                    "spiffe_id": "spiffe://aim.microsoft.com/ests/bp/x/aid/approval",
                    "rules": [
                        {
                            "path": "/mgmt/*",
                            "methods": ["GET", "PUT"],
                            "action": "allow",
                        }
                    ],
                },
            ],
        }

        merged = service.harden_policy_additive(current_policy)
        self.assertEqual(merged.get("default_action"), "deny")

        report = next(p for p in merged["policies"] if "budget-report" in p.get("name", ""))
        report_rules = report.get("rules", [])

        self.assertTrue(any(r.get("path") == "/budget/read" and r.get("action") == "allow" for r in report_rules))
        self.assertTrue(any(r.get("path") == "/budget/*" and r.get("action") == "deny" for r in report_rules))
        self.assertFalse(any(r.get("path") == "/budget/*" and r.get("methods") == ["*"] and r.get("action") == "allow" for r in report_rules))

    def test_ensure_control_plane_policy_restores_management_rules(self):
        service = _make_service()
        policy = {"version": "4.0", "policies": [{"name": "budget-report", "rules": []}]}

        guarded = service.ensure_control_plane_policy(policy)
        control_plane = next(entry for entry in guarded["policies"] if entry.get("name") == "admin-control-plane")

        self.assertTrue(control_plane["ca"]["skip_target_tag_check"])
        self.assertTrue(any(rule.get("path") == "/mgmt/*" and rule.get("action") == "allow" for rule in control_plane["rules"]))

    def test_ensure_control_plane_in_mtls_adds_management_spiffe_id(self):
        service = _make_service()
        guarded_ids = service.ensure_control_plane_in_mtls(["spiffe://aim.microsoft.com/ests/bp/x/aid/report"])

        self.assertIn("spiffe://aim.microsoft.com/ests/bp/x/aid/admin", guarded_ids)


class TestSecurityScan(unittest.IsolatedAsyncioTestCase):
    async def test_scan_reports_disabled_jwt_validation(self):
        policy_service = SimpleNamespace(
            get_mtls_policy=AsyncMock(return_value={"allowed_ids": []}),
            get_policy=AsyncMock(
                return_value={
                    "default_action": "allow",
                    "policies": [
                        {
                            "name": "budget-report",
                            "rules": [
                                {
                                    "path": "/budget/submit",
                                    "methods": ["POST"],
                                    "action": "allow",
                                }
                            ],
                        }
                    ],
                    "federated_policies": [],
                }
            ),
            settings=SimpleNamespace(agents={}, control_plane=SimpleNamespace(spiffe_id="")),
            get_agent_spiffe_id=lambda key: "spiffe://aim.microsoft.com/{0}".format(key),
            build_hardened_rbac_yaml=lambda: "version: '5.0'",
            is_agent_policy=lambda policy, agent_key: False,
        )

        result = await ScanService(policy_service).run_scan("request-id")
        finding = next(item for item in result["findings"] if item["id"] == "oauth-jwt-validation-disabled")

        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["fix_type"], "oauth-jwt")


if __name__ == "__main__":
    unittest.main()
