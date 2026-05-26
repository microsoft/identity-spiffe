#!/usr/bin/env python3
"""Unit tests for additive RBAC quick-fix policy merge behavior."""

import unittest

import yaml

from portal.app.services.policy import PolicyService
from portal.app.settings import ControlPlaneConfig, PortalSettings


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
    def test_build_permissive_rbac_yaml_enforces_submit_role_for_budget_report(self):
        service = _make_service()

        policy = yaml.safe_load(service.build_permissive_rbac_yaml())
        report = next(entry for entry in policy["policies"] if entry.get("name") == "budget-report")
        submit_rule = next(rule for rule in report["rules"] if rule.get("path") == "/budget/submit")

        self.assertEqual(submit_rule.get("action"), "allow")
        self.assertTrue(submit_rule.get("require_jwt"))
        self.assertEqual(submit_rule.get("required_roles"), ["Budget.Submit"])

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


if __name__ == "__main__":
    unittest.main()
