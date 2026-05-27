import os
import sys
import unittest


SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from entra_scope import (  # noqa: E402
    EntraScope,
    agent_identity_display_name,
    blueprint_display_name,
    fic_name,
    portal_admin_group_display_name,
    portal_admin_group_mail_nickname,
    portal_securityportal_app_display_name,
    portal_management_app_display_name,
    portal_viewer_group_display_name,
    portal_viewer_group_mail_nickname,
    resolve_scope,
    sanitize_scope_key,
)


class EntraScopeTests(unittest.TestCase):
    def test_fresh_environment_defaults_to_scoped(self):
        env = {"AZURE_ENV_NAME": "isp-second-env"}
        persisted = {}

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "scoped")
        self.assertEqual(scope.scope_key, "isp-second-env")
        self.assertEqual(scope.mode_source, "auto-scoped")
        self.assertEqual(persisted["ISP_ENV_SCOPE_MODE"], "scoped")
        self.assertEqual(persisted["ISP_ENV_SCOPE_KEY"], "isp-second-env")

    def test_existing_bootstrap_state_defaults_to_legacy(self):
        env = {"AZURE_ENV_NAME": "isp-existing"}
        persisted = {"ENTRA_BLUEPRINT_OBJECT_ID": "blueprint-obj"}

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "legacy")
        self.assertEqual(scope.scope_key, "isp-existing")
        self.assertEqual(scope.mode_source, "auto-legacy")
        self.assertEqual(persisted["ISP_ENV_SCOPE_MODE"], "legacy")

    def test_shared_portal_group_ids_do_not_force_legacy(self):
        env = {"AZURE_ENV_NAME": "isp-existing"}
        persisted = {
            "ISP_ADMIN_GROUP_ID": "shared-admin-group-id",
            "ISP_VIEWER_GROUP_ID": "shared-viewer-group-id",
        }

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "scoped")
        self.assertEqual(scope.mode_source, "auto-scoped")

    def test_scope_key_sanitization_is_stable(self):
        self.assertEqual(sanitize_scope_key("Isp__Prod!!!West"), "isp-prod-west")
        self.assertEqual(sanitize_scope_key("a" * 40), "a" * 32)

    def test_scoped_name_generation_matches_contract(self):
        scope = EntraScope(
            mode="scoped",
            env_name="isp-bc4d",
            scope_key="isp-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )

        self.assertEqual(
            blueprint_display_name(scope),
            "Agent Management Budget Backend Agents [isp-bc4d]",
        )
        self.assertEqual(
            agent_identity_display_name("budget-report", scope),
            "isp-bc4d-budget-report",
        )
        self.assertEqual(
            fic_name("budget-report", scope),
            "isp-fic-bc4d-budget-report",
        )
        self.assertEqual(
            portal_management_app_display_name(scope),
            "Agent Management Portal - Management [isp-bc4d]",
        )
        self.assertEqual(
            portal_securityportal_app_display_name(scope),
            "Agent Management Portal - Security Portal Mock [isp-bc4d]",
        )
        self.assertEqual(
            portal_admin_group_display_name(scope),
            "Agent Management Administrators",
        )
        self.assertEqual(
            portal_viewer_group_display_name(scope),
            "Agent Management Viewers",
        )
        self.assertEqual(
            portal_admin_group_mail_nickname(scope),
            "isp-administrators",
        )
        self.assertEqual(
            portal_viewer_group_mail_nickname(scope),
            "isp-viewers",
        )

    def test_legacy_name_generation_matches_current_production_names(self):
        scope = EntraScope(
            mode="legacy",
            env_name="isp-prod",
            scope_key="isp-prod",
            mode_source="explicit",
            key_source="explicit",
        )

        self.assertEqual(
            blueprint_display_name(scope),
            "Agent Management Budget Backend Agents",
        )
        self.assertEqual(
            agent_identity_display_name("budget-report", scope),
            "isp-budget-report",
        )
        self.assertEqual(fic_name("budget-report", scope), "isp-fic-budget-report")
        self.assertEqual(
            portal_management_app_display_name(scope),
            "Agent Management Portal - Management",
        )
        self.assertEqual(
            portal_admin_group_display_name(scope),
            "Agent Management Administrators",
        )


if __name__ == "__main__":
    unittest.main()
