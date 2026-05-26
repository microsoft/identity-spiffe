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
    portal_crowdstrike_app_display_name,
    portal_management_app_display_name,
    portal_viewer_group_display_name,
    portal_viewer_group_mail_nickname,
    resolve_scope,
    sanitize_scope_key,
)


class EntraScopeTests(unittest.TestCase):
    def test_fresh_environment_defaults_to_scoped(self):
        env = {"AZURE_ENV_NAME": "aim-second-env"}
        persisted = {}

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "scoped")
        self.assertEqual(scope.scope_key, "aim-second-env")
        self.assertEqual(scope.mode_source, "auto-scoped")
        self.assertEqual(persisted["AIM_ENV_SCOPE_MODE"], "scoped")
        self.assertEqual(persisted["AIM_ENV_SCOPE_KEY"], "aim-second-env")

    def test_existing_bootstrap_state_defaults_to_legacy(self):
        env = {"AZURE_ENV_NAME": "aim-existing"}
        persisted = {"ENTRA_BLUEPRINT_OBJECT_ID": "blueprint-obj"}

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "legacy")
        self.assertEqual(scope.scope_key, "aim-existing")
        self.assertEqual(scope.mode_source, "auto-legacy")
        self.assertEqual(persisted["AIM_ENV_SCOPE_MODE"], "legacy")

    def test_shared_portal_group_ids_do_not_force_legacy(self):
        env = {"AZURE_ENV_NAME": "aim-existing"}
        persisted = {
            "AIM_ADMIN_GROUP_ID": "shared-admin-group-id",
            "AIM_VIEWER_GROUP_ID": "shared-viewer-group-id",
        }

        scope = resolve_scope(
            env_get=lambda key: persisted.get(key),
            env_set=lambda key, value: persisted.__setitem__(key, value),
            environ=env,
        )

        self.assertEqual(scope.mode, "scoped")
        self.assertEqual(scope.mode_source, "auto-scoped")

    def test_scope_key_sanitization_is_stable(self):
        self.assertEqual(sanitize_scope_key("Aim__Prod!!!West"), "aim-prod-west")
        self.assertEqual(sanitize_scope_key("a" * 40), "a" * 32)

    def test_scoped_name_generation_matches_contract(self):
        scope = EntraScope(
            mode="scoped",
            env_name="aim-bc4d",
            scope_key="aim-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )

        self.assertEqual(
            blueprint_display_name(scope),
            "AIM Prototype Platform Budget Backend Agents [aim-bc4d]",
        )
        self.assertEqual(
            agent_identity_display_name("budget-report", scope),
            "aim-bc4d-budget-report",
        )
        self.assertEqual(
            fic_name("budget-report", scope),
            "aim-fic-bc4d-budget-report",
        )
        self.assertEqual(
            portal_management_app_display_name(scope),
            "AIM Portal - Management [aim-bc4d]",
        )
        self.assertEqual(
            portal_crowdstrike_app_display_name(scope),
            "AIM Portal - CrowdStrike Mock [aim-bc4d]",
        )
        self.assertEqual(
            portal_admin_group_display_name(scope),
            "AIM Administrators",
        )
        self.assertEqual(
            portal_viewer_group_display_name(scope),
            "AIM Viewers",
        )
        self.assertEqual(
            portal_admin_group_mail_nickname(scope),
            "aim-administrators",
        )
        self.assertEqual(
            portal_viewer_group_mail_nickname(scope),
            "aim-viewers",
        )

    def test_legacy_name_generation_matches_current_production_names(self):
        scope = EntraScope(
            mode="legacy",
            env_name="aim-prod",
            scope_key="aim-prod",
            mode_source="explicit",
            key_source="explicit",
        )

        self.assertEqual(
            blueprint_display_name(scope),
            "AIM Prototype Platform Budget Backend Agents",
        )
        self.assertEqual(
            agent_identity_display_name("budget-report", scope),
            "aim-budget-report",
        )
        self.assertEqual(fic_name("budget-report", scope), "aim-fic-budget-report")
        self.assertEqual(
            portal_management_app_display_name(scope),
            "AIM Portal - Management",
        )
        self.assertEqual(
            portal_admin_group_display_name(scope),
            "AIM Administrators",
        )


if __name__ == "__main__":
    unittest.main()
