import importlib.util
import os
import sys
import unittest
from unittest.mock import patch


SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from entra_scope import EntraScope  # noqa: E402


def load_script_module(module_name, filename):
    path = os.path.join(SCRIPTS_DIR, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CreateEntraAgentIdsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_script_module("create_entra_agent_ids", "create-entra-agent-ids.py")

    def setUp(self):
        self.module._SCOPE = None

    def test_find_existing_agent_identity_prefers_stored_app_id(self):
        calls = []

        class Response:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.text = ""

            def json(self):
                return self._payload

        def fake_graph_request(method, path, token, json_body=None, retry=True):
            calls.append(path)
            if "appId eq 'stored-app'" in path:
                return Response(200, {"value": [{"id": "sp-id", "appId": "stored-app"}]})
            return Response(200, {"value": []})

        with patch.object(self.module, "graph_request", side_effect=fake_graph_request):
            existing = self.module.find_existing_agent_identity(
                "token",
                "aim-aim-bc4d-budget-report",
                stored_app_id="stored-app",
            )

        self.assertEqual(existing["appId"], "stored-app")
        self.assertEqual(len(calls), 1)
        self.assertIn("appId eq 'stored-app'", calls[0])

    def test_create_agent_identities_uses_scoped_display_names(self):
        scoped = EntraScope(
            mode="scoped",
            env_name="aim-bc4d",
            scope_key="aim-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )
        self.module._SCOPE = scoped
        seen_display_names = []
        stored_pairs = []

        def fake_find_existing(token, display_name, stored_app_id=None):
            seen_display_names.append(display_name)
            return {"appId": f"app-for-{display_name}"}

        with patch.object(self.module, "find_existing_agent_identity", side_effect=fake_find_existing):
            with patch.object(self.module, "get_signed_in_user_id", return_value=None):
                with patch.object(self.module, "set_azd_env", side_effect=lambda key, value: stored_pairs.append((key, value))):
                    self.module.create_agent_identities("token", "blueprint-app-id")

        self.assertIn("aim-bc4d-budget-report", seen_display_names)
        self.assertIn("aim-bc4d-admin-control-plane", seen_display_names)
        self.assertIn(
            ("ENTRA_AGENT_ID_BUDGET_REPORT", "app-for-aim-bc4d-budget-report"),
            stored_pairs,
        )

    def test_scoped_fic_repair_only_deletes_scoped_name(self):
        scoped = EntraScope(
            mode="scoped",
            env_name="aim-bc4d",
            scope_key="aim-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )
        self.module._SCOPE = scoped
        deleted_paths = []

        class Response:
            def __init__(self, status_code, payload=None, text=""):
                self.status_code = status_code
                self._payload = payload or {}
                self.text = text

            def json(self):
                return self._payload

        def fake_graph_request(method, path, token, json_body=None, retry=True):
            if method == "PATCH":
                return Response(204)
            if method == "GET" and path.endswith("/federatedIdentityCredentials"):
                return Response(
                    200,
                    {
                        "value": [
                            {
                                "id": "scoped-fic-id",
                                "name": "aim-fic-bc4d-budget-report",
                                "subject": "stale-principal",
                            },
                            {
                                "id": "legacy-fic-id",
                                "name": "aim-fic-budget-report",
                                "subject": "legacy-principal",
                            },
                        ]
                    },
                )
            if method == "DELETE":
                deleted_paths.append(path)
                return Response(204)
            if method == "POST":
                return Response(201)
            return Response(200, {"value": []})

        env_values = {
            "AZURE_TENANT_ID": "tenant-id",
            "AZURE_ENV_NAME": "aim-bc4d",
            "AZURE_RESOURCE_GROUP": "rg-example",
            "ENTRA_BLUEPRINT_APP_ID": "blueprint-app-id",
            "ENTRA_BLUEPRINT_OBJECT_ID": "blueprint-obj-id",
        }

        with patch.object(self.module, "graph_request", side_effect=fake_graph_request):
            with patch.object(self.module, "get_azd_env", side_effect=lambda key: env_values.get(key)):
                with patch.object(self.module, "set_azd_env", return_value=None):
                    with patch.object(self.module, "get_managed_identity_client_id", return_value="mi-client"):
                        with patch.object(self.module, "get_managed_identity_principal_id", return_value="new-principal"):
                            with patch.object(self.module, "time") as fake_time:
                                fake_time.sleep.return_value = None
                                self.module.create_federated_credentials("token")

        self.assertEqual(
            deleted_paths,
            [
                "/applications/blueprint-obj-id/federatedIdentityCredentials/scoped-fic-id",
            ],
        )


if __name__ == "__main__":
    unittest.main()
