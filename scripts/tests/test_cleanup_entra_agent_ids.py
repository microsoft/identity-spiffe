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


class CleanupEntraAgentIdsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_script_module("cleanup_entra_agent_ids", "cleanup-entra-agent-ids.py")

    def test_scoped_cleanup_targets_only_current_env_prefix(self):
        scope = EntraScope(
            mode="scoped",
            env_name="isp-bc4d",
            scope_key="isp-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )
        queried_paths = []

        class Response:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.text = ""

            def json(self):
                return self._payload

        def fake_graph_request(method, path, token, retry=True):
            queried_paths.append(path)
            return Response(200, {"value": [{"id": "sp1", "displayName": "isp-isp-bc4d-budget-report"}]})

        with patch.object(self.module, "graph_request", side_effect=fake_graph_request):
            targets = self.module.find_target_service_principals("token", scope, all_envs=False)

        self.assertEqual(len(targets), 1)
        self.assertIn("startswith(displayName,'isp-isp-bc4d-')", queried_paths[0])

    def test_all_envs_cleanup_remains_explicit(self):
        scope = EntraScope(
            mode="scoped",
            env_name="isp-bc4d",
            scope_key="isp-bc4d",
            mode_source="explicit",
            key_source="explicit",
        )
        queried_paths = []

        class Response:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.text = ""

            def json(self):
                return self._payload

        def fake_graph_request(method, path, token, retry=True):
            queried_paths.append(path)
            return Response(200, {"value": []})

        with patch.object(self.module, "graph_request", side_effect=fake_graph_request):
            self.module.find_target_service_principals("token", scope, all_envs=True)

        self.assertEqual(queried_paths[0], "/servicePrincipals?$filter=startswith(displayName,'isp-')")

    def test_legacy_demo_fic_name_maps_back_to_current_env_sp_name(self):
        scope = EntraScope(
            mode="legacy",
            env_name="isp-prod",
            scope_key="isp-prod",
            mode_source="explicit",
            key_source="explicit",
        )

        self.assertEqual(
            self.module.derive_sp_name_from_fic_name("isp-fic-audit-reviewer", scope),
            "isp-audit-reviewer",
        )


if __name__ == "__main__":
    unittest.main()
