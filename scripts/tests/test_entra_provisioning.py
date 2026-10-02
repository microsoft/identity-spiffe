import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import entra_provisioning


class TestGraphToken(unittest.TestCase):
    def _requests_module(self, response=None, error=None):
        class RequestException(Exception):
            pass

        def post(url, data, timeout):
            self.request = (url, data, timeout)
            if error:
                raise RequestException(error)
            return response

        return SimpleNamespace(post=post, RequestException=RequestException)

    @patch.object(
        entra_provisioning,
        "ensure_app_registration",
        return_value=("client-id", "client-secret", "tenant-id"),
    )
    def test_get_graph_token_uses_client_credentials(self, _ensure):
        response = SimpleNamespace(
            status_code=200,
            json=lambda: {"access_token": "graph-token"},
        )
        requests = self._requests_module(response=response)

        with patch.dict(sys.modules, {"requests": requests}):
            token = entra_provisioning.get_graph_token(
                required_values=[], wait_for_propagation=False
            )

        self.assertEqual(token, "graph-token")
        url, data, timeout = self.request
        self.assertEqual(
            url,
            "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
        )
        self.assertEqual(data["grant_type"], "client_credentials")
        self.assertEqual(data["scope"], "https://graph.microsoft.com/.default")
        self.assertEqual(timeout, 30)

    @patch.object(
        entra_provisioning,
        "ensure_app_registration",
        return_value=("client-id", "client-secret", "tenant-id"),
    )
    def test_get_graph_token_fails_closed_on_http_error(self, _ensure):
        response = SimpleNamespace(status_code=401)
        requests = self._requests_module(response=response)

        with patch.dict(sys.modules, {"requests": requests}):
            with self.assertRaisesRegex(
                entra_provisioning.ProvisionerBootstrapError,
                "HTTP 401",
            ):
                entra_provisioning.get_graph_token(
                    required_values=[], wait_for_propagation=False
                )

    @patch.object(
        entra_provisioning,
        "ensure_app_registration",
        return_value=("client-id", "client-secret", "tenant-id"),
    )
    def test_get_graph_token_rejects_missing_token(self, _ensure):
        response = SimpleNamespace(status_code=200, json=lambda: {})
        requests = self._requests_module(response=response)

        with patch.dict(sys.modules, {"requests": requests}):
            with self.assertRaisesRegex(
                entra_provisioning.ProvisionerBootstrapError,
                "did not contain",
            ):
                entra_provisioning.get_graph_token(
                    required_values=[], wait_for_propagation=False
                )


if __name__ == "__main__":
    unittest.main()
