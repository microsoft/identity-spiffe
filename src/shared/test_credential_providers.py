"""Tests for credential provider strategy pattern and token exchange.

Covers test plan items 10-15:
  10. GoogleOIDCProvider success (mocked GCE metadata)
  11. GoogleOIDCProvider metadata server unreachable → fail closed
  12. GoogleOIDCProvider metadata error response → fail closed
  13. AzureMIProvider refactored path still works
  14. Two-hop exchange with Google assertion (mocked)
  15. FIC mismatch → clear error propagation
"""
import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the directory containing entra_token_exchange.py is importable
_THIS_DIR = str(Path(__file__).resolve().parent)
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)


def _fresh_import():
    """Re-import the module to pick up env var changes.

    The module reads env vars at import time, so we need to force a reload
    after patching os.environ.
    """
    mod_name = "entra_token_exchange"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import entra_token_exchange
    return entra_token_exchange


class TestGoogleOIDCProvider(unittest.TestCase):
    """Test plan items 10-12: GoogleOIDCProvider."""

    def test_success_returns_token(self):
        """Item 10: GoogleOIDCProvider success with mocked GCE metadata."""
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake-google-token"

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp) as mock_get:
            token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertEqual(token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake-google-token")
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["headers"], {"Metadata-Flavor": "Google"})
        self.assertIn("audience", call_kwargs.kwargs["params"])

    def test_metadata_unreachable_fails_closed(self):
        """Item 11: Metadata server unreachable → returns None, not an exception."""
        import httpx as _httpx
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        with patch("entra_token_exchange.httpx.get", side_effect=_httpx.ConnectError("Connection refused")):
            token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertIsNone(token)
        self.assertIn("unreachable", mod._last_token_error)

    def test_metadata_timeout_fails_closed(self):
        """Item 11 (variant): Metadata server timeout → returns None."""
        import httpx as _httpx
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        with patch("entra_token_exchange.httpx.get", side_effect=_httpx.TimeoutException("timed out")):
            token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertIsNone(token)
        self.assertIn("unreachable", mod._last_token_error)

    def test_metadata_error_status_fails_closed(self):
        """Item 12: Metadata server returns non-200 → returns None."""
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 404
        fake_resp.text = "Not Found"

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp):
            token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertIsNone(token)
        self.assertIn("404", mod._last_token_error)

    def test_metadata_empty_token_fails_closed(self):
        """Item 12 (variant): Metadata returns empty body → returns None."""
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = "   "

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp):
            token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertIsNone(token)
        self.assertIn("empty", mod._last_token_error)

    def test_custom_metadata_url_via_kwargs(self):
        """GoogleOIDCProvider accepts metadata_url override via kwargs."""
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = "custom-token"

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp) as mock_get:
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                metadata_url="http://custom-metadata:8080/identity",
            )

        self.assertEqual(token, "custom-token")
        actual_url = mock_get.call_args.args[0]
        self.assertEqual(actual_url, "http://custom-metadata:8080/identity")


class TestGitHubOIDCProvider(unittest.TestCase):
    """GitHub Actions OIDC provider tests."""

    def test_success_returns_token(self):
        """GitHubOIDCProvider fetches OIDC token from Actions request URL."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"value": "eyJhbGciOiJSUzI1NiJ9.github-oidc-token"}

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp) as mock_get:
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/.well-known/openid-configuration",
                request_token="ghs_fake_token_value",
            )

        self.assertEqual(token, "eyJhbGciOiJSUzI1NiJ9.github-oidc-token")
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        self.assertIn("Bearer ghs_fake_token_value", call_kwargs.kwargs["headers"]["Authorization"])
        self.assertEqual(call_kwargs.kwargs["params"], {"audience": "api://AzureADTokenExchange"})

    def test_missing_request_url_fails_closed(self):
        """Missing ACTIONS_ID_TOKEN_REQUEST_URL → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        token = provider.get_upstream_assertion(
            "api://AzureADTokenExchange",
            request_url="",
            request_token="ghs_token",
        )

        self.assertIsNone(token)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", mod._last_token_error)

    def test_missing_request_token_fails_closed(self):
        """Missing ACTIONS_ID_TOKEN_REQUEST_TOKEN → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        token = provider.get_upstream_assertion(
            "api://AzureADTokenExchange",
            request_url="https://vstoken.actions.githubusercontent.com/token",
            request_token="",
        )

        self.assertIsNone(token)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", mod._last_token_error)

    def test_endpoint_unreachable_fails_closed(self):
        """OIDC endpoint unreachable → returns None, not an exception."""
        import httpx as _httpx
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        with patch("entra_token_exchange.httpx.get", side_effect=_httpx.ConnectError("Connection refused")):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("unreachable", mod._last_token_error)

    def test_endpoint_timeout_fails_closed(self):
        """OIDC endpoint timeout → returns None."""
        import httpx as _httpx
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        with patch("entra_token_exchange.httpx.get", side_effect=_httpx.TimeoutException("timed out")):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("unreachable", mod._last_token_error)

    def test_error_status_fails_closed(self):
        """OIDC endpoint non-200 → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Forbidden"

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("403", mod._last_token_error)

    def test_empty_value_fails_closed(self):
        """OIDC response with empty 'value' field → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"value": ""}

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("missing", mod._last_token_error.lower())

    def test_invalid_json_fails_closed(self):
        """OIDC response that isn't valid JSON → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.side_effect = ValueError("not json")

        with patch("entra_token_exchange.httpx.get", return_value=fake_resp):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("not valid JSON", mod._last_token_error)

    def test_generic_exception_fails_closed(self):
        """Unexpected exception during request → returns None."""
        mod = _fresh_import()
        provider = mod.GitHubOIDCProvider()

        with patch("entra_token_exchange.httpx.get", side_effect=RuntimeError("unexpected error")):
            token = provider.get_upstream_assertion(
                "api://AzureADTokenExchange",
                request_url="https://vstoken.actions.githubusercontent.com/token",
                request_token="ghs_token",
            )

        self.assertIsNone(token)
        self.assertIn("request failed", mod._last_token_error)


class TestAzureMIProvider(unittest.TestCase):
    """Test plan item 13: AzureMIProvider refactored path."""

    def test_success_returns_token(self):
        """Item 13: AzureMIProvider wraps ManagedIdentityCredential correctly."""
        mod = _fresh_import()
        provider = mod.AzureMIProvider()

        mock_token = MagicMock()
        mock_token.token = "azure-mi-token-value"
        mock_cred = MagicMock()
        mock_cred.get_token.return_value = mock_token
        provider._credential = mock_cred  # inject mock credential

        token = provider.get_upstream_assertion("api://AzureADTokenExchange")

        self.assertEqual(token, "azure-mi-token-value")
        mock_cred.get_token.assert_called_once_with("api://AzureADTokenExchange/.default")

    def test_required_env_vars(self):
        """AzureMIProvider requires MI_CLIENT_ID."""
        mod = _fresh_import()
        provider = mod.AzureMIProvider()
        self.assertIn("MI_CLIENT_ID", provider.required_env_vars)

    def test_google_provider_no_extra_env_vars(self):
        """GoogleOIDCProvider has no extra required env vars."""
        mod = _fresh_import()
        provider = mod.GoogleOIDCProvider()
        self.assertEqual(provider.required_env_vars, [])


class TestBuildProvider(unittest.TestCase):
    """TOKEN_SOURCE env var selection."""

    def test_azure_mi_default(self):
        mod = _fresh_import()
        provider = mod._build_provider("azure_mi")
        self.assertIsInstance(provider, mod.AzureMIProvider)

    def test_google_oidc(self):
        mod = _fresh_import()
        provider = mod._build_provider("google_oidc")
        self.assertIsInstance(provider, mod.GoogleOIDCProvider)

    def test_empty_defaults_to_azure(self):
        mod = _fresh_import()
        provider = mod._build_provider("")
        self.assertIsInstance(provider, mod.AzureMIProvider)

    def test_github_oidc(self):
        mod = _fresh_import()
        provider = mod._build_provider("github_oidc")
        self.assertIsInstance(provider, mod.GitHubOIDCProvider)

    def test_unknown_source_raises(self):
        mod = _fresh_import()
        with self.assertRaises(ValueError) as ctx:
            mod._build_provider("aws_sts")
        self.assertIn("aws_sts", str(ctx.exception))


class TestTwoHopExchange(unittest.TestCase):
    """Test plan items 14-15: Two-hop exchange with Google assertion."""

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_full_exchange_with_google_assertion(self):
        """Item 14: Two-hop exchange using GoogleOIDCProvider (all hops mocked)."""
        mod = _fresh_import()
        # Reset module state
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        # Mock Hop 0: Google metadata
        google_token = "google-oidc-token"
        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.text = google_token

        # Mock Hop 1: Blueprint exchange
        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "blueprint-t1-token"}

        # Mock Hop 2: Agent Identity exchange
        hop2_resp = MagicMock()
        hop2_resp.status_code = 200
        hop2_resp.json.return_value = {"access_token": "agent-t2-token", "expires_in": 3600}

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]) as mock_post:
            token = mod.get_entra_token()

        self.assertEqual(token, "agent-t2-token")
        self.assertIsNone(mod._last_token_error)

        # Verify Hop 1 used the Google token as client_assertion
        hop1_data = mock_post.call_args_list[0].kwargs["data"]
        self.assertEqual(hop1_data["client_assertion"], google_token)
        self.assertEqual(hop1_data["client_id"], "bp-app-id")
        self.assertEqual(hop1_data["fmi_path"], "agent-id")

        # Verify Hop 2 used T1 as client_assertion
        hop2_data = mock_post.call_args_list[1].kwargs["data"]
        self.assertEqual(hop2_data["client_assertion"], "blueprint-t1-token")
        self.assertEqual(hop2_data["client_id"], "agent-id")

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_fic_mismatch_propagates_error(self):
        """Item 15: FIC mismatch at Hop 1 → clear error in _last_token_error."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        # Mock Hop 0: Google metadata succeeds
        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.text = "google-oidc-token"

        # Mock Hop 1: FIC mismatch error
        hop1_resp = MagicMock()
        hop1_resp.status_code = 400
        hop1_resp.text = "AADSTS70021: No matching federated identity record found for presented assertion subject"

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", return_value=hop1_resp):
            token = mod.get_entra_token()

        self.assertIsNone(token)
        self.assertIn("AADSTS70021", mod._last_token_error)
        self.assertIn("Blueprint token exchange failed", mod._last_token_error)

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_ca_block_detected(self):
        """Conditional Access block (AADSTS53003) is logged as error, not warning."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.text = "google-oidc-token"

        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "t1"}

        hop2_resp = MagicMock()
        hop2_resp.status_code = 400
        hop2_resp.text = "AADSTS53003: Access blocked by Conditional Access"

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]):
            token = mod.get_entra_token()

        self.assertIsNone(token)
        self.assertIn("AADSTS53003", mod._last_token_error)

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_missing_shared_env_var_returns_none(self):
        """Missing shared env var (ENTRA_OAUTH2_AUDIENCE) → None with descriptive error."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        token = mod.get_entra_token()

        self.assertIsNone(token)
        self.assertIn("ENTRA_OAUTH2_AUDIENCE", mod._last_token_error)

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "github_oidc",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://vstoken.actions.githubusercontent.com/token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ghs_fake_runner_token",
    })
    def test_full_exchange_with_github_assertion(self):
        """Two-hop exchange using GitHubOIDCProvider (all hops mocked)."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        # Mock Hop 0: GitHub Actions OIDC
        github_token = "eyJhbGciOiJSUzI1NiJ9.github-actions-oidc"
        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.json.return_value = {"value": github_token}

        # Mock Hop 1: Blueprint exchange
        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "blueprint-t1-token"}

        # Mock Hop 2: Agent Identity exchange
        hop2_resp = MagicMock()
        hop2_resp.status_code = 200
        hop2_resp.json.return_value = {"access_token": "agent-t2-token", "expires_in": 3600}

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]) as mock_post:
            token = mod.get_entra_token()

        self.assertEqual(token, "agent-t2-token")
        self.assertIsNone(mod._last_token_error)

        # Verify Hop 1 used the GitHub token as client_assertion
        hop1_data = mock_post.call_args_list[0].kwargs["data"]
        self.assertEqual(hop1_data["client_assertion"], github_token)
        self.assertEqual(hop1_data["client_id"], "bp-app-id")
        self.assertEqual(hop1_data["fmi_path"], "agent-id")

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "github_oidc",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://vstoken.actions.githubusercontent.com/token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ghs_fake_runner_token",
    })
    def test_fic_mismatch_with_github_assertion(self):
        """FIC mismatch at Hop 1 with GitHub assertion → clear error."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.json.return_value = {"value": "github-oidc-token"}

        hop1_resp = MagicMock()
        hop1_resp.status_code = 400
        hop1_resp.text = "AADSTS70021: No matching federated identity record found for presented assertion subject"

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", return_value=hop1_resp):
            token = mod.get_entra_token()

        self.assertIsNone(token)
        self.assertIn("AADSTS70021", mod._last_token_error)


class TestTokenProvenance(unittest.TestCase):
    """M-AGENT-3: Verify provenance structure after successful exchange."""

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_provenance_structure_after_successful_exchange(self):
        """get_token_provenance() returns a dict with expected keys after exchange."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        # Mock all three hops
        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.text = "google-oidc-token"

        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "t1-token"}

        hop2_resp = MagicMock()
        hop2_resp.status_code = 200
        hop2_resp.json.return_value = {"access_token": "t2-token", "expires_in": 3600}

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]):
            token = mod.get_entra_token()

        self.assertEqual(token, "t2-token")
        provenance = mod.get_token_provenance()
        self.assertIsNotNone(provenance)
        self.assertIn("provider", provenance)
        self.assertIn("token_source", provenance)
        self.assertIn("hops", provenance)
        self.assertEqual(provenance["provider"], "GoogleOIDCProvider")
        self.assertEqual(provenance["token_source"], "google_oidc")
        # Verify hops structure
        self.assertEqual(len(provenance["hops"]), 3)
        self.assertEqual(provenance["hops"][0]["hop"], 0)
        self.assertEqual(provenance["hops"][1]["hop"], 1)
        self.assertEqual(provenance["hops"][2]["hop"], 2)

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "github_oidc",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://vstoken.actions.githubusercontent.com/token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ghs_fake_runner_token",
    })
    def test_provenance_structure_github(self):
        """Provenance shows GitHubOIDCProvider after successful exchange."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.json.return_value = {"value": "eyJhbGciOiJSUzI1NiJ9.fake.sig"}

        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "t1-token"}

        hop2_resp = MagicMock()
        hop2_resp.status_code = 200
        hop2_resp.json.return_value = {"access_token": "t2-token", "expires_in": 3600}

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]):
            token = mod.get_entra_token()

        self.assertEqual(token, "t2-token")
        provenance = mod.get_token_provenance()
        self.assertIsNotNone(provenance)
        self.assertEqual(provenance["provider"], "GitHubOIDCProvider")
        self.assertEqual(provenance["token_source"], "github_oidc")
        self.assertEqual(len(provenance["hops"]), 3)
        self.assertEqual(provenance["hops"][0]["provider"], "GitHubOIDCProvider")

    @patch.dict(os.environ, {
        "ENTRA_OAUTH2_AUDIENCE": "bp-app-id",
        "ENTRA_AGENT_ID": "agent-id",
        "AZURE_TENANT_ID": "tenant-id",
        "TOKEN_SOURCE": "google_oidc",
    })
    def test_flush_clears_provenance(self):
        """flush_cached_token() clears provenance along with the cached token."""
        mod = _fresh_import()
        mod._cached_token = None
        mod._token_expires_at = 0
        mod._provider = None

        # Mock all three hops
        hop0_resp = MagicMock()
        hop0_resp.status_code = 200
        hop0_resp.text = "google-oidc-token"

        hop1_resp = MagicMock()
        hop1_resp.status_code = 200
        hop1_resp.json.return_value = {"access_token": "t1-token"}

        hop2_resp = MagicMock()
        hop2_resp.status_code = 200
        hop2_resp.json.return_value = {"access_token": "t2-token", "expires_in": 3600}

        with patch("entra_token_exchange.httpx.get", return_value=hop0_resp), \
             patch("entra_token_exchange.httpx.post", side_effect=[hop1_resp, hop2_resp]):
            mod.get_entra_token()

        self.assertIsNotNone(mod.get_token_provenance())

        mod.flush_cached_token()
        self.assertIsNone(mod.get_token_provenance())
        self.assertIsNone(mod._cached_token)
        self.assertIsNone(mod._last_token_error)


if __name__ == "__main__":
    unittest.main()
