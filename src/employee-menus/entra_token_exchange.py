"""
entra_token_exchange.py — Two-Hop Agent Identity Token Exchange
================================================================
Implements the Microsoft Entra Agent Identity autonomous token flow:

  Hop 0: Upstream credential (platform-specific)
    - Azure: ManagedIdentityCredential → MI token
    - Google: GCE metadata server → Google-signed OIDC token
    - GitHub: Actions OIDC endpoint → GitHub-signed OIDC token

  Hop 1: Upstream assertion → Blueprint exchange token (T1)
    POST /oauth2/v2.0/token
      client_id     = Blueprint app ID
      scope         = api://AzureADTokenExchange/.default
      fmi_path      = Agent Identity client ID
      client_assertion = upstream assertion (MI token or Google OIDC token)
      grant_type    = client_credentials

  Hop 2: T1 → Agent Identity token (T2)
    POST /oauth2/v2.0/token
      client_id     = Agent Identity client ID
      scope         = api://{Blueprint app ID}/.default
      client_assertion = T1
      grant_type    = client_credentials

T2 carries oid = Agent Identity SP, appid = Agent Identity client ID.
CA policies evaluate against this identity, not the upstream credential.

The TOKEN_SOURCE env var selects the credential provider:
  - "azure_mi"    (default) — Azure Managed Identity
  - "google_oidc"           — GCE metadata server OIDC token
  - "github_oidc"           — GitHub Actions OIDC token

Ref: https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/autonomous-agent-request-tokens

Shared module — maintained in src/shared/, copied to each agent dir by deploy.sh.
"""
import asyncio
import base64
import json as _json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(os.getenv("AGENT_NAME", "entra-token-exchange"))

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
_MI_CLIENT_ID = os.getenv("MI_CLIENT_ID", "")
_BLUEPRINT_APP_ID = os.getenv("ENTRA_OAUTH2_AUDIENCE", "")
_AGENT_IDENTITY_ID = os.getenv("ENTRA_AGENT_ID", "")
_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
_TOKEN_SOURCE = os.getenv("TOKEN_SOURCE", "azure_mi")

_TOKEN_ENDPOINT = (
    f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token"
    if _TENANT_ID else ""
)

# ---------------------------------------------------------------------------
# Credential provider strategy pattern
# ---------------------------------------------------------------------------

# GCE metadata server URL for OIDC identity tokens
_GCE_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/identity"
)


class CredentialProvider(ABC):
    """Base class for upstream credential providers.

    Each provider implements Hop 0: acquiring the platform-specific assertion
    that gets exchanged with Entra in Hop 1.  Providers MUST fail closed —
    return None only on genuine failure, never silently degrade.

    Subclasses accept **kwargs on get_upstream_assertion() so future providers
    (e.g. ServiceNow) can accept stored credentials without breaking the
    interface contract.
    """

    @abstractmethod
    def get_upstream_assertion(self, audience, **kwargs):
        # type: (str, ...) -> str | None
        """Return a signed assertion token for the given audience.

        Returns the raw token string on success, or None on failure.
        Implementations MUST log the failure reason and set _last_token_error.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def required_env_vars(self):
        # type: () -> list[str]
        """Return env var names this provider requires beyond the shared ones."""
        raise NotImplementedError


class AzureMIProvider(CredentialProvider):
    """Acquires an upstream assertion via Azure Managed Identity.

    Uses ManagedIdentityCredential with a ThreadPoolExecutor timeout to
    prevent hangs when the IMDS/Container Apps identity endpoint is slow.
    The credential is lazily initialized and cached for reuse.
    """

    def __init__(self):
        self._credential = None

    @property
    def required_env_vars(self):
        return ["MI_CLIENT_ID"]

    def get_upstream_assertion(self, audience, **kwargs):
        # type: (str, ...) -> str | None
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

        global _last_token_error

        if self._credential is None:
            from azure.identity import ManagedIdentityCredential
            mi_client_id = kwargs.get("mi_client_id", _MI_CLIENT_ID)
            self._credential = (
                ManagedIdentityCredential(client_id=mi_client_id)
                if mi_client_id
                else ManagedIdentityCredential()
            )

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self._credential.get_token, f"{audience}/.default")
            try:
                tok = future.result(timeout=10)
            except FuturesTimeout:
                _last_token_error = (
                    "Timed out acquiring managed identity token from "
                    "ManagedIdentityCredential after 10 seconds."
                )
                logger.error(_last_token_error)
                return None
            except Exception as exc:
                _last_token_error = f"ManagedIdentityCredential error: {exc}"
                logger.error(_last_token_error)
                return None
        return tok.token


class GoogleOIDCProvider(CredentialProvider):
    """Acquires an upstream assertion via GCE metadata server OIDC token.

    Calls the GCE instance identity endpoint to get a Google-signed JWT.
    Fails closed if the metadata server is unreachable or returns an error.

    MSAL Python does not support FIC (WithClientAssertion). This provider
    uses raw HTTP — see hard-won-learnings #31.
    """

    @property
    def required_env_vars(self):
        return []  # No extra env vars — metadata server is always available on GCE

    def get_upstream_assertion(self, audience, **kwargs):
        # type: (str, ...) -> str | None
        global _last_token_error

        metadata_url = kwargs.get("metadata_url", _GCE_METADATA_URL)
        try:
            resp = httpx.get(
                metadata_url,
                params={"audience": audience, "format": "full"},
                headers={"Metadata-Flavor": "Google"},
                timeout=5,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            _last_token_error = (
                f"GCE metadata server unreachable: {exc}"
            )
            logger.error(_last_token_error)
            return None
        except Exception as exc:
            _last_token_error = f"GCE metadata request failed: {exc}"
            logger.error(_last_token_error)
            return None

        if resp.status_code != 200:
            _last_token_error = (
                f"GCE metadata server returned {resp.status_code}: "
                f"{resp.text[:200]}"
            )
            logger.error(_last_token_error)
            return None

        token = resp.text.strip()
        if not token:
            _last_token_error = "GCE metadata server returned empty token"
            logger.error(_last_token_error)
            return None

        return token


class GitHubOIDCProvider(CredentialProvider):
    """Acquires an upstream assertion via GitHub Actions OIDC token.

    Inside a GitHub Actions workflow with `permissions: id-token: write`,
    the runner injects ACTIONS_ID_TOKEN_REQUEST_URL and
    ACTIONS_ID_TOKEN_REQUEST_TOKEN env vars. This provider calls that
    URL to get a GitHub-signed JWT.

    Fails closed if the env vars are missing or the request fails.
    """

    @property
    def required_env_vars(self):
        return []  # Env vars are checked in get_upstream_assertion via kwargs

    def get_upstream_assertion(self, audience, **kwargs):
        # type: (str, ...) -> str | None
        global _last_token_error

        request_url = kwargs.get(
            "request_url", os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        )
        request_token = kwargs.get(
            "request_token", os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        )

        if not request_url or not request_token:
            _last_token_error = (
                "GitHub Actions OIDC not available: "
                "ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN "
                "not set. Ensure the workflow has 'permissions: id-token: write'."
            )
            logger.error(_last_token_error)
            return None

        try:
            resp = httpx.get(
                request_url,
                params={"audience": audience},
                headers={"Authorization": f"Bearer {request_token}"},
                timeout=10,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            _last_token_error = (
                f"GitHub Actions OIDC endpoint unreachable: {exc}"
            )
            logger.error(_last_token_error)
            return None
        except Exception as exc:
            _last_token_error = f"GitHub Actions OIDC request failed: {exc}"
            logger.error(_last_token_error)
            return None

        if resp.status_code != 200:
            _last_token_error = (
                f"GitHub Actions OIDC endpoint returned {resp.status_code}: "
                f"{resp.text[:200]}"
            )
            logger.error(_last_token_error)
            return None

        try:
            token = resp.json().get("value", "").strip()
        except Exception:
            _last_token_error = "GitHub Actions OIDC response is not valid JSON"
            logger.error(_last_token_error)
            return None

        if not token:
            _last_token_error = "GitHub Actions OIDC response missing 'value' field"
            logger.error(_last_token_error)
            return None

        return token


def _build_provider(token_source=None):
    # type: (str | None) -> CredentialProvider
    """Instantiate the credential provider based on TOKEN_SOURCE."""
    source = (token_source or _TOKEN_SOURCE).lower().strip()
    if source == "google_oidc":
        return GoogleOIDCProvider()
    if source == "github_oidc":
        return GitHubOIDCProvider()
    if source in ("azure_mi", ""):
        return AzureMIProvider()
    raise ValueError(
        f"Unknown TOKEN_SOURCE: {source!r}. "
        f"Expected 'azure_mi', 'google_oidc', or 'github_oidc'."
    )


# Module-level provider instance (lazy-initialized on first token request)
_provider = None  # type: CredentialProvider | None


def _get_provider():
    # type: () -> CredentialProvider
    global _provider
    if _provider is None:
        with _lock:
            if _provider is None:
                _provider = _build_provider()
                logger.info(f"Token source: {_TOKEN_SOURCE} -> {type(_provider).__name__}")
    return _provider


# ---------------------------------------------------------------------------
# Token cache (T2 only — T1 is intermediate)
# ---------------------------------------------------------------------------
_cached_token = None       # type: str | None
_token_expires_at = 0.0
_last_token_error = None   # type: str | None
_last_token_provenance = None  # type: dict | None
_lock = threading.Lock()
_async_lock = None  # type: asyncio.Lock | None  # lazily created per event loop


def get_last_token_error():
    # type: () -> str | None
    """Return the error string from the most recent failed token acquisition."""
    return _last_token_error


def get_token_provenance():
    # type: () -> dict | None
    """Return provenance metadata from the most recent successful token exchange.

    Shows the full 3-hop call tree so callers can prove the upstream credential
    source (e.g. Google OIDC metadata server vs Azure Managed Identity).
    """
    return _last_token_provenance


def flush_cached_token():
    """Clear the cached Agent Identity token.

    Call after app role assignments change so the next request acquires a
    fresh token with updated roles.
    """
    global _cached_token, _token_expires_at, _last_token_error, _last_token_provenance
    with _lock:
        _cached_token = None
        _token_expires_at = 0
        _last_token_error = None
        _last_token_provenance = None


def _exchange_for_blueprint_token(upstream_assertion):
    # type: (str) -> str
    """Hop 1: Exchange upstream assertion for Blueprint exchange token (T1).

    POST /oauth2/v2.0/token with fmi_path pointing to the Agent Identity.
    """
    data = {
        "client_id": _BLUEPRINT_APP_ID,
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": _AGENT_IDENTITY_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": upstream_assertion,
        "grant_type": "client_credentials",
    }
    resp = httpx.post(_TOKEN_ENDPOINT, data=data, timeout=15)
    if resp.status_code != 200:
        body = resp.text
        raise RuntimeError(
            f"Blueprint token exchange failed ({resp.status_code}): {body[:500]}"
        )
    return resp.json()["access_token"]


def _exchange_for_agent_identity_token(t1):
    # type: (str) -> tuple
    """Hop 2: Exchange Blueprint token (T1) for Agent Identity token (T2).

    Returns (access_token, expires_in_seconds).
    """
    data = {
        "client_id": _AGENT_IDENTITY_ID,
        "scope": f"api://{_BLUEPRINT_APP_ID}/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": t1,
        "grant_type": "client_credentials",
    }
    resp = httpx.post(_TOKEN_ENDPOINT, data=data, timeout=15)
    if resp.status_code != 200:
        body = resp.text
        raise RuntimeError(
            f"Agent Identity token exchange failed ({resp.status_code}): {body[:500]}"
        )
    payload = resp.json()
    return payload["access_token"], int(payload.get("expires_in", 3600))


def get_entra_token():
    # type: () -> str | None
    """Acquire an Agent Identity token via the two-hop exchange.

    Returns the T2 access token string, or None on failure.
    Caches T2 and refreshes 60s before expiry.

    Hop 0 is provider-specific (selected by TOKEN_SOURCE env var).
    Hops 1 and 2 are shared across all providers.
    """
    global _cached_token, _token_expires_at, _last_token_error, _last_token_provenance

    # Return cached token if still valid
    if _cached_token and time.time() < _token_expires_at - 60:
        with _lock:
            _last_token_error = None
        return _cached_token

    # Validate shared configuration
    missing = []
    if not _BLUEPRINT_APP_ID:
        missing.append("ENTRA_OAUTH2_AUDIENCE")
    if not _AGENT_IDENTITY_ID:
        missing.append("ENTRA_AGENT_ID")
    if not _TENANT_ID:
        missing.append("AZURE_TENANT_ID")

    # Validate provider-specific configuration
    provider = _get_provider()
    for var in provider.required_env_vars:
        if not os.getenv(var, ""):
            missing.append(var)

    if missing:
        with _lock:
            _last_token_error = f"Missing env vars: {', '.join(missing)}"
        logger.warning(f"Token exchange not configured: {_last_token_error}")
        return None

    try:
        # Hop 0: Get upstream assertion (provider-specific)
        provider_name = type(provider).__name__
        logger.info("Acquiring upstream assertion via %s...", provider_name)
        upstream = provider.get_upstream_assertion("api://AzureADTokenExchange")
        if not upstream:
            with _lock:
                if not _last_token_error:
                    _last_token_error = "Failed to acquire upstream assertion"
            logger.error(_last_token_error)
            return None

        # Decode upstream token header to capture issuer info (best-effort)
        hop0_issuer = "unknown"
        try:
            parts = upstream.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                claims = _json.loads(base64.urlsafe_b64decode(padded))
                hop0_issuer = claims.get("iss", "unknown")
        except Exception:
            pass

        # Hop 1: Upstream assertion → Blueprint exchange token (T1)
        logger.info("Exchanging upstream assertion for Blueprint token (T1)...")
        t1 = _exchange_for_blueprint_token(upstream)

        # Hop 2: T1 → Agent Identity token (T2)
        logger.info("Exchanging Blueprint token for Agent Identity token (T2)...")
        t2, expires_in = _exchange_for_agent_identity_token(t1)

        # Cache T2 and record provenance
        with _lock:
            _cached_token = t2
            _token_expires_at = time.time() + expires_in
            _last_token_error = None
            _last_token_provenance = {
                "token_source": _TOKEN_SOURCE,
                "provider": provider_name,
                "hops": [
                    {
                        "hop": 0,
                        "description": "Upstream credential (platform-native)",
                        "provider": provider_name,
                        "issuer": hop0_issuer,
                        "audience": "api://AzureADTokenExchange",
                    },
                    {
                        "hop": 1,
                        "description": "Blueprint exchange token (T1)",
                        "endpoint": f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token",
                        "client_id": _BLUEPRINT_APP_ID,
                        "grant_type": "client_credentials (FIC)",
                    },
                    {
                        "hop": 2,
                        "description": "Agent Identity token (T2)",
                        "endpoint": f"https://login.microsoftonline.com/{_TENANT_ID}/oauth2/v2.0/token",
                        "client_id": _AGENT_IDENTITY_ID,
                        "grant_type": "client_credentials (OBO)",
                    },
                ],
            }
        logger.info(
            f"Acquired Agent Identity token (expires in {expires_in}s)"
        )
        return t2

    except Exception as e:
        with _lock:
            _last_token_error = str(e)
        if "AADSTS53003" in _last_token_error:
            logger.error(f"Token BLOCKED by Conditional Access policy: {e}")
        else:
            logger.warning(f"Agent Identity token exchange failed: {e}")
        return None


def _get_async_lock():
    # type: () -> asyncio.Lock
    """Return a per-event-loop asyncio.Lock, creating it lazily.

    asyncio.Lock must be created inside a running event loop. We store
    it in a module-level variable and recreate if the event loop changes
    (e.g. during testing).
    """
    global _async_lock
    if _async_lock is None:
        _async_lock = asyncio.Lock()
    return _async_lock


async def get_entra_token_async():
    # type: () -> str | None
    """Async version of get_entra_token for use in async route handlers.

    Prevents event loop blocking by running the synchronous token
    acquisition (IMDS calls, HTTP exchanges) in a background thread
    via asyncio.to_thread. An asyncio.Lock serialises concurrent
    refresh attempts so only one thread performs the exchange while
    others wait and then read the cached result.

    Returns the T2 access token string, or None on failure.
    """
    global _cached_token, _token_expires_at, _last_token_error

    # Fast path: return cached token without acquiring the async lock
    if _cached_token and time.time() < _token_expires_at - 60:
        _last_token_error = None
        return _cached_token

    async with _get_async_lock():
        # Double-check after acquiring lock — another coroutine may have refreshed
        if _cached_token and time.time() < _token_expires_at - 60:
            _last_token_error = None
            return _cached_token

        # Offload the blocking sync token acquisition to a thread
        return await asyncio.to_thread(get_entra_token)
