"""
Shared JWT Validator for AIM Portals
========================================
Validates Entra ID JWT tokens for the AIM portal and CrowdStrike mock portal.
Handles JWKS key fetching/caching, signature verification, claim validation,
and role-based access control via Entra security group membership.

Security model: FAIL CLOSED. Any validation failure → 401/403.
If JWKS keys cannot be fetched, access is DENIED (per CLAUDE.md).

Usage:
    from jwt_validator import EntraJWTValidator

    validator = EntraJWTValidator(
        tenant_id="...",
        client_id="...",
        admin_group_id="...",
        viewer_group_id="...",
    )

    # In a FastAPI dependency:
    user = await validator.validate_request(request)
    # user = {"email": "...", "name": "...", "role": "admin"|"viewer", "groups": [...]}
"""
import logging
import time
from typing import Any, Optional

import httpx
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


class EntraJWTValidator:
    """Validates Entra ID v2.0 JWTs with JWKS caching and role-based access."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        admin_group_id: str = "",
        viewer_group_id: str = "",
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.admin_group_id = admin_group_id
        self.viewer_group_id = viewer_group_id
        # Accept both v1.0 and v2.0 issuers — Entra issues either depending on
        # the app registration's accessTokenAcceptedVersion setting. v1.0 uses
        # sts.windows.net, v2.0 uses login.microsoftonline.com/v2.0.
        self.issuers = [
            f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            f"https://sts.windows.net/{tenant_id}/",
        ]
        self.jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self._jwk_client: Optional[PyJWKClient] = None
        self._jwk_client_created_at: float = 0
        # Refresh JWKS client every 24 hours
        self._jwk_client_ttl: float = 86400

    def _get_jwk_client(self) -> PyJWKClient:
        """Get or create a PyJWKClient, refreshing if stale."""
        now = time.time()
        if self._jwk_client is None or (now - self._jwk_client_created_at) > self._jwk_client_ttl:
            self._jwk_client = PyJWKClient(self.jwks_uri)
            self._jwk_client_created_at = now
        return self._jwk_client

    def validate_token(self, token: str) -> dict:
        """Validate a JWT token and return decoded claims.

        Raises:
            jwt.InvalidTokenError: If the token is invalid (expired, bad signature, etc.)
            ValueError: If JWKS keys cannot be fetched (fail-closed)
            PermissionError: If user is not in required groups
        """
        # Fetch signing key — fail closed if JWKS unreachable
        try:
            jwk_client = self._get_jwk_client()
            signing_key = jwk_client.get_signing_key_from_jwt(token)
        except jwt.exceptions.PyJWKClientError:
            # Key ID not found — refresh JWKS and retry once
            self._jwk_client = None
            try:
                jwk_client = self._get_jwk_client()
                signing_key = jwk_client.get_signing_key_from_jwt(token)
            except Exception as e:
                logger.error("JWKS key fetch failed after refresh: %s", e)
                raise ValueError(f"Cannot validate token: JWKS unavailable ({e})") from e
        except Exception as e:
            logger.error("JWKS key fetch failed: %s", e)
            raise ValueError(f"Cannot validate token: JWKS unavailable ({e})") from e

        # Decode and validate
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=self.issuers,
            options={
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        return decoded

    def check_role(self, claims: dict) -> str:
        """Check group membership and return role.

        Checks both 'groups' and 'roles' claims — Entra emits group IDs
        in 'roles' when optionalClaims has emit_as_roles, or in 'groups'
        when groupMembershipClaims is set.

        Returns:
            "admin" or "viewer"

        Raises:
            PermissionError: If user is not in any required group
        """
        groups = claims.get("groups", [])
        if not isinstance(groups, list):
            groups = []
        roles = claims.get("roles", [])
        if not isinstance(roles, list):
            roles = []
        # Merge both — group IDs can appear in either claim
        all_memberships = set(groups) | set(roles)

        if self.admin_group_id and self.admin_group_id in all_memberships:
            return "admin"
        if self.viewer_group_id and self.viewer_group_id in all_memberships:
            return "viewer"

        raise PermissionError(
            "Not authorized — request AIM Administrator or AIM Viewer role "
            "from your tenant administrator"
        )

    def get_user_info(self, claims: dict, role: str) -> dict:
        """Extract user info from validated JWT claims."""
        return {
            "email": claims.get("preferred_username", claims.get("upn", "")),
            "name": claims.get("name", ""),
            "role": role,
            "groups": claims.get("groups", []),
            "oid": claims.get("oid", ""),
        }

