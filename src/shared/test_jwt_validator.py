"""
Unit tests for the shared JWT validator.

Tests cover all 6 failure modes per the engineering review:
1. Valid token → decoded claims
2. Expired token → rejected
3. Bad signature → rejected
4. Wrong audience → rejected
5. No groups claim → PermissionError
6. JWKS fetch failure → ValueError (fail-closed)
"""
import time
import unittest
from unittest.mock import MagicMock, patch

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a test RSA key pair for signing/verifying JWTs
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()
_private_pem = _private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
_public_pem = _public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Second key pair for "wrong key" tests
_wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_wrong_private_pem = _wrong_private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

TENANT_ID = "test-tenant-id"
CLIENT_ID = "test-client-id"
ADMIN_GROUP = "admin-group-oid"
VIEWER_GROUP = "viewer-group-oid"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


def _make_token(claims=None, key=None, headers=None):
    """Create a signed JWT for testing."""
    now = int(time.time())
    default_claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-oid",
        "exp": now + 3600,
        "nbf": now - 60,
        "iat": now,
        "preferred_username": "user@example.com",
        "name": "Test User",
        "groups": [ADMIN_GROUP],
        "oid": "user-oid",
    }
    if claims:
        default_claims.update(claims)
    return pyjwt.encode(
        default_claims,
        key or _private_pem,
        algorithm="RS256",
        headers=headers or {"kid": "test-kid"},
    )


class MockSigningKey:
    """Mock PyJWK signing key that uses our test public key."""
    def __init__(self, key=None):
        self.key = key or _public_key


# Import after defining helpers
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from jwt_validator import EntraJWTValidator


class TestJWTValidation(unittest.TestCase):
    """Test JWT token validation."""

    def _make_validator(self):
        v = EntraJWTValidator(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            admin_group_id=ADMIN_GROUP,
            viewer_group_id=VIEWER_GROUP,
        )
        return v

    @patch.object(EntraJWTValidator, '_get_jwk_client')
    def test_valid_token(self, mock_jwk):
        """Valid token with correct signature, audience, issuer → decoded."""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MockSigningKey()
        mock_jwk.return_value = mock_client

        v = self._make_validator()
        token = _make_token()
        claims = v.validate_token(token)

        self.assertEqual(claims["preferred_username"], "user@example.com")
        self.assertEqual(claims["name"], "Test User")
        self.assertIn(ADMIN_GROUP, claims["groups"])

    @patch.object(EntraJWTValidator, '_get_jwk_client')
    def test_expired_token(self, mock_jwk):
        """Expired token → rejected with ExpiredSignatureError."""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MockSigningKey()
        mock_jwk.return_value = mock_client

        v = self._make_validator()
        token = _make_token({"exp": int(time.time()) - 3600})

        with self.assertRaises(pyjwt.ExpiredSignatureError):
            v.validate_token(token)

    @patch.object(EntraJWTValidator, '_get_jwk_client')
    def test_bad_signature(self, mock_jwk):
        """Token signed with wrong key → rejected."""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MockSigningKey()
        mock_jwk.return_value = mock_client

        v = self._make_validator()
        # Sign with incorrect key
        token = _make_token(key=_wrong_private_pem)

        with self.assertRaises(pyjwt.InvalidSignatureError):
            v.validate_token(token)

    @patch.object(EntraJWTValidator, '_get_jwk_client')
    def test_wrong_audience(self, mock_jwk):
        """Token with wrong audience → rejected."""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MockSigningKey()
        mock_jwk.return_value = mock_client

        v = self._make_validator()
        token = _make_token({"aud": "wrong-audience"})

        with self.assertRaises(pyjwt.InvalidAudienceError):
            v.validate_token(token)

    @patch.object(EntraJWTValidator, '_get_jwk_client')
    def test_wrong_issuer(self, mock_jwk):
        """Token with wrong issuer → rejected."""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MockSigningKey()
        mock_jwk.return_value = mock_client

        v = self._make_validator()
        token = _make_token({"iss": "https://evil.com/v2.0"})

        with self.assertRaises(pyjwt.InvalidIssuerError):
            v.validate_token(token)

    def test_jwks_fetch_failure(self):
        """JWKS endpoint unreachable → ValueError (fail closed)."""
        v = self._make_validator()
        # Force JWKS client creation to raise
        v._jwk_client = MagicMock()
        v._jwk_client.get_signing_key_from_jwt.side_effect = Exception("connection refused")
        v._jwk_client_created_at = time.time()

        token = _make_token()

        with self.assertRaises(ValueError) as ctx:
            v.validate_token(token)
        self.assertIn("JWKS unavailable", str(ctx.exception))


class TestRoleCheck(unittest.TestCase):
    """Test group membership → role mapping."""

    def _make_validator(self):
        return EntraJWTValidator(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            admin_group_id=ADMIN_GROUP,
            viewer_group_id=VIEWER_GROUP,
        )

    def test_admin_role(self):
        v = self._make_validator()
        role = v.check_role({"groups": [ADMIN_GROUP]})
        self.assertEqual(role, "admin")

    def test_viewer_role(self):
        v = self._make_validator()
        role = v.check_role({"groups": [VIEWER_GROUP]})
        self.assertEqual(role, "viewer")

    def test_admin_takes_precedence(self):
        """User in both groups → admin wins."""
        v = self._make_validator()
        role = v.check_role({"groups": [ADMIN_GROUP, VIEWER_GROUP]})
        self.assertEqual(role, "admin")

    def test_no_groups(self):
        """No groups claim → PermissionError."""
        v = self._make_validator()
        with self.assertRaises(PermissionError):
            v.check_role({"groups": []})

    def test_wrong_groups(self):
        """Groups present but not matching → PermissionError."""
        v = self._make_validator()
        with self.assertRaises(PermissionError):
            v.check_role({"groups": ["other-group-id"]})

    def test_missing_groups_key(self):
        """No 'groups' key in claims → PermissionError."""
        v = self._make_validator()
        with self.assertRaises(PermissionError):
            v.check_role({})

    def test_groups_not_list(self):
        """Groups claim is not a list → PermissionError."""
        v = self._make_validator()
        with self.assertRaises(PermissionError):
            v.check_role({"groups": "not-a-list"})


class TestUserInfo(unittest.TestCase):
    """Test user info extraction."""

    def test_user_info(self):
        v = EntraJWTValidator(tenant_id=TENANT_ID, client_id=CLIENT_ID)
        claims = {
            "preferred_username": "user@example.com",
            "name": "Test User",
            "groups": [ADMIN_GROUP],
            "oid": "user-oid",
        }
        info = v.get_user_info(claims, "admin")
        self.assertEqual(info["email"], "user@example.com")
        self.assertEqual(info["name"], "Test User")
        self.assertEqual(info["role"], "admin")
        self.assertEqual(info["oid"], "user-oid")


if __name__ == "__main__":
    unittest.main()
