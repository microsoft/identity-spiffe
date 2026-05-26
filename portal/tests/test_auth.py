import unittest
from types import SimpleNamespace
from unittest.mock import patch

from portal.app.auth import PortalAuth
from portal.app.errors import PortalError
from portal.app.settings import ControlPlaneConfig, PortalSettings


def _settings(**overrides):
    base = PortalSettings(
        mode="live",
        runtime_environment="local",
        trust_domain="aim.microsoft.com",
        control_plane=ControlPlaneConfig(
            name="AdminControlPlane",
            url="https://admin-control-plane.example",
            spiffe_id="spiffe://aim.microsoft.com/ests/bp/x/aid/admin",
            entra_agent_id="admin-app-id",
        ),
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _request(headers=None, query_params=None):
    return SimpleNamespace(
        headers=headers or {},
        query_params=query_params or {},
        state=SimpleNamespace(),
    )


class TestPortalAuth(unittest.IsolatedAsyncioTestCase):
    async def test_local_mode_defaults_to_admin(self):
        auth = PortalAuth(_settings())
        request = _request()

        user = await auth.admin_only(request)

        self.assertEqual(user.role, "admin")
        self.assertEqual(request.state.user_role, "admin")
        self.assertEqual(request.state.user.oid, "local-operator")

    async def test_viewer_cannot_use_admin_endpoint(self):
        with patch("portal.app.auth.EntraJWTValidator") as validator_cls:
            validator = validator_cls.return_value
            validator.validate_token.return_value = {"groups": ["viewer-group-id"], "oid": "viewer-oid"}
            validator.check_role.return_value = "viewer"
            validator.get_user_info.return_value = {
                "email": "viewer@example.com",
                "name": "Viewer User",
                "role": "viewer",
                "groups": ["viewer-group-id"],
                "oid": "viewer-oid",
            }
            auth = PortalAuth(
                _settings(
                    runtime_environment="cloud",
                    auth_client_id="portal-client-id",
                    azure_tenant_id="tenant-id",
                    admin_group_id="admin-group-id",
                    viewer_group_id="viewer-group-id",
                )
            )

            viewer_request = _request({"Authorization": "Bearer viewer-token"})
            viewer = await auth.viewer_or_admin(viewer_request)
            self.assertEqual(viewer.role, "viewer")

            with self.assertRaises(PortalError) as ctx:
                await auth.admin_only(_request({"Authorization": "Bearer viewer-token"}))

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.error_code, "forbidden")

    async def test_cloud_mode_requires_bearer_token(self):
        auth = PortalAuth(
            _settings(
                runtime_environment="cloud",
                auth_client_id="portal-client-id",
                azure_tenant_id="tenant-id",
                admin_group_id="admin-group-id",
                viewer_group_id="viewer-group-id",
            )
        )

        with self.assertRaises(PortalError) as ctx:
            await auth.viewer_or_admin(_request())

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.error_code, "auth_required")

    async def test_jwks_failure_returns_fail_closed_401(self):
        with patch("portal.app.auth.EntraJWTValidator") as validator_cls:
            validator = validator_cls.return_value
            validator.validate_token.side_effect = ValueError("JWKS unavailable")
            auth = PortalAuth(
                _settings(
                    runtime_environment="cloud",
                    auth_client_id="portal-client-id",
                    azure_tenant_id="tenant-id",
                    admin_group_id="admin-group-id",
                    viewer_group_id="viewer-group-id",
                )
            )

            with self.assertRaises(PortalError) as ctx:
                await auth.viewer_or_admin(_request({"Authorization": "Bearer viewer-token"}))

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.error_code, "jwks_unavailable")

    async def test_invalid_token_returns_fail_closed_401(self):
        with patch("portal.app.auth.EntraJWTValidator") as validator_cls:
            validator = validator_cls.return_value
            validator.validate_token.side_effect = RuntimeError("bad signature")
            auth = PortalAuth(
                _settings(
                    runtime_environment="cloud",
                    auth_client_id="portal-client-id",
                    azure_tenant_id="tenant-id",
                    admin_group_id="admin-group-id",
                    viewer_group_id="viewer-group-id",
                )
            )

            with self.assertRaises(PortalError) as ctx:
                await auth.viewer_or_admin(_request({"Authorization": "Bearer viewer-token"}))

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.error_code, "invalid_token")

    async def test_access_token_query_param_accepted_when_no_header(self):
        """EventSource can't set Authorization headers, so SSE routes pass the
        MSAL bearer token as ?access_token=... The query-param path must
        validate identically to the Authorization header path."""
        with patch("portal.app.auth.EntraJWTValidator") as validator_cls:
            validator = validator_cls.return_value
            validator.validate_token.return_value = {"groups": ["viewer-group-id"], "oid": "viewer-oid"}
            validator.check_role.return_value = "viewer"
            validator.get_user_info.return_value = {
                "email": "viewer@example.com",
                "name": "Viewer User",
                "role": "viewer",
                "oid": "viewer-oid",
            }
            auth = PortalAuth(
                _settings(
                    runtime_environment="cloud",
                    auth_client_id="portal-client-id",
                    azure_tenant_id="tenant-id",
                    admin_group_id="admin-group-id",
                    viewer_group_id="viewer-group-id",
                )
            )

            user = await auth.viewer_or_admin(_request(query_params={"access_token": "valid-bearer"}))

        self.assertEqual(user.role, "viewer")
        validator.validate_token.assert_called_once_with("valid-bearer")

    async def test_missing_both_header_and_query_param_returns_401(self):
        with patch("portal.app.auth.EntraJWTValidator"):
            auth = PortalAuth(
                _settings(
                    runtime_environment="cloud",
                    auth_client_id="portal-client-id",
                    azure_tenant_id="tenant-id",
                    admin_group_id="admin-group-id",
                    viewer_group_id="viewer-group-id",
                )
            )

            with self.assertRaises(PortalError) as ctx:
                await auth.viewer_or_admin(_request())

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.error_code, "auth_required")
