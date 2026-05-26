"""Authentication and role-based access control helpers."""

import html
from dataclasses import dataclass
from typing import List, Optional

from fastapi import Request

from shared.jwt_validator import EntraJWTValidator

from .errors import PortalError
from .settings import PortalSettings


@dataclass
class AuthenticatedUser:
    email: str
    name: str
    role: str
    groups: List[str]
    oid: str


class PortalAuth:
    """Role-aware authentication helpers."""

    def __init__(self, settings):
        # type: (PortalSettings) -> None
        self.settings = settings
        self._validator = None  # type: Optional[EntraJWTValidator]
        if settings.auth_required:
            self._validator = EntraJWTValidator(
                tenant_id=settings.azure_tenant_id,
                client_id=settings.auth_client_id,
                admin_group_id=settings.admin_group_id,
                viewer_group_id=settings.viewer_group_id,
            )

    def auth_config(self):
        # type: () -> dict
        return {
            "auth_required": self.settings.auth_required,
            "client_id": self.settings.auth_client_id,
            "authority": (
                "https://login.microsoftonline.com/{0}".format(self.settings.azure_tenant_id)
                if self.settings.azure_tenant_id else ""
            ),
            "admin_group_id": self.settings.admin_group_id,
            "viewer_group_id": self.settings.viewer_group_id,
        }

    def _attach_user(self, request, user):
        # type: (Request, AuthenticatedUser) -> None
        request.state.user_email = html.escape(user.email or "")
        request.state.user_name = html.escape(user.name or "")
        request.state.user_role = user.role
        request.state.user = user

    async def _authenticate(self, request):
        # type: (Request) -> AuthenticatedUser
        if self._validator is None:
            user = AuthenticatedUser(
                email="",
                name="Local Operator",
                role="admin",
                groups=[],
                oid="local-operator",
            )
            self._attach_user(request, user)
            return user

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        else:
            # EventSource cannot set custom headers, so SSE endpoints fall back
            # to an access_token query parameter. This carries the same MSAL
            # bearer token; validation below is identical to the header path.
            token = request.query_params.get("access_token", "")
            if not token:
                raise PortalError(401, "auth_required", "Authentication required")
        try:
            claims = self._validator.validate_token(token)
        except ValueError as exc:
            raise PortalError(401, "jwks_unavailable", str(exc))
        except Exception as exc:
            raise PortalError(401, "invalid_token", "Invalid token: {0}".format(exc))
        try:
            role = self._validator.check_role(claims)
        except PermissionError as exc:
            raise PortalError(403, "forbidden", str(exc))
        info = self._validator.get_user_info(claims, role)
        user = AuthenticatedUser(
            email=info.get("email", ""),
            name=info.get("name", ""),
            role=info.get("role", role),
            groups=info.get("groups", []),
            oid=info.get("oid", ""),
        )
        self._attach_user(request, user)
        return user

    async def viewer_or_admin(self, request):
        # type: (Request) -> AuthenticatedUser
        return await self._authenticate(request)

    async def admin_only(self, request):
        # type: (Request) -> AuthenticatedUser
        user = await self._authenticate(request)
        if user.role != "admin":
            raise PortalError(403, "forbidden", "Viewer role does not have permission for this action")
        return user
