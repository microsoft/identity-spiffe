# Authentication Flows

This page describes the current authentication and authorization flows across browsers, management APIs, workload-to-workload traffic, and Microsoft Graph provisioning.

## 1. Browser Sign-In For The Portals

Both `aim-portal` and `securityportal-mock` use the same model:

1. Browser loads `/api/auth-config`.
2. If `auth_required=false`, local development bypasses Entra sign-in.
3. Otherwise the SPA initializes MSAL with the returned `client_id` and tenant authority.
4. Sign-in uses redirect flow.
5. The SPA acquires a token and attaches `Authorization: Bearer <token>` on protected calls.
6. The backend validates the token and maps group membership to `admin` or `viewer`.

### Role Resolution

Portal role checks accept group IDs from either claim shape:

- `groups`
- `roles`

That supports tenants configured with `emit_as_roles` as well as standard group claims.

## 2. Portal Backend Authentication

The portal backend uses the shared validator in `src/shared/jwt_validator.py`.

Validation requirements:

- correct Entra tenant
- correct audience for the portal app registration
- valid signature from Entra JWKS
- caller belongs to `Identity Research for Agent Management Using SPIFFE Administrators` or `Identity Research for Agent Management Using SPIFFE Viewers`

Failures are explicit:

- missing token returns `401 auth_required`
- invalid token returns `401 invalid_token`
- token validation infrastructure failure returns `401 jwks_unavailable`
- insufficient role returns `403 forbidden`

## 3. Management API Authentication

The browser never sends the raw management key to business services.

Instead:

1. Browser authenticates to the portal with Entra.
2. Portal authorizes the user as admin or viewer.
3. Portal calls `admin-control-plane` using the management key.
4. `admin-control-plane` calls the protected sidecar `/mgmt/*` routes using the same management key.

That separates user authentication from sidecar management authentication.

## 4. Agent-to-Agent Runtime Authentication

There are two governed request paths in the repo.

### SPIFFE Path

- caller proves workload identity through SPIFFE mTLS
- sidecar enforces Layer 1 and Layer 2
- target sidecar or app validates Layer 3 token requirements
- Layer 4 governance may still deny

### Direct A2A HTTPS Path

- caller acquires an Entra token for the target app
- target app validates JWT locally
- target app checks governance state such as risk, `agent_state`, and tag matching

## 5. Microsoft Graph And OData Control-Plane Flows

Graph is used for:

- Agent Identity Blueprint and principal provisioning
- federated identity credential lifecycle
- portal governance sync
- risky service principal state
- custom security attribute synchronization

Graph filter queries use OData. The repo treats those as internal control-plane calls and escapes dynamic values before issuing them. The goal is simple:

- never let a display name or agent identifier change the query shape
- never interpret Graph read failure as "no policy" or "no risk"

New Graph/OData usage should follow the same fail-closed pattern.

## 6. Parallel Deployment Auth Model

New environments use env-scoped names for:

- Agent Identity Blueprint
- Agent Identities
- federated identity credentials
- portal app registrations

These stay shared tenant-wide:

- `Identity Research for Agent Management Using SPIFFE Administrators`
- `Identity Research for Agent Management Using SPIFFE Viewers`
- the provisioner app
- the Conditional Access schema and generic policy model

That split lets two environments run concurrently without overwriting each other's FICs or browser app registrations.

## Related Reading

- [Management APIs](management-apis.md)
- [Portal Runtime](../developer/portal-runtime.md)
- [Parallel Deployments](../developer/parallel-deployments.md)
