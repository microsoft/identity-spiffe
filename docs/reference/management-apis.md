# Management APIs

This page documents the main runtime management surfaces in the current architecture.

## Portal Public Routes

These routes do not require a portal bearer token.

| Route | Method | Purpose |
|---|---|---|
| `/` | `GET` | Serve the portal UI |
| `/api/auth-config` | `GET` | Return MSAL/bootstrap auth settings |
| `/healthz/live` | `GET` | Process liveness |
| `/healthz/ready` | `GET` | Dependency readiness |
| `/health` | `GET` | Liveness alias |

## Portal Authenticated API

Viewer and admin roles can read operational state:

| Route | Method | Role |
|---|---|---|
| `/api/config` | `GET` | viewer or admin |
| `/api/system-status` | `GET` | viewer or admin |
| `/api/health` | `GET` | viewer or admin |
| `/api/policy` | `GET` | viewer or admin |
| `/api/audit` | `GET` | viewer or admin |
| `/api/mtls-policy` | `GET` | viewer or admin |
| `/api/metrics` | `GET` | viewer or admin |
| `/api/oauth-status` | `GET` | viewer or admin |
| `/api/ca-sample` | `GET` | viewer or admin |
| `/api/ca-policies` | `GET` | viewer or admin |
| `/api/policy-configs` | `GET` | viewer or admin |
| `/api/preset-policies` | `GET` | viewer or admin |
| `/api/identity-mapping` | `GET` | viewer or admin |
| `/api/ca-status` | `GET` | viewer or admin |
| `/api/enforcement-matrix` | `GET` | viewer or admin |
| `/api/settings/risk` | `GET` | viewer or admin |

Admin-only mutation and execution routes:

| Route | Method | Purpose |
|---|---|---|
| `/api/execute` | `POST` | Run a governed request through a selected caller |
| `/api/a2a-call` | `POST` | Run a direct A2A request |
| `/api/policy` | `PUT` | Update RBAC policy |
| `/api/mtls-policy` | `PUT` | Update Layer 1 allow-list state |
| `/api/policy-configs` | `POST` | Save a named policy config |
| `/api/policy-configs/{name}` | `DELETE` | Delete a named policy config |
| `/api/scan` | `POST` | Run a portal security scan |
| `/api/quick-fix` | `POST` | Apply a remediation |
| `/api/reload-config` | `POST` | Local-only config reload |
| `/api/agent-risk` | `PUT` | Update risk/governance state |
| `/api/flush-all-tokens` | `POST` | Flush cached tokens |
| `/api/sync-attributes` | `POST` | Pull Entra attributes into portal state |
| `/api/settings/risk-signal` | `PUT` | Set portal monitoring with `{"enabled": bool}` |
| `/api/settings/risk-enforcement` | `PUT` | Set gateway Entra enforcement with `{"enabled": bool}` |
| `/api/settings/risk-cache` | `PUT` | Set maximum evidence age with `{"seconds": integer}`; default 90, zero checks every call |

## Admin Control Plane

`admin-control-plane` is the only external management service that should proxy `/mgmt/*` requests to governed business services.

| Route | Method | Auth |
|---|---|---|
| `/health` | `GET` | none |
| `/admin/agents` | `GET` | `X-Spiffe-Admin-Key` |
| `/admin/{mgmt_path}` | `GET`, `PUT` | `X-Spiffe-Admin-Key` |

Key behaviors:

- derives agent URLs from the Container Apps environment DNS suffix
- keeps the recovery path separate from business agents
- should be treated as the management front door, not a generic public proxy

## Protected Sidecar Management API

`budget-backend` exposes the management API on the sidecar port and expects the management key.

| Route | Method | Purpose |
|---|---|---|
| `/mgmt/health` | `GET` | proxy/sidecar health |
| `/mgmt/policy` | `GET`, `PUT` | RBAC policy read/write |
| `/mgmt/audit` | `GET` | audit trail |
| `/mgmt/metrics` | `GET` | enforcement metrics |
| `/mgmt/mtls-policy` | `GET`, `PUT` | transport allow-list state |
| `/mgmt/oauth-status` | `GET` | OAuth/JWT status |
| `/mgmt/agent-risk` | `GET`, `PUT` | governance risk state |
| `/mgmt/entra-risk` | `GET` | Gateway Entra/effective risk evidence; optional `spiffe_id` query |
| `/mgmt/agent-tags` | `GET` | synced tag state |
| `/mgmt/ca-policy-effective` | `GET` | effective CA-driven state |

All of those routes are guarded by `X-Spiffe-Admin-Key`.

After a sidecar restart, the in-memory risk store has no trusted entries and
normal management requests fail closed. The exact `admin-control-plane`
SPIFFE identity may still call `PUT /mgmt/agent-risk` to establish explicit
risk evidence. In Entra runtime mode, this manual write cannot clear or replace
Entra evidence. This recovery exception does not apply to any other identity,
method, or management route, and a disabled control-plane identity remains
blocked.

## Contract Guidance

- Public browsers should only talk to the portal or security portal mock.
- External automation should prefer the portal or admin-control-plane instead of calling protected `/mgmt/*` endpoints directly.
- New management endpoints should document both the browser-facing route and the downstream management route they drive.
