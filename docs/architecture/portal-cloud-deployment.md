# Portal Cloud Deployment with Entra Auth

> Architecture plan and implementation status for deploying both portals (AIM Management + CrowdStrike Mock)
> as Azure Container Apps with MSAL.js-based Entra sign-in and role-gated access.

## Status: DEPLOYED (refactored runtime)

**Merged into `main`:** Mar 29, 2026
- Both portals live as Container Apps with Entra sign-in
- AIM portal backend refactored into `portal/app/` with a thin `portal/server.py` wrapper
- Agent discovery via `/admin/agents` endpoint on admin-control-plane
- Durable policy config storage moved to Azure Blob Storage for the AIM portal
- `/healthz/live`, `/healthz/ready`, and `/api/system-status` added for truthful health reporting
- VM operations use `az vm run-command`
- 14/14 JWT validator unit tests passing

### Known Issues (fix on next session)

1. **~~SECURITY: All API endpoints temporarily public~~** — ✅ FIXED. `_PUBLIC_PATHS` restored to minimum
   (`/api/auth-config`, `/api/health`, `/`, `/health`, favicon). All other `/api/*` routes require a valid
   Entra JWT Bearer token. Root cause of original 401 was ACR cache serving stale code. Verified via
   Playwright headless browser with imported Chrome cookies.

2. **BudgetReport stale CA risk** — `AADSTS53003` can persist for BudgetReport across deploys.
   `test_agents.py` has active-probing wait logic but Entra risk propagation can still take longer than the local demo loop.

3. **~~ACR Docker layer caching~~** — ✅ FIXED. `deploy.sh` passes `--no-cache` to `az acr build` for both portal images. No more stale layers.

4. **`emit_as_roles` vs `groups` claim** — Some app registrations emit group IDs in `roles`
   instead of `groups`. `jwt_validator.py` checks both, so this is currently safe but should stay documented.

## Overview

Both portals currently run locally. This feature deploys them as Azure Container Apps
in the same Container Apps Environment as the agents, adds Entra ID sign-in via MSAL.js,
and gates access with dual-role Entra security groups.

**Approach:** Container Apps + MSAL.js frontend auth (not EasyAuth, not SWA)

## Scope

### Core
- Both portals as Container Apps with external ingress
- Entra sign-in via MSAL.js (redirect flow)
- Shared `AIM Administrators` / `AIM Viewers` groups with env-scoped portal app registrations
- Per-user audit trail (who changed what policy)
- deploy.sh integration (build, provision, deploy portals)
- fast `./deploy.sh --portal-only` path for portal/CrowdStrike changes without agent re-attestation
- Local mode preserved (no auth when `AUTH_CLIENT_ID` absent)
- Cloud mode is live-only: no simulated/demo fallbacks in the backend

### Cherry-Picks
1. Per-user audit trail on policy mutations
2. Dual-role access (Admin vs Viewer)
3. Demo scenario deep links (`#/demo/mtls-block`, etc.)
4. MSAL token auto-refresh + session expiry warning
5. Health status indicators in portal header

### NOT in scope
- Custom VNet integration (managed networking sufficient)
- Azure Front Door / CDN (premature for PoC)
- CI/CD pipeline (deploy.sh sufficient)
- Rate limiting / WAF (future hardening)
- Per-user policy sandboxes
- Custom domain names
- Real EDR integration

## Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │          Azure Container Apps Environment               │
                    │                                                         │
  ┌──────────┐     │  ┌───────────────┐        ┌──────────────────┐         │
  │ Browser  │────▶│  │ AIM Portal    │───────▶│ Admin Control    │         │
  │ (MSAL.js)│     │  │ Container App │  HTTPS │ Plane (external) │         │
  │ Entra JWT│     │  │ :8550 ext     │        │ → BudgetBackend  │         │
  └──────────┘     │  └───────────────┘        │   (internal)     │         │
                    │                            └──────────────────┘         │
  ┌──────────┐     │  ┌───────────────┐              │                      │
  │ Browser  │────▶│  │ CrowdStrike   │──────────────┘                      │
  │ (MSAL.js)│     │  │ Mock App      │  HTTPS (risk push)                  │
  │ Entra JWT│     │  │ :8560 ext     │                                     │
  └──────────┘     │  └───────────────┘                                     │
                    │                                                         │
                    │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │
                    │  │ BudgetReport│ │ BudgetApprv │ │ EmpMenus    │      │
                    │  │ :8000 ext   │ │ :8000 ext   │ │ :8000 ext   │      │
                    │  └─────────────┘ └─────────────┘ └─────────────┘      │
                    └─────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────┐
  │               Entra ID                          │
  │                                                  │
  │  App Reg: "AIM Portal - Management [<env>]"     │
  │  App Reg: "AIM Portal - CrowdStrike Mock [<env>]"│
  │  Group: "AIM Administrators"                     │
  │  Group: "AIM Viewers"                            │
  └────────────────────────────────────────────────┘
```

## Auth Flow

```
  Browser                    Entra ID                 Portal Backend
    │                           │                           │
    ├──loginRedirect()─────────▶│                           │
    │                           │ (user signs in)           │
    │◀──redirect + id_token─────┤                           │
    │                           │                           │
    ├──acquireTokenSilent()────▶│                           │
    │◀──access_token────────────┤                           │
    │                           │                           │
    ├──GET /api/policy──────────────────────────────────────▶│
    │  Authorization: Bearer <token>                        │
    │                           │      validate JWT ────────┤
    │                           │      check groups claim──┤
    │                           │      check role ─────────┤
    │◀──200 {policy} ──────────────────────────────────────┤
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Auth approach | MSAL.js + backend JWT validation | Full UX control, industry standard SPA pattern |
| App registrations | Two separate (one per portal) | Cleaner isolation, independent redirect URIs |
| Entra naming scope | Legacy envs keep shared names; new envs default to env-scoped names | Allows parallel fully functional deployments without FIC collisions |
| Config in cloud | Environment variables + admin-control-plane discovery | No config file baked into image, secrets via Container App secrets API |
| VNet | Same Container Apps Environment (managed) | Portals reach agents via admin-control-plane external HTTPS |
| Auth bypass | Skip when AUTH_CLIENT_ID absent | Local dev mode preserved |
| JWT validation | `src/shared/jwt_validator.py` | DRY — single module for both portals |
| Graph token cache | `src/shared/graph_token.py` | DRY — extract existing duplicated logic |
| Docker build context | Repo root | Enables COPY of scripts/ and src/shared/ |
| Secrets | Container App secrets API + `secretref:` env wiring | `MGMT_API_KEY`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET` stay secret-backed |
| Policy config storage | Azure Blob Storage + managed identity | Durable across Container App restarts/revisions |
| Observability | Azure Monitor OpenTelemetry + App Insights | Structured logs, dependency spans, build-derived versioning |

## New Files

| File | Purpose |
|------|---------|
| `src/shared/jwt_validator.py` | Shared JWT validation (JWKS fetch, signature, role check) |
| `src/shared/graph_token.py` | Shared Graph token caching (extract from both server.py) |
| `infra/modules/portal-app.bicep` | Container App module for portals (no sidecar) |
| `portal/Dockerfile` | Portal container image |
| `portal/requirements.txt` | Python dependencies |
| `portal/app/*` | Modular portal runtime (settings, auth, clients, services, storage, routers) |
| `crowdstrike-mock/Dockerfile` | CrowdStrike mock container image |
| `crowdstrike-mock/requirements.txt` | Python dependencies |
| `src/shared/test_jwt_validator.py` | Unit tests for JWT validation |

## Modified Files

| File | Changes |
|------|---------|
| `infra/main.bicep` | Add portal + crowdstrike-mock Container App modules, Blob storage, App Insights, MI RBAC |
| `portal/server.py` | Thin wrapper/CLI over `portal/app.main:create_app` |
| `portal/index.html` | MSAL.js auth, user banner, live dependency health, no reset-demo flow |
| `crowdstrike-mock/server.py` | JWT middleware, /api/auth-config, viewer restrictions |
| `crowdstrike-mock/index.html` | MSAL.js auth, sign-in page, user banner |
| `deploy.sh` | Portal build, Entra app reg, group creation, secretRef-safe Container App deploy |

## Security

- JWT tokens validated server-side on EVERY /api/* request
- JWKS keys cached, refreshed on unknown kid (key rotation safe)
- Auth bypass ONLY when AUTH_CLIENT_ID env var absent (local dev mode)
- Secrets passed as Container App secrets, not plain env vars
- SPA app registration: no client secret (PKCE flow only)
- Group membership checked server-side via JWT groups claim
- Fail-closed: JWT validation failure → 401 (per CLAUDE.md security principles)
- XSS prevention: HTML-escape all user claims before rendering
- `portal-config.json` with `MGMT_API_KEY` never baked into Docker image
- Cloud startup fails if required secret-backed config is missing instead of silently fabricating demo responses

## Entra Scope Model

- Existing deployed environments remain `legacy` and continue using the historical tenant-wide names.
- New `azd` environments default to `scoped` naming derived from `AZURE_ENV_NAME`.
- Portal app registrations are env-scoped for new deployments, but the portal
  administrator/viewer groups stay shared tenant-wide.
- The dedicated provisioner app, custom security attribute schema, and the generic high-risk CA policy remain shared tenant-wide.

This split avoids breaking the running legacy environment while preventing new
deployments from resetting another environment's Agent Identity FICs.

## Deployment Sequence

```
  Existing Steps (1-15)
        │
        ▼
  Step 16: Build portal images (az acr build --file portal/Dockerfile .)
        │
        ▼
  Step 17: Create Entra app registrations (if not exist)
        │  (stored-id first, then env-scoped display-name lookup/create)
        ▼
  Step 18: Create AIM security groups (if not exist)
        │  (stored-id first, then shared display-name lookup/create)
        │
        ▼
  Step 19: Deploy portal Container Apps with env vars
        │  (inject AUTH_CLIENT_ID, GROUP_IDs, Blob storage config, App Insights, GRAPH creds as secrets)
        ▼
  Step 20: Print portal URLs in deploy summary
```

For portal-only changes after a full environment already exists, `./deploy.sh --portal-only`
reuses the current environment, rebuilds the two portal images, refreshes portal auth wiring,
and updates only the portal Container Apps. It intentionally skips SPIRE VM work, join-token
generation, sidecar updates, and agent re-attestation.

## Role-Based Access

| Endpoint | Admin | Viewer |
|----------|-------|--------|
| GET /api/config | ✅ | ✅ |
| GET /api/policy | ✅ | ✅ |
| GET /api/mtls-policy | ✅ | ✅ |
| GET /api/health | ✅ | ✅ |
| GET /api/audit | ✅ | ✅ |
| GET /api/metrics | ✅ | ✅ |
| GET /api/auth-config | ✅ (no auth) | ✅ (no auth) |
| PUT /api/policy | ✅ | ❌ 403 |
| PUT /api/mtls-policy | ✅ | ❌ 403 |
| POST /api/execute | ✅ | ❌ 403 |
| POST /api/a2a-call | ✅ | ❌ 403 |
| POST /api/scan | ✅ | ❌ 403 |
| POST /api/quick-fix | ✅ | ❌ 403 |
| PUT /set-risk (CrowdStrike) | ✅ | ❌ 403 |

## Deep Link Scenarios

| URL Hash | Pre-selects |
|----------|-------------|
| `#/demo/mtls-block` | EmployeeMenus → BudgetBackend (mTLS reject) |
| `#/demo/rbac-deny` | BudgetReport → POST /budget/submit (RBAC deny) |
| `#/demo/a2a-tag-mismatch` | EmployeeMenus → BudgetApproval (tag mismatch) |
| `#/demo/risk-block` | BudgetReport (high-risk) → BudgetBackend (CA deny) |
| `#/demo/full-access` | BudgetApproval → all endpoints (full access) |
