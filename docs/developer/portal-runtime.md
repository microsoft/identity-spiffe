# Portal Runtime

The portal backend is no longer a monolithic `server.py`. The runtime now lives under `portal/app/` and `portal/server.py` is a thin compatibility wrapper and CLI entrypoint.

## Package Layout

| Module | Purpose |
|---|---|
| `main.py` | FastAPI app factory, middleware, lifespan |
| `settings.py` | local and cloud settings validation |
| `auth.py` | Entra auth and role dependencies |
| `routers/` | public and authenticated route registration |
| `clients/` | admin-control-plane, agent, and Graph clients |
| `services/` | policy, scan, CA, and health orchestration |
| `storage/` | file and Blob-backed policy config persistence |

## Runtime Model

The app builds a single container object and stores it on `app.state`.

That container owns:

- settings
- pooled HTTP clients
- auth validator
- policy config store
- services

This replaced the old pattern of globals and ad-hoc caches inside one large file.

## Health Model

The portal exposes three different health surfaces on purpose:

| Route | Meaning |
|---|---|
| `/healthz/live` | process is running |
| `/healthz/ready` | required dependencies are ready |
| `/api/system-status` | authenticated dependency-level operational detail |

That split keeps readiness honest without overloading the public liveness contract.

## Cloud Versus Local

Local mode:

- may run without Entra auth
- uses `portal/portal-config.json`
- stores saved policy configs in `portal/policy-configs.json`

Cloud mode:

- requires admin-control-plane URL and management key
- requires Entra auth settings
- discovers agents from `admin-control-plane`
- stores policy configs in Azure Blob Storage through managed identity

## Storage Contract

Policy config persistence is intentionally different by environment:

- local development uses the file-backed store
- cloud runtime uses Blob storage for durability across revisions and restarts

The portal Container App managed identity must have Blob data permissions on the portal policy store.

## Request Handling Notes

- request IDs flow through to downstream dependency calls
- mutation routes are admin-only
- Graph failures are surfaced as real errors, not fabricated healthy state
- cloud startup should fail fast when required runtime configuration is missing

## Related Reading

- [Portal Cloud Deployment](../architecture/portal-cloud-deployment.md)
- [Management APIs](../reference/management-apis.md)
- [Authentication Flows](../reference/authentication-flows.md)
