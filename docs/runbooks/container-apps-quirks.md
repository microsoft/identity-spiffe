# Container Apps Platform Quirks

> Undocumented behaviors discovered during PoC development.

## Multi-Container Sidecar Deployment

Container Apps supports multiple containers per app (sidecar pattern), but:

- **Updating one container resets others to placeholder images.** Always deploy the full container spec in a single operation. Never do incremental container updates.
- **Init containers vs. sidecar containers** have different lifecycle semantics. SPIRE Agent should be a sidecar (runs alongside), not an init container (runs once and exits).
- **Resource limits are per-container.** Each sidecar needs its own CPU/memory allocation.

## Networking

- **Internal TCP routing:** Use the Container App name as hostname (e.g., `budget-backend`), not the FQDN. The FQDN goes through the environment's TLS termination which breaks our mTLS.
- **Internal-only ingress:** Set `ingress.external: false` for agents that should not be reachable from outside the Container Apps environment. BudgetBackend uses internal-only.
- **Port configuration:** The `targetPort` in ingress config must match what the application actually listens on. For our agents, that's port 8000 (FastAPI) or 8443 (sidecar TLS listener).

## Environment Variables

- Container Apps supports env vars from secrets, but **secrets can't be updated without redeploying the container.** For join tokens that change every deployment, use plain env vars (not secrets).
- Env vars are visible in the Azure Portal. Don't put actual secrets in plain env vars in production.

## IMDS (Instance Metadata Service)

- **Container Apps does NOT expose IMDS (169.254.169.254) to user containers.** This breaks any workload identity flow that depends on IMDS, including SPIRE's `azure_msi` NodeAttestor.
- The Container Apps managed identity is accessible via the `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` env vars (Container Apps-specific, not standard IMDS). SPIRE doesn't know how to use these.

## Revision Management

- Each deployment creates a new revision. Old revisions linger unless cleaned up.
- `revisionSuffix` in the YAML must be unique per deployment or stripped entirely.
- `az containerapp revision list` to see revision history; `az containerapp revision deactivate` to clean up.

## Logs

```bash
# Real-time logs from a specific container in a multi-container app
az containerapp logs show -n budget-backend -g <rg> --container spiffe-proxy --follow

# Historical logs
az containerapp logs show -n budget-backend -g <rg> --container spiffe-proxy --type console
```
