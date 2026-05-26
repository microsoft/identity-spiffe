# SPIRE Operations Runbook

> Commands for managing the SPIRE Server on the Azure VM and debugging agent attestation.

## SPIRE Server Access

```bash
# SSH into the SPIRE Server VM (via az vm run-command for non-SSH setups)
az vm run-command invoke \
  --resource-group <rg> \
  --name <vm-name> \
  --command-id RunShellScript \
  --scripts '<command>'

# Parse output (returns JSON-wrapped stdout/stderr)
az vm run-command invoke ... | jq -r '.value[0].message'
```

## Common SPIRE Server Commands

```bash
# View all registered entries
spire-server entry show

# Generate a join token for a new agent (1hr TTL)
spire-server token generate -spiffeID spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid> -ttl 3600

# Register a workload entry
spire-server entry create \
  -spiffeID spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid> \
  -parentID <node-spiffe-id> \
  -selector unix:uid:0

# Delete all entries (for clean redeploy)
spire-server entry show | grep "Entry ID" | awk '{print $4}' | xargs -I {} spire-server entry delete -entryID {}

# Check SPIRE Server health
spire-server healthcheck

# View connected agents
spire-server agent list
```

## Join Token Lifecycle

1. **Generate:** `spire-server token generate` on the VM
2. **Capture node SPIFFE ID:** After agent connects, `spire-server agent list` shows the node entry
3. **Register workload:** Use the node SPIFFE ID as the parent ID
4. **Deploy:** Inject token as `SPIRE_JOIN_TOKEN` env var in Container App
5. **Agent connects:** Token consumed, SVID issued
6. **Token expired:** Single-use. If container restarts, must regenerate token and redeploy.

## Debugging Agent Attestation Failures

```bash
# Check if SPIRE Agent is running in the sidecar
az containerapp logs show -n <app> -g <rg> --container spire-agent --follow

# Look for attestation errors
# Common: "join token does not exist or has already been used"
# Fix: Generate new token and redeploy

# Check if the SPIRE Agent can reach the SPIRE Server
# SPIRE Agent logs will show "server address: <vm-ip>:8081"
# Verify Container App can reach the VM IP on port 8081

# Check workload API socket
# Inside the container: ls -la /tmp/spire-agent/public/api.sock
# If missing: SPIRE Agent hasn't successfully attested yet
```

## Certificate Rotation

SPIRE auto-rotates SVIDs with a default 1-hour TTL. No manual intervention needed. The Go proxy watches the Workload API for updates and hot-swaps certificates without connection drops.

## SPIRE Server Configuration

The SPIRE Server config lives at `/opt/spire/conf/server/server.conf` on the VM. Key settings:

- `trust_domain`: `aim.microsoft.com`
- `bind_address`: `0.0.0.0`
- `bind_port`: `8081`
- `data_dir`: `/opt/spire/data/server`
- NodeAttestor: `join_token` (see ADR-003)
