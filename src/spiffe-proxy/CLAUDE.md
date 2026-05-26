# CLAUDE.md — spiffe-proxy (Go Sidecar)

> The custom Go proxy that handles mTLS and RBAC enforcement. This is the core enforcement component.

## What This Does

A transparent sidecar proxy written in Go (~2,900 lines) that:
1. **Egress mode (port 8080):** Accepts plain HTTP from the local agent, wraps in gRPC+mTLS, tunnels to the target agent's ingress proxy on port 8443
2. **Ingress mode (port 8443):** Accepts gRPC+mTLS connections from egress proxies, terminates TLS, extracts caller SPIFFE ID, checks mTLS allow list, enforces RBAC, forwards to local agent on port 8000
3. **Management API (port 9443):** REST API for CRUD operations on RBAC policy and mTLS allow list

## Package Structure

```
spiffe-proxy/
├── cmd/
│   └── main.go              ← Entrypoint (~370 lines), starts egress or ingress mode
├── internal/
│   ├── gateway/
│   │   └── interceptor.go   ← HTTP gateway interceptor for gRPC-tunneled requests
│   ├── inspect/
│   │   └── http.go          ← HTTP request inspection and logging
│   ├── logging/
│   │   └── access.go        ← Structured access logging (SPIFFE ID, method, path, action)
│   ├── mgmt/
│   │   └── server.go        ← Management REST API on :9443 (RBAC + mTLS CRUD)
│   ├── mtls/
│   │   ├── authorizer.go    ← mTLS allow list checking (transport layer)
│   │   └── authorizer_test.go
│   ├── rbac/
│   │   ├── engine.go        ← Policy evaluation: (spiffe_id, method, path) → allow/deny
│   │   ├── policy.go        ← YAML policy v3.0 parsing with name-based lookup
│   │   └── engine_test.go   ← 558-line test suite for RBAC engine
│   ├── spiffe/
│   │   └── workload.go      ← SPIRE Workload API client for X.509 SVID retrieval
│   └── tunnel/
│       ├── client.go        ← gRPC mTLS tunnel client (egress side)
│       └── server.go        ← gRPC mTLS tunnel server (ingress side)
├── config/
│   ├── spiffe-rbac-policy.yaml          ← Hardened RBAC policy (default deny)
│   └── spiffe-rbac-policy-permissive.yaml ← Permissive baseline for progressive hardening demo
├── proto/
│   └── tunnel.proto         ← gRPC protobuf definition for tunnel service
├── spire-config/
│   ├── agent.conf           ← SPIRE Agent configuration template
│   └── server.conf          ← SPIRE Server configuration template
├── entrypoint.sh            ← Container entrypoint (starts SPIRE Agent + proxy + agent monitor)
├── imds-mock.py             ← Mock IMDS server for local development
├── Dockerfile
├── go.mod
└── go.sum
```

## RBAC Policy Format (v3.0)

```yaml
version: "3.0"
trust_domain: "aim.microsoft.com"
default_action: deny

policies:
  - spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/"
    name: "budget-report"
    entra_agent_id: ""
    description: "Read-only access to budget data"
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
      - path: "/budget/submit"
        methods: ["*"]
        action: deny
```

- Default deny. Rules evaluated per-policy. First match wins.
- Policies matched by `name` field (enriched at runtime via `SPIFFE_PREFIX_<NAME>` env vars)
- Wildcards supported for methods (`*`) and paths (`/budget/*`)
- Path normalization prevents bypass via URL encoding, dot segments, double slashes

## Key Implementation Notes

- **SPIRE Workload API** is accessed via Unix domain socket at `/opt/spire/sockets/workload.sock`. The proxy watches for certificate updates and hot-swaps without dropping connections.
- **Caller SPIFFE ID** is extracted from the peer certificate's URI SAN after mTLS handshake. This is the identity that both mTLS allow lists and RBAC evaluate.
- **Three-layer enforcement:** mTLS allow list rejects untrusted callers at TLS handshake (Layer 1: transport); RBAC evaluates method+path for trusted callers (Layer 2: application); OAuth2/JWT validates Entra tokens and app roles (Layer 3: token).
- **Structured access logs** include: timestamp, caller SPIFFE ID, method, path, action (allow/deny), response code.
- **Management API** endpoints: `GET /mgmt/policy`, `PUT /mgmt/policy`, `GET /mgmt/allowed-ids`, `PUT /mgmt/allowed-ids`, `GET /mgmt/health`
- **gRPC tunnel** multiplexes HTTP requests over a single mTLS connection between egress and ingress proxies.
- **SPIRE Agent monitor** — a background loop in `entrypoint.sh` checks the agent process every 10s and restarts it if it dies. This handles mid-run crashes (agent re-attests using cached key material in `/opt/spire/data/agent/`). Does NOT help on full container restart where the data dir is wiped and the join token is consumed.
- **No `proxy-only` mode** — `entrypoint.sh` only supports `CONTAINER_MODE=server` and `CONTAINER_MODE=agent-proxy`. There is no mode for connecting to an external SPIRE Agent socket (needed for SPIFFE federation with `gcp_iit` attestation). See `docs/architecture/next-google-cloud-agent-federation.md` and hard-won-learnings #32.

## Building

```bash
# Build and push to ACR (deploy.sh Step 3 handles this)
docker build -t <acr>.azurecr.io/spiffe-proxy:v21 .
docker push <acr>.azurecr.io/spiffe-proxy:v21
```

deploy.sh handles this in Step 3. Don't build manually unless debugging the proxy itself.

## Environment Variables

| Var | Purpose | Example |
|-----|---------|---------|| `CONTAINER_MODE` | Container mode: `server` or `agent-proxy` (only two supported values) | `agent-proxy` || `PROXY_MODE` | Proxy mode: egress or ingress | `ingress` |
| `SPIRE_SOCKET_PATH` | Path to SPIRE Workload API socket | `/opt/spire/sockets/workload.sock` |
| `LISTEN_PORT` | Outbound proxy port (egress mode) | `8080` |
| `TLS_PORT` | Inbound mTLS port (ingress mode) | `8443` |
| `MGMT_PORT` | Management API port | `9443` |
| `BACKEND_PORT` | Local agent port to forward to | `8000` |
| `ALLOWED_SPIFFE_IDS` | Comma-separated list of trusted caller IDs | `spiffe://aim.microsoft.com/ests/bp/.../aid/...` |
| `RBAC_POLICY` | YAML policy string (injected via deploy.sh) | See format above |
| `SPIFFE_PREFIX_<NAME>` | Runtime SPIFFE ID prefix override per agent | `spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid>` |
| `ENTRA_ID_<NAME>` | Entra Agent Identity OID per agent | UUID |
| `TARGET_HOST` | Target agent hostname (egress mode) | `budget-backend` |
| `TARGET_PORT` | Target agent mTLS port (egress mode) | `8443` |
