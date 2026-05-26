# ADR-004: Transparent Proxy, Not SDK

**Status:** Accepted
**Date:** February 2026
**Deciders:** Project contributors

## Context

The sidecar needs to intercept agent traffic and add mTLS. Two patterns: give agents an SDK to call, or make the proxy transparent so agents don't know it exists.

## Decision

**Transparent proxy.** Agent sends plain HTTP to `localhost:8080`. Proxy intercepts, wraps in mTLS, forwards to the target agent's proxy on port 8443. Target proxy terminates mTLS, extracts caller SPIFFE ID, enforces RBAC, forwards plain HTTP to the agent on its local port.

## Rationale

- **Works with any language / framework.** Python, Go, Node, Java — doesn't matter. If it can make an HTTP call to localhost, it works.
- **Zero code changes to existing agents.** Foundry agents are already written. Asking developers to import an SDK and refactor networking is a non-starter for adoption.
- **Same pattern as Envoy / Istio.** This is exactly how service mesh sidecars work. We're not inventing architecture; we're applying proven patterns to a new context.
- **Decouples identity from application logic.** The agent's concern is business logic. The sidecar's concern is identity and authorization. Clean separation.

## How It Works

```
Agent (Python)                    Sidecar (Go)                     Target Sidecar (Go)         Target Agent
    |                                 |                                 |                          |
    |-- POST http://localhost:8080 -->|                                 |                          |
    |   /budget/submit                |-- mTLS POST https://target:8443 -->|                       |
    |                                 |   X-SPIFFE-ID: caller's ID     |-- check RBAC policy ---> |
    |                                 |                                 |   allowed? ✅            |
    |                                 |                                 |-- POST http://localhost:8000 -->|
    |                                 |                                 |   X-Forwarded-SPIFFE-ID  |
    |<-- 200 OK ----------------------|<-- 200 OK --------------------|<-- 200 OK ---------------|
```

## Consequences

- Agents must use `localhost:8080` as their target (configured via `BACKEND_ENDPOINT` env var)
- The proxy needs to know the target's internal hostname for TCP routing
- Adds one network hop per direction (agent → proxy → network → proxy → agent)
- Proxy must handle connection pooling and timeouts to avoid latency overhead

## Related

- ADR-001 (Sidecar, Not Gateway) — the architectural frame this sits within
- `src/spiffe-proxy/CLAUDE.md` — implementation details of the Go proxy
