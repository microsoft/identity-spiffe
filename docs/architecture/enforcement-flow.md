# Enforcement Flow

## Allowed Call (BudgetReport → GET /budget/read)

```
BudgetReport Agent                BudgetReport Proxy              BudgetBackend Proxy             BudgetBackend Agent
      |                                 |                                |                              |
      |-- GET http://localhost:8080 --> |                                |                              |
      |   /budget/read                  |                                |                              |
      |                                 |-- mTLS GET -----------------> |                              |
      |                                 |   cert: spiffe://aim.ms.com/ |                              |
      |                                 |     ests/bp/<bp>/aid/<rpt>   |                              |
      |                                 |                                |-- extract SPIFFE ID         |
      |                                 |                                |   from peer cert SAN        |
      |                                 |                                |                              |
      |                                 |                                |-- RBAC check:               |
      |                                 |                                |   caller=budget-report       |
      |                                 |                                |   method=GET                 |
      |                                 |                                |   path=/budget/read          |
      |                                 |                                |   → ALLOW ✅                |
      |                                 |                                |                              |
      |                                 |                                |-- GET localhost:8000 ------> |
      |                                 |                                |   X-Forwarded-SPIFFE-ID:     |
      |                                 |                                |   budget-report              |
      |                                 |                                |                              |
      |<-- 200 OK --------------------- |<-- 200 OK ------------------- |<-- 200 OK ------------------|
```

## Blocked at RBAC (BudgetReport → POST /budget/submit)

```
BudgetReport Agent                BudgetReport Proxy              BudgetBackend Proxy
      |                                 |                                |
      |-- POST http://localhost:8080 -->|                                |
      |   /budget/submit                |                                |
      |                                 |-- mTLS POST ----------------> |
      |                                 |   cert: budget-report         |
      |                                 |                                |-- RBAC check:
      |                                 |                                |   caller=budget-report
      |                                 |                                |   method=POST
      |                                 |                                |   path=/budget/submit
      |                                 |                                |   → DENY ❌
      |                                 |                                |
      |<-- 403 Forbidden --------------- |<-- 403 Forbidden ----------- |
      |                                 |                                |
      |   (BudgetBackend Agent NEVER    |                                |
      |    sees this request)           |                                |
```

## Blocked at Transport (EmployeeMenus → BudgetBackend)

```
EmployeeMenus Agent               EmployeeMenus Proxy             BudgetBackend Proxy
      |                                 |                                |
      |-- GET http://localhost:8080 --> |                                |
      |   /budget/read                  |                                |
      |                                 |-- mTLS attempt --------------> |
      |                                 |   cert: employee-menus        |
      |                                 |                                |-- TLS handshake
      |                                 |                                |   check ALLOWED_SPIFFE_IDS
      |                                 |                                |   employee-menus NOT in list
      |                                 |                                |   → REJECT ❌
      |                                 |                                |
      |<-- connection refused ----------|<-- TLS handshake failed ------|
      |                                 |                                |
      |   (RBAC is NEVER reached.      |                                |
      |    Blocked at transport layer.) |                                |
```

## Direct A2A Call (BudgetReport → EmployeeMenus → Blocked by CA Tag Mismatch)

```
BudgetReport App                  EmployeeMenus App                Admin Control Plane
      |                                  |                                 |
      |-- HTTPS GET /call-agent -------> |                                 |
      |   target=employee-menus          |                                 |
      |                                  |-- acquire Entra JWT ----------> |
      |                                  |                                 |
      |-- HTTPS GET /a2a/status -----------------------------------------> |
      |   Authorization: Bearer <JWT>    |                                 |
      |                                  |-- validate JWT locally          |
      |                                  |-- query synced caller tag ----> |
      |                                  |   /admin/policy                |
      |                                  |<-- budget-report = finance ---- |
      |                                  |                                 |
      |                                  |-- compare caller_tag vs target_tag
      |                                  |   finance != "" → DENY ❌
      |<-- 403 agent_tag_mismatch -------|                                 |
```

This direct A2A path is separate from the SPIFFE transport path. It currently demonstrates
target-side CA/tag enforcement after JWT issuance, not STS-side token denial.

## Why Four Layers Matter

The EmployeeMenus scenario shows **defense in depth**: even if an RBAC policy bug accidentally allowed employee-menus access, the transport layer would still block the connection. The three layers are independent enforcement points.

Layer 3 (OAuth2/JWT) adds a third dimension: even when a caller passes mTLS (Layer 1) and RBAC (Layer 2), it must present a valid Entra token with the required app roles. Layer 4b adds direct app/data-plane governance checks such as risk level and Entra-backed custom-attribute tag matching for direct A2A calls.

This is the core differentiator vs. Apigee: Apigee operates at the perimeter (north-south). It cannot enforce lateral (east-west) agent-to-agent policy. Our sidecar pattern gives you transport-layer identity verification (mTLS), application-layer authorization (RBAC), and token-layer proof of Entra identity (OAuth2/JWT) for every agent-to-agent call.
