# Connected browser-to-backend E2E

This suite closes the gap between isolated browser tests and protocol tests:

```text
Chromium (existing portal HTML/JS)
  -> actual portal FastAPI routes/services/AgentInvokerClient
  -> actual BudgetReport FastAPI /call-backend-raw
  -> production Go tunnel.Client (egress)
  -> real SPIFFE mutual TLS + gRPC
  -> production tunnel.Server, gateway, RBAC, OAuth and CA
  -> actual BudgetBackend FastAPI /budget/read or /budget/submit
```

The test records actual caller invocation, production gateway audit, and backend
dispatch. A UI badge alone cannot pass. Before each negative journey, the same
stack must complete a healthy browser-to-backend control. Scenario setup resets
observations; stale/extra audit entries and unexpected backend dispatch fail.

```bash
# Setup once using the parent README, then run unattended:
tests/.venv/bin/python tests/run.py --profile local --suite e2e
tests/.venv/bin/python tests/check.py --repeat 2
```

## Matrix

The dependency-free inventory is authoritative:
`python3 -S tests/e2e/run.py --list`.

- Valid JWT, allowed identity and policy: one actual backend dispatch.
- Denied submit route: RBAC audit denial and zero backend dispatch.
- Missing token: the real caller's acquisition guard stops before the proxy.
- Expired, wrong-audience, bad-signature and expiration-less JWTs: actual
  signature/claim validation, not a mocked allow/deny response.
- Disabled caller, tag mismatch and high risk: actual conditional-access denial.
- Missing risk, initial Graph policy outage and absent Graph tag: required
  fail-closed regressions. Product failures remain FAIL.
- Removed mTLS caller: actual transport rejection evidence, not an arbitrary
  connection failure interpreted as denial. The raw client fixture closes its
  socket on handshake rejection; the real caller reports `http_status=0` and
  the portal displays `0 ERROR`. That display alone cannot pass: the actual
  mTLS rejection callback and zero backend dispatch are mandatory. This does
  not claim the UI identifies the enforcement layer correctly.
- Security Portal risk round-trip: click **Apply** for high risk, observe actual
  sidecar state and Management Portal denial, click **Apply** for low risk, then
  prove backend access recovers. Verify restoration even if a browser assertion
  fails. Only the dedicated loopback fixture is eligible for these writes.

HTTP framing attacks remain in the protocol suite: browser APIs do not permit
arbitrary HTTP request framing. They are not mislabeled as browser journeys.

## Isolation and boundaries

The applications, HTTP routes, request forwarding, policy decisions, TLS
handshakes and backend handlers are real production code. All processes bind
to ephemeral loopback ports and own temporary configuration/stores. Every run
tears them down. No application code is copied and patched to make tests pass.

Inherited browser debug settings and `SELENIUM_REMOTE_URL`,
`SELENIUM_REMOTE_HEADERS`, or `SELENIUM_REMOTE_CAPABILITIES` block execution
before any resource starts. A local run never intentionally selects a remote
browser service or forwards inherited remote-browser credentials.

The controlled external boundaries are:

- Browser/operator Entra identity (the existing local MSAL-shaped identity
  fixture); actual portal role middleware still executes.
- Workload certificate and JWT issuance, and Graph-shaped policy data.
  The Go validator and policy parser consume these inputs normally.
- Tenant risk publication from Security Portal is explicitly skipped locally;
  its sidecar risk update and resulting data-plane enforcement are real.
- The local management bridge connects to the real sidecar management API;
  it is not proof of the deployed admin-control-plane network topology.

This does **not** start Azure, perform Entra sign-in/MFA, attest a SPIRE node,
prove SPIRE recovery/rotation, or test Google/GitHub provisioning. Use the live
profile only with explicitly supplied infrastructure and legitimate sessions.

## Extending safely

Add expectations to [evidence.py](evidence.py), a controlled input scenario to
the [local stack](../stack/), and a real UI journey to [journeys.py](journeys.py).
Tests for evidence reconciliation must show that UI success without backend
dispatch/audit cannot pass, and that a generic outage cannot pass as a denial.
Keep all tokens, claims, private keys and raw browser/network artifacts out of
reports. Never fix production to make harness construction look successful.
