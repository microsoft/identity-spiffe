# Connected local production-tunnel fixture

Read [`../AGENTS.md`](../AGENTS.md). This helper belongs to the connected E2E
test system; it never changes product code, deploys, downloads dependencies,
reads Azure configuration, or installs tools.

```python
from runtime import running_stack  # add tests/stack to sys.path

with running_stack("http://127.0.0.1:8000") as stack:
    # egress_url, management_url, control_url, caller_spiffe_id, audience,
    # source_sha256
    ...
```

The backend must already be running on numeric IPv4 loopback with an explicit
port and no path, credentials, query, or fragment. The parent harness owns the
actual FastAPI caller/backend, portal processes, and browser interactions.

## Actual path and explicit fixture boundaries

The egress TCP listener passes connections directly to production
`tunnel.NewClient` / `Client.ForwardConnection`. That client authenticates over
real gRPC mutual TLS to production `tunnel.NewServer`, with the actual gateway,
RBAC engine, OAuth validator, dynamic mTLS authorizer, Graph CA policy cache,
risk/tag stores, and access logger. Authorized bytes reach the supplied backend.
There is no synthetic HTTP allow/deny decision or copied tunnel algorithm.

Certificates are issued by a fresh synthetic Ed25519 CA; tokens are signed by
an ephemeral RSA key. The production OAuth/Graph HTTP clients' fixed cloud
destinations are redirected to a loopback issuance/metadata/Graph fixture;
other HTTP destinations are blocked. Risk/tag inputs are controlled synthetic
Graph-sourced store inputs. This does **not** launch SPIRE or prove attestation,
Entra issuance, tenant CA behavior, real admin authentication, or cloud topology.

`management_url` is a root URL and a thin loopback prefix adapter over **actual**
`mgmt.NewServer` endpoints: `/admin/policy` (the production portal
`AdminControlPlaneClient` shape), `/mgmt/policy`, and `/policy` work, as do
`/mgmt/agent-risk`, `/mgmt/agent-tags`, `/mgmt/audit`, and other production paths.
Management mutations affect the same production stores used for enforcement.
The child does not inherit `MGMT_API_KEY`, cloud credentials, HTTP proxy settings,
or policy-enrichment environment variables. Management is local and unauthenticated.
The product constructor accepts only a port, so the helper selects ephemeral
management ports and retries bounded bind failures.

## Control contract

All public listeners are distinct, ephemeral `127.0.0.1` ports.

| Request | Response |
|---|---|
| `GET /health` | `{"status":"ready"}` |
| `POST /scenario` with `{"name":"allowed"}` | `{"scenario":"allowed"}` |
| `GET /token` | `{"access_token":"<ephemeral signed fixture JWT>"}` or empty string for `jwt_missing` |
| `GET /evidence` | `{"scenario":"allowed","audit":[...],"mtls_rejections":0}` |

Scenario names are strictly validated: `allowed`, `rbac_deny`, `jwt_missing`,
`jwt_expired`, `jwt_wrong_audience`, `jwt_wrong_signature`, `jwt_no_expiry`,
`ca_disabled`, `ca_tag_mismatch`, `ca_high_risk`, `ca_missing_risk`,
`ca_policy_outage`, `ca_graph_tag_absent`, and `mtls_denied`.

Every reset creates fresh production policy/risk/tag stores, access logger,
OAuth validator, cold Graph policy cache, TLS certificates, and ingress server.
A correct token must validate before any JWT scenario is ready. A healthy real
client/server mTLS health exchange must pass before its allowlist is removed for
`mtls_denied`. The outage scenario verifies a failed **initial** Graph fetch.
Every egress connection uses a new production client, so mTLS changes trigger
a new handshake. Resets are serialized with in-flight forwarding.

The base policy permits only `GET /budget/read` with `Budget.Read` and a valid
JWT, and denies `/budget/submit`. The caller identity is
`spiffe://stack.test/caller`; audience is `stack-budget-api`. `rbac_deny` selects
the base policy; the parent sends `POST /budget/submit`.

Audit entries come from the actual access logger. `/evidence` separates transport
rejections into `mtls_rejections` (they are not HTTP gateway audit entries), removes raw JWT
validation errors and custom claim values, contains no token or raw exceptions,
and resets per scenario. mTLS rejection counts come from the production
authorizer's reject callback, not from a timeout. Token responses are transient
inputs only and must never be saved in reports. No access to `/token` is needed
for readiness.

## Validation and cleanup

Prepared Go/protobuf prerequisites are shared with [`../protocols`](../protocols).
The launcher reuses its offline-environment and generator-resolution helpers
without altering that suite. Both tool commands and the Go runtime use the
shared [`../processes.py`](../processes.py) supervisor. Every command starts a
new process group and registers it in a private nested scope **before exec**.
`IDENTITY_TEST_PROCESS_REGISTRY` carries ownership through the gate and adapters,
so outer cleanup finds registered groups even after intermediate leaders die.
A quiet group guardian preserves a PID/birth identity until cleanup, including
for fast-exiting commands with orphaned children. This replaces ancestry polling;
the OS `ps` command is used only to verify identities and termination.

Registration and ancestor-closing checks share a file lock; a closed scope cannot
exec a new command. Cleanup marks the scope closing before signalling only its
verified registered groups, escalates TERM to KILL, and completes before workspace
removal. Stale identities, unsafe registries or failed cleanup retain the private
scope/workspace and raise `StackCleanupFailure`, never PASS. Registry scopes
default to `tests/artifacts/processes`, never a system temporary directory.
The shared context manager accepts `registry_base=<private-check-output>` to
place a fresh root under that directory's `processes/` child (the base must be
inside `tests/artifacts`). An inherited registry always takes precedence, so
nested checks cannot use this option to escape outer ownership. Startup/exec
errors raise `ProcessLaunchError`; unverified cleanup raises
`ProcessCleanupError`. These map to the stack's existing typed exceptions.
Build inputs are copied verbatim into a
private mode-0700 `.work-*` directory **under this directory**, with generated
protobufs only in that copy. `GOTMPDIR` and `TMPDIR` stay there. Go's module path
permits `internal` imports and declares Go 1.24. Production source inputs receive
a SHA-256 digest. No production Go source, module, or generated file is modified.

```bash
# Pure launcher safety regressions.
tests/.venv/bin/python -m unittest discover -s tests/stack -p test_runtime.py

# Discoverable wrappers: Go topology self-test and Python launcher -> real Go
# tunnel -> observed HTTP backend + cleanup.
tests/.venv/bin/python -m unittest discover -s tests/stack -p test_connected.py

# Go topology assertions: real 200/401/403, no denied backend dispatch, management
# risk updates, mTLS evidence, cold Graph state, control validation and redaction.
tests/.venv/bin/python tests/stack/runtime.py --self-test
```

The Go self-test uses a small observed HTTP backend, not the parent's FastAPI
backend, and tests fixture wiring rather than hiding known product failures.
The discoverable unittest wrappers explicitly skip only `StackUnavailable`
prerequisites/startup; the unattended gate treats skips as incomplete. Actual Go
assertion/build/runtime failures remain errors or failures, never skips.
Missing expiry/risk/tag and policy-outage enforcement assertions belong in the
parent E2E matrix and must remain FAIL if actual production code allows them.

The context manager verifies readiness, bounds tool/startup/request/cleanup time,
terminates its exact child, waits for exit, and removes its private workspace.
The gate must launch through `owned_process` as well; the inherited registry, not
the legacy `IDENTITY_TEST_INHERIT_PROCESS_GROUP` flag, governs nested cleanup.
Forced cleanup, build failures, unexpected runtime exits, malformed readiness and
execution timeouts raise `StackFailure`. Missing prerequisites, startup exits or
startup readiness deadlines raise `StackUnavailable` (`StackBlocked` remains an
alias; exit 2 from `--self-test`). Both inherit `RuntimeError` independently.
Neither is an authorization PASS.
