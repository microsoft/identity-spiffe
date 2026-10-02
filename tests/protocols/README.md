# Local real-Go protocol matrix

This suite imports the **actual** proxy `internal/mtls`, `internal/rbac`,
`internal/oauth`, `internal/ca`, `internal/gateway`, and `internal/tunnel`
packages. It does not reimplement their policy algorithms. All listeners bind
to loopback; no container, Azure login, deployed environment, or SPIRE server is
required. No production files are modified.

Read [../AGENTS.md](../AGENTS.md) and [../README.md](../README.md) first.

## Run

From the repository root:

```bash
# Pure standard-library inventory: no Go/protoc probes or network.
python3 tests/protocols/run.py --list

# Adapter/report safety tests (no Go/protoc required).
python3 -m unittest discover -s tests/protocols -p test_adapter.py

# Go-backed harness regression: metadata outages cannot satisfy JWT-denial tests.
# Requires the same prepared Go/protobuf prerequisites as the local matrix.
python3 -m unittest discover -s tests/protocols -p test_fixture_regression.py

# Preferred coordinator entry point, including aggregate JSON/Markdown reports.
python3 tests/run.py --profile local --suite protocols

# Standalone adapter, same case IDs/results.
python3 tests/protocols/run.py --profile local --output /tmp/protocol-matrix.json
```

Requirements:

- Python 3.10+ standard library (verified with 3.14).
- Go compatible with the production [go.mod](../../src/spiffe-proxy/go.mod).
- `protoc`, `protoc-gen-go` **1.36.10**, and `protoc-gen-go-grpc` **1.5.1**.
  Plugins are resolved from the isolated `tests/.tools/bin` directory first,
  then PATH, then the Go workspace's `bin` directories. Nonexecutable files
  are not selected.
- Production Go module dependencies already present in the local module cache.

The harness [go.mod](go.mod) declares `go 1.24.0`, matching production; it
does not declare a newer toolchain. The supported pinned generator pair is
`protoc-gen-go@v1.36.10` and `protoc-gen-go-grpc@v1.5.1`, matching the harness
CI/bootstrap instructions. Do not substitute grpc generator 1.6.2: its module
requires Go 1.25. CI should select Go from the production module and provision
the pinned pair rather than installing `@latest`. Local verification used
Go 1.27.1 and is not itself proof of execution on Go 1.24. Any dependency
changes Go makes while running the adapter affect only the disposable module
copy, never the checked-in module.

The adapter **does not download** tools, modules, or toolchains. Go execution
uses `GOPROXY=off`, `GONOPROXY=none`, `GOVCS=*:off`, `GOTOOLCHAIN=local`, and
`GOWORK=off`. Missing dependencies/tooling produce BLOCKED results; coordinate
installation separately. Build errors, missing test completions, zero tests,
invalid test output, and test timeouts cannot produce PASS.

The test module deliberately has a path below the production module, which
permits Go's `internal` imports. The adapter copies only production Go source,
module metadata, and the tunnel protobuf into a unique temporary directory,
generates protobuf bindings **there**, and points an isolated test module at
that copy. It does not patch the copied enforcement code. The temporary
workspace is removed on exit. Reports include a SHA-256 digest of the copied
production source inputs; ephemeral private keys and tokens are not persisted.
Direct `go test` in this directory is not the supported entry point, because a
clean source checkout intentionally lacks generated tunnel bindings.

## Evidence and boundaries

| Group | Actual execution | Fixture boundary |
|---|---|---|
| `MTLS` | Real client/server TLS handshakes; go-spiffe verifier and production dynamic allowlist | Generated Ed25519 CA and X.509 SPIFFE URI SVIDs, not SPIRE issuance/rotation |
| `Enforcement` | Production policy loading and engine, real RSA-signed JWT verification, role checks, reason/layer/status assertions | Loopback OIDC discovery/JWKS responses and locally signed tokens; not Entra token issuance |
| `CA` | Production Graph client, CA cache JSON parsing, enabled/report-only/disabled/grant-control and risk-level logic, tag store, engine | Local Graph/token HTTP responses and explicit risk/tag inputs; not tenant policy enforcement |
| `Tunnel` | Production gRPC service over real mutual TLS, production gateway and JWT checks, real backend HTTP server | Local SVIDs, OAuth metadata and backend |

These are **local component and server-side transport integration tests**, not
a full deployed tunnel E2E or SPIRE lifecycle test. The harness constructs TLS
configs from generated SVIDs using go-spiffe primitives and the real dynamic
authorizer; it does not construct `WorkloadIdentity` through the SPIRE
Workload API. Tunnel cases use a generated gRPC client against the real
production tunnel server with its gateway attached. They do not launch the
production egress client, sidecar executable, SPIRE agent/server, or deployment.

The HTTP transport for the production OAuth/Graph clients is replaced only at
the I/O boundary: recognized cloud hostnames are routed to a loopback fixture,
and other destinations are rejected. Production token parsing, signature
validation, claim validation, CA policy parsing, and enforcement still run.
There are no tests in parallel because this boundary uses the process-wide
default HTTP transport.

Coverage includes:

- Allowed, nonallowlisted, absent, untrusted, expired, no-URI and removed client
  identities, with **specific server-side handshake rejection categories**.
  A generic network error does not count as a security rejection.
- Caller/method/route policy matching, identity prefix boundaries, path
  normalization, required JWT availability/structure/signature/issuer/audience/
  time checks, all-required-role semantics, and absent-validator fail-closed.
  Each mutated-token case first validates a good control token with that same
  fixture and validator, confirms JWKS initialization, and then asserts the
  specific JWT error category. The Go-backed harness regression injects OIDC
  and JWKS outages into disposable test-fixture copies and requires all seven
  JWT-rejection subtests to fail, rather than mistake the outage for rejection.
- Actual implementation precedence: CA admin governance runs before RBAC,
  RBAC denial before JWT validation; tests also assert OAuth discovery was
  never called when an earlier layer denies.
- `EntraRisk` exercises production Graph reads and gateway decisions: Entra high
  overrides manual low, explicit none, licensing/permission errors, missing and
  invalid ratings, valid cache reuse, zero-lifetime lookups, and failed refreshes
  without a manual-safe fallback. Graph responses are loopback fixtures, not
  evidence of tenant licensing or a deployed rollout.
- Locally supported CA risk conditions: scalar/array risk levels, enabled
  block policies, disabled and report-only policies, non-block grant controls,
  unions, explicit low/medium/high inputs, initial outage, cached outage, tag
  match/mismatch/missing/override/exemption and the disabled-agent kill switch.
- Authorized and denied backend dispatch, identity-header overwrite, valid
  split request bodies, and second-request framing in both first and body
  continuation DATA frames. The backend counts actual parsed HTTP requests.

These cases are `profiles: ["local"]`, `mutation: false`: they mutate only
ephemeral local state. `--profile live` returns an empty case array, exit 2, and does
not execute local tests or claim live coverage. `--config PATH` is accepted
for coordinator compatibility but is intentionally not read by this local
suite. Live cases belong to [../live/](../live/).

Coordinator configuration can omit this suite's section or use:

```json
{
  "protocols": {}
}
```

There are no protocol-specific configuration fields. This is deliberately not
a source of endpoint, credential, command, or fixture overrides. Inventory is
the dependency-free JSON array from `--list`; the coordinator should select
its `profiles` rather than infer live coverage from the presence of this
configuration section.

Not verified: interactive browser OAuth/PKCE/OBO, tenant Conditional Access at
token issuance, app registration semantics, full Graph filter expressions,
Graph pagination, actual Graph attribute synchronization, SPIRE attestation
and renewal, cloud deployment/network topology, or every protocol combination.

## Result contract and known product failures

`--list` prints JSON descriptors with stable IDs, suite, layer, profile,
description, expected behavior, and mutation classification. The adapter
maps each ID to a named Go subtest and consumes `go test -json`; each selected
case is present in `{"cases": [...]}` with PASS/FAIL/BLOCKED/SKIPPED, a sanitized
observation, numeric duration, and evidence. Raw Go output, backend bodies,
JWTs, keys, and error text from remote-shaped responses are not reported.

Exit codes: `0` all selected cases PASS, `1` one or more FAIL (takes precedence),
`2` any BLOCKED/SKIPPED or an empty selection. SKIPPED is not PASS.

Standalone reports are written with mode `0600`, including when overwriting
an existing less-restrictive file. Final-path symlinks, hardlinks, nonregular
files, and files owned by another user are rejected before truncation. Report
write failures exit 2 with a fixed diagnostic, never filesystem paths or raw
exception output.

The first verified run exposed these failures against the current production
code. They are intentionally **not** marked expected-failure or skipped:

| Case ID | Required security property |
|---|---|
| `protocols.enforcement.jwt_no_expiry` | Required access tokens must have an expiration |
| `protocols.ca.policy_outage` | Initial unavailable Graph policy must not allow high-risk access |
| `protocols.ca.missing_risk` | Missing risk evidence must not become low risk |
| `protocols.ca.graph_tag_absent` | Missing configured Graph tag evidence must not become an allowing YAML fallback |
| `protocols.tunnel.same_frame` | A second HTTP request in the initial DATA frame must not reach the backend |
| `protocols.tunnel.overflow_frame` | An oversized body continuation must not forward a second ungoverned request |

The two tunnel regressions are fixed by the
[governed one-request contract](../../docs/architecture/layers/transport-mtls.md#governed-http-tunnel-contract):
HTTP parsing bounds the streamed body independently of DATA frames. They remain
ordinary executable assertions, not removed cases or expected failures. The
other four findings above remain outside this transport fix.
The later-frame case accepts only a completed-stream EOF when attempting its
second send: the server may already have closed after the first response.
It still requires the complete healthy response, graceful stream termination,
and exactly one authenticated backend dispatch; arbitrary transport errors
cannot satisfy the rejection.

These are product findings, not harness errors. Fixes require separate
authorization; this suite does not weaken assertions or change production to
make the matrix green. Always use the current generated report for counts,
not this historical list.
