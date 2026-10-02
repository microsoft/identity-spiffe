# Explicit-target live enforcement adapter

This suite calls **existing configured services only**. It never provisions,
discovers cloud endpoints or secrets, mints tokens, calls Graph, resets tenant
risk, invokes the legacy live script, or modifies production code.
Python's standard library is sufficient, including for inventory.

```bash
python3 tests/live/run.py --list
python3 tests/live/run.py --profile live --config tests/config.local.json \
  --output /private/new-live-results.json
python3 -m unittest discover -s tests/live -p 'test_live.py'
```

Output is a newly created mode-0600 file, `{"cases": [...]}`. Its parent
directory must already exist. Existing output files and symlinks are rejected.
`--profile local` selects zero live cases and writes `{"cases":[]}`; it does not
claim live coverage. Missing configuration yields BLOCKED for every selected
case. Exit codes: 0 all selected cases pass (or none selected), 1 any FAIL,
2 otherwise any BLOCKED/SKIPPED. Use the parent runner for aggregate reports.

## Explicit configuration

Merge [config.example.json](config.example.json) into your parent configuration.
`live` accepts only these fields:

| Field | Contract |
| --- | --- |
| `endpoints` | Map of named base URLs; no queries, fragments, userinfo or percent-encoded paths |
| `identities` | Map of designated test identities described below |
| `a2a_controls` | Map of A2A target endpoint names to allowed identity fixture names in `identities` |
| `admin_key_env` | Environment variable **name**, not a secret value |
| `timeout_seconds` | Number from 1 to 60; default 20 per HTTP exchange |
| `exclusive_observation` | Explicit `true` only for quiescent single-caller JWT audit tests |
| `mutations` | Optional local-only scoped opt-in; disabled by default |

All URLs must use HTTPS, or HTTP with a literal loopback address/`localhost`.
TLS certificate verification remains enabled. Redirects are never followed,
even without credentials. Proxy environment variables are not used. Do not
point loopback URLs at unreviewed forwarding services. Configuration is trusted
operator input: the harness cannot establish deployment ownership from a URL.
Identity-provider, Graph and ARM endpoints are rejected.

Each exchange runs in a short-lived spawned worker with a parent-enforced
wall-clock deadline covering DNS, TLS, headers and slow/trickled bodies.
Requests and responses use private in-memory pipes, not command arguments,
stdout or log files. Timed-out workers are terminated and reaped before control
returns; cleanup receives its own fresh deadline. Worker teardown can add up
to 1.1 seconds. Responses are capped at 1 MiB. The output path is exclusively
reserved before any live request, so a path collision cannot trigger work
without a report destination.

Named endpoints:

- `budget-report`, `budget-approval`, `employee-menus`: caller/target application
  bases, with `/call-backend-raw` and `/a2a/status` as appropriate.
- `management`: explicit management base, normally
  `https://your-admin-control-plane/admin`; the adapter appends `/audit`.
- `sidecar`: optional **loopback** native sidecar management base, normally
  `http://127.0.0.1:9443`; the adapter appends `/agent-risk` or `/agent-tags`.
  Do not use portal risk routes or a Graph-writing management proxy.
- `dynamic`, `federated`: optional existing fixtures implementing the same
  authenticated `/call-backend-raw?method=GET&path=/budget/read` envelope.
  A cloud function with a different invocation/auth contract is not compatible;
  leave its cases BLOCKED rather than route credentials to arbitrary APIs.

Each identity uses the same name as its endpoint/caller and contains:

```json
{
  "spiffe_id": "spiffe://your.test.domain/ests/bp/BLUEPRINT/aid/AGENT",
  "oid": "EXACT_AGENT_OBJECT_ID",
  "audience": "EXACT_EXPECTED_JWT_AUDIENCE",
  "token_env": "LIVE_REPORT_TO_APPROVAL_TOKEN",
  "invalid_token_env": "LIVE_INVALID_TARGET_TOKEN"
}
```

`oid` must equal the backend `entra_agent_id` and echoed JWT `oid`.
Audience comparisons are exact, not substring or alias matches. `token_env`
is an already legitimately acquired workload token for the A2A target audience;
the suite neither creates nor renews it. `invalid_token_env` is an explicitly
provided negative token fixture used only against the target JWT guard.
Missing/expired valid credentials must be corrected through the normal
authentication flow. Never copy token values into JSON or report artifacts.

Every A2A negative case requires an explicit healthy control for its target.
For example, `"a2a_controls": {"budget-approval": "budget-report"}` reuses the
configured report identity and `token_env` for a fresh allowed request to the
approval target. Add mappings for `budget-report` and `employee-menus` only when
legitimate allowed fixtures for those targets exist. A control fixture needs
the same identity fields above and a supplied `token_env` valid for that exact
target. It does not need an endpoint of its own: requests always use the
negative case's target endpoint, never the identity fixture name as a URL.
Use separately named identity fixtures when different targets require different
tokens for the same caller. Tag-deny probes retain their original caller's
`token_env`; their control must use an identity whose tags actually allow access
to that target. Do not substitute a token for another audience, an arbitrary
endpoint or an unauthenticated health check.

## Matrix and evidence boundaries

The inventory is a bounded 29-case matrix. Every selected descriptor appears
in the results with `status`, sanitized `observed`, numeric
`duration_seconds`, and optional safe `evidence`. Descriptors contain `id`,
`suite: "live"`, `layer`, `profiles: ["live"]`, `description`, `expected`,
and boolean `mutation`. Evidence contains only fixed source labels, HTTP
status, boolean identity/JWT/tag checks, audit correlation and cleanup flags;
no tokens, identity values, URLs, response bodies or exception messages.

- Seeded report/approval read calls prove transport and RBAC allowance through
  the exact configured SPIFFE identity echoed by the backend.
- Identity cases additionally compare Entra OID and audience. Echoed token
  claims are **not** proof of signature validation.
- OAuth-valid cases require before/after sidecar audit snapshots and exactly
  one new matching caller/method/path entry with `jwt_present`, `jwt_valid`,
  expected audience, `oauth` layer and allow decision. The event's RFC3339
  timestamp must fall between the current caller request's start and completion.
  Both audit snapshots must retain at least one identical full anchor entry
  predating that window; changed shared entries, duplicate IDs, empty or
  disjoint snapshots cannot establish continuity of the sidecar's in-memory
  audit source and are BLOCKED. There is no invented replica-ID telemetry.
  Explicit exclusive observation is still required because successful caller
  responses do not carry a request ID. Clocks must be synchronized; stale,
  future-dated, malformed, ambiguous or unavailable audit evidence cannot pass.
- A read-only `GET /budget/submit` probe checks report wrong-method RBAC denial.
  Before the negative request, it requires a fresh full-identity
  `GET /budget/read` control through the same configured budget-report raw
  caller, backend and sidecar stack, with the OAuth-valid audit checks above.
  Thus `exclusive_observation`, management audit access and an authenticated
  report fixture are prerequisites even if another matrix read row passed.
  The allowed read path is necessary because the report's `GET /budget/submit`
  is deliberately forbidden; no business POST is used as a control.
  The negative requires 403 `forbidden` and exact response/audit request-ID
  correlation with caller, path, method, deny decision and `rbac` layer.
- Seeded report-deny/approval-allow **POST submit** descriptors remain BLOCKED:
  the real API has no snapshot/delete/rollback contract. Even a nominal denial
  test might execute business work if authorization regresses. This adapter
  deliberately does not assume the sample's current synthetic storage behavior.
- Employee-menus transport rejection remains FAIL for outages or unexpected
  allowance, otherwise BLOCKED until the caller exposes explicit transport
  authorization evidence. `http_status=0`, 502, timeouts, TLS errors or generic
  403s are never passing mTLS-denial evidence. Use real transport protocol
  coverage for the missing transport telemetry boundary.
- A2A cases call `/a2a/status` **directly**, not the unauthenticated
  `/call-agent`, `/call-approval` or `/call-backend` invocation handlers.
  Every missing-token, invalid-token and tag-deny case first executes a healthy
  authenticated control on the **same target and exact GET `/a2a/status` path**.
  The control must return 200 `ok`, validated JWT for the mapped fixture's exact
  OID and nonempty matching tags; a 401/403, generic health response or another
  target's success cannot satisfy it. Controls run anew in each case before
  its negative probe; earlier allowance rows are not cached or prerequisites
  supplied by the runner. Missing control mappings, identities or supplied
  credentials yield BLOCKED without requests. A configured control's failed
  response or network exchange yields FAIL and prevents the negative request.
  Missing negative credentials likewise block before control dispatch.
  Anonymous missing-token probes then stop at the JWT guard before privileged
  downstream work; they are not independently passing unauthenticated guards.
  Negative-token probes require exact `invalid_token`/`jwt` responses.
  Successful negative rows include `healthy_control_verified: true` in safe
  evidence. Allowed A2A requires target JWT validation, matching configured
  OID, a claimed tag match, and nonempty string `caller_tag`/`target_tag` values
  in the enforcement object that actually match case-insensitively. Empty or
  whitespace-only tags never prove allowance. Tag-deny cases require JWT
  validation, matching OID and string tags containing non-whitespace content
  that differ case-insensitively. Missing, null, non-string, empty or
  whitespace-only tags are not proof of policy enforcement. Presence checks
  do not trim tags for comparison; the backend compares their lowercase values.
- Dynamic/federated descriptors use the same transport/identity/JWT evidence
  against **already existing** compatible fixtures. They do not establish
  provider-specific token exchange, federation setup or provisioning.

Host unavailability produces FAIL, never denied PASS. Missing fixtures,
permissions or safely testable API contracts produce BLOCKED with a requirement.
The `test_live.py` unit tests mock HTTP only to test the harness itself; none of
their results are evidence of deployed enforcement.

## Optional reversible local sidecar exercises

Do not enable these merely to make a report green. They require separate
authorization for a dedicated test environment and specific SPIFFE identities.

```json
{
  "enabled": true,
  "environment": "dedicated-test",
  "marker_env": "LIVE_DEDICATED_ENVIRONMENT",
  "scope_ids": ["spiffe://your.test.domain/ests/bp/BLUEPRINT/aid/AGENT"],
  "exclusive": true
}
```

The named marker environment variable must equal `dedicated-test`.
The scope must contain the exact configured `budget-report.spiffe_id`.
The sidecar endpoint must be loopback and expose the native in-memory risk/tag
API; writes are never sent to portal or tenant APIs.

Preconditions: an existing explicit risk/tag entry, exclusive fixture ownership
with no concurrent tests/Graph tag sync overwriting the fixture, and a successful
baseline full-identity read. Absent entries are BLOCKED: the API cannot remove
an entry to restore absence.

Each test snapshots the entire store in memory, writes **only** its scoped
entry (`high` risk or a mismatching tag), reads it back, checks the explicit
CA-layer denial for that identity, and uses `try/finally` to restore the
original scoped value even if the mutation request times out. Cleanup reads
back and compares the **entire** snapshot. A restored allowed read is required
for PASS. Cleanup failure or concurrent store drift produces FAIL, overriding
any earlier success. Unrelated entries are never overwritten to conceal drift.

If the original mutation times out or is not acknowledged with HTTP 200,
restoration is still attempted, but `cleanup_verified` remains false and the
case requires operator recovery. A server-side write can finish after both
restoration and its readback; a matching snapshot alone cannot prove cleanup
in this case. Recover the dedicated fixture through its approved operational
procedure before retrying.

Risk/tag writes here affect only the local sidecar store, not Entra risk,
Graph tags or token caches. No Graph `confirmSafe` operation exists in this
adapter. If the live policy does not block these local signals, the case fails
rather than editing tenant policies to force a result.

Forced process termination/power loss cannot guarantee remote cleanup. The
parent runner must allow enough time (up to eight bounded requests per mutation)
and treat interrupted cleanup as incomplete. Snapshots are intentionally not
persisted because they contain identities. In an interruption, restore the
dedicated fixture through its approved operational recovery procedure before
retrying.
