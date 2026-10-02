# Browser and enforcement test harness

This directory is the entry point for humans, Copilot, Claude Code, Codex, and CI.
The harness runs real browser interactions and real enforcement code, and can
exercise an explicitly configured deployed environment. It does not provision
Azure resources or discover credentials from a developer's cloud environment.

## Start here

Run commands from the repository root on macOS or Linux (including Linux under
WSL). The local process supervisor requires POSIX process groups, `ps`, and file
locks. Python 3.14 is the tested harness runtime. Go must satisfy the version in
the proxy's `go.mod`.

```bash
python3.14 -m venv tests/.venv
tests/.venv/bin/python -m pip install --require-hashes -r tests/requirements.lock
PLAYWRIGHT_SKIP_BROWSER_GC=1 tests/.venv/bin/python -m playwright install chromium

# Install protoc with your OS package manager first (protobuf on Homebrew,
# protobuf-compiler on Ubuntu), then prefill the offline protocol prerequisites:
GOBIN="$PWD/tests/.tools/bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
GOBIN="$PWD/tests/.tools/bin" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
export PATH="$PWD/tests/.tools/bin:$PATH"
go -C src/spiffe-proxy mod download

# Inventory all cases, without dependencies, sign-in, or network access:
python3 tests/run.py --list

# Run the local browser, protocol and connected E2E suites; no Azure credentials required:
tests/.venv/bin/python tests/run.py --profile local

# Run one suite. All other cases remain visible as NOT_RUN:
tests/.venv/bin/python tests/run.py --profile local --suite browser
tests/.venv/bin/python tests/run.py --profile local --suite protocols
tests/.venv/bin/python tests/run.py --profile local --suite e2e
```

An existing virtual environment can be reused instead of recreating it. `uv pip
install --python tests/.venv/bin/python --require-hashes -r
tests/requirements.lock` is an alternative installer. Keep browser garbage
collection disabled on shared developer machines so installing a new revision
does not remove another project's browser.

The dependency lock is for this isolated test runtime, not a replacement for
production dependency manifests. If a registry download fails, resolve the
network problem rather than disabling TLS verification or removing package
hash verification.

## What each suite proves

| Suite | Evidence | Not established by a local pass |
|---|---|---|
| [Browser](browser/README.md) | Actual portal frontend/backend interactions in Chromium; live authenticated role checks when configured | Real Entra sign-in, tenant CA, or deployed enforcement from local fixtures |
| [Protocols](protocols/README.md) | Actual Go transport/authorization implementations with controlled certificate, JWT and policy inputs | Azure provisioning, SPIRE server recovery, or the complete deployed topology |
| [Connected E2E](e2e/README.md) | Chromium -> real portal -> real caller -> real Go egress/ingress -> real backend, with actual audit/dispatch checks and cross-portal risk changes | Real Entra/SPIRE issuance, attestation, cloud topology or tenant risk |
| [Live](live/README.md) | Explicit configured workload calls and approved reversible governance exercises against a running environment | Unconfigured platforms, unsupported policy semantics, or unexecuted lifecycle scenarios |

The executable inventory is the source of truth for case IDs, dimensions,
expected results, profile selection, and mutation classification:

```bash
python3 tests/run.py --list
```

This is a bounded, extensible matrix, not a claim that every possible Entra
policy, browser, cloud, or failure combination has been tested. Keep external
platform behavior separate from simulated fixtures and unit-test outcomes.

## Unattended agent workflow

After the setup above, an agent can run local verification without your presence:

```bash
tests/.venv/bin/python tests/check.py --repeat 2
```

This runs the harness's own tests and repeats the complete local matrix in fresh
ephemeral environments. It does not run the live profile, prompt for sign-in,
install dependencies, deploy, or repair product code. Use its private summary
alongside each full matrix to distinguish a stable product failure from a flaky
or incomplete test environment. Repeated failures are still failures, not a
passing baseline.

Each invocation produces `check.md` and `check.json`, structured self-test
reports, and the complete per-run JSON/Markdown/JUnit matrices. Report timestamps,
distinct run IDs, source commit and source fingerprints are checked; stale
reports or source edits during verification cannot establish readiness. Let
implementation agents finish editing before running the gate.

For `check.py --output PATH`, choose a new directory outside the checkout or a
Git-ignored directory such as `tests/artifacts/my-check`. Unignored in-checkout
output is rejected before any commands run: generated reports would change the
whole-worktree provenance, and the gate does not exclude arbitrary output trees
from source verification. Ignored destinations containing tracked files are
also rejected, even when those files have been deleted locally. Existing
directories and symlink paths remain invalid.

Commands register their process groups before execution, including nested Go
tools. Cleanup can therefore find descendants even after their parent exits.
Pre-registration scopes are explicitly marked under the shared registry lock.
An interrupted or invalid child registration does not block termination of
independently verified groups: cleanup closes the ancestor, stops those groups,
then reports the incomplete/unsafe state and retains its ownership evidence.
Missing or stale ownership never authorizes signalling an unverified group.
Private process registries are retained only if cleanup cannot be verified;
that is a failed run requiring attention, not permission to delete arbitrary
processes or directories.

For TDD, first add a discriminating E2E scenario and observe it fail for the
intended behavior. Prove that the healthy control succeeds and that the observed
failure is not a network outage, missing session, or fixture problem. Product
changes require separate authorization; this harness's construction does not
authorize fixing the defects it exposes. After an authorized fix, run the
targeted scenario, the connected matrix, and the unattended gate.

## Live environment and sign-in

Use a dedicated nonproduction environment and designated test accounts. Start
with `tests/config.example.json`, copy it to the ignored
`tests/config.local.json`, and follow the suite-specific configuration guides.
Credentials are supplied through explicitly named environment variables or
private browser session files, never committed JSON values.

```bash
tests/.venv/bin/python tests/run.py --profile live --config tests/config.local.json
```

Without configuration the same command produces BLOCKED results and exit code
2. Missing accounts, sessions, permissions, licensing, endpoints, or tools must
remain visible; they must never become passing tests.

Browser setup uses interactive sign-in for each configured role. A human
completes MFA/consent through the normal identity-provider UI. The harness
preserves the app's MSAL session storage as well as browser storage: copying
cookies alone is not a reliable authenticated fixture. See the
[browser authentication commands](browser/README.md).

Never manufacture a cloud-role token, disable portal authentication, bypass
MFA, or substitute local auto-admin mode to get a live test to pass. An expired
or mismatched session requires a new legitimate sign-in.

## Safety contract

- Default live execution does not reset risk or change policy. Workload calls
  still require designated test resources; a synthetic POST in this sample
  must not be assumed harmless in a customized deployment.
- Mutating cases require explicit opt-in and dedicated-environment configuration.
  Read the live suite's exact target and permission requirements first.
- Preserve original state before a mutation, restore it in cleanup, and verify
  restoration. A failed restore fails the run and requires operator attention.
- Never call Graph `confirmSafe` as test preparation or cleanup: clearing a
  real security decision is not a reversible cache flush.
- Do not invoke `scripts/test_agents.py` from this harness. That legacy script
  resets risk even for selected transport tests and uses looser denial checks.
- A timeout, DNS failure, unhealthy service, wrong HTTP layer, or arbitrary
  server error is not proof of an authorization denial.
- No automatic credential enumeration, provisioning, reattestation, restart,
  deployment, or tenant-wide policy changes.
- Browser storage and per-run artifacts are ignored and private. Do not publish
  them wholesale. HARs, traces and screenshots can contain tokens and personal
  information; they are not enabled as blanket live artifacts.
- The runner applies a per-suite timeout. Forced interruption cannot guarantee
  remote cleanup completed: inspect the reported outcome and recover the test
  fixture before retrying any mutating test.

## Reports and exit codes

Each run creates a new private `tests/artifacts/<UTC timestamp>-<run ID>/`:

| File | Audience |
|---|---|
| `matrix.md` | Human or initiating LLM: complete case table, expected/observed outcomes |
| `matrix.json` | Automation: schema version, run metadata, counts, stable IDs and evidence |
| `junit.xml` | CI test result integrations |
| `<suite>.json` | Suite-specific sanitized results for diagnosis |

Use `--output PATH` to choose a **new** directory. Existing directories are
rejected to avoid overwriting a prior run or confusing old results with fresh
evidence. Use `--timeout SECONDS` to adjust the per-suite timeout.

| Status | Meaning |
|---|---|
| PASS | This case executed and satisfied its stated assertions |
| FAIL | Wrong observed behavior, harness failure, missing result, or failed cleanup |
| BLOCKED | Required environment, authentication, tool, or permission unavailable |
| SKIPPED | Selected case intentionally not exercised; does not count as a pass |
| NOT_RUN | Case is outside the selected profile/suite |

Exit **0** means every selected case passed. Exit **1** means a failure occurred.
Exit **2** means the run is blocked/incomplete, invalid, or selects no cases.
NOT_RUN cases outside the selection do not fail a successful selected run, but
remain in the report. JUnit marks blocked/unexecuted cases as skipped; consumers
must also check the command exit code and JSON summary.

**A successful local run is not a successful live run.** The report always shows
the selected profile and all inventory cases, including those not run.

### Initial security regression baseline

The initial local baseline exposed six product defects across ten failing
protocol and connected E2E rows: expiration-less
JWT acceptance, an initial policy-control-plane outage allowing access, missing
risk treated as low risk, absent Graph tags falling back to YAML, and two HTTP
request-framing bypasses. See the
[exact case IDs and evidence boundaries](protocols/README.md#result-contract-and-known-product-failures).
Production fixes are separately authorized; current outcomes come from fresh
reports, not this historical baseline. The regression gate requires every
selected assertion and harness self-test to pass. Any unresolved failure remains
a normal FAIL result, never an expected failure or skip. A red security regression
is useful evidence, not a reason to loosen the test.

## Harness self-tests

These verify the test machinery, not application security:

```bash
tests/.venv/bin/python -m unittest discover -s tests -p 'test_runner.py' -v
tests/.venv/bin/python -m unittest discover -s tests -p 'test_check.py' -v
tests/.venv/bin/python -m unittest discover -s tests -p 'test_processes.py' -v
tests/.venv/bin/python -m unittest discover -s tests/browser -p 'test_*.py' -v
tests/.venv/bin/python -m unittest discover -s tests/browser/regressions -p 'test_*.py' -v
tests/.venv/bin/python -m unittest discover -s tests/protocols -p 'test_*.py' -v
tests/.venv/bin/python -m unittest discover -s tests/live -p 'test_*.py' -v
tests/.venv/bin/python -m unittest discover -s tests/stack -p 'test_*.py' -v
tests/.venv/bin/python -m unittest discover -s tests/e2e -p 'test_*.py' -v
```

Existing production component tests remain in place. This harness supplements
them rather than moving or deleting them.

The browser regression group launches Chromium and local servers; the protocol
fixture regression requires the prepared Go/protobuf tools and module cache.
Run these after setup, as CI does. A missing-prerequisite skip is not evidence
that the affected harness safeguard was verified.

## Extending the matrix

Every suite implements the adapter contract:

1. `run.py --list` emits dependency-free JSON case descriptors.
2. `run.py --profile local|live --config PATH --output PATH` executes the selected
   profile and reports every applicable descriptor exactly once.
3. Descriptors contain `id`, `suite`, `layer`, `profiles`, `description`,
   `expected`, and explicit boolean `mutation`.
4. Results add `status`, sanitized `observed`, finite nonnegative
   `duration_seconds`, and optional sanitized `evidence`.
5. Exit codes follow the contract above. Unknown/duplicate IDs, omitted cases,
   malformed results, and exit-code disagreements fail validation.

Use stable IDs and meaningful supported combinations. Add a negative test for
the harness assertion before adding a new helper. Test each enforcement layer
with previous layers passing, plus precedence cases where earlier layers deny.
Do not inflate the matrix with rows that have no executable implementation.

Complete deployment/recovery testing needs dedicated infrastructure orchestration
and fixtures beyond the local matrix. Additional browsers, licensed live Graph
policy outage experiments, and Google/GitHub lifecycle tests must be claimed only
when implemented and run. List these gaps explicitly when reporting readiness.
