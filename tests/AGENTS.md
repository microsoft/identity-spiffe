# Instructions for test-running agents

Read [README.md](README.md) and the relevant suite README before running tests.
This file is the operational contract for an LLM asked to validate a change.

## Mandatory sequence

1. Identify the changed components and requested profile. Inventory with
   `python3 tests/run.py --list`; choose suites deliberately.
2. Check prerequisites without dumping credentials, browser state, or `.azure`
   configuration. Do not read other agents' recovery/session artifacts.
3. Run harness self-tests when changing the harness. Run local browser/protocol
   and connected E2E coverage for relevant application behavior. After setup,
   `tests/.venv/bin/python tests/check.py --repeat 2` is the unattended local gate:
   no interactive sign-in, cloud credentials, dependency installation or deployment.
4. For live runs, require explicit target configuration. Explain prerequisites
   for legitimate human sign-in if session state is absent or expired. Before
   starting capture or a terminal-driven test, explicitly tell the user:
   **Do not close the terminal while authentication or tests are running.**
   Wait for confirmed session capture or final test reports and command completion;
   a signed-in browser page alone does not mean the session was saved.
5. Do not enable mutations unless the caller explicitly authorizes the
   dedicated test environment and mutation scope. Never enable them just
   because the nonmutating cases passed.
6. Execute the coordinator, preserve its exit status, and read `matrix.json`
   and `matrix.md`. Do not infer success from process completion or a UI banner.
7. Report the whole selected matrix plus unselected coverage counts. Include
   failed cleanup, known product defects, blocked prerequisites and untested
   layers. A failing security regression stays FAIL until the product is fixed.

## E2E-first development contract

- Do not fix product failures merely because the harness exposes them. The current
  authorization is to build and validate the test system, not repair production.
- The basic browser suite uses mocked workload responses. It is not sufficient
  evidence for an enforcement change. Use the connected `e2e` suite to exercise
  the actual caller, egress client, ingress gateway and backend from Chromium.
- A healthy same-stack control must pass before a negative outcome counts.
  Match UI/API results to actual gateway audit and backend dispatch observations.
- Add the regression and record its failing result before an authorized product
  edit. Do not use expected failures, skips, rerun-until-green, or a changed
  expected result to hide a defect.
- Repeat local checks from fresh ephemeral processes. Report unstable outcomes
  rather than treating the last successful attempt as the result.
- Real Entra/MFA and SPIRE attestation still need explicit live fixtures. Local
  identity issuance is deliberately controlled, not evidence about cloud behavior.

## Completion message to the initiating human or LLM

Use this structure, populated from the report rather than estimates:

```text
Run: <run ID>, source commit <commit>, profile <local/live>
Executed suites: <names>; report: <absolute matrix.md and matrix.json paths>
PASS: <n>; FAIL: <n>; BLOCKED: <n>; SKIPPED: <n>; NOT_RUN: <n>

Failed/blocked cases:
<ID> | <expected> | <observed> | <next action>

Evidence scope:
<real browser / local actual enforcement code / live deployed services>
<which identity/control-plane boundaries were fixtures>

Mutations and cleanup:
<none, or exact scoped action and verified restoration outcome>

Not verified:
<live sign-in, other browsers, unsupported policy shapes, cloud lifecycle, etc.>

Verdict: <selected checks passed / product failure / blocked / incomplete>
```

Do not paste tokens, credentials, response bodies, session JSON, personal
account claims, or unreviewed browser traces into chat or CI artifacts. Keep
run artifacts private; only publish reviewed sanitized summaries with the
caller's permission.

## Important distinctions

- The browser authenticates the operator; SPIFFE authenticates the workload.
  Operator sign-in alone proves neither mTLS nor workload OAuth authorization.
- A fixture implementing a response is not proof that the corresponding remote
  platform behaves that way.
- The existing legacy live script clears sidecar and Graph risk; do not call it.
- A generic transport error is not a successful security rejection.
- A local auto-admin page must never satisfy a live-role assertion.
- Do not change production behavior or weaken assertions merely to green the
  harness. Follow root contributor guidance and regression-first development
  for separately authorized product fixes.
