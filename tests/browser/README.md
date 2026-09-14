# Browser harness

This suite owns only browser testing. Run from the repository root, preferably
through the [matrix coordinator](../README.md). It changes no production files.

## Evidence boundaries

The local profile launches **the existing FastAPI apps and existing HTML/JS** for
both [management](../../portal/) and [security](../../securityportal-mock/), then
uses real Chromium clicks, navigation, form entry and HTTP assertions. It does
not render a substitute UI or fulfill portal API routes with static JSON.

External boundaries are deliberately mocked:

- A small MSAL-shaped test double replaces the external MSAL CDN script locally.
  It supplies deterministic admin/viewer/unassigned identity claims. The backend
  JWT validator boundary supplies corresponding roles. The apps' auth middleware,
  role checks, routes, services and stores remain real.
- An `httpx.MockTransport` supplies admin-control-plane and workload responses.
  Unexpected outbound calls fail. Audit streaming has an explicit fixture stream.
- Local settings are constructed in memory; file stores use per-run temporary
  directories. Credential-free subprocess environments prevent cloud discovery,
  telemetry and accidental use of inherited credentials.
- Browser network access is restricted to the loopback app and local identity
  fixture. No local case is evidence of real Entra, Graph, SPIRE, mTLS, workload
  JWT, Azure availability, or production security policy.

Every passing row includes boolean evidence labels identifying these boundaries.
The actual UI still says "live" for execute results because the app has no demo
mode; **that UI wording is not the harness evidence classification**.

Live mode uses only explicitly configured HTTPS portal origins and private
human-captured sessions. It neither discovers deployed resources nor reads cloud
environment/recovery files. It does not stub MSAL, JWT validation, or portal APIs.

## Run

Dependencies are managed by the parent in [requirements.txt](../requirements.txt):
Python Playwright, Chromium, FastAPI, Uvicorn, HTTPX, PyJWT with crypto and PyYAML.
Use [the parent installation commands](../README.md); this suite never installs
packages automatically.

On shared machines, always use `PLAYWRIGHT_SKIP_BROWSER_GC=1` when installing
Chromium so Playwright does not remove browser revisions used by other projects:

```bash
PLAYWRIGHT_SKIP_BROWSER_GC=1 tests/.venv/bin/python -m playwright install chromium
```

Both portals currently embed their application CSS and JavaScript in the served
HTML. Their only external script is MSAL, replaced by the identity fixture in the
local profile; application navigation and rendering still execute the original
inline scripts. Local runs do not validate the real MSAL CDN or Entra sign-in.

```bash
# No third-party packages, browser imports, or network:
python3 -S tests/browser/run.py --list

# Dependency-free session/report/safety self-tests:
python3 -m unittest discover -s tests/browser -p 'test_*.py'

# Separate real-Chromium redirect containment and backend-role regressions:
tests/.venv/bin/python -m unittest discover \
  -s tests/browser/regressions -p 'test_*.py'

# Actual local browser + backend:
tests/.venv/bin/python tests/browser/run.py \
  --profile local --output tests/browser/artifacts/local.json

# Live without config accurately reports all selected cases BLOCKED:
tests/.venv/bin/python tests/browser/run.py \
  --profile live --output tests/browser/artifacts/live-missing.json

tests/.venv/bin/python tests/browser/run.py --profile live \
  --config tests/config.local.json --output tests/browser/artifacts/live.json
```

The adapter writes `{"cases":[...]}` at `--output`; the parent chooses report
paths. Output contains only descriptors, statuses, fixed allowlisted messages,
durations and safe scalar evidence. Exit codes: `0` all PASS, `1` any FAIL,
`2` any BLOCKED/SKIPPED and no FAIL. There is no success-shaped fallback for a
missing session, dependency, browser, target or assertion.

Chromium regressions explicitly skip when runtime dependencies or the matching
browser are unavailable; a skip is not verification. The adapter independently
reports missing prerequisites as BLOCKED.

The network boundary attaches Chromium DevTools request interception to the
blank page **before navigation**. Unlike Playwright `route.continue_`, it
revalidates every redirect hop before dispatch, including redirected POST
payloads. Browser API probes also use `redirect: 'error'`; the startup HTTP
client disables redirects. This keeps streaming responses usable without
buffering entire responses to inspect them. The harness uses one page per
context and does not use Playwright's separate APIRequestContext for probes.
A context-level pre-dispatch gate denies popup, iframe, and unattributed
requests before their first network dispatch; these child targets cannot escape
the page-scoped Chromium interceptor. Only the owned top-level page is supported.

## Configuration

Only the top-level `browser` object belongs to this suite. Example (replace
example origins with your explicitly selected nonproduction targets):

```json
{
  "browser": {
    "management": {
      "url": "https://management.example.test",
      "sessions": {
        "admin": "tests/browser/.auth/management-admin.json",
        "viewer": "tests/browser/.auth/management-viewer.json",
        "unassigned": "tests/browser/.auth/management-unassigned.json"
      },
      "execute_read": {
        "enabled": false,
        "dedicated_test_environment": false,
        "caller_key": "budget-report",
        "caller_name": "BudgetReport"
      }
    },
    "security": {
      "url": "https://security.example.test",
      "sessions": {
        "admin": "tests/browser/.auth/security-admin.json",
        "viewer": "tests/browser/.auth/security-viewer.json",
        "unassigned": "tests/browser/.auth/security-unassigned.json"
      }
    }
  }
}
```

Origins must be HTTPS, without credentials, paths, queries, fragments or loopback
addresses. Sessions are resolved relative to the repository root (not the config
file) and must be under this suite's ignored `.auth/` directory. Absolute paths
inside that directory also work. An omitted portal blocks its cases. An omitted
role blocks only cases needing that session; anonymous uses a fresh empty context.
Local mode needs no configuration and ignores all live targets.

`execute_read` is conservative opt-in: **both** booleans must be true and both the
exact portal caller key and exact display name must be supplied. Only
`POST /api/execute` with `{caller: caller_key, method: "GET",
path: "/budget/read"}` can pass the browser's write guard. Selecting another
caller, method, endpoint or additional payload fields fails closed. Even a read
can cause audit traffic and token acquisition: authorize a designated test agent
and test environment before enabling this case.

## Human-assisted auth setup (MFA stays human)

Run from an interactive local terminal with a graphical desktop:

**DO NOT CLOSE THE TERMINAL while authentication or tests are running.**
Closing it can stop authentication or the test process before the session or
reports are saved. A signed-in browser page is not completion: wait for
`Captured private ...` and command completion, or for the test summary and
report paths when running the matrix.

```bash
tests/.venv/bin/python tests/browser/auth_setup.py \
  --config tests/config.local.json --portal management --role admin --auto-capture
```

Repeat separately for `viewer` and `unassigned`, then repeat for `--portal
security`. Use designated test accounts whose real group assignments correspond
to the requested role. The unassigned account signs in legitimately but must see
Access Denied and receive HTTP 403 from the protected read endpoint.

The helper does not select an authentication method or require a passkey.
For password sign-in, use Microsoft's normal email/username screen; select
**Back** from the alternative "Sign-in options" menu if necessary. Available
password, passkey, and MFA methods are controlled by the account and tenant policy.

1. A fresh headed Chromium opens the configured portal, not an existing browser
   profile. Click the normal Sign in button.
2. **You** enter credentials, complete MFA and any consent. The harness never
   supplies passwords, manufactures live tokens, clicks through MFA, or weakens
   authentication.
3. With `--auto-capture`, the helper detects the portal token after the browser
   returns, validates the real server role, and saves automatically. No terminal
   Enter is required. Without this flag, press Enter after returning; terminal
   confirmation runs separately while Chromium events continue.
   Both modes have a 15-minute deadline (`--timeout-seconds 60..3600`).
4. Capture verifies `auth_required=true`, a configured client ID, the real role
   shown by the app, and protected API authorization. A local auto-admin page
   cannot satisfy capture or live testing. Viewers must also receive 403 on a
   deliberately invalid, non-actionable write probe.
   Admins must instead receive 400/422 on the same schema-invalid probe,
   proving backend admin authorization independently of frontend group claims.
   The probes are exactly POST `/api/execute` with `{}` or PUT `/set-risk`
   with `{}` and no query parameters. Required handler inputs are absent,
   preventing actual execution or risk mutation.
5. The suite saves `.auth/<portal>-<role>.json` with mode `0600`, in a `0700`
   directory. Failure does not claim a valid capture.

A separate private status report records the capture stage and any blocked
hostnames/reasons, never URL queries, fragments, credentials, or tokens. Use
`--status-output PATH` for a known report path; the default is a process-specific
file under `artifacts/`. Browser sign-in alone is not proof the capture succeeded:
the report must say `CAPTURED` and the session must pass subsequent server checks.
The status path must not alias the input configuration or the session destination,
even through normalized paths or hard links. Collisions are blocked before any
status write or browser launch, preserving existing files.

Human sign-in uses normal Chromium redirects, with every hop restricted to the
configured portal plus the explicit HTTPS origins `login.microsoftonline.com`,
`login.microsoft.com` (the passkey/FIDO bridge observed during interactive sign-in),
`login.live.com`, `browser.events.data.microsoft.com`,
`alcdn.msauth.net`, `aadcdn.msauth.net`, `aadcdn.msftauth.net`,
`logincdn.msauth.net`, `aadcdn.msauthimages.net`, and
`aadcdn.msftauthimages.net`. These identity-provider origins permit the human
authentication exchanges; portal writes remain restricted to the empty
authorization probes. Other identity-provider domains or custom federation
are not supported by this allowlist and cannot silently become a valid capture.
An unexpected blocked request fails capture. Real MFA/sign-in against these
origins has not been verified by the local fixtures.
Microsoft lists `login.microsoft.com` as a
[sign-in endpoint](https://learn.microsoft.com/microsoft-365/copilot/add-copilot-endpoints-allowlist#sign-in).
It is allowed only during human capture, not added to ordinary test replay or
local fixture network access. Lookalike domains remain blocked.
The Microsoft account endpoint and the
[Microsoft monitoring endpoint](https://learn.microsoft.com/industry/healthcare/dragon-copilot/installation/allow-list-urls#list-all-urls-explicitly)
were also observed during the production sign-in flow and are restricted to
human capture. This is an explicit origin list, not a Microsoft-domain wildcard.
Top-level `loginRedirect`/`acquireTokenRedirect` navigation is supported.
Popup authentication, iframe-based silent renewal, and identity-provider
challenges requiring embedded frames are intentionally unsupported and fail
closed; they must not be worked around by disabling the network boundary.

Both apps cache MSAL in **sessionStorage**, which Playwright `storage_state`
does not include. Capture therefore saves sessionStorage alongside same-origin
cookies/localStorage; replay restores sessionStorage before the app starts,
once per context so subsequent token refreshes are not overwritten.
Identity-provider cookies and cross-origin storage are excluded.

The private envelope is bound to the exact portal, origin and role. It expires
after four hours by default (`--lifetime-seconds 60..86400` can adjust it).
This is a harness maximum reuse window, **not a claim about token validity**.
Each case rechecks server acceptance. Missing/expired/rejected sessions are
BLOCKED and need legitimate recapture; mismatched authorization behavior is FAIL.
Symlinks, cross-origin state, permissive file modes and malformed envelopes are
rejected.

Session files contain credentials. Do not print, attach, commit or publish them.
Keep them only on a trusted machine, remove individual files when finished and
recapture after account/group changes. Do not enable Playwright API debugging or
driver protocol logging while handling sessions. Nonempty `DEBUG`, `PWDEBUG`,
`DEBUG_FILE`, or `NODE_OPTIONS` variables block browser execution/capture before
the driver starts, to prevent inherited debugging from leaking state.

## Coverage and mutation safety

The executable inventory currently contains 16 stable IDs (15 local, 13 live):

- Both portals: anonymous splash + HTTP 401; admin/viewer/unassigned role and
  protected read behavior. Viewer invalid write probes must produce HTTP 403
  (not merely 400/422).
- Management admin/viewer: all seven sidebar tabs, policy editor content, empty
  execute form, network-access input without submitting, logs filter,
  agent detail navigation and browser Back. Each tab's backing read API must
  return 200; an empty/error fallback is not sufficient.
- Security admin/viewer: populated agent cards, risk selector without Apply,
  and isolate/restore confirmation **Cancel**, never confirmation submission.
- Local management: execute-read ALLOWED and explicit fixture RBAC DENY, using
  the actual form, API and response rendering.
- Local management: save/delete a unique `browser-<run suffix>` policy config
  through the UI and real file store, then verify absence via the API. This does
  not push policy to a sidecar. Temporary stores are removed when servers stop.
- Live management: opt-in, exactly scoped read execution described above.

The browser write interceptor denies every other application write. Viewer
probes send `{}` without query parameters, which remains non-actionable even if
server authorization regresses. Local saved-config writes are restricted to
the unique generated name. Unexpected writes fail the case rather than being
silently ignored. Live risk changes, isolation, policy pushes, token flushing,
tenant-wide actions and Graph risk clearing are **not implemented or attempted**.

There are no blanket screenshots, traces, videos, HARs, console capture, token
dumps, header dumps or response-body artifacts. Error messages intentionally
omit raw exception text. Reports are private by default and contain no credential
state. Local diagnostic artifacts are ignored. The adapter owns and terminates
only its own local server processes.

## Limits

Only Chromium is exercised. There is no mobile, cross-browser, accessibility,
tenant lifecycle, deployment, real MFA policy evaluation or real workload
cryptographic proof in a local PASS. Live sign-in is only verified after a human
has captured valid sessions for the explicitly selected targets. Unsupported
identity hosts, stale app markup, absent test agents, cloud failures or rejected
sessions remain failures/blocked prerequisites rather than being replaced with
fixtures.
