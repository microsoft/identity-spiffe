"""Human-assisted sign-in; never enter credentials or automate MFA."""
import argparse
import json
import os
from pathlib import Path
from queue import SimpleQueue
import sys
import threading
import time
from urllib.parse import urlsplit

from browser_guards import OBSERVATIONS, validate_debug_environment, validate_session, write_private_json


def wait_for_sign_in(page, origin, portal, timeout_seconds=900):
    token = "_accessToken" if portal == "management" else "_securityPortalToken"
    page.wait_for_function(
        """args => location.origin === args.origin &&
            typeof window[args.token] === 'string' && window[args.token].length > 0""",
        arg={"origin": origin, "token": token}, polling=100, timeout=timeout_seconds * 1000)


def wait_for_human(page, timeout_seconds=900):
    outcome = SimpleQueue()
    deadline = time.monotonic() + timeout_seconds

    def confirm():
        try:
            input("After the portal returns (or shows Access Denied for unassigned), press Enter here: ")
        except (EOFError, OSError, ValueError, KeyboardInterrupt) as exc:
            outcome.put(exc)
        else:
            outcome.put(None)

    # Only stdin runs off-thread; all Playwright/CDP work stays on its owning
    # thread so intercepted login requests continue while the human completes MFA.
    reader = threading.Thread(target=confirm, name="browser-human-confirmation", daemon=True)
    reader.start()
    while outcome.empty():
        if time.monotonic() >= deadline:
            raise TimeoutError("Human confirmation deadline exceeded")
        page.wait_for_timeout(100)
    error = outcome.get()
    reader.join()
    if error is not None:
        raise error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--portal", choices=("management", "security"), required=True)
    parser.add_argument("--role", choices=("admin", "viewer", "unassigned"), required=True)
    parser.add_argument("--lifetime-seconds", type=int, default=14400)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--auto-capture", action="store_true",
                        help="Validate and save automatically after human browser sign-in")
    parser.add_argument("--status-output", type=Path, help="Private status report; never contains tokens")
    args = parser.parse_args(argv)
    if not 60 <= args.lifetime_seconds <= 86400:
        parser.error("--lifetime-seconds must be between 60 and 86400")
    if not 60 <= args.timeout_seconds <= 3600:
        parser.error("--timeout-seconds must be between 60 and 3600")
    if not args.auto_capture and not sys.stdin.isatty():
        print("BLOCKED: interactive terminal and human MFA completion required.")
        return 2
    try:
        validate_debug_environment(os.environ)
    except ValueError:
        print("BLOCKED: " + OBSERVATIONS["unsafe_debug"])
        return 2
    try:
        from browser_engine import AUTH_DIR, CaseProblem, assert_access, route_boundary, target_config
        from playwright.sync_api import Error as PlaywrightError, sync_playwright
    except ImportError:
        print("BLOCKED: browser dependencies unavailable.")
        return 2
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        _, origin = target_config(config.get("browser", {}), args.portal)
    except (OSError, ValueError, AttributeError, CaseProblem):
        print("BLOCKED: explicit browser target configuration required.")
        return 2
    status_path = args.status_output or (
        Path(__file__).resolve().parent / "artifacts" / f"capture-{args.portal}-{args.role}-{os.getpid()}.json")
    path = AUTH_DIR / f"{args.portal}-{args.role}.json"
    try:
        for protected in (args.config, path):
            if status_path.resolve() == protected.resolve() or (
                    status_path.exists() and protected.exists() and status_path.samefile(protected)):
                raise ValueError("capture status aliases a protected file")
    except (OSError, ValueError):
        print("BLOCKED: status output must be distinct from the configuration and session files.")
        return 2
    blocked_details = []
    stage = "opening_browser"

    def status(state, reason=""):
        write_private_json(status_path, {
            "status": state, "stage": stage, "reason": reason,
            "blocked_requests": list(blocked_details),
        })

    def on_block(detail):
        if detail not in blocked_details and len(blocked_details) < 32:
            blocked_details.append(detail)
            status("RUNNING")

    status("RUNNING")
    print("DO NOT CLOSE THIS TERMINAL while authentication or tests are running.", flush=True)
    print("Closing it can stop authentication before your session is saved. "
          "Wait for 'Captured private' and command completion.", flush=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=False)
            try:
                with browser.new_context(service_workers="block", accept_downloads=False) as context:
                    page = context.new_page()
                    blocked = route_boundary(context, origin, args.role, False,
                                             human_login=True, on_block=on_block)
                    page.goto(origin + "/", wait_until="domcontentloaded")
                    print("Use the normal portal Sign in button. Complete sign-in, consent and MFA yourself.")
                    print("Use the designated account for the selected role. No credentials are read from your shell.")
                    stage = "awaiting_browser_sign_in"
                    status("RUNNING")
                    if args.auto_capture:
                        print("Capture is automatic after browser sign-in. No terminal Enter is required.")
                        wait_for_sign_in(page, origin, args.portal, args.timeout_seconds)
                    else:
                        wait_for_human(page, args.timeout_seconds)
                    if page.url.split("#", 1)[0].rstrip("/") != origin:
                        raise CaseProblem("BLOCKED", "session_rejected")
                    stage = "validating_server_role"
                    status("RUNNING")
                    assert_access(page, args.portal, args.role, live=True)
                    stage = "checking_network_boundary"
                    status("RUNNING")
                    if blocked:
                        raise CaseProblem("FAIL", "assertion_failed")
                    stage = "saving_private_session"
                    status("RUNNING")
                    state = context.storage_state()
                    state["origins"] = [o for o in state["origins"] if o["origin"] == origin]
                    state["cookies"] = [c for c in state["cookies"]
                                        if c["domain"] == urlsplit(origin).hostname]
                    session_storage = page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
                    now = time.time()
                    session = {
                        "version": 1, "origin": origin, "portal": args.portal, "role": args.role,
                        "created_at": now, "expires_at": now + args.lifetime_seconds,
                        "storage_state": state, "session_storage": session_storage,
                    }
                    validate_session(session, portal=args.portal, role=args.role, origin=origin)
                    if AUTH_DIR.is_symlink():
                        raise ValueError("symlink auth directory")
                    AUTH_DIR.mkdir(mode=0o700, exist_ok=True)
                    os.chmod(AUTH_DIR, 0o700)
                    write_private_json(path, session)
                    status("CAPTURED")
                    print(f"Captured private {args.portal}/{args.role} session in tests/browser/.auth/.")
                    print("Session expires by the configured lifetime; server acceptance is checked on every run.")
            finally:
                browser.close()
    except CaseProblem as exc:
        status(exc.status, exc.code)
        print(f"{exc.status}: {OBSERVATIONS[exc.code]}")
        return 1 if exc.status == "FAIL" else 2
    except AssertionError:
        status("FAIL", "assertion_failed")
        print("FAIL: " + OBSERVATIONS["assertion_failed"])
        return 1
    except TimeoutError:
        status("BLOCKED", "confirmation_timeout")
        print("BLOCKED: human sign-in confirmation timed out; no session captured.")
        return 2
    except (OSError, ValueError, EOFError, PlaywrightError):
        status("BLOCKED", "capture_failed")
        print("BLOCKED: sign-in/capture did not complete safely; no diagnostic credentials were retained.")
        return 2
    except KeyboardInterrupt:
        status("BLOCKED", "cancelled")
        print("BLOCKED: human-assisted sign-in cancelled.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
