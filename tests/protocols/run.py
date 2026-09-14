#!/usr/bin/env python3
"""Run the actual Go proxy packages in an isolated, offline local workspace."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
from processes import owned_process, ProcessCleanupError, ProcessLaunchError
TOOLS_BIN = HERE.parent / ".tools" / "bin"
MODULE = "github.com/microsoft/identity-spiffe/src/spiffe-proxy"
TEST_PACKAGE = MODULE + "/tests/protocols"

# Names correspond exactly to individual Go subtests, not aggregate package exits.
CATALOG = {
    "MTLS": {
        "allowed": "Trusted, allowlisted SVID completes mutual TLS",
        "disallowed": "Trusted but nonallowlisted SVID is rejected by the authorizer",
        "absent": "Missing client certificate is rejected",
        "untrusted": "Client SVID issued by an untrusted CA is rejected",
        "expired": "Expired client SVID is rejected",
        "no_uri": "Trusted certificate without a SPIFFE URI is rejected",
        "revoked": "Removing an identity prevents its next handshake",
    },
    "Enforcement": {
        "allowed": "Caller, method, route, signed JWT and roles allow access",
        "unknown_caller": "Unknown caller is denied at RBAC",
        "wrong_method": "Unpermitted method is denied at RBAC",
        "wrong_route": "Unpermitted route is denied at RBAC",
        "normalized_deny": "Encoded and dot-segment paths cannot bypass a deny rule",
        "prefix_boundary": "Caller prefix does not match a sibling identity",
        "jwt_missing": "Required missing JWT is denied with OAuth 401",
        "jwt_malformed": "Malformed JWT is denied with OAuth 401",
        "jwt_bad_signature": "JWT signed by an unknown private key is denied",
        "jwt_wrong_audience": "JWT for another resource is denied",
        "jwt_wrong_issuer": "JWT from another issuer is denied",
        "jwt_expired": "Expired signed JWT is denied",
        "jwt_future": "JWT not yet valid is denied",
        "jwt_no_expiry": "A required access token without expiration must be denied",
        "role_missing": "JWT without required role is denied with OAuth 403",
        "role_partial": "JWT must contain all required roles",
        "validator_absent": "Unavailable required JWT validator fails closed with 503",
        "rbac_before_oauth": "Explicit RBAC deny wins over invalid JWT",
        "ca_before_rbac": "Admin disabled state wins over explicit RBAC deny",
        "ca_before_oauth": "Admin disabled state wins over invalid JWT",
    },
    "CA": {
        "enabled_low": "Enabled high-risk block policy allows explicitly low risk",
        "enabled_high": "Enabled high-risk block policy denies high risk",
        "enabled_medium": "Enabled medium-risk block policy denies medium risk",
        "disabled_policy": "Disabled Graph policy is not enforced",
        "report_only": "Report-only Graph policy is not enforced",
        "nonblock_policy": "A non-block grant control does not become a block",
        "string_risk": "Scalar agentIdRiskLevels input is enforced",
        "union_risk": "Enabled block policies contribute a union of risk levels",
        "tag_match": "Matching target and caller tags allow access",
        "tag_mismatch": "Mismatched tags deny at Conditional Access",
        "tag_missing": "Missing required caller tag denies at Conditional Access",
        "tag_graph_override": "Graph-sourced tag overrides matching YAML tag",
        "tag_exemption": "Explicit target-tag exemption bypasses only the tag check",
        "disabled_agent": "Admin disabled agent is denied before tag exemption",
        "policy_outage": "Unavailable initial Graph policy must not allow high-risk access",
        "missing_risk": "Missing required risk data must not be interpreted as low risk",
        "graph_tag_absent": "Missing configured Graph tag data must not fall back to an allowing YAML tag",
        "warm_policy_outage": "A cached enabled block survives a subsequent Graph outage",
    },
    "Tunnel": {
        "allowed": "Real gRPC/mTLS tunnel forwards an authorized JWT-bearing request",
        "denied": "Denied route receives 403 and no backend request",
        "jwt_missing": "Real tunnel rejects missing JWT before backend dispatch",
        "ca_disabled": "Real tunnel rejects disabled caller before backend dispatch",
        "spoofed_identity": "Backend receives certificate-derived identity, not forged headers",
        "split_body": "A legitimate Content-Length body can span DATA frames",
        "second_frame": "A second request in a new DATA frame never reaches backend",
        "same_frame": "A second request in the first DATA frame never reaches backend",
        "overflow_frame": "Body continuation cannot carry a second ungoverned request",
    },
}
LAYERS = {"MTLS": "mtls", "Enforcement": "rbac_oauth_precedence",
          "CA": "conditional_access", "Tunnel": "transport_integration"}


def descriptors():
    return [
        {"id": f"protocols.{group.lower()}.{name}", "suite": "protocols",
         "layer": LAYERS[group], "profiles": ["local"], "description": expected,
         "expected": expected, "mutation": False}
        for group, cases in CATALOG.items() for name, expected in cases.items()
    ]


def test_name(case):
    _, group, name = case["id"].split(".")
    actual_group = next(key for key in CATALOG if key.lower() == group)
    return f"Test{actual_group}/{name}"


def result(case, status, observed, duration=0.0, evidence=None):
    item = {"id": case["id"], "status": status, "observed": observed,
            "duration_seconds": duration}
    if evidence is not None:
        item["evidence"] = evidence
    return item


def typed_evidence(output):
    """Only permit a closed schema, never arbitrary test or production text."""
    marker = "PROTOCOL_EVIDENCE "
    if not isinstance(output, str) or marker not in output:
        return None
    try:
        value = json.loads(output.split(marker, 1)[1])
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    if set(value) == {"action", "layer", "status_code"}:
        if (value["action"] in ("allow", "deny")
                and value["layer"] in ("rbac", "oauth", "conditional_access")
                and type(value["status_code"]) is int
                and value["status_code"] in (0, 200, 401, 403, 503)):
            return value
    if (set(value) == {"backend_requests"}
            and type(value["backend_requests"]) is int
            and 0 <= value["backend_requests"] <= 100):
        return value
    return None


def parse_results(output, returncode, selected):
    """Accept only completed named tests from this package; never emit Go logs."""
    terminals = {}
    starts = set()
    package_actions = []
    actual = {}
    malformed = False
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            malformed = True
            continue
        if not isinstance(event, dict):
            malformed = True
            continue
        if event.get("Package") != TEST_PACKAGE:
            continue
        name, action = event.get("Test"), event.get("Action")
        if not name:
            if action in ("pass", "fail", "skip"):
                package_actions.append(action)
            continue
        if not isinstance(name, str):
            malformed = True
            continue
        if action == "output":
            evidence = typed_evidence(event.get("Output"))
            if evidence is not None:
                actual[name] = evidence
        if action == "run":
            starts.add(name)
        if action in ("pass", "fail", "skip"):
            terminals.setdefault(name, []).append(event)

    attributable_failure = any(
        any(e["Action"] == "fail" for e in terminals.get(test_name(case), []))
        for case in selected
    )
    package_valid = (
        not malformed and len(package_actions) == 1
        and ((returncode == 0 and package_actions[0] == "pass")
             or (returncode == 1 and package_actions[0] == "fail" and attributable_failure))
    )
    results = []
    for case in selected:
        name = test_name(case)
        entries = terminals.get(name, [])
        evidence = {"go_test": name, "scope": "local_actual_go_code"}
        if not package_valid or len(entries) != 1 or name not in starts:
            results.append(result(case, "FAIL", "Go test did not produce a trustworthy completion record",
                                  evidence=evidence))
            continue
        event = entries[0]
        elapsed = event.get("Elapsed", 0.0)
        if (isinstance(elapsed, bool) or not isinstance(elapsed, (float, int))
                or not 0 <= elapsed <= 86400 or not math.isfinite(elapsed)):
            results.append(result(case, "FAIL", "Invalid Go test timing record", evidence=evidence))
            continue
        status = {"pass": "PASS", "fail": "FAIL", "skip": "SKIPPED"}[event["Action"]]
        observed = {
            "PASS": "Actual Go test completed and its assertions passed",
            "FAIL": "Actual Go assertion failed; expected security property was not established",
            "SKIPPED": "Go explicitly skipped this test; property not verified",
        }[status]
        if name in actual:
            evidence["actual"] = actual[name]
            observed += "; " + ", ".join(f"{key}={value}" for key, value in actual[name].items())
        results.append(result(case, status, observed, float(elapsed), evidence))
    return results


def offline_environment():
    env = os.environ.copy()
    env.update({"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
                "GOWORK": "off", "GOFLAGS": "", "GONOPROXY": "none",
                "GOVCS": "*:off"})
    return env


def invoke(command, cwd, env, timeout=180):
    with owned_process(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True, errors="replace") as process:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def resolve_plugin(name, gopath):
    isolated = TOOLS_BIN / name
    if isolated.is_file() and os.access(isolated, os.X_OK):
        return str(isolated)
    executable = shutil.which(name)
    if executable:
        return executable
    for root in gopath.split(os.pathsep):
        if not root:
            continue
        candidate = Path(root) / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def run_cases(profile):
    selected = [case for case in descriptors() if profile in case["profiles"]]
    if not selected:
        return []
    go = shutil.which("go")
    protoc = shutil.which("protoc")
    if not go or not protoc:
        return [result(c, "BLOCKED", "Required Go or protoc executable is missing") for c in selected]
    env = offline_environment()
    started = time.monotonic()
    try:
        gopath = invoke([go, "env", "GOPATH"], HERE, env)
        if gopath.returncode:
            return [result(c, "BLOCKED", "Go environment is unavailable") for c in selected]
        plugins = {}
        for name in ("protoc-gen-go", "protoc-gen-go-grpc"):
            executable = resolve_plugin(name, gopath.stdout.strip())
            if not executable:
                return [result(c, "BLOCKED", f"Required {name} executable is missing") for c in selected]
            plugins[name] = executable

        with tempfile.TemporaryDirectory(prefix="identity-protocols-") as directory:
            work = Path(directory)
            production, suite = work / "proxy", work / "protocols"
            production.mkdir()
            suite.mkdir()
            source = ROOT / "src" / "spiffe-proxy"
            digest = hashlib.sha256()
            source_files = [source / "go.mod", source / "go.sum", source / "proto" / "tunnel.proto"]
            source_files += sorted(
                p for p in (source / "internal").rglob("*.go")
                if not p.name.endswith("_test.go") and "tunnelpb" not in p.parts
            )
            for file in source_files:
                relative = file.relative_to(source)
                data = file.read_bytes()
                digest.update(str(relative).encode() + b"\0" + data)
                destination = production / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            for file in HERE.glob("*_test.go"):
                shutil.copyfile(file, suite / file.name)
            module_text = (HERE / "go.mod").read_text(encoding="utf-8")
            module_text = module_text.replace("../../../src/spiffe-proxy", json.dumps(str(production)))
            (suite / "go.mod").write_text(module_text, encoding="utf-8")
            shutil.copyfile(source / "go.sum", suite / "go.sum")
            generated = invoke([
                protoc, "--plugin=protoc-gen-go=" + plugins["protoc-gen-go"],
                "--plugin=protoc-gen-go-grpc=" + plugins["protoc-gen-go-grpc"],
                "--go_out=.", "--go_opt=module=" + MODULE,
                "--go-grpc_out=.", "--go-grpc_opt=module=" + MODULE,
                "proto/tunnel.proto",
            ], production, env)
            if generated.returncode:
                return [result(c, "FAIL", "Isolated protobuf generation failed") for c in selected]
            completed = invoke(
                [go, "test", "-mod=mod", "-json", "-count=1", "-timeout=90s", "."],
                suite, env,
            )
            results = parse_results(completed.stdout, completed.returncode, selected)
            # Dependency acquisition is deliberately offline. A missing cached module
            # is a prerequisite failure, not evidence about product enforcement.
            if completed.returncode and any(marker in completed.stderr for marker in (
                "module lookup disabled by GOPROXY=off",
                "requires go >=", "toolchain not available",
                "cannot find GOROOT directory", "C compiler",
            )):
                results = [result(c, "BLOCKED", "Go toolchain or cached module dependency is unavailable")
                           for c in selected]
            for item in results:
                item.setdefault("evidence", {})["production_source_sha256"] = digest.hexdigest()
                item["evidence"]["fixture_boundary"] = "Ephemeral CA/SVID; local OIDC/JWKS/Graph responses"
            return results
    except FileNotFoundError:
        return [result(c, "BLOCKED", "Required executable or source fixture is unavailable")
                for c in selected]
    except subprocess.TimeoutExpired:
        return [result(c, "FAIL", "Protocol execution exceeded its bounded timeout",
                       time.monotonic() - started) for c in selected]
    except ProcessCleanupError:
        return [result(c, "FAIL", "Protocol tool cleanup could not be verified") for c in selected]
    except ProcessLaunchError:
        return [result(c, "BLOCKED", "Protocol tool could not start with safe process ownership") for c in selected]
    except OSError:
        return [result(c, "BLOCKED", "Local workspace or executable could not be accessed")
                for c in selected]


def exit_status(results):
    if any(item["status"] == "FAIL" for item in results):
        return 1
    if not results or any(item["status"] in ("BLOCKED", "SKIPPED") for item in results):
        return 2
    return 0


def write_report(output, results):
    output.parent.mkdir(parents=True, exist_ok=True)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Secure report-file opening is not supported")
    # Do not truncate until the opened inode has passed the safety checks.
    flags = os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(output, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()):
            raise OSError("Unsafe report-file destination")
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
            json.dump({"cases": results}, handle, indent=2, allow_nan=False)
            handle.write("\n")
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profile", choices=("local", "live"), default="local")
    parser.add_argument("--config", type=Path, help="Accepted for coordinator compatibility; local suite ignores it")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(descriptors()))
        return 0
    if args.output is None:
        parser.error("--output is required unless --list is used")
    results = run_cases(args.profile)
    try:
        write_report(args.output, results)
    except OSError:
        print("Protocol report could not be written securely.", file=sys.stderr)
        return 2
    return exit_status(results)


if __name__ == "__main__":
    raise SystemExit(main())
