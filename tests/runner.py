"""Dependency-free coordinator for separately labeled local and live evidence."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import html
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit
from processes import owned_process, ProcessCleanupError, ProcessLaunchError


ROOT = Path(__file__).resolve().parent
SUITES = ("browser", "protocols", "e2e", "live")
STATUSES = ("PASS", "FAIL", "BLOCKED", "SKIPPED", "NOT_RUN")
SECRET_KEY = re.compile(
    r"authorization|cookie|password|secret|token|credential|api.?key|storage.?state|session.?storage",
    re.IGNORECASE,
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
URL = re.compile(r"https?://[^\s<>\"']+")


def safe_url(match):
    try:
        parsed = urlsplit(match.group())
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))
    except ValueError:
        return "[REDACTED-URL]"


def redact(value):
    """Minimize report data even when an adapter accidentally returns credentials."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]", "", value)
    value = JWT.sub("[REDACTED-JWT]", value)
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+\S+", r"\1 [REDACTED]", value)
    value = re.sub(r"(?im)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+", "Cookie: [REDACTED]", value)
    value = re.sub(
        r"""(?i)\b(access_token|refresh_token|id_token|client_secret|password|api[_-]?key|"""
        r"""x-spiffe-admin-key)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}]+)""",
        r"\1=[REDACTED]", value,
    )
    value = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED-PRIVATE-KEY]", value, flags=re.DOTALL,
    )
    value = URL.sub(safe_url, value)
    for key, secret in os.environ.items():
        if SECRET_KEY.search(key) and len(secret) >= 8:
            value = value.replace(secret, "[REDACTED]")
    return value


def validate_matrix(cases):
    if not isinstance(cases, list) or not cases:
        raise ValueError("The case inventory is empty or invalid")
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("A case must be an object")
        for key in ("id", "suite", "layer", "description", "expected"):
            if not isinstance(case.get(key), str) or not case[key].strip():
                raise ValueError("Case descriptors require nonempty " + key)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", case["id"]) or case["id"] in seen:
            raise ValueError("Case IDs must be safe and unique")
        if case["suite"] not in SUITES:
            raise ValueError("Unknown suite")
        if (not isinstance(case.get("profiles"), list) or not case["profiles"]
                or any(profile not in ("local", "live") for profile in case["profiles"])):
            raise ValueError("Unknown or missing case profile")
        if not isinstance(case.get("mutation"), bool):
            raise ValueError("Case mutation flag must be explicit")
        seen.add(case["id"])
    return cases


def outcome(case, status, observed, duration=0):
    return {**case, "status": status, "observed": observed, "duration_seconds": duration}


def reconcile(expected, report, returncode):
    def invalid(message):
        return [outcome(case, "FAIL", message) for case in expected]

    if not isinstance(report, dict) or not isinstance(report.get("cases"), list):
        return invalid("Adapter did not produce a valid case report")
    expected_ids = {case["id"] for case in expected}
    indexed = {}
    for result in report["cases"]:
        if (not isinstance(result, dict) or not isinstance(result.get("id"), str)
                or result["id"] not in expected_ids
                or result["id"] in indexed):
            return invalid("Adapter reported duplicate, unknown, or malformed case IDs")
        duration = result.get("duration_seconds")
        if (result.get("status") not in STATUSES[:-1]
                or not isinstance(result.get("observed"), str)
                or isinstance(duration, bool)
                or not isinstance(duration, (float, int))
                or duration < 0 or duration > 2147483647 or not math.isfinite(duration)):
            return invalid("Adapter reported invalid outcome fields")
        try:
            json.dumps(result.get("evidence"), allow_nan=False)
        except (TypeError, ValueError):
            return invalid("Adapter evidence is not finite JSON data")
        indexed[result["id"]] = result
    results = []
    for case in expected:
        if case["id"] not in indexed:
            results.append(outcome(case, "FAIL", "Adapter omitted this selected case"))
            continue
        result = indexed[case["id"]]
        merged = outcome(case, result["status"], result["observed"], result["duration_seconds"])
        if "evidence" in result:
            merged["evidence"] = result["evidence"]
        results.append(merged)
    if returncode != exit_code(results):
        return invalid("Adapter exit code disagrees with its case outcomes")
    return redact(results)


def exit_code(cases):
    statuses = [case["status"] for case in cases if case["status"] != "NOT_RUN"]
    if "FAIL" in statuses:
        return 1
    if not statuses or any(status != "PASS" for status in statuses):
        return 2
    return 0


def prepare_output(path):
    if path.exists() or path.is_symlink():
        raise ValueError("Output directory must be new; existing artifacts are never overwritten")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Output directory cannot have symlink parents")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)
    return path


def private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def finalize_adapter(output, results):
    if output.is_symlink():
        output.unlink()
    fd = os.open(
        output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump({"cases": redact(results)}, stream, indent=2, allow_nan=False)
    return results


def terminate_adapter(process, own_group=True):
    if os.name == "posix" and own_group:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "posix" or not own_group:
            process.kill()
    if os.name == "posix" and own_group:
        # The group can outlive its leader; do not rely on leader.wait alone.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            time.sleep(0.2)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    process.wait()


def run_adapter(script, cases, profile, config, output, timeout):
    command = [
        sys.executable, str(script), "--profile", profile, "--output", str(output),
    ]
    if config is not None:
        command += ["--config", str(config)]
    start = time.monotonic()
    environment = dict(os.environ, IDENTITY_TEST_INHERIT_PROCESS_GROUP="1")
    interrupted = False
    try:
        with owned_process(command, cwd=ROOT.parent, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env=environment) as process:
            try:
                process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                interrupted = True
    except (ProcessCleanupError, ProcessLaunchError, OSError):
        return finalize_adapter(output, [
            outcome(case, "FAIL", "Adapter startup or registered cleanup could not be verified",
                    time.monotonic() - start) for case in cases
        ])
    if interrupted:
        return finalize_adapter(output, [
            outcome(case, "FAIL", "Adapter interrupted or timed out; verify fixture cleanup",
                    time.monotonic() - start)
            for case in cases
        ])
    if output.is_symlink() or not output.is_file():
        return finalize_adapter(output, [
            outcome(case, "FAIL", "Adapter exited without a regular report file") for case in cases
        ])
    try:
        output.chmod(0o600)
        report = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report = None
    results = reconcile(cases, report, process.returncode)
    return finalize_adapter(output, results)


def markdown_cell(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", "<br>")


def write_reports(directory, cases, profile, run_id, metadata):
    cases = redact(cases)
    counts = Counter(case["status"] for case in cases)
    report = {
        "schema_version": 1, "run_id": run_id, "profile": profile,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "exit_code": exit_code(cases), "metadata": redact(metadata),
        "summary": {status: counts[status] for status in STATUSES},
        "cases": cases,
    }
    private_write(directory / "matrix.json", json.dumps(report, indent=2, allow_nan=False) + "\n")
    lines = [
        "# Identity SPIFFE test matrix", "",
        f"Run: `{run_id}` | Profile: **{profile}** | Exit code: **{report['exit_code']}**", "",
        "Local results are not evidence of live Entra/SPIRE deployment behavior.",
        "BLOCKED, SKIPPED and NOT_RUN cases are not passes. No claim of exhaustive platform coverage.", "",
        " | ".join(f"**{status}: {counts[status]}**" for status in STATUSES), "",
        "| ID | Suite / layer | Status | Expected | Observed | Seconds |",
        "|---|---|---|---|---|---|",
    ]
    for case in cases:
        values = [
            case["id"], case["suite"] + " / " + case["layer"], case["status"],
            case["expected"], case["observed"], f"{case['duration_seconds']:.3f}",
        ]
        lines.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
    private_write(directory / "matrix.md", "\n".join(lines) + "\n")
    suite = ET.Element("testsuite", {
        "name": "identity-spiffe-" + profile, "tests": str(len(cases)),
        "failures": str(counts["FAIL"]), "errors": "0",
        "skipped": str(counts["BLOCKED"] + counts["SKIPPED"] + counts["NOT_RUN"]),
        "time": str(sum(case["duration_seconds"] for case in cases)),
    })
    for case in cases:
        test = ET.SubElement(suite, "testcase", {
            "name": case["id"], "classname": case["suite"] + "." + case["layer"],
            "time": str(case["duration_seconds"]),
        })
        if case["status"] == "FAIL":
            ET.SubElement(test, "failure", {"message": case["observed"]})
        elif case["status"] != "PASS":
            ET.SubElement(test, "skipped", {
                "type": case["status"], "message": case["observed"],
            })
        ET.SubElement(test, "system-out").text = case["expected"] + "\n" + case["observed"]
    private_write(directory / "junit.xml", ET.tostring(suite, encoding="unicode") + "\n")
    return report


def inventory():
    cases = []
    for name in SUITES:
        process = subprocess.run(
            [sys.executable, str(ROOT / name / "run.py"), "--list"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=30, check=False,
        )
        if process.returncode:
            raise ValueError(f"Could not inventory {name}; run its --list command")
        batch = validate_matrix(json.loads(process.stdout))
        if any(case["suite"] != name for case in batch):
            raise ValueError("An adapter declared cases for a different suite")
        cases.extend(batch)
    return validate_matrix(cases)


def git_metadata():
    metadata = {"source_commit": "unavailable", "worktree_dirty": None}
    for key, arguments in (
        ("source_commit", ["rev-parse", "HEAD"]),
        ("worktree_dirty", ["status", "--porcelain"]),
    ):
        try:
            result = subprocess.run(
                ["git", *arguments], cwd=ROOT.parent, capture_output=True,
                text=True, check=False, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            metadata[key] = bool(result.stdout.strip()) if key == "worktree_dirty" else result.stdout.strip()
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Print every case without network access")
    parser.add_argument("--profile", choices=("local", "live"), default="local")
    parser.add_argument("--suite", choices=SUITES, action="append", help="Select suites; others remain NOT_RUN")
    parser.add_argument("--config", type=Path, help="Explicit JSON config; no environment auto-discovery")
    parser.add_argument("--output", type=Path, help="New private report directory")
    parser.add_argument("--timeout", type=int, default=600, help="Per-adapter timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        cases = inventory()
        if args.list:
            print(json.dumps(cases, indent=2))
            return 0
        chosen = list(dict.fromkeys(args.suite or SUITES))
        selected = [case for case in cases if args.profile in case["profiles"] and case["suite"] in chosen]
        if not selected:
            raise ValueError("Selection has no applicable cases")
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        directory = prepare_output((args.output or ROOT / "artifacts" / run_id).absolute())
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("Harness preflight failed (" + type(exc).__name__ + "). Check inventory, config and output path.",
              file=sys.stderr)
        return 2
    config_error = False
    if args.config is not None:
        args.config = args.config.absolute()
        try:
            config = json.loads(args.config.read_text(encoding="utf-8"))
            config_error = not isinstance(config, dict)
        except (OSError, ValueError):
            config_error = True
    results = {}
    for name in chosen:
        batch = [case for case in selected if case["suite"] == name]
        if not batch:
            continue
        if config_error:
            results.update({
                case["id"]: outcome(case, "BLOCKED", "Config is unreadable or not a JSON object")
                for case in batch
            })
            continue
        print(f"Running {name}: {len(batch)} cases ({args.profile})", flush=True)
        try:
            suite_results = run_adapter(
                ROOT / name / "run.py", batch, args.profile, args.config,
                directory / (name + ".json"), args.timeout,
            )
        except OSError:
            suite_results = [outcome(case, "FAIL", "Could not launch adapter") for case in batch]
        results.update({result["id"]: result for result in suite_results})
    complete = [
        results.get(case["id"], outcome(case, "NOT_RUN", "Outside selected profile or suite"))
        for case in cases
    ]
    report = write_reports(directory, complete, args.profile, run_id, {
        **git_metadata(),
        "selected_suites": chosen, "selected_count": len(selected),
        "python_version": sys.version.split()[0],
    })
    print(" ".join(f"{key}={value}" for key, value in report["summary"].items()))
    print("Reports: " + str(directory))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
