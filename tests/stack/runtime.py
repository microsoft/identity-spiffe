#!/usr/bin/env python3
"""Private loopback launcher for the real production Go egress/ingress topology."""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import subprocess
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CALLER_SPIFFE_ID = "spiffe://stack.test/caller"
AUDIENCE = "stack-budget-api"
MODULE = "github.com/microsoft/identity-spiffe/src/spiffe-proxy"

_spec = importlib.util.spec_from_file_location(
    "_stack_protocol_helpers", HERE.parent / "protocols" / "run.py")
_protocols = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_protocols)
_process_spec = importlib.util.spec_from_file_location(
    "_stack_owned_processes", HERE.parent / "processes.py")
_processes = importlib.util.module_from_spec(_process_spec)
_process_spec.loader.exec_module(_processes)


class StackFailure(RuntimeError):
    """A fixture/setup/cleanup failure, never evidence of a security denial."""


class StackUnavailable(RuntimeError):
    """Unavailable tools, cached modules, or startup; report BLOCKED."""


StackBlocked = StackUnavailable


class StackCleanupFailure(StackFailure):
    """Process cleanup could not be verified; preserve its private workspace."""


def invoke_tool(command, cwd, env, timeout=180):
    """Capture a registered command; the registry survives early parent exits."""
    try:
        with _processes.owned_process(
            command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace",
        ) as process:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except _processes.ProcessCleanupError:
        raise StackCleanupFailure("Tool process cleanup could not be verified; workspace retained") from None
    except _processes.ProcessLaunchError:
        raise StackUnavailable("Tool process supervision could not start") from None


def validate_backend_url(value):
    try:
        url = urlsplit(value)
        valid = (url.scheme == "http" and url.hostname == "127.0.0.1"
                 and url.port is not None and 0 < url.port < 65536
                 and not url.username and not url.password
                 and url.path in ("", "/") and not url.query and not url.fragment
                 and value == f"http://127.0.0.1:{url.port}" + url.path)
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise StackFailure("Stack endpoints require numeric IPv4 loopback HTTP and an explicit port")
    return value.rstrip("/")


def validate_ready(value):
    keys = {"egress_url", "management_url", "control_url", "caller_spiffe_id", "audience"}
    if (not isinstance(value, dict) or set(value) != keys
            or value["caller_spiffe_id"] != CALLER_SPIFFE_ID
            or value["audience"] != AUDIENCE):
        raise StackFailure("Stack readiness schema is invalid")
    endpoints = [validate_backend_url(value[key]) for key in
                 ("egress_url", "management_url", "control_url")]
    if len(set(endpoints)) != 3:
        raise StackFailure("Stack listeners must be distinct")
    return value


def read_ready(pipe, timeout=25):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while b"\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([pipe], [], [], remaining)[0]:
            raise StackUnavailable("Stack readiness deadline exceeded")
        chunk = os.read(pipe.fileno(), 8193 - len(data))
        if not chunk:
            raise StackUnavailable("Stack stopped before valid readiness")
        data.extend(chunk)
        if len(data) > 8192:
            raise StackFailure("Stack readiness exceeded its size bound")
    if data.count(b"\n") != 1 or not data.endswith(b"\n"):
        raise StackFailure("Stack returned unexpected readiness output")
    try:
        return validate_ready(json.loads(data))
    except (ValueError, UnicodeError):
        raise StackFailure("Stack returned malformed readiness") from None


def stack_environment(work):
    offline = _protocols.offline_environment()
    env = {key: offline[key] for key in (
        "PATH", "HOME", "USER", "SYSTEMROOT", "GOPATH", "GOCACHE", "GOROOT",
        "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOWORK", "GOFLAGS", "GONOPROXY", "GOVCS",
    ) if key in offline}
    env.update({"TMPDIR": str(work), "GOTMPDIR": str(work),
                "GRPC_GO_LOG_SEVERITY_LEVEL": "error"})
    return env


def _checked(command, cwd, env, phase, timeout=180):
    try:
        completed = invoke_tool(command, cwd, env, timeout=timeout)
    except FileNotFoundError:
        raise StackBlocked("Required stack executable is unavailable") from None
    except subprocess.TimeoutExpired:
        raise StackFailure(f"Stack {phase} exceeded its bounded deadline") from None
    text = completed.stdout + completed.stderr
    if completed.returncode:
        if any(marker in text for marker in (
            "module lookup disabled by GOPROXY=off", "requires go >=",
            "toolchain not available", "cannot find GOROOT", "C compiler",
        )):
            raise StackBlocked("Go toolchain or cached module dependency is unavailable")
        raise StackFailure(f"Stack {phase} failed (exit {completed.returncode}); raw logs withheld")
    return completed


@contextmanager
def prepared_stack():
    """Copy unmodified production inputs and build offline under tests/stack."""
    go, protoc = shutil.which("go"), shutil.which("protoc")
    if not go or not protoc:
        raise StackBlocked("Required Go or protoc executable is missing")
    work = HERE / (".work-" + secrets.token_hex(12))
    work.mkdir(mode=0o700)
    prepared = False
    retain_workspace = False
    try:
        env = stack_environment(work)
        gopath = _checked([go, "env", "GOPATH"], HERE, env, "toolchain probe").stdout.strip()
        plugins = {}
        for name in ("protoc-gen-go", "protoc-gen-go-grpc"):
            executable = _protocols.resolve_plugin(name, gopath)
            if not executable:
                raise StackBlocked(f"Required {name} executable is missing")
            plugins[name] = executable
        production, suite = work / "proxy", work / "stack"
        production.mkdir(mode=0o700)
        suite.mkdir(mode=0o700)
        source = ROOT / "src" / "spiffe-proxy"
        digest = hashlib.sha256()
        inputs = [source / "go.mod", source / "go.sum", source / "proto" / "tunnel.proto"]
        inputs += sorted(p for p in (source / "internal").rglob("*.go")
                         if not p.name.endswith("_test.go") and "tunnelpb" not in p.parts)
        for path in inputs:
            relative, data = path.relative_to(source), path.read_bytes()
            digest.update(str(relative).encode() + b"\0" + data)
            target = production / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
        for path in HERE.glob("*.go"):
            shutil.copyfile(path, suite / path.name)
        module = (HERE / "go.mod").read_text(encoding="utf-8")
        # Go module replacement paths with spaces must be quoted.
        module = module.replace("../../../src/spiffe-proxy", json.dumps(str(production)))
        (suite / "go.mod").write_text(module, encoding="utf-8")
        shutil.copyfile(source / "go.sum", suite / "go.sum")
        _checked([
            protoc, "--plugin=protoc-gen-go=" + plugins["protoc-gen-go"],
            "--plugin=protoc-gen-go-grpc=" + plugins["protoc-gen-go-grpc"],
            "--go_out=.", "--go_opt=module=" + MODULE,
            "--go-grpc_out=.", "--go-grpc_opt=module=" + MODULE,
            "proto/tunnel.proto",
        ], production, env, "protobuf generation")
        binary = work / "connected-stack"
        _checked([go, "build", "-mod=mod", "-o", str(binary), "."], suite, env, "build")
        prepared = True
        yield {"binary": binary, "directory": suite, "env": env,
               "go": go, "source_sha256": digest.hexdigest()}
    except StackCleanupFailure:
        retain_workspace = True
        raise
    except OSError:
        if prepared:
            raise
        raise StackBlocked("Private stack workspace or tool could not be accessed") from None
    finally:
        if not retain_workspace:
            shutil.rmtree(work)


@contextmanager
def start_stack(built, backend_url):
    try:
        with _processes.owned_process(
            [str(built["binary"]), "--backend", backend_url],
            cwd=built["directory"], env=built["env"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ) as process:
            yield process
    except _processes.ProcessCleanupError:
        raise StackCleanupFailure("Stack process cleanup could not be verified; workspace retained") from None
    except (OSError, _processes.ProcessLaunchError):
        raise StackUnavailable("Stack executable could not start") from None


@contextmanager
def running_stack(backend_url):
    """Yield stable loopback endpoints; stop and remove all child state on exit."""
    backend_url = validate_backend_url(backend_url)
    with prepared_stack() as built, start_stack(built, backend_url) as process:
        started = False
        try:
            ready = read_ready(process.stdout)
            if process.poll() is not None:
                raise StackUnavailable("Stack process exited during readiness")
            try:
                with build_opener(ProxyHandler({})).open(
                    ready["control_url"] + "/health", timeout=3
                ) as response:
                    if response.status != 200 or json.load(response) != {"status": "ready"}:
                        raise StackFailure("Stack readiness probe failed")
            except OSError:
                raise StackUnavailable("Stack control listener is not responsive") from None
            ready["source_sha256"] = built["source_sha256"]
            started = True
            yield ready
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                code = process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                raise StackFailure("Stack cleanup exceeded deadline and required forced termination") from None
            finally:
                process.stdout.close()
            if code != 0:
                error = StackFailure if started else StackUnavailable
                raise error(f"Stack exited abnormally (exit {code}); raw logs withheld")


def self_test():
    with prepared_stack() as built:
        completed = _checked(
            [built["go"], "test", "-mod=mod", "-json", "-count=1", "-timeout=80s", "."],
            built["directory"], built["env"], "self-test", timeout=100,
        )
        names = []
        package_pass = False
        for line in completed.stdout.splitlines():
            event = json.loads(line)
            if event.get("Action") == "pass":
                if event.get("Test"):
                    names.append(event["Test"])
                else:
                    package_pass = True
        if not package_pass or not names:
            raise StackFailure("Stack self-test omitted completed Go assertions")
        return {"status": "PASS", "tests": names, "production_source_sha256": built["source_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    try:
        print(json.dumps(self_test()))
        return 0
    except StackBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "observed": str(exc)}))
        return 2
    except StackFailure as exc:
        print(json.dumps({"status": "FAIL", "observed": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
