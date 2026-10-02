"""Bounded POSIX command groups registered before exec, including nested scopes."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE / "artifacts"
BASE = ARTIFACTS / "processes"
REGISTRY_ENV = "IDENTITY_TEST_PROCESS_REGISTRY"
SCOPE_NAME = re.compile(r"scope-[a-f0-9]{32}\Z")


class ProcessLaunchError(RuntimeError):
    """A supervisor could not establish safe command ownership."""


class ProcessCleanupError(RuntimeError):
    """Ownership or termination could not be verified; scope is retained."""


def _private_directory(path, forbidden_permissions=0o077):
    data = path.lstat()
    if (not stat.S_ISDIR(data.st_mode) or data.st_uid != os.geteuid()
            or data.st_mode & forbidden_permissions):
        raise ProcessCleanupError("Unsafe process registry directory")


def _open_file(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    data = os.fstat(fd)
    if (not stat.S_ISREG(data.st_mode) or data.st_uid != os.geteuid()
            or data.st_nlink != 1 or data.st_mode & 0o077):
        os.close(fd)
        raise ProcessCleanupError("Unsafe process registry file")
    return fd


def _write_json(path, value):
    fd = _open_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _read_json(path):
    fd = _open_file(path, os.O_RDONLY)
    with os.fdopen(fd) as stream:
        text = stream.read(4097)
    if len(text) > 4096:
        raise ProcessCleanupError("Oversized process registry file")
    return json.loads(text)


def _base_directory(base, create=False):
    if (not base.is_absolute() or ".." in base.parts or not base.is_relative_to(ARTIFACTS)
            or base.name != "processes"):
        raise ProcessCleanupError("Process registry must be inside the private harness directory")
    if create:
        ARTIFACTS.mkdir(mode=0o700, exist_ok=True)
    _private_directory(ARTIFACTS, 0o022)
    current = ARTIFACTS
    for part in base.relative_to(ARTIFACTS).parts:
        current /= part
        if create and not os.path.lexists(current):
            current.mkdir(mode=0o700)
        _private_directory(current, 0o077 if current == base else 0o022)


def _root(scope):
    scope = Path(scope)
    if not scope.is_absolute() or ".." in scope.parts or not scope.is_relative_to(ARTIFACTS):
        raise ProcessCleanupError("Process registry must be inside the private harness directory")
    root = scope
    count = 1
    if not SCOPE_NAME.fullmatch(root.name):
        raise ProcessCleanupError("Invalid process registry scope")
    while SCOPE_NAME.fullmatch(root.parent.name):
        root = root.parent
        count += 1
    if count > 32:
        raise ProcessCleanupError("Process registry nesting limit exceeded")
    base = root.parent
    _base_directory(base)
    parts = scope.relative_to(base).parts
    current = base
    for part in parts:
        current /= part
        _private_directory(current)
        if _read_json(current / "scope.json") != {"version": 1}:
            raise ProcessCleanupError("Invalid process registry metadata")
    return root


@contextmanager
def _locked(scope):
    root = _root(scope)
    fd = _open_file(root / ".lock", os.O_RDWR)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ProcessCleanupError("Process registry lock deadline exceeded")
                time.sleep(0.01)
        yield root
    finally:
        os.close(fd)


def _assert_open(scope, root):
    current = scope
    while True:
        _private_directory(current)
        if os.path.lexists(current / ".closing"):
            raise ProcessLaunchError("Process registry scope is closing")
        if current == root:
            return
        current = current.parent


def _new_scope(environment, registry_base=None):
    inherited = environment.get(REGISTRY_ENV, os.environ.get(REGISTRY_ENV, ""))
    if inherited:
        parent = Path(inherited)
        with _locked(parent) as root:
            _assert_open(parent, root)
            scope = parent / ("scope-" + secrets.token_hex(16))
            scope.mkdir(mode=0o700)
            _write_json(scope / ".pending", {"version": 1})
            _write_json(scope / "scope.json", {"version": 1})
            return scope
    base = BASE if registry_base is None else Path(registry_base) / "processes"
    _base_directory(base, create=True)
    scope = base / ("scope-" + secrets.token_hex(16))
    scope.mkdir(mode=0o700)
    _write_json(scope / ".pending", {"version": 1})
    _write_json(scope / "scope.json", {"version": 1})
    os.close(_open_file(scope / ".lock", os.O_CREAT | os.O_EXCL | os.O_RDWR))
    return scope


def _table():
    result = subprocess.run(
        ["ps", "-A", "-o", "pid=,pgid=,lstart=,stat="],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1, check=False,
        env=dict(os.environ, LC_ALL="C", TZ="UTC"),
    )
    if result.returncode:
        raise ProcessCleanupError("Process identity inspection failed")
    table = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 8:
            raise ProcessCleanupError("Process identity metadata is malformed")
        table[int(fields[0])] = {
            "group": int(fields[1]), "birth": " ".join(fields[2:7]), "state": fields[7],
        }
    return table


def _guardian():
    """Keep a birth-verifiable member alive after the actual command exits."""
    read_fd, write_fd = os.pipe()
    middle = os.fork()
    if middle == 0:
        os.close(read_fd)
        if os.fork() != 0:
            os._exit(0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        os.closerange(3, write_fd)
        os.closerange(write_fd + 1, 1048576 if limit < 0 else min(limit, 1048576))
        os.write(write_fd, str(os.getpid()).encode() + b"\n")
        os.close(write_fd)
        while True:
            signal.pause()
    os.close(write_fd)
    try:
        if not select.select([read_fd], [], [], 3)[0]:
            raise ProcessLaunchError("Process guardian startup deadline exceeded")
        guardian = int(os.read(read_fd, 64).strip())
    finally:
        os.close(read_fd)
        os.waitpid(middle, 0)
    return guardian


def _register_and_exec(scope, ready_fd, command):
    with _locked(scope) as root:
        _assert_open(scope, root)
        pid = os.getpid()
        if os.getpgrp() != pid:
            raise ProcessLaunchError("Supervisor must own its process group")
        if _read_json(scope / ".pending") != {"version": 1}:
            raise ProcessLaunchError("Invalid pending process registration")
        # Once consumed, missing process.json means interrupted registration,
        # not an empty scope: guardian creation may already have happened.
        (scope / ".pending").unlink()
        guardian = _guardian()
        table = _table()
        _write_json(scope / "process.json", {
            "pid": pid, "pgid": pid, "birth": table[pid]["birth"],
            "guardian_pid": guardian, "guardian_birth": table[guardian]["birth"],
        })
        os.write(ready_fd, b"registered\n")
        os.set_inheritable(ready_fd, False)
        # The lock FD is close-on-exec: an ancestor cannot close the scope
        # between this registration and actual execution.
        try:
            os.execvpe(command[0], command, os.environ)
        except OSError:
            os.write(ready_fd, b"exec-failed\n")
            raise


def _read_registration(fd):
    deadline = time.monotonic() + 8
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ProcessLaunchError("Command ownership registration deadline exceeded")
        chunk = os.read(fd, 64)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 64:
            raise ProcessLaunchError("Unexpected supervisor registration output")
    if data != b"registered\n":
        raise ProcessLaunchError("Command ownership or executable startup failed")


def _records(scope):
    records = []
    errors = []
    _private_directory(scope)
    if _read_json(scope / "scope.json") != {"version": 1}:
        raise ProcessCleanupError("Invalid process registry metadata")
    invalid_content = False
    for path in scope.iterdir():
        if SCOPE_NAME.fullmatch(path.name):
            try:
                nested_records, nested_errors = _records(path)
                records.extend(nested_records)
                errors.extend(nested_errors)
            except (ProcessCleanupError, OSError, ValueError):
                errors.append(f"Invalid nested process registry in {path.name}")
        else:
            try:
                if path.name not in {"scope.json", "process.json", ".closing", ".lock", ".pending"}:
                    raise ProcessCleanupError("Unexpected process registry content")
                fd = _open_file(path, os.O_RDONLY)
                os.close(fd)
            except (ProcessCleanupError, OSError):
                invalid_content = True
                errors.append(f"Unsafe process registry content in {scope.name}")
    if invalid_content:
        return records, errors
    try:
        if os.path.lexists(scope / ".pending"):
            if (_read_json(scope / ".pending") != {"version": 1}
                    or os.path.lexists(scope / "process.json")):
                raise ProcessCleanupError("Invalid pending process registration")
            errors.append(f"Incomplete process registration in {scope.name} (pending)")
            return records, errors
        if not os.path.lexists(scope / "process.json"):
            errors.append(f"Incomplete process registration in {scope.name} (ownership unavailable)")
            return records, errors
        value = _read_json(scope / "process.json")
        keys = {"pid", "pgid", "birth", "guardian_pid", "guardian_birth"}
        if (not isinstance(value, dict) or set(value) != keys
                or any(type(value[k]) is not int or value[k] <= 1 for k in ("pid", "pgid", "guardian_pid"))
                or value["pid"] != value["pgid"] or value["guardian_pid"] == value["pid"]
                or any(not isinstance(value[k], str) or not value[k] for k in ("birth", "guardian_birth"))):
            raise ProcessCleanupError("Invalid registered process identity")
        records.append(value)
    except (ProcessCleanupError, OSError, ValueError):
        errors.append(f"Invalid process registration in {scope.name}")
    return records, errors


def _members(record, table):
    return {pid: row for pid, row in table.items()
            if row["group"] == record["pgid"] and not row["state"].startswith("Z")}


def _validate_identity(record, table):
    members = _members(record, table)
    for pid_key, birth_key in (("pid", "birth"), ("guardian_pid", "guardian_birth")):
        row = table.get(record[pid_key])
        if row is not None and (row["birth"] != record[birth_key] or row["group"] != record["pgid"]):
            raise ProcessCleanupError("Registered process identity is stale; refusing signal")
    if members and record["guardian_pid"] not in members:
        raise ProcessCleanupError("Live process group has no verifiable ownership guardian")
    return members


def cleanup_scope(scope):
    """Close registrations and terminate only verified groups within this scope."""
    scope = Path(scope)
    try:
        with _locked(scope):
            marker = scope / ".closing"
            if not marker.exists():
                os.close(_open_file(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            records, errors = _records(scope)
            table = _table()
            verified = []
            for record in records:
                try:
                    _validate_identity(record, table)
                    verified.append(record)
                except ProcessCleanupError as error:
                    errors.append(str(error))
            records = verified
            for record in records:
                if _members(record, table):
                    os.killpg(record["pgid"], signal.SIGTERM)
            deadline = time.monotonic() + 0.3
            while time.monotonic() < deadline:
                table = _table()
                if not any(set(_members(r, table)) - {r["guardian_pid"]} for r in records):
                    break
                time.sleep(0.02)
            table = _table()
            verified = []
            for record in records:
                try:
                    members = _validate_identity(record, table)
                except ProcessCleanupError as error:
                    errors.append(str(error))
                    continue
                verified.append(record)
                if members:
                    os.killpg(record["pgid"], signal.SIGKILL)
            records = verified
            deadline = time.monotonic() + 3
            while any(_members(r, _table()) for r in records):
                if time.monotonic() >= deadline:
                    raise ProcessCleanupError("Registered process groups survived bounded cleanup")
                time.sleep(0.02)
            if errors:
                raise ProcessCleanupError("; ".join(errors) + "; scope retained")
            shutil.rmtree(scope)
    except ProcessCleanupError:
        raise
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise ProcessCleanupError("Process registry cleanup could not be verified; scope retained") from error


@contextmanager
def owned_process(command, *, cwd, env=None, registry_base=None, stdin=subprocess.DEVNULL,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  text=False, errors=None, **popen_kwargs):
    """Yield Popen; registry_base is used only when no registry is inherited.

    A fresh scope is created under registry_base/processes (default:
    tests/artifacts/processes). Custom bases must be inside tests/artifacts.
    stdout/stderr may be caller-owned file handles or subprocess constants.
    ProcessLaunchError distinguishes startup from ProcessCleanupError.
    """
    if (os.name != "posix" or not isinstance(command, (list, tuple)) or not command
            or any(not isinstance(arg, (str, os.PathLike)) for arg in command)
            or any(k in popen_kwargs for k in ("start_new_session", "preexec_fn", "shell", "executable"))):
        raise ProcessLaunchError("Unsupported owned-process launch options")
    environment = dict(os.environ if env is None else env)
    scope = None
    process = None
    registered = False
    read_fd, write_fd = os.pipe()
    try:
        try:
            scope = _new_scope(environment, registry_base)
            environment[REGISTRY_ENV] = str(scope)
            passed = tuple(popen_kwargs.pop("pass_fds", ())) + (write_fd,)
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--exec", str(scope),
                 str(write_fd), "--", *[str(arg) for arg in command]],
                cwd=cwd, env=environment, stdin=stdin, stdout=stdout, stderr=stderr,
                text=text, errors=errors, start_new_session=True, pass_fds=passed,
                **popen_kwargs,
            )
            process.identity_process_registry = str(scope)
            os.close(write_fd)
            write_fd = None
            _read_registration(read_fd)
            registered = True
        except ProcessLaunchError:
            raise
        except (OSError, ValueError, ProcessCleanupError) as error:
            raise ProcessLaunchError("Private command supervision could not start") from error
        yield process
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        try:
            if scope is not None:
                if registered:
                    cleanup_scope(scope)
                elif process is not None:
                    # No command was acknowledged. The new, unreaped child PID
                    # directly identifies the group created by this Popen call.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    if any(row["group"] == process.pid and not row["state"].startswith("Z")
                           for row in _table().values()):
                        raise ProcessCleanupError("Unregistered supervisor group survived cleanup")
                    with _locked(scope):
                        shutil.rmtree(scope)
                else:
                    with _locked(scope):
                        shutil.rmtree(scope)
            if process is not None:
                process.wait(timeout=3)
        finally:
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) < 6 or sys.argv[1] != "--exec" or sys.argv[4] != "--":
            raise ProcessLaunchError("Invalid supervisor invocation")
        _register_and_exec(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[5:])
    except BaseException:
        os._exit(126)
