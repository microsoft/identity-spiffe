"""Real process-group ownership regressions for the local test harness."""

import importlib.util
import inspect
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def alive(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                            capture_output=True, text=True, timeout=2)
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")


class OwnedProcessTests(unittest.TestCase):
    def setUp(self):
        path = HERE / "processes.py"
        self.assertTrue(path.exists(), "registered process supervision helper is missing")
        spec = importlib.util.spec_from_file_location("owned_process_test", path)
        self.processes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.processes)
        self.work = HERE / "artifacts" / ("process-test-" + secrets.token_hex(8))
        self.work.mkdir(mode=0o700, parents=True)
        self.addCleanup(shutil.rmtree, self.work)

    def orphan(self, inherited, keep_pipe):
        marker = self.work / "orphan.pid"
        redirect = "" if keep_pipe else " >/dev/null 2>&1"
        command = ["/bin/sh", "-c", f"sleep 30{redirect} & echo $! > \"$1\"; exit",
                   "orphan-test", str(marker)]
        env = dict(os.environ, IDENTITY_TEST_INHERIT_PROCESS_GROUP=str(int(inherited)))
        child = None
        try:
            with self.processes.owned_process(command, cwd=self.work, env=env,
                                              stdout=subprocess.PIPE, text=True) as process:
                if keep_pipe:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.communicate(timeout=0.2)
                else:
                    self.assertEqual(process.communicate(timeout=2)[0], "")
                    self.assertEqual(process.returncode, 0)
                child = int(marker.read_text().strip())
                self.assertTrue(alive(child), "fixture must prove a surviving orphan before cleanup")
            self.assertFalse(alive(child), "orphan survived its registered scope")
        finally:
            if child is None and marker.exists():
                child = int(marker.read_text().strip())
            if child is not None and alive(child):
                os.kill(child, signal.SIGKILL)

    def test_fast_parent_exit_cleans_orphan_on_success(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                self.orphan(inherited, keep_pipe=False)

    def test_fast_parent_exit_cleans_orphan_on_timeout(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                self.orphan(inherited, keep_pipe=True)

    def test_process_identity_does_not_depend_on_locale_or_timezone(self):
        with patch.dict(os.environ, {"LC_ALL": "C", "TZ": "UTC"}):
            canonical = self.processes._table()[os.getpid()]["birth"]
        with patch.dict(os.environ, {"LC_ALL": "fr_FR.UTF-8", "TZ": "America/Los_Angeles"}):
            localized = self.processes._table()[os.getpid()]["birth"]
        self.assertEqual(localized, canonical, "Process ownership must use canonical ps timestamps")

    def test_cleanup_with_different_parent_and_supervisor_locales(self):
        child_env = dict(os.environ, LC_ALL="C", TZ="UTC")
        cleaned = False
        try:
            with patch.dict(os.environ, {"LC_ALL": "fr_FR.UTF-8", "TZ": "America/Los_Angeles"}):
                try:
                    with self.processes.owned_process(
                            [sys.executable, "-c", "import time; time.sleep(30)"],
                            cwd=self.work, env=child_env, registry_base=self.work) as process:
                        with self.assertRaises(subprocess.TimeoutExpired):
                            process.wait(timeout=0.1)
                    cleaned = True
                except (self.processes.ProcessCleanupError, self.processes.ProcessLaunchError):
                    cleaned = False
        finally:
            with patch.dict(os.environ, {"LC_ALL": "C", "TZ": "UTC"}):
                for scope in (self.work / "processes").glob("scope-*"):
                    self.processes.cleanup_scope(scope)
        self.assertTrue(cleaned, "Locale mismatch must not abandon a running owned command")

    def test_outer_owner_reaps_registered_inner_scope_after_parent_is_killed(self):
        marker = self.work / "nested.pid"
        code = (
            "import os,pathlib,signal,subprocess,sys,time\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "from processes import owned_process\n"
            f"with owned_process(['/bin/sh','-c','sleep 30 & echo $! > \"$1\"; exit',"
            f"'inner',{str(marker)!r}], cwd={str(self.work)!r}) as child:\n"
            " child.wait(timeout=2)\n"
            " while True: time.sleep(1)\n"
        )
        descendant = None
        try:
            with self.processes.owned_process([sys.executable, "-c", code], cwd=self.work) as outer:
                deadline = time.monotonic() + 4
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "inner command never registered/executed")
                descendant = int(marker.read_text().strip())
                self.assertTrue(alive(descendant))
                outer.kill()
                outer.wait(timeout=2)
            self.assertFalse(alive(descendant), "outer cleanup lost inner groups after leader death")
        finally:
            if descendant is not None and alive(descendant):
                os.kill(descendant, signal.SIGKILL)

    def test_scope_registered_before_actual_command_exec(self):
        code = (
            "import json,os,pathlib\n"
            "scope=pathlib.Path(os.environ['IDENTITY_TEST_PROCESS_REGISTRY'])\n"
            "record=json.loads((scope/'process.json').read_text())\n"
            "assert record['pid']==os.getpid()==os.getpgrp()\n"
            "assert record['guardian_pid']!=os.getpid()\n"
            "print('registered')\n"
        )
        with self.processes.owned_process([sys.executable, "-c", code], cwd=self.work,
                                          stdout=subprocess.PIPE, text=True) as process:
            self.assertEqual(process.communicate(timeout=3)[0].strip(), "registered")
            self.assertEqual(process.returncode, 0)

    def test_outer_owner_cleans_inner_stack_setup_tool_after_parent_kill(self):
        marker = self.work / "stack-tool.pid"
        command = ["/bin/sh", "-c", 'sleep 30 & echo $! > "$1"; wait',
                   "stack-setup-tool", str(marker)]
        code = (
            "import pathlib,sys\n"
            f"sys.path.insert(0, {str(HERE / 'stack')!r})\n"
            "import runtime\n"
            f"work=pathlib.Path({str(self.work)!r})\n"
            f"runtime._checked({command!r},work,runtime.stack_environment(work),'setup',timeout=60)\n"
        )
        descendant = None
        try:
            with self.processes.owned_process([sys.executable, "-c", code], cwd=self.work) as outer:
                deadline = time.monotonic() + 4
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "registered stack setup tool did not start")
                descendant = int(marker.read_text().strip())
                outer.kill()
                outer.wait(timeout=2)
            self.assertFalse(alive(descendant), "outer cleanup missed registered stack tool group")
        finally:
            if descendant is not None and alive(descendant):
                os.kill(descendant, signal.SIGKILL)

    def test_stale_identity_is_not_signalled_or_deleted(self):
        scope = None
        original = None
        with self.assertRaises(self.processes.ProcessCleanupError):
            with self.processes.owned_process(["sleep", "30"], cwd=self.work) as process:
                scope = Path(process.identity_process_registry)
                original = json.loads((scope / "process.json").read_text())
                changed = dict(original, guardian_birth="not-the-recorded-process")
                (scope / "process.json").write_text(json.dumps(changed))
                self.assertTrue(alive(process.pid))
        self.assertTrue(scope.exists(), "unsafe registry must be retained")
        self.assertTrue(alive(process.pid), "stale ownership must not authorize a signal")
        (scope / "process.json").write_text(json.dumps(original))
        self.processes.cleanup_scope(scope)
        process.wait(timeout=2)

    def test_closing_ancestor_refuses_nested_exec(self):
        marker = self.work / "must-not-exist"
        with self.processes.owned_process(["sleep", "30"], cwd=self.work) as process:
            scope = Path(process.identity_process_registry)
            (scope / ".closing").touch(mode=0o600)
            env = dict(os.environ, IDENTITY_TEST_PROCESS_REGISTRY=str(scope))
            with self.assertRaises(self.processes.ProcessLaunchError):
                with self.processes.owned_process(
                    [sys.executable, "-c", f"open({str(marker)!r},'w').close()"],
                    cwd=self.work, env=env,
                ):
                    self.fail("closing ancestor allowed an executable")
            self.assertFalse(marker.exists())

    def test_caller_private_base_and_stdout_file_are_supported(self):
        self.assertIn("registry_base", inspect.signature(self.processes.owned_process).parameters,
                      "caller-provided private registry base is missing")
        output = self.work / "stdout.txt"
        with output.open("w") as stream:
            with self.processes.owned_process(
                [sys.executable, "-c", "print('captured')"], cwd=self.work,
                registry_base=self.work, stdout=stream,
            ) as process:
                scope = Path(process.identity_process_registry)
                inherited = os.environ.get("IDENTITY_TEST_PROCESS_REGISTRY")
                if inherited:
                    self.assertEqual(scope.parent, Path(inherited))
                else:
                    self.assertTrue(scope.is_relative_to(self.work))
                process.wait(timeout=2)
            self.assertFalse(stream.closed, "caller-owned stdout file must remain open")
        self.assertEqual(output.read_text(), "captured\n")
        self.assertFalse(scope.exists())

    def test_custom_base_does_not_escape_an_inherited_registry(self):
        self.assertIn("registry_base", inspect.signature(self.processes.owned_process).parameters,
                      "caller-provided private registry base is missing")
        with self.processes.owned_process(["sleep", "30"], cwd=self.work) as outer:
            parent = Path(outer.identity_process_registry)
            env = dict(os.environ, IDENTITY_TEST_PROCESS_REGISTRY=str(parent))
            with self.processes.owned_process(
                [sys.executable, "-c", "pass"], cwd=self.work, env=env,
                registry_base=self.work / "do-not-create",
            ) as inner:
                self.assertEqual(Path(inner.identity_process_registry).parent, parent)
                inner.wait(timeout=2)
            self.assertFalse((self.work / "do-not-create").exists())

    def test_missing_executable_is_a_typed_startup_failure(self):
        with self.assertRaises(self.processes.ProcessLaunchError):
            with self.processes.owned_process([str(self.work / "missing-executable")], cwd=self.work) as process:
                process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
