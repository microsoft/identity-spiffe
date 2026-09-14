"""Real descendant regressions for bounded, ownership-scoped tool cleanup."""

import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("stack_process_runtime_test", HERE / "runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def alive(pid):
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True, timeout=2)
    state = result.stdout.strip()
    return bool(state) and not state.startswith("Z")


class ProcessCleanupTests(unittest.TestCase):
    def exercise_interruption(self, inherited, cancelled, ignore_term=False):
        work = HERE / (".work-process-regression-" + secrets.token_hex(8))
        work.mkdir(mode=0o700)
        marker = work / "descendant.pid"
        child_command = "(trap '' TERM; exec sleep 60)" if ignore_term else "sleep 60"
        command = ["/bin/sh", "-c",
                   child_command + ' </dev/null >/dev/null 2>&1 & child=$!; '
                   'printf "%s\\n" "$child" > "$1"; wait "$child"',
                   "stack-descendant-test", str(marker)]
        child = None
        started = time.monotonic()
        communicate = subprocess.Popen.communicate
        interrupted = False

        def cancel_after_spawn(process, *args, **kwargs):
            nonlocal interrupted
            if process.args[-len(command):] == command and not interrupted:
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "real child was not spawned")
                interrupted = True
                raise KeyboardInterrupt
            return communicate(process, *args, **kwargs)

        try:
            with mock.patch.dict(os.environ, {"IDENTITY_TEST_INHERIT_PROCESS_GROUP": "1" if inherited else ""}):
                with mock.patch.object(subprocess.Popen, "communicate",
                                       cancel_after_spawn if cancelled else communicate):
                    expected = KeyboardInterrupt if cancelled else runtime.StackFailure
                    with self.assertRaises(expected):
                        runtime._checked(command, work, runtime.stack_environment(work),
                                         "descendant regression", timeout=0.2)
            self.assertTrue(marker.exists(), "timeout happened before actual descendant startup")
            child = int(marker.read_text().strip())
            self.assertFalse(alive(child), "tool descendant survived _checked before workspace cleanup")
            self.assertTrue(work.exists(), "cleanup proof must precede workspace removal")
            self.assertLess(time.monotonic() - started, 8, "descendant cleanup was not bounded")
        finally:
            if child is None and marker.exists():
                child = int(marker.read_text().strip())
            if child is not None and alive(child):
                os.kill(child, signal.SIGKILL)
            shutil.rmtree(work)

    def test_timeout_terminates_actual_descendant_before_workspace_cleanup(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                self.exercise_interruption(inherited, cancelled=False)

    def test_cancellation_terminates_actual_descendant_before_workspace_cleanup(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                self.exercise_interruption(inherited, cancelled=True)

    def test_timeout_escalates_for_actual_term_ignoring_descendant(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                self.exercise_interruption(inherited, cancelled=False, ignore_term=True)

    def test_prepared_workspace_is_removed_only_after_descendant_is_stopped(self):
        original_checked = runtime._checked
        original_remove = shutil.rmtree
        work = None
        child = None
        observed_cleanup = []

        def failing_probe(_command, cwd, env, phase, timeout=180):
            nonlocal work
            work = Path(env["GOTMPDIR"])
            command = ["/bin/sh", "-c",
                       'sleep 60 </dev/null >/dev/null 2>&1 & child=$!; '
                       'printf "%s\\n" "$child" > "$1"; wait "$child"',
                       "workspace-cleanup-test", str(work / "child.pid")]
            return original_checked(command, cwd, env, phase, timeout=0.2)

        def observe_remove(directory):
            nonlocal child
            if Path(directory) != work:
                return original_remove(directory)
            child = int((Path(directory) / "child.pid").read_text().strip())
            observed_cleanup.append(not alive(child))
            original_remove(directory)

        try:
            with mock.patch.object(runtime.shutil, "which", return_value="/bin/sh"):
                with mock.patch.object(runtime, "_checked", side_effect=failing_probe):
                    with mock.patch.object(runtime.shutil, "rmtree", side_effect=observe_remove):
                        with self.assertRaises(runtime.StackFailure):
                            with runtime.prepared_stack():
                                self.fail("timed-out probe must not yield a built workspace")
            self.assertEqual(observed_cleanup, [True],
                             "private build workspace was removed while tool child still lived")
            self.assertFalse(work.exists())
        finally:
            if child is not None and alive(child):
                os.kill(child, signal.SIGKILL)
            if work is not None and work.exists():
                original_remove(work)

    def test_fast_exit_orphan_does_not_escape_checked_in_gate_mode(self):
        for keep_pipe in (False, True):
            with self.subTest(keep_pipe=keep_pipe):
                work = HERE / (".work-orphan-regression-" + secrets.token_hex(8))
                work.mkdir(mode=0o700)
                marker = work / "child.pid"
                redirect = "" if keep_pipe else " >/dev/null 2>&1"
                command = ["/bin/sh", "-c", f"sleep 30{redirect} & echo $! > \"$1\"; exit",
                           "fast-exit-test", str(marker)]
                child = None
                try:
                    with mock.patch.dict(os.environ, {"IDENTITY_TEST_INHERIT_PROCESS_GROUP": "1"}):
                        if keep_pipe:
                            with self.assertRaises(runtime.StackFailure):
                                runtime._checked(command, work, runtime.stack_environment(work), "orphan", timeout=0.2)
                        else:
                            result = runtime._checked(command, work, runtime.stack_environment(work), "orphan", timeout=2)
                            self.assertEqual(result.returncode, 0)
                    child = int(marker.read_text().strip())
                    self.assertFalse(alive(child), "fast-exiting tool orphan survived registered cleanup")
                finally:
                    if child is None and marker.exists():
                        child = int(marker.read_text().strip())
                    if child is not None and alive(child):
                        os.kill(child, signal.SIGKILL)
                    shutil.rmtree(work)

    def test_outer_registry_reaps_real_go_tool_descendants_after_parent_kill(self):
        go = shutil.which("go")
        if not go:
            self.skipTest("Go is required for registered setup-descendant integration")
        work = HERE / (".work-go-owner-regression-" + secrets.token_hex(8))
        work.mkdir(mode=0o700)
        marker = work / "go-child.pid"
        source = work / "fixture.go"
        source.write_text(
            'package main\nimport ("os"; "os/exec"; "strconv")\n'
            'func main() { child := exec.Command("sleep", "30"); '
            'if child.Start() != nil { os.Exit(1) }; '
            'if os.WriteFile(os.Args[1], []byte(strconv.Itoa(child.Process.Pid)), 0600) != nil { os.Exit(1) }; '
            '_ = child.Wait() }\n'
        )
        code = (
            "import pathlib,sys\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "import runtime\n"
            f"work=pathlib.Path({str(work)!r})\n"
            f"runtime._checked({[go, 'run', str(source), str(marker)]!r},work,"
            "runtime.stack_environment(work),'go setup',timeout=30)\n"
        )
        child = None
        try:
            with runtime._processes.owned_process([sys.executable, "-c", code], cwd=work) as owner:
                deadline = time.monotonic() + 15
                while not marker.exists() and time.monotonic() < deadline and owner.poll() is None:
                    time.sleep(0.02)
                self.assertTrue(marker.exists(), "real Go setup command did not spawn its fixture child")
                child = int(marker.read_text().strip())
                self.assertTrue(alive(child))
                owner.kill()
                owner.wait(timeout=2)
            self.assertFalse(alive(child), "outer registry lost a real Go descendant after parent death")
        finally:
            if child is None and marker.exists():
                child = int(marker.read_text().strip())
            if child is not None and alive(child):
                os.kill(child, signal.SIGKILL)
            shutil.rmtree(work)


if __name__ == "__main__":
    unittest.main()
