"""Launcher safety regressions; no cloud, dependencies, or product edits."""

import importlib.util
import os
from pathlib import Path
import time
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent


class LauncherTests(unittest.TestCase):
    def runtime(self):
        path = HERE / "runtime.py"
        self.assertTrue(path.is_file(), "connected production-tunnel launcher is missing")
        spec = importlib.util.spec_from_file_location("stack_runtime_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_backend_requires_numeric_loopback_http_and_explicit_port(self):
        runtime = self.runtime()
        for url in (
            "https://example.org:443", "http://localhost:8000",
            "http://169.254.169.254:80", "http://127.0.0.1",
            "http://user:secret@127.0.0.1:8000", "http://127.0.0.1:8000/path",
            "http://127.0.0.1:8000/?x=1", "http://127.0.0.1:0",
            "http://127.0.0.1:8000/#fragment", "http://[::1]:8000",
        ):
            with self.subTest(url=url), self.assertRaises(runtime.StackFailure):
                runtime.validate_backend_url(url)
        self.assertEqual(runtime.validate_backend_url("http://127.0.0.1:8000"),
                         "http://127.0.0.1:8000")

    def test_missing_tools_are_blocked_without_installation(self):
        runtime = self.runtime()
        self.assertTrue(hasattr(runtime, "StackUnavailable"),
                        "parent-facing prerequisite exception is missing")
        self.assertTrue(issubclass(runtime.StackUnavailable, RuntimeError))
        self.assertFalse(issubclass(runtime.StackUnavailable, runtime.StackFailure))
        with mock.patch.object(runtime.shutil, "which", return_value=None):
            with self.assertRaises(runtime.StackUnavailable):
                with runtime.prepared_stack():
                    self.fail("missing Go/protoc must not yield a runnable stack")

    def test_environment_is_offline_and_does_not_inherit_cloud_secrets(self):
        runtime = self.runtime()
        with mock.patch.dict(runtime.os.environ, {
            "AZURE_CLIENT_SECRET": "do-not-inherit", "MGMT_API_KEY": "do-not-inherit",
            "HTTP_PROXY": "http://example.invalid", "GOFLAGS": "-toolexec=bad",
            "SPIFFE_PREFIX_BUDGET_REPORT": "unrelated-identity",
        }):
            env = runtime.stack_environment(HERE)
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOVCS"], "*:off")
        self.assertEqual(env["GONOPROXY"], "none")
        self.assertEqual(env["GOFLAGS"], "")
        for name in ("AZURE_CLIENT_SECRET", "MGMT_API_KEY", "HTTP_PROXY",
                     "SPIFFE_PREFIX_BUDGET_REPORT"):
            self.assertNotIn(name, env)
        self.assertTrue(Path(env["GOTMPDIR"]).is_relative_to(HERE))

    def test_readiness_is_a_closed_typed_loopback_schema(self):
        runtime = self.runtime()
        valid = {
            "egress_url": "http://127.0.0.1:12001",
            "management_url": "http://127.0.0.1:12002",
            "control_url": "http://127.0.0.1:12003",
            "caller_spiffe_id": runtime.CALLER_SPIFFE_ID,
            "audience": runtime.AUDIENCE,
        }
        self.assertEqual(runtime.validate_ready(valid), valid)
        for change in (
            {"token": "not-for-reports"}, {"egress_url": "http://example.org:80"},
            {"audience": 1}, {"caller_spiffe_id": "spiffe://unrelated.test/caller"},
            {"management_url": valid["egress_url"]},
        ):
            with self.subTest(change=change), self.assertRaises(runtime.StackFailure):
                runtime.validate_ready(dict(valid, **change))

    def test_partial_readiness_cannot_wait_forever(self):
        runtime = self.runtime()
        self.assertTrue(hasattr(runtime, "read_ready"), "bounded readiness framing is missing")
        self.assertTrue(hasattr(runtime, "StackUnavailable"),
                        "parent-facing startup exception is missing")
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"partial":')
            started = time.monotonic()
            with os.fdopen(read_fd, "rb", buffering=0) as pipe:
                with self.assertRaises(runtime.StackUnavailable):
                    runtime.read_ready(pipe, timeout=0.05)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(write_fd)

    def test_prerequisite_failures_and_timeouts_are_not_pass(self):
        runtime = self.runtime()
        invoke = runtime.invoke_tool
        with mock.patch.object(runtime, "invoke_tool",
                               side_effect=runtime.subprocess.TimeoutExpired("go", 1)):
            with self.assertRaises(runtime.StackFailure):
                runtime._checked(["go"], HERE, {}, "test", timeout=1)
        for marker in ("module lookup disabled by GOPROXY=off", "requires go >= 1.24"):
            completed = runtime.subprocess.CompletedProcess(["go"], 1, "", marker)
            with mock.patch.object(runtime, "invoke_tool", return_value=completed):
                with self.assertRaises(runtime.StackBlocked):
                    runtime._checked(["go"], HERE, {}, "build")
        self.assertIs(runtime.invoke_tool, invoke)

    def test_stack_launch_delegates_to_registered_group_ownership(self):
        runtime = self.runtime()
        built = {"binary": HERE / "unused", "directory": HERE, "env": {}}
        for inherit in ("1", "0", ""):
            with mock.patch.dict(runtime.os.environ, {"IDENTITY_TEST_INHERIT_PROCESS_GROUP": inherit}):
                with mock.patch.object(runtime._processes, "owned_process") as owned:
                    with runtime.start_stack(built, "http://127.0.0.1:8000") as process:
                        self.assertIs(process, owned.return_value.__enter__.return_value)
                    self.assertNotIn("start_new_session", owned.call_args.kwargs)
                    self.assertEqual(owned.call_args.kwargs["env"], built["env"])

    def test_unittest_wrappers_skip_unavailable_but_do_not_hide_go_failures(self):
        spec = importlib.util.spec_from_file_location("stack_connected_wrapper_test", HERE / "test_connected.py")
        connected = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(connected)
        cases = (
            ("test_context_serves_real_stack_and_removes_ephemeral_process_state", "running_stack"),
            ("test_actual_go_topology_self_test", "self_test"),
        )
        for name, operation in cases:
            self.assertTrue(hasattr(connected.ConnectedLauncherTests, name),
                            "Go topology self-test needs a discoverable unittest wrapper")
            for unavailable in (True, False):
                error_type = (connected.runtime.StackUnavailable if unavailable
                              else connected.runtime.StackFailure)
                result = unittest.TestResult()
                with mock.patch.object(connected.runtime, operation, side_effect=error_type("controlled failure")):
                    connected.ConnectedLauncherTests(name).run(result)
                self.assertEqual(len(result.skipped), 1 if unavailable else 0)
                self.assertEqual(len(result.errors) + len(result.failures), 0 if unavailable else 1)


if __name__ == "__main__":
    unittest.main()
