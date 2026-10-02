"""Safety tests for the dependency-free protocol adapter."""

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("protocol_adapter", HERE / "run.py")
        if not (HERE / "run.py").exists():
            cls.adapter = None
        else:
            cls.adapter = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.adapter)

    def adapter_module(self):
        self.assertIsNotNone(self.adapter, "protocol adapter has not been implemented")
        return self.adapter

    def selected(self):
        return self.adapter_module().descriptors()[:2]

    def events(self, cases, action="pass", package_action="pass"):
        module = self.adapter_module()
        rows = []
        for case in cases:
            rows.extend([
                {"Action": "run", "Package": module.TEST_PACKAGE, "Test": module.test_name(case)},
                {"Action": action, "Package": module.TEST_PACKAGE,
                 "Test": module.test_name(case), "Elapsed": 0.125},
            ])
        rows.append({"Action": package_action, "Package": module.TEST_PACKAGE})
        return "\n".join(json.dumps(row) for row in rows)

    def test_inventory_is_stable_unique_and_complete(self):
        module = self.adapter_module()
        inventory = module.descriptors()
        self.assertGreaterEqual(len(inventory), 30)
        self.assertEqual(len(inventory), len({case["id"] for case in inventory}))
        for case in inventory:
            self.assertEqual(case["suite"], "protocols")
            self.assertEqual(case["profiles"], ["local"])
            self.assertFalse(case["mutation"])
            self.assertTrue(case["description"])
            self.assertTrue(case["expected"])
            self.assertTrue(module.test_name(case).startswith("Test"))

    def test_copied_module_replacement_quotes_paths_with_spaces(self):
        module = self.adapter_module()
        with tempfile.TemporaryDirectory(prefix="protocol path ") as directory:
            def invoke(command, cwd, _env, **_kwargs):
                if command[1:3] == ["env", "GOPATH"]:
                    return subprocess.CompletedProcess(command, 0, "/fixture/go", "")
                if command[1] == "test":
                    contents = (Path(cwd) / "go.mod").read_text()
                    self.assertIn("=> " + json.dumps(str(Path(directory) / "proxy")), contents)
                    return subprocess.CompletedProcess(command, 0, self.events(module.descriptors()), "")
                return subprocess.CompletedProcess(command, 0, "", "")
            with patch.object(module.tempfile, "TemporaryDirectory",
                              return_value=contextlib.nullcontext(directory)), \
                    patch.object(module.shutil, "which", return_value="/fixture/tool"), \
                    patch.object(module, "resolve_plugin", return_value="/fixture/plugin"), \
                    patch.object(module, "invoke", side_effect=invoke):
                results = module.run_cases("local")
            self.assertTrue(all(row["status"] == "PASS" for row in results))

    def test_go_commands_use_registered_cleanup_scope(self):
        module = self.adapter_module()
        self.assertTrue(hasattr(module, "owned_process"), "Go tooling needs registered process ownership")
        process = Mock(returncode=0)
        process.communicate.return_value = ("fixture-output", "")
        with patch.object(module, "owned_process", return_value=contextlib.nullcontext(process)) as scope:
            result = module.invoke(["go", "env", "GOPATH"], HERE, {}, timeout=5)
        self.assertEqual(result.stdout, "fixture-output")
        process.communicate.assert_called_once_with(timeout=5)
        self.assertEqual(scope.call_args.args[0], ["go", "env", "GOPATH"])

    def test_only_completed_actual_tests_pass(self):
        cases = self.selected()
        results = self.adapter.parse_results(self.events(cases), 0, cases)
        self.assertEqual([r["status"] for r in results], ["PASS", "PASS"])
        self.assertEqual([r["duration_seconds"] for r in results], [0.125, 0.125])

    def test_empty_output_and_zero_tests_never_pass(self):
        for output in ("", "ok package [no test files]", '{"Action":"pass","Package":"other"}'):
            with self.subTest(output=output):
                results = self.adapter_module().parse_results(output, 0, self.selected())
                self.assertEqual([r["status"] for r in results], ["FAIL", "FAIL"])

    def test_missing_case_never_passes(self):
        cases = self.selected()
        results = self.adapter.parse_results(self.events(cases[:1]), 0, cases)
        self.assertEqual([r["status"] for r in results], ["PASS", "FAIL"])

    def test_build_error_never_passes_and_is_sanitized(self):
        secret = "Bearer do-not-publish-this-secret"
        results = self.adapter_module().parse_results(secret, 1, self.selected())
        self.assertTrue(all(r["status"] == "FAIL" for r in results))
        self.assertNotIn(secret, json.dumps(results))

    def test_failure_preserved_without_raw_logs(self):
        cases = self.selected()
        output = self.events(cases, action="fail", package_action="fail")
        output += '\n' + json.dumps({"Action": "output", "Output": "secret-token"})
        results = self.adapter.parse_results(output, 1, cases)
        self.assertEqual([r["status"] for r in results], ["FAIL", "FAIL"])
        self.assertNotIn("secret-token", json.dumps(results))

    def test_skip_is_not_pass(self):
        cases = self.selected()
        results = self.adapter.parse_results(self.events(cases, action="skip"), 0, cases)
        self.assertEqual([r["status"] for r in results], ["SKIPPED", "SKIPPED"])

    def test_wrong_package_cannot_spoof_success(self):
        cases = self.selected()
        output = self.events(cases).replace(self.adapter.TEST_PACKAGE, "unrelated")
        self.assertTrue(all(r["status"] == "FAIL" for r in self.adapter.parse_results(output, 0, cases)))

    def test_missing_package_completion_invalidates_success(self):
        cases = self.selected()
        output = "\n".join(self.events(cases).splitlines()[:-1])
        self.assertTrue(all(r["status"] == "FAIL" for r in self.adapter.parse_results(output, 0, cases)))

    def test_unattributed_process_error_invalidates_success(self):
        cases = self.selected()
        results = self.adapter.parse_results(self.events(cases), 1, cases)
        self.assertTrue(all(r["status"] == "FAIL" for r in results))

    def test_failures_do_not_erase_completed_passes(self):
        cases = self.selected()
        rows = self.events(cases[:1], package_action="fail").splitlines()[:-1]
        rows.extend(self.events(cases[1:], action="fail", package_action="fail").splitlines())
        results = self.adapter.parse_results("\n".join(rows), 1, cases)
        self.assertEqual([r["status"] for r in results], ["PASS", "FAIL"])

    def test_bad_elapsed_or_duplicate_terminal_event_fails(self):
        cases = self.selected()
        for output in (
            self.events(cases).replace("0.125", "-3"),
            self.events(cases).replace("0.125", "NaN"),
            self.events(cases).replace("0.125", str(10**400)),
            self.events(cases) + "\n" + self.events(cases),
        ):
            results = self.adapter.parse_results(output, 0, cases)
            self.assertTrue(all(r["status"] == "FAIL" for r in results))

    def test_missing_tools_block_every_selected_case(self):
        module = self.adapter_module()
        with patch.object(module.shutil, "which", return_value=None):
            results = module.run_cases("local")
        self.assertEqual(len(results), len(module.descriptors()))
        self.assertTrue(all(r["status"] == "BLOCKED" for r in results))
        self.assertEqual(module.exit_status(results), 2)

    def plugin_resolver(self):
        resolver = getattr(self.adapter_module(), "resolve_plugin", None)
        self.assertIsNotNone(resolver, "Isolated plugin resolver has not been implemented")
        return resolver

    def test_isolated_plugin_precedes_path(self):
        resolver = self.plugin_resolver()
        with tempfile.TemporaryDirectory() as directory:
            isolated = Path(directory)
            plugin = isolated / "protoc-gen-go"
            plugin.write_text("fixture executable", encoding="utf-8")
            plugin.chmod(0o700)
            with patch.object(self.adapter, "TOOLS_BIN", isolated), \
                    patch.object(self.adapter.shutil, "which", return_value="/global/plugin") as which:
                self.assertEqual(resolver("protoc-gen-go", "/unused"), str(plugin))
                which.assert_not_called()

    def test_nonexecutable_isolated_plugin_falls_back_to_path(self):
        resolver = self.plugin_resolver()
        with tempfile.TemporaryDirectory() as directory:
            isolated = Path(directory)
            plugin = isolated / "protoc-gen-go"
            plugin.write_text("not executable", encoding="utf-8")
            plugin.chmod(0o600)
            with patch.object(self.adapter, "TOOLS_BIN", isolated), \
                    patch.object(self.adapter.shutil, "which", return_value="/global/plugin"):
                self.assertEqual(resolver("protoc-gen-go", "/unused"), "/global/plugin")

    def test_plugin_gopath_fallback_and_missing(self):
        resolver = self.plugin_resolver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "workspace" / "bin" / "protoc-gen-go-grpc"
            plugin.parent.mkdir(parents=True)
            plugin.write_text("fixture executable", encoding="utf-8")
            plugin.chmod(0o700)
            with patch.object(self.adapter, "TOOLS_BIN", root / "isolated"), \
                    patch.object(self.adapter.shutil, "which", return_value=None):
                gopath = os.pathsep.join((str(root / "absent"), str(root / "workspace")))
                self.assertEqual(resolver("protoc-gen-go-grpc", gopath), str(plugin))
                self.assertIsNone(resolver("protoc-gen-go", gopath))
                self.assertIsNone(resolver("protoc-gen-go", ""))

    def test_runner_uses_isolated_plugin_resolver(self):
        self.plugin_resolver()
        module = self.adapter_module()
        with patch.object(module.shutil, "which", return_value="/fixture/tool"), \
                patch.object(module, "invoke", return_value=subprocess.CompletedProcess(
                    [], 0, stdout="/fixture/gopath\n", stderr="")), \
                patch.object(module, "resolve_plugin", return_value=None) as resolve:
            results = module.run_cases("local")
        resolve.assert_called_once_with("protoc-gen-go", "/fixture/gopath")
        self.assertEqual(len(results), len(module.descriptors()))
        self.assertTrue(all(case["status"] == "BLOCKED" for case in results))

    def test_live_does_not_run_local_evidence(self):
        module = self.adapter_module()
        with patch.object(module.subprocess, "run", side_effect=AssertionError("must not execute")):
            self.assertEqual(module.run_cases("live"), [])

    def test_status_precedence(self):
        module = self.adapter_module()
        for statuses, code in [
            (["PASS"], 0), (["SKIPPED"], 2), (["BLOCKED"], 2),
            (["FAIL", "BLOCKED"], 1), (["FAIL", "SKIPPED"], 1),
            (["PASS", "SKIPPED"], 2), ([], 2),
        ]:
            with self.subTest(statuses=statuses):
                self.assertEqual(module.exit_status([{"status": s} for s in statuses]), code)

    def invoke_main(self, output):
        module = self.adapter_module()
        stderr = io.StringIO()
        with patch.object(sys, "argv", ["run.py", "--profile", "local", "--output", str(output)]), \
                patch.object(module, "run_cases", return_value=[{
                    "id": "protocols.mtls.allowed", "status": "PASS",
                    "observed": "sanitized", "duration_seconds": 0.1,
                }]), contextlib.redirect_stderr(stderr):
            code = module.main()
        return code, stderr.getvalue()

    def test_output_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private-target-name"
            target.write_text("must remain unchanged", encoding="utf-8")
            link = Path(directory) / "report.json"
            link.symlink_to(target)
            code, stderr = self.invoke_main(link)
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "must remain unchanged")
            self.assertTrue(link.is_symlink())
            self.assertNotIn(str(target), stderr)
            self.assertNotIn(str(link), stderr)
            self.assertNotIn("Traceback", stderr)

    def test_existing_output_permissions_are_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("old report", encoding="utf-8")
            output.chmod(0o644)
            code, stderr = self.invoke_main(output)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text())["cases"][0]["status"], "PASS")

    def test_output_hardlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private-target"
            target.write_text("must remain unchanged", encoding="utf-8")
            output = Path(directory) / "report.json"
            os.link(target, output)
            code, stderr = self.invoke_main(output)
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "must remain unchanged")
            self.assertNotIn(str(target), stderr)

    def test_output_directory_error_is_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            code, stderr = self.invoke_main(Path(directory))
            self.assertEqual(code, 2)
            self.assertNotIn(directory, stderr)
            self.assertNotIn("Traceback", stderr)

    def test_list_has_no_dependency_probe(self):
        self.adapter_module()
        result = subprocess.run(
            [sys.executable, str(HERE / "run.py"), "--list"],
            env={"PATH": ""}, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.adapter.descriptors())

    def test_evidence_accepts_only_sanitized_typed_values(self):
        cases = self.selected()
        event = {"Action": "output", "Package": self.adapter.TEST_PACKAGE,
                 "Test": self.adapter.test_name(cases[0]),
                 "Output": 'fixture_test.go:1: PROTOCOL_EVIDENCE {"action":"deny","layer":"rbac","status_code":403}\n'}
        output = self.events(cases) + "\n" + json.dumps(event)
        results = self.adapter.parse_results(output, 0, cases)
        self.assertEqual(results[0]["evidence"]["actual"]["status_code"], 403)
        self.assertIn("action=deny", results[0]["observed"])
        for payload in (
            {"action": "secret-token", "layer": "rbac", "status_code": 403},
            {"action": "deny", "layer": "rbac", "status_code": "secret-token"},
            {"action": "deny", "secret": "secret-token"},
            {"backend_requests": -1},
            {"backend_requests": True},
        ):
            event["Output"] = "PROTOCOL_EVIDENCE " + json.dumps(payload)
            result = self.adapter.parse_results(self.events(cases) + "\n" + json.dumps(event), 0, cases)
            self.assertNotIn("secret-token", json.dumps(result))
            self.assertNotIn("actual", result[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
