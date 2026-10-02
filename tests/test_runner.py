"""Contract tests for the coordinator, not evidence of application enforcement."""

import importlib.util
from contextlib import nullcontext
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def descriptor(case_id="browser.one", suite="browser", profiles=None):
    return {
        "id": case_id, "suite": suite, "layer": "ux",
        "profiles": profiles or ["local"], "description": "Exercise actual UX",
        "expected": "An authorized page loads", "mutation": False,
    }


class RunnerContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("matrix_runner", ROOT / "runner.py")
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_matrix_rejects_duplicate_ids(self):
        with self.assertRaises(ValueError):
            self.runner.validate_matrix([descriptor(), descriptor()])

    def test_connected_e2e_is_part_of_default_local_inventory(self):
        self.assertIn("e2e", self.runner.SUITES)
        case = descriptor("e2e.allowed", suite="e2e")
        self.assertEqual(self.runner.validate_matrix([case]), [case])

    def test_adapter_uses_registered_process_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            output.write_text(json.dumps({"cases": [dict(
                descriptor(), status="PASS", observed="verified", duration_seconds=0)]}))
            process = Mock(returncode=0)
            self.assertTrue(hasattr(self.runner, "owned_process"),
                            "Adapter must use the same registered process ownership as the gate")
            with patch.dict(os.environ, {"IDENTITY_TEST_PROCESS_REGISTRY": "fixture-parent"}), \
                    patch.object(self.runner, "owned_process", return_value=nullcontext(process)) as launch:
                self.runner.run_adapter(Path("fixture.py"), [descriptor()], "local", None, output, 10)
            self.assertEqual(launch.call_args.kwargs["env"]["IDENTITY_TEST_PROCESS_REGISTRY"], "fixture-parent")

    def test_inherited_group_timeout_never_signals_own_process_group(self):
        process = Mock()
        self.assertIn("own_group", self.runner.terminate_adapter.__code__.co_varnames,
                      "Inherited process group termination is not yet supported")
        with patch.object(self.runner.os, "killpg") as kill_group:
            self.runner.terminate_adapter(process, own_group=False)
        kill_group.assert_not_called()
        process.terminate.assert_called_once()

    def test_matrix_rejects_empty_selection_inventory(self):
        with self.assertRaises(ValueError):
            self.runner.validate_matrix([])

    def test_matrix_rejects_unknown_profile_and_missing_expected(self):
        for bad in [
            descriptor(profiles=["production"]),
            {key: value for key, value in descriptor().items() if key != "expected"},
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.runner.validate_matrix([bad])

    def test_missing_result_is_failure_not_pass(self):
        results = self.runner.reconcile([descriptor()], {"cases": []}, 0)
        self.assertEqual(results[0]["status"], "FAIL")

    def test_unexpected_result_rejects_entire_adapter_report(self):
        report = {"cases": [
            {"id": "not.in.inventory", "status": "PASS", "observed": "ok", "duration_seconds": 0}
        ]}
        result = self.runner.reconcile([descriptor()], report, 0)
        self.assertEqual(result[0]["status"], "FAIL")

    def test_duplicate_result_cannot_hide_a_failure(self):
        report = {"cases": [
            {"id": "browser.one", "status": status, "observed": "result", "duration_seconds": 0}
            for status in ("FAIL", "PASS")
        ]}
        self.assertEqual(self.runner.reconcile([descriptor()], report, 1)[0]["status"], "FAIL")

    def test_bad_result_schema_fails(self):
        for duration in (-1, "zero", float("nan"), True, 10**400):
            report = {"cases": [
                {"id": "browser.one", "status": "PASS", "observed": "ok",
                 "duration_seconds": duration}
            ]}
            with self.subTest(duration=duration):
                self.assertEqual(self.runner.reconcile([descriptor()], report, 0)[0]["status"], "FAIL")

    def test_unhashable_case_ids_become_failures(self):
        for case_id in ([], {}):
            with self.subTest(case_id=case_id):
                result = self.runner.reconcile([descriptor()], {"cases": [{"id": case_id}]}, 0)
                self.assertEqual(result[0]["status"], "FAIL")

    def test_nonfinite_evidence_becomes_failure(self):
        report = {"cases": [{
            "id": "browser.one", "status": "PASS", "observed": "ok",
            "duration_seconds": 0, "evidence": {"number": float("nan")},
        }]}
        self.assertEqual(self.runner.reconcile([descriptor()], report, 0)[0]["status"], "FAIL")

    def test_nonzero_exit_with_all_passes_cannot_pass(self):
        report = {"cases": [
            {"id": "browser.one", "status": "PASS", "observed": "ok", "duration_seconds": 0}
        ]}
        self.assertEqual(self.runner.reconcile([descriptor()], report, 1)[0]["status"], "FAIL")

    def test_blocked_is_preserved(self):
        report = {"cases": [
            {"id": "browser.one", "status": "BLOCKED",
             "observed": "Browser not installed", "duration_seconds": 0}
        ]}
        self.assertEqual(self.runner.reconcile([descriptor()], report, 2)[0]["status"], "BLOCKED")

    def test_failure_dominates_blocked_and_skips_are_incomplete(self):
        for statuses, expected in [
            (["PASS"], 0), (["BLOCKED"], 2), (["SKIPPED"], 2),
            (["NOT_RUN"], 2), ([], 2), (["PASS", "NOT_RUN"], 0),
            (["BLOCKED", "FAIL"], 1),
        ]:
            with self.subTest(statuses=statuses):
                self.assertEqual(self.runner.exit_code([{"status": s} for s in statuses]), expected)

    def test_reports_do_not_contain_credentials_or_url_queries(self):
        value = {
            "Authorization": "Bearer some-sensitive-value",
            "observed": "GET https://example.test/path?access_token=private#token data",
            "evidence": {"cookie": "secret", "message": "token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature"},
        }
        text = json.dumps(self.runner.redact(value))
        for secret in ("some-sensitive-value", "access_token=private", "#token", "eyJhbGci", '"secret"'):
            self.assertNotIn(secret, text)

    def test_reports_strip_url_credentials_and_private_keys(self):
        value = (
            "https://operator:private-password@example.test/status?secret=yes "
            "-----BEGIN PRIVATE KEY-----\nsensitive-key-data\n-----END PRIVATE KEY-----"
        )
        text = self.runner.redact(value)
        self.assertNotIn("private-password", text)
        self.assertNotIn("sensitive-key-data", text)

    def test_free_text_headers_and_json_credentials_are_redacted(self):
        for text, secret in [
            ("Authorization: Basic cHJpdmF0ZTpwYXNzd29yZA==", "cHJpdmF0ZTpwYXNzd29yZA=="),
            ("Cookie: session=private-cookie; other=private-other", "private-cookie"),
            ('error {"access_token": "private-json-token", "error": "unauthorized"}', "private-json-token"),
            ("client_secret=private-secret response=401", "private-secret"),
        ]:
            with self.subTest(text=text):
                self.assertNotIn(secret, self.runner.redact(text))

    def test_invalid_config_still_reports_every_selected_case_as_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text("invalid config containing private-token")
            output = Path(tmp).resolve() / "results"
            with patch.object(self.runner, "inventory", return_value=[descriptor()]):
                code = self.runner.main(["--config", str(config), "--output", str(output)])
            self.assertEqual(code, 2)
            report = json.loads((output / "matrix.json").read_text())
            self.assertEqual(report["cases"][0]["status"], "BLOCKED")
            self.assertNotIn("private-token", json.dumps(report))

    def test_reports_escape_markup_and_include_unexecuted_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = [
                {**descriptor(), "status": "PASS", "observed": "OK | <script>",
                 "duration_seconds": 0.2},
                {**descriptor("live.one", "live", ["live"]), "status": "NOT_RUN",
                 "observed": "Not selected", "duration_seconds": 0},
            ]
            self.runner.write_reports(Path(tmp), cases, "local", "test-run", {})
            report = json.loads((Path(tmp) / "matrix.json").read_text())
            self.assertEqual(report["summary"]["NOT_RUN"], 1)
            self.assertIn("NOT_RUN", (Path(tmp) / "matrix.md").read_text())
            self.assertNotIn("<script>", (Path(tmp) / "matrix.md").read_text())
            import xml.etree.ElementTree as ET
            xml = ET.parse(Path(tmp) / "junit.xml")
            self.assertEqual(len(xml.findall(".//testcase")), 2)
            self.assertIsNotNone(xml.find(".//skipped"))
            if os.name == "posix":
                self.assertEqual((Path(tmp) / "matrix.json").stat().st_mode & 0o777, 0o600)

    def test_junit_is_parseable_with_ansi_and_control_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = [{**descriptor(), "status": "PASS", "observed": "\x1b[32mOK\x1b[0m\x00",
                      "duration_seconds": 0}]
            self.runner.write_reports(Path(tmp), cases, "local", "run", {})
            import xml.etree.ElementTree as ET
            self.assertEqual(len(ET.parse(Path(tmp) / "junit.xml").findall(".//testcase")), 1)

    def test_output_directory_must_be_new_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                self.runner.prepare_output(Path(tmp))
            link = Path(tmp) / "link"
            link.symlink_to(Path(tmp), target_is_directory=True)
            with self.assertRaises(ValueError):
                self.runner.prepare_output(link)

    def test_adapter_timeout_becomes_results_without_leaking_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "adapter.py"
            script.write_text("import time\nprint('secret', flush=True)\ntime.sleep(10)\n")
            results = self.runner.run_adapter(
                script, [descriptor()], "local", None, Path(tmp) / "result.json", 0.05
            )
            self.assertEqual(results[0]["status"], "FAIL")
            self.assertNotIn("secret", json.dumps(results))

    def test_timeout_replaces_partial_raw_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "adapter.py"
            script.write_text(
                "import time,sys\n"
                "open(sys.argv[sys.argv.index('--output')+1],'w').write('private-token')\n"
                "time.sleep(10)\n"
            )
            output = Path(tmp) / "report.json"
            self.runner.run_adapter(script, [descriptor()], "local", None, output, 0.2)
            self.assertNotIn("private-token", output.read_text())
            self.assertEqual(json.loads(output.read_text())["cases"][0]["status"], "FAIL")
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_unverified_adapter_cleanup_overrides_success(self):
        self.assertTrue(hasattr(self.runner, "ProcessCleanupError"),
                        "Cleanup failure must be represented explicitly")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(self.runner, "owned_process",
                              side_effect=self.runner.ProcessCleanupError("fixture")):
                results = self.runner.run_adapter(
                    Path(tmp) / "script", [descriptor()], "local", None,
                    Path(tmp) / "report.json", 0.1,
                )
            self.assertEqual(results[0]["status"], "FAIL")
            self.assertIn("cleanup", results[0]["observed"])

    def test_git_metadata_launch_errors_do_not_lose_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve() / "report"
            case = {**descriptor(), "status": "PASS", "observed": "ok", "duration_seconds": 0}
            with patch.object(self.runner, "inventory", return_value=[descriptor()]), \
                    patch.object(self.runner, "run_adapter", return_value=[case]), \
                    patch.object(self.runner.subprocess, "run", side_effect=FileNotFoundError):
                self.assertEqual(self.runner.main(["--output", str(output)]), 0)
            self.assertEqual(json.loads((output / "matrix.json").read_text())["summary"]["PASS"], 1)

    def test_adapter_crash_stderr_not_copied_to_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "adapter.py"
            script.write_text("raise RuntimeError('private-token')\n")
            results = self.runner.run_adapter(
                script, [descriptor()], "local", None, Path(tmp) / "result.json", 5
            )
            self.assertEqual(results[0]["status"], "FAIL")
            self.assertNotIn("private-token", json.dumps(results))

    def test_raw_adapter_artifact_is_also_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "adapter.py"
            script.write_text(
                "import json,sys\n"
                "result={'cases':[{'id':'browser.one','status':'PASS',"
                "'observed':'Bearer private-token','duration_seconds':0}]}\n"
                "open(sys.argv[sys.argv.index('--output')+1],'w').write(json.dumps(result))\n"
            )
            output = Path(tmp) / "result.json"
            results = self.runner.run_adapter(script, [descriptor()], "local", None, output, 5)
            self.assertEqual(results[0]["status"], "PASS")
            self.assertNotIn("private-token", output.read_text())


if __name__ == "__main__":
    unittest.main()
