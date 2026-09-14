"""Small, offline contracts for the unattended gate; never run the real matrix."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent


def descriptor(case_id="browser.one", suite="browser", profiles=None):
    return {
        "id": case_id, "suite": suite, "profiles": profiles or ["local"],
        "layer": "test-fixture", "description": "Offline gate fixture",
        "expected": "Fixture executes", "mutation": False,
    }


class CheckContracts(unittest.TestCase):
    def setUp(self):
        path = ROOT / "check.py"
        self.assertTrue(path.is_file(), "The unattended check orchestrator is missing")
        spec = importlib.util.spec_from_file_location("unattended_check", path)
        self.check = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.check)
        artifacts = ROOT / "artifacts"
        artifacts.mkdir(mode=0o700, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="check-selftest-", dir=artifacts)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.unit = self.root / "unit"
        self.unit.mkdir()
        (self.unit / "test_fixture.py").write_text(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    def test_ok(self): self.assertTrue(True)\n"
        )
        self.cases = [
            descriptor(), descriptor("e2e.one", "e2e"),
            descriptor("live.one", "live", ["live"]),
        ]
        self.modes = [{}, {}]
        (self.root / "e2e").mkdir()
        (self.root / "e2e" / "run.py").write_text("# available fixture adapter\n")
        (self.root / "run.py").write_text(textwrap.dedent(f"""\
            import json, os, pathlib, sys
            sys.path.insert(0, {str(ROOT)!r})
            import runner
            root = pathlib.Path(__file__).parent
            with (root / 'calls.jsonl').open('a') as stream:
                stream.write(json.dumps(sys.argv[1:]) + '\\n')
            cases = json.loads((root / 'cases.json').read_text())
            if '--list' in sys.argv:
                print(json.dumps(cases))
                raise SystemExit(0)
            assert sys.argv[sys.argv.index('--profile') + 1] == 'local'
            assert '--config' not in sys.argv
            output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
            index = int(output.name.split('-')[-1]) - 1
            mode = json.loads((root / 'modes.json').read_text())[index]
            directory = runner.prepare_output(output)
            print('password=private-stdout-secret')
            print('private-stderr-secret', file=sys.stderr)
            if mode.get('missing_report'):
                raise SystemExit(mode.get('returncode', 0))
            rows = [
                runner.outcome(c, mode.get('status', 'PASS') if 'local' in c['profiles']
                               else 'NOT_RUN', mode.get('observed', 'fixture'), 0.01)
                for c in cases
            ]
            if mode.get('change_id'):
                rows[0]['id'] = 'browser.changed'
            metadata = {{
                **json.loads((root / 'source.json').read_text()),
                'selected_suites': list(runner.SUITES),
                'selected_count': sum('local' in c['profiles'] for c in cases),
                'python_version': sys.version.split()[0],
            }}
            report = runner.write_reports(directory, rows, 'local', 'fixture-' + str(index), metadata)
            report.update(mode.get('report_fields', {{}}))
            report['metadata'].update(mode.get('source_fields', {{}}))
            if mode.get('bad_summary'):
                report['summary']['PASS'] = 999
            if mode.get('bad_metadata'):
                report['metadata']['selected_count'] = 0
            if mode.get('bad_profile'):
                report['profile'] = 'live'
            if mode.get('symlink_report'):
                (directory / 'matrix.json').unlink()
                (directory / 'matrix.json').symlink_to(root / 'cases.json')
            else:
                (directory / 'matrix.json').write_text(json.dumps(report))
            raise SystemExit(mode.get('returncode', report['exit_code']))
        """))

    def run_gate(self, **kwargs):
        (self.root / "cases.json").write_text(json.dumps(self.cases))
        (self.root / "modes.json").write_text(json.dumps(self.modes))
        (self.root / "source.json").write_text(json.dumps(self.check.runner.git_metadata()))
        output = kwargs.pop("output", self.root / kwargs.pop("name", "result"))
        console = io.StringIO()
        with patch.object(self.check, "ROOT", self.root), \
                patch.object(self.check, "GROUPS", (("fixture", "unit", "test_*.py"),)), \
                patch.object(self.check, "source_digest", create=True, return_value="0" * 64,
                             side_effect=kwargs.pop("source_digests", None)), \
                redirect_stdout(console), redirect_stderr(console):
            code = self.check.main(["--repeat", "2", "--output", str(output), *kwargs.pop("args", [])])
        self.assertEqual(kwargs, {})
        report = json.loads((output / "check.json").read_text())
        self.assertEqual(code, report["exit_code"])
        return code, report, output, console.getvalue()

    def test_stable_pass_is_ready_with_fresh_reports_and_counts(self):
        code, report, output, _ = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "READY")
        self.assertEqual(report["stability"]["status"], "STABLE")
        unit = next(step for step in report["steps"] if step["id"] == "unit.fixture")
        self.assertEqual(unit["counts"]["tests"], 1)
        self.assertEqual(unit["counts"]["skipped"], 0)
        runs = [step for step in report["steps"] if step["id"].startswith("run-")]
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(step["counts"]["PASS"] == 2 for step in runs))
        self.assertTrue(all(step["counts"]["NOT_RUN"] == 1 for step in runs))
        for index in (1, 2):
            self.assertTrue((output / f"run-{index}" / "matrix.json").is_file())
            self.assertIn(f"run-{index}/matrix.md", (output / "check.md").read_text())
        if os.name == "posix":
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "check.json").stat().st_mode & 0o777, 0o600)

    def test_summary_records_source_metadata_and_private_report_locations(self):
        metadata = {"source_commit": "1234567890abcdef", "worktree_dirty": True}
        with patch.object(self.check.runner, "git_metadata", return_value=metadata):
            _, report, output, _ = self.run_gate()
        self.assertIn("metadata", report)
        self.assertEqual(report["metadata"]["source_commit"], metadata["source_commit"])
        self.assertIs(report["metadata"]["worktree_dirty"], True)
        self.assertEqual(report["metadata"]["python_version"], sys.version.split()[0])
        self.assertEqual(report["reports"]["json"], str(output / "check.json"))
        self.assertEqual(report["reports"]["markdown"], str(output / "check.md"))
        self.assertIn(metadata["source_commit"], (output / "check.md").read_text())

    def test_reproducible_failures_are_red_not_an_accepted_baseline(self):
        self.modes = [{"status": "FAIL"}, {"status": "FAIL"}]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["stability"]["status"], "REPRODUCIBLE_FAILURE")
        self.assertIn("e2e.one", report["stability"]["stable_failures"])
        self.assertEqual(len([s for s in report["steps"] if s["id"].startswith("run-")]), 2)

    def test_changed_outcomes_are_unstable_even_if_last_passes(self):
        self.modes = [{"status": "FAIL"}, {}]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(report["stability"]["status"], "UNSTABLE")
        self.assertEqual(report["stability"]["changes"]["e2e.one"], ["FAIL", "PASS"])

    def test_changed_ids_are_invalid_and_unstable(self):
        self.modes = [{}, {"change_id": True}]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(report["stability"]["status"], "UNSTABLE")

    def test_observation_text_and_duration_do_not_define_stability(self):
        self.modes = [{"observed": "port 41230"}, {"observed": "port 41888"}]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(report["stability"]["status"], "STABLE")

    def test_old_future_and_wrong_source_reports_are_rejected_before_stability(self):
        modes = (
            {"report_fields": {"created_at": "2000-01-01T00:00:00+00:00"}},
            {"report_fields": {"created_at": "2999-01-01T00:00:00+00:00"}},
            {"source_fields": {"source_commit": "different-source"}},
            {"source_fields": {"worktree_dirty": "not-a-boolean"}},
            {"source_fields": {"worktree_dirty": not self.check.runner.git_metadata()["worktree_dirty"]}},
        )
        for index, mode in enumerate(modes):
            self.modes = [mode, {}]
            with self.subTest(mode=mode):
                code, report, _, _ = self.run_gate(name=f"freshness-{index}")
                self.assertEqual(code, 1)
                self.assertEqual(report["stability"]["status"], "INCOMPLETE")
                self.assertEqual(next(s for s in report["steps"] if s["id"] == "run-1")["status"], "FAIL")

    def test_reused_matrix_run_id_is_rejected_even_with_fresh_timestamps(self):
        self.modes = [{"report_fields": {"run_id": "reused"}}, {"report_fields": {"run_id": "reused"}}]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertEqual(report["stability"]["status"], "INCOMPLETE")
        self.assertEqual(next(s for s in report["steps"] if s["id"] == "run-2")["status"], "FAIL")

    def test_dirty_source_changes_between_repeats_invalidate_comparison(self):
        code, report, _, _ = self.run_gate(source_digests=["0" * 64, "1" * 64, "1" * 64])
        self.assertEqual(code, 1)
        self.assertEqual(report["stability"]["status"], "INCOMPLETE")

    def test_source_digest_hashes_actual_listed_bytes_and_not_ignored_state(self):
        listing = subprocess.CompletedProcess([], 0, stdout=b"unit/test_fixture.py\0")
        with patch.object(self.check.subprocess, "run", return_value=listing) as command:
            before = self.check.source_digest(self.root)
            (self.root / "private-ignored-state.json").write_text('{"private": "not-source"}')
            self.assertEqual(before, self.check.source_digest(self.root))
            (self.unit / "test_fixture.py").write_text("# different uncommitted source\n")
            self.assertNotEqual(before, self.check.source_digest(self.root))
        self.assertIn("--exclude-standard", command.call_args.args[0])
        self.assertIn("tests", command.call_args.args[0])
        self.assertNotIn(".azure", command.call_args.args[0])

    def test_security_portal_source_is_fingerprinted_but_private_state_is_not(self):
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        portal = self.root / "portal"
        portal.mkdir()
        (portal / "app.py").write_text("# management source\n")
        security = self.root / "securityportal-mock"
        security.mkdir()
        application = security / "server.py"
        application.write_text("# security source before\n")
        before = self.check.source_digest(self.root)
        application.write_text("# security source after\n")
        after = self.check.source_digest(self.root)
        self.assertNotEqual(before, after)
        for folder in (".auth", ".work"):
            private = security / folder
            private.mkdir()
            (private / "state.json").write_text('{"private": "fixture-only"}')
        self.assertEqual(after, self.check.source_digest(self.root))

    def test_source_fingerprint_failure_blocks_matrix_without_stopping_selftests(self):
        code, report, output, _ = self.run_gate(source_digests=[None])
        self.assertEqual(code, 2)
        self.assertFalse((output / "run-1").exists())
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["status"], "PASS")

    def test_skipped_unittest_never_makes_gate_ready(self):
        (self.unit / "test_fixture.py").write_text(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    @unittest.skip('dependency missing')\n"
            "    def test_skip(self): pass\n"
        )
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "INCOMPLETE")
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["counts"]["skipped"], 1)
        self.assertNotEqual(unit["status"], "PASS")

    def test_missing_python_dependency_is_blocked_not_a_traceback(self):
        (self.unit / "test_fixture.py").write_text("import nonexistent_gate_fixture_dependency\n")
        code, report, _, console = self.run_gate()
        self.assertEqual(code, 2)
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["status"], "BLOCKED")
        self.assertEqual(unit["counts"]["errors"], 1)
        self.assertNotIn("Traceback", console)

    def test_unittest_failures_do_not_stop_matrix_repeats(self):
        (self.unit / "test_fixture.py").write_text(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    def test_fail(self): self.fail('password=private-assertion')\n"
        )
        code, report, output, console = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue((output / "run-2" / "matrix.json").is_file())
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["counts"]["failures"], 1)
        self.assertNotIn("private-assertion", json.dumps(report) + console)

    def test_empty_unittest_discovery_is_incomplete(self):
        (self.unit / "test_fixture.py").write_text("# no tests\n")
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_stopped_real_suite_is_incomplete_even_after_a_passing_test(self):
        (self.unit / "test_fixture.py").write_text(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    def run(self, result=None):\n"
            "        completed = super().run(result)\n"
            "        result.stop()\n"
            "        return completed\n"
            "    def test_first(self): self.assertTrue(True)\n"
            "    def test_second(self): self.fail('must not execute after stop')\n"
        )
        code, report, _, _ = self.run_gate()
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["counts"]["discovered"], 2)
        self.assertEqual(unit["counts"]["tests"], 1)
        self.assertEqual(unit["counts"]["failures"], 0)
        self.assertEqual(code, 2)
        self.assertEqual(unit["status"], "INCOMPLETE")

    def test_expected_failure_does_not_turn_a_regression_green(self):
        (self.unit / "test_fixture.py").write_text(
            "import unittest\n"
            "class Fixture(unittest.TestCase):\n"
            "    @unittest.expectedFailure\n"
            "    def test_defect(self): self.fail('defect')\n"
        )
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_matrix_blocked_and_skipped_are_incomplete(self):
        for status in ("BLOCKED", "SKIPPED", "NOT_RUN"):
            self.modes = [{"status": status}, {"status": status}]
            with self.subTest(status=status):
                code, report, _, _ = self.run_gate(name=status)
                self.assertIn(code, (1, 2))
                self.assertNotEqual(report["status"], "READY")

    def test_missing_report_and_exit_disagreement_fail_but_continue(self):
        for mode in (
            {"missing_report": True}, {"returncode": 1},
            {"status": "FAIL", "returncode": 0},
        ):
            self.modes = [mode, {}]
            with self.subTest(mode=mode):
                code, report, output, _ = self.run_gate(name="case-" + str(len(list(self.root.glob("case-*")))))
                self.assertEqual(code, 1)
                self.assertTrue((output / "run-2" / "matrix.json").exists())
                first = next(s for s in report["steps"] if s["id"] == "run-1")
                self.assertEqual(first["status"], "FAIL")

    def test_schema_summary_profile_metadata_and_symlinks_are_checked(self):
        for problem in ("bad_summary", "bad_profile", "bad_metadata", "symlink_report"):
            self.modes = [{problem: True}, {}]
            with self.subTest(problem=problem):
                code, _, _, _ = self.run_gate(name=problem)
                self.assertEqual(code, 1)

    def test_empty_inventory_fails_and_never_launches_matrix(self):
        self.cases = []
        code, report, output, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertFalse((output / "run-1").exists())
        self.assertTrue(any(s["id"] == "unit.fixture" for s in report["steps"]))

    def test_missing_e2e_marks_gate_incomplete_without_blocking_selftests(self):
        self.cases = [c for c in self.cases if c["suite"] != "e2e"]
        code, report, _, _ = self.run_gate()
        self.assertEqual(code, 2)
        self.assertNotEqual(report["status"], "READY")
        unit = next(s for s in report["steps"] if s["id"] == "unit.fixture")
        self.assertEqual(unit["status"], "PASS")
        self.assertTrue(any("E2E" in s["detail"] for s in report["steps"]))

    def test_every_invocation_is_explicitly_local_without_config_or_mutation_flags(self):
        self.run_gate()
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls[0], ["--list"])
        self.assertEqual(len(calls), 3)
        for call in calls[1:]:
            self.assertEqual(call[call.index("--profile") + 1], "local")
            self.assertNotIn("--config", call)
            self.assertFalse(any("mutation" in value for value in call))

    def test_unsafe_browser_environment_blocks_all_commands_and_writes_safe_reports(self):
        for name in ("DEBUG", "PWDEBUG", "DEBUG_FILE", "NODE_OPTIONS",
                     "SELENIUM_REMOTE_URL", "SELENIUM_REMOTE_HEADERS", "SELENIUM_REMOTE_CAPABILITIES"):
            value = "private-browser-environment-fixture"
            with self.subTest(name=name), patch.dict(os.environ, {name: value}), \
                    patch.object(self.check, "run_command", return_value={
                        "returncode": 0, "timed_out": False, "launch_error": False,
                        "cleanup_error": False, "duration_seconds": 0,
                    }) as command:
                code, report, output, console = self.run_gate(name="blocked-" + name)
                self.assertEqual(code, 2)
                command.assert_not_called()
                self.assertEqual(report["steps"][0]["status"], "BLOCKED")
                self.assertFalse(any(s["id"].startswith("unit.") for s in report["steps"]))
                self.assertEqual(os.environ[name], value)
                self.assertNotIn(value, json.dumps(report) + (output / "check.md").read_text() + console)

    def test_child_unittest_entry_rejects_unsafe_environment_before_discovery(self):
        marker = self.root / "imported-marker"
        (self.unit / "test_fixture.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('imported')\n"
            "import unittest\nclass Fixture(unittest.TestCase):\n"
            "    def test_ok(self): pass\n"
        )
        output = self.root / "blocked-unit.json"
        with patch.dict(os.environ, {"SELENIUM_REMOTE_HEADERS": "private-fixture-headers"}):
            code = self.check.run_unittests(self.unit, "test_*.py", output, "fixture")
        self.assertEqual(code, 2)
        self.assertFalse(marker.exists())
        self.assertNotIn("private-fixture-headers", output.read_text())

    def test_private_summary_redacts_observations_and_omits_raw_logs(self):
        secret = "sensitive-environment-value"
        self.modes = [
            {"status": "FAIL", "observed": "Authorization: Bearer private-matrix-secret " + secret},
            {"status": "FAIL", "observed": "password=private-password-secret"},
        ]
        with patch.dict(os.environ, {"GATE_CLIENT_SECRET": secret}):
            _, report, output, console = self.run_gate()
        all_summary = json.dumps(report) + (output / "check.md").read_text() + console
        for value in (secret, "private-matrix-secret", "private-password-secret",
                      "private-stdout-secret", "private-stderr-secret"):
            self.assertNotIn(value, all_summary)

    def test_output_collision_and_symlink_parent_are_rejected(self):
        existing = self.root / "preserve"
        existing.mkdir()
        link = self.root / "link"
        link.symlink_to(existing, target_is_directory=True)
        for output in (existing, link / "child", self.root / "missing" / ".." / "escape"):
            with self.subTest(output=output), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = self.check.main(["--output", str(output)])
                self.assertEqual(code, 2)
        self.assertEqual(list(existing.iterdir()), [])

    def test_repeat_and_timeout_bounds_reject_without_starting(self):
        for args in (["--repeat", "1"], ["--repeat", "11"], ["--timeout", "0"], ["--timeout", "3601"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), \
                    patch.object(self.check, "run_command") as command:
                self.assertEqual(self.check.main(args), 2)
                command.assert_not_called()

    def test_command_launch_failure_is_recorded(self):
        result = self.check.run_command([str(self.root / "missing-python")], self.root, 1)
        self.assertTrue(result["launch_error"])
        self.assertFalse(result["timed_out"])
        self.assertIsNone(result["returncode"])

    def test_command_uses_and_cleans_shared_private_registry_scope(self):
        output = self.root / "registry-observation.json"
        script = self.root / "observe_registry.py"
        script.write_text(
            "import json, os\nfrom pathlib import Path\n"
            f"Path({str(output)!r}).write_text(json.dumps(os.environ.get('IDENTITY_TEST_PROCESS_REGISTRY')))\n"
        )
        result = self.check.run_command([sys.executable, str(script)], self.root, 2)
        self.assertEqual(result["returncode"], 0)
        scope = json.loads(output.read_text())
        self.assertIsInstance(scope, str, "Every gate command must register a private owned scope")
        self.assertTrue(Path(scope).is_relative_to(ROOT / "artifacts"))
        self.assertFalse(Path(scope).exists(), "Successful command scope must be cleaned")

    def test_custom_report_directory_does_not_move_registry_outside_private_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="check-output-", dir=ROOT.parent) as directory:
            output = Path(directory).resolve() / "check"
            code, report, _, _ = self.run_gate(output=output)
            self.assertEqual(code, 0)
            for step in report["steps"]:
                if "process_registry" in step:
                    self.assertTrue(Path(step["process_registry"]).is_relative_to(ROOT / "artifacts"))

    def test_cleanup_error_is_a_failure_even_after_successful_command(self):
        original = self.check.owned_process

        @contextmanager
        def cleanup_failure(*args, **kwargs):
            with original(*args, **kwargs) as process:
                yield process
            raise self.check.ProcessCleanupError("private-cleanup-error")

        with patch.object(self.check, "owned_process", side_effect=cleanup_failure):
            step = self.check.command_step("fixture", [sys.executable, "-c", "pass"], self.root, 2)
        self.assertEqual(step["returncode"], 0)
        self.assertEqual(step["status"], "FAIL")
        self.assertTrue(step["cleanup_error"])
        self.assertNotIn("private-cleanup-error", json.dumps(step))

    def test_command_failures_and_timeouts_still_get_both_summary_reports(self):
        original = self.check.run_command
        for kind in ("launch_error", "timed_out"):
            def command(args, cwd, timeout, **kwargs):
                if "--profile" in args and args[args.index("--output") + 1].endswith("run-1"):
                    return {"returncode": None if kind == "launch_error" else -15,
                            "launch_error": kind == "launch_error",
                            "timed_out": kind == "timed_out", "duration_seconds": 0.01}
                return original(args, cwd, timeout, **kwargs)

            with self.subTest(kind=kind), patch.object(self.check, "run_command", side_effect=command):
                code, report, output, _ = self.run_gate(name=kind)
            self.assertEqual(code, 2 if kind == "launch_error" else 1)
            self.assertTrue((output / "check.md").is_file())
            self.assertTrue((output / "run-2" / "matrix.json").is_file())
            first = next(s for s in report["steps"] if s["id"] == "run-1")
            self.assertTrue(first[kind])

    def test_partial_repeat_does_not_claim_a_stable_failure(self):
        result = self.check.stability([{"e2e.one": "FAIL"}, None])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["stable_failures"], [])

    def test_new_parent_directories_are_private_too(self):
        output = self.root / "nested" / "parents" / "check"
        with patch.object(self.check, "ROOT", self.root), \
                patch.object(self.check, "GROUPS", ()), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.check.main(["--output", str(output), "--timeout", "1"])
        if os.name == "posix":
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.parent.parent.stat().st_mode & 0o777, 0o700)

    def test_symlink_json_is_rejected_without_reading_target(self):
        target = self.root / "sensitive.json"
        target.write_text('{"password": "private-target-secret"}')
        link = self.root / "report.json"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            self.check.read_json(link)
        self.assertEqual(target.read_text(), '{"password": "private-target-secret"}')

    def test_duplicate_and_nonfinite_json_are_invalid(self):
        for data in ('{"cases": [], "cases": []}', '{"count": NaN}'):
            path = self.root / "invalid.json"
            path.write_text(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check.read_json(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO file type")
    def test_nonregular_report_cannot_block_the_gate(self):
        path = self.root / "report.fifo"
        os.mkfifo(path, mode=0o600)
        script = self.root / "read_report.py"
        script.write_text(
            f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
            "import check\n"
            f"try: check.read_json(check.Path({str(path)!r}))\n"
            "except ValueError: raise SystemExit(0)\n"
            "raise SystemExit(1)\n"
        )
        try:
            result = subprocess.run([sys.executable, str(script)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=2, check=False)
        except subprocess.TimeoutExpired:
            self.fail("Reading a FIFO report blocked past the validation deadline")
        self.assertEqual(result.returncode, 0)

    def test_secret_in_an_unexpected_id_is_not_published_by_stability(self):
        value = "privateUnexpectedIdentifier"
        with patch.dict(os.environ, {"GATE_CLIENT_SECRET": value}):
            result = self.check.stability([{"e2e.one": "PASS"}, {value: "PASS"}])
            self.assertNotIn(value, json.dumps(result))

    def test_structured_unit_report_rejects_impossible_success_counts(self):
        counts = dict.fromkeys(self.check.UNIT_COUNTS, 0)
        counts.update(discovered=1, tests=2)
        report = {"schema_version": 1, "kind": "unittest", "group": "fixture",
                  "counts": counts, "exit_code": 0}
        with self.assertRaises(ValueError):
            self.check.validate_unit(report, "fixture", 0)

    def test_matrix_validation_checks_all_ids_outcome_types_and_selection(self):
        rows = [
            self.check.runner.outcome(c, "PASS" if "local" in c["profiles"] else "NOT_RUN", "ok", 0)
            for c in self.cases
        ]
        directory = self.root / "validation"
        directory.mkdir()
        report = self.check.runner.write_reports(directory, rows, "local", "fixture", {
            "selected_suites": list(self.check.runner.SUITES), "selected_count": 2,
            "python_version": sys.version.split()[0],
        })
        self.assertEqual(self.check.validate_report(self.cases, report, 0)["PASS"], 2)
        for key, value in (("duration_seconds", True), ("duration_seconds", float("inf")),
                           ("status", "GREEN"), ("observed", None), ("id", "unknown"),
                           ("expected", "weakened assertion")):
            broken = json.loads(json.dumps(report))
            broken["cases"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check.validate_report(self.cases, broken, 0)
        for transform in (
            lambda data: data["cases"].pop(),
            lambda data: data["cases"].append(data["cases"][0]),
            lambda data: data["cases"][-1].update(status="PASS"),
            lambda data: data["summary"].update(PASS=True),
        ):
            broken = json.loads(json.dumps(report))
            transform(broken)
            with self.assertRaises(ValueError):
                self.check.validate_report(self.cases, broken, 0)

    @unittest.skipUnless(os.name == "posix", "POSIX group lifecycle")
    def test_registered_nested_group_is_cleaned_after_its_parent_exits_immediately(self):
        pid_file = self.root / "registered-orphan.pid"
        leaf = self.root / "registered_leaf.py"
        leaf.write_text(
            "import os, signal, time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
            "while True: time.sleep(1)\n"
        )
        parent = self.root / "fast_parent.py"
        parent.write_text(
            f"import os, sys, time\nsys.path.insert(0, {str(ROOT)!r})\n"
            "from pathlib import Path\nfrom processes import owned_process\n"
            f"scope = owned_process([sys.executable, {str(leaf)!r}], cwd={str(self.root)!r})\n"
            "process = scope.__enter__()\n"
            f"while not Path({str(pid_file)!r}).exists(): time.sleep(0.01)\n"
            "os._exit(0)\n"
        )
        pid = None
        try:
            result = self.check.run_command([sys.executable, str(parent)], self.root, 5)
            self.assertEqual(result["returncode"], 0)
            self.assertFalse(result["cleanup_error"])
            pid = int(pid_file.read_text())
            status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                    capture_output=True, text=True, check=False, timeout=2)
            self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith("Z"),
                            "Registered nested group survived its parent's immediate exit")
        finally:
            if pid is None and pid_file.exists():
                pid = int(pid_file.read_text())
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "POSIX group lifecycle")
    def test_outer_timeout_reaps_nested_check_commands_and_their_children(self):
        pids = self.root / "nested-pids.json"
        leaf = self.root / "nested_leaf.py"
        leaf.write_text(textwrap.dedent(f"""\
            import json, os, pathlib, signal, time
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            child = os.fork()
            if child:
                pathlib.Path({str(pids)!r}).write_text(json.dumps([os.getpid(), child]))
            while True: time.sleep(1)
        """))
        nested = self.root / "nested_check.py"
        nested.write_text(
            f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
            "import check\n"
            f"check.run_command([sys.executable, {str(leaf)!r}], check.Path({str(self.root)!r}), 30)\n"
        )
        children = []
        try:
            with patch.dict(os.environ, {"IDENTITY_TEST_INHERIT_PROCESS_GROUP": ""}):
                result = self.check.run_command(
                    [sys.executable, str(nested)], self.root, 0.7,
                    env=dict(os.environ, IDENTITY_TEST_INHERIT_PROCESS_GROUP="1"),
                )
            self.assertTrue(result["timed_out"])
            self.assertTrue(pids.is_file())
            children = json.loads(pids.read_text())
            for pid in children:
                status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                        capture_output=True, text=True, check=False, timeout=2)
                self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith("Z"),
                                "Nested check created a session escaping outer timeout cleanup")
        finally:
            if not children and pids.exists():
                children = json.loads(pids.read_text())
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "POSIX group lifecycle")
    def test_normal_exit_still_reaps_root_group_without_adapter_teardown(self):
        pid_file = self.root / "orphan.pid"
        script = self.root / "leaves_descendant.py"
        script.write_text(textwrap.dedent(f"""\
            import os, pathlib, signal, time
            ready = pathlib.Path({str(pid_file)!r})
            child = os.fork()
            if child == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                ready.write_text(str(os.getpid()))
                while True: time.sleep(1)
            while not ready.exists(): time.sleep(0.01)
        """))
        pid = None
        try:
            with patch.dict(os.environ, {"IDENTITY_TEST_INHERIT_PROCESS_GROUP": "1"}), \
                    patch.object(self.check.runner, "terminate_adapter", side_effect=lambda p: p.wait(timeout=2)):
                result = self.check.run_command([sys.executable, str(script)], self.root, 2)
            self.assertEqual(result["returncode"], 0)
            self.assertFalse(result["timed_out"])
            pid = int(pid_file.read_text())
            status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                    capture_output=True, text=True, check=False, timeout=2)
            self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith("Z"),
                            "A normally exited matrix left a live descendant behind")
        finally:
            if pid is None and pid_file.exists():
                pid = int(pid_file.read_text())
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "POSIX group lifecycle")
    def test_timeout_cleans_descendant_even_if_leader_already_exited(self):
        pid_file = self.root / "child.pid"
        script = self.root / "hanging.py"
        script.write_text(textwrap.dedent(f"""\
            import os, pathlib, signal, time
            child = os.fork()
            if child == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))
                while True: time.sleep(1)
            time.sleep(60)
        """))
        start = time.monotonic()
        result = self.check.run_command([sys.executable, str(script)], self.root, 0.4)
        self.assertTrue(result["timed_out"])
        self.assertLess(time.monotonic() - start, 8)
        self.assertTrue(pid_file.exists())
        pid = int(pid_file.read_text())
        try:
            status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                    capture_output=True, text=True, check=False, timeout=2)
            self.assertTrue(status.returncode != 0 or status.stdout.strip().startswith("Z"),
                            "The timed-out descendant is still running")
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_optional_groups_are_added_only_when_their_directories_exist(self):
        names = {group[0] for group in self.check.selftest_groups(self.root)}
        self.assertTrue({"runner", "check", "browser", "browser-regressions", "protocols", "live"} <= names)
        self.assertIn("e2e", names)
        self.assertNotIn("stack", names)
        (self.root / "stack").mkdir()
        self.assertIn("stack", {g[0] for g in self.check.selftest_groups(self.root)})
        self.assertNotIn("processes", {g[0] for g in self.check.selftest_groups(self.root)})
        (self.root / "test_processes.py").write_text("# shared manager contracts\n")
        self.assertIn("processes", {g[0] for g in self.check.selftest_groups(self.root)})


if __name__ == "__main__":
    unittest.main()
