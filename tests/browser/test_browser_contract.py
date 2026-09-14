import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class BrowserAdapterTests(unittest.TestCase):
    def command(self, *args):
        runner = Path(__file__).with_name("run.py")
        self.assertTrue(runner.exists(), "browser adapter must be implemented")
        return subprocess.run([sys.executable, "-S", str(runner), *args],
                              capture_output=True, text=True, timeout=15)

    def test_inventory_dependency_free_and_unique(self):
        run = self.command("--list")
        self.assertEqual(run.returncode, 0, run.stderr)
        cases = json.loads(run.stdout)
        self.assertGreater(len(cases), 0)
        self.assertEqual(len(cases), len({c["id"] for c in cases}))
        for case in cases:
            self.assertEqual(set(case), {"id", "suite", "layer", "profiles",
                                         "description", "expected", "mutation"})
            self.assertEqual(case["suite"], "browser")

    def test_missing_live_config_blocks_every_live_case(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "result.json"
            run = self.command("--profile", "live", "--output", str(output))
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertEqual(run.stdout, "")
            rows = json.loads(output.read_text())["cases"]
            declared = json.loads(self.command("--list").stdout)
            self.assertEqual({r["id"] for r in rows},
                             {c["id"] for c in declared if "live" in c["profiles"]})
            self.assertTrue(all(row["status"] == "BLOCKED" for row in rows))

    def test_dependency_missing_is_blocked_and_no_exception_dump(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "result.json"
            run = self.command("--profile", "local", "--output", str(output))
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertEqual(run.stdout, "")
            self.assertEqual(run.stderr, "")
            self.assertTrue(all(c["status"] == "BLOCKED"
                                for c in json.loads(output.read_text())["cases"]))

    def test_nonobject_configuration_is_blocked_without_dumping_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            config = directory / "config.json"
            config.write_text('["sensitive-fixture-value"]')
            output = directory / "result.json"
            run = self.command("--profile", "live", "--config", str(config),
                               "--output", str(output))
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stdout + run.stderr, "")
            self.assertNotIn("sensitive-fixture-value", output.read_text())


if __name__ == "__main__":
    unittest.main()
