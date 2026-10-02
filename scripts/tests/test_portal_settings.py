"""Deployment lifecycle tests for the environment-owned settings blob."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/lib/portal-settings.sh"


class TestPortalSettingsDeployment(unittest.TestCase):
    def run_helper(self, exists="false", fail_upload=False):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "commands"
            env = dict(os.environ, EXISTS=exists, FAIL_UPLOAD=str(int(fail_upload)), LOG=str(log))
            script = """
set -euo pipefail
az() {
    printf '%s\\n' "$*" >> "$LOG"
    if [ "$1 $2 $3" = "storage blob exists" ]; then
        printf '%s\\n' "$EXISTS"
    elif [ "$1 $2 $3" = "storage blob upload" ] && [ "$FAIL_UPLOAD" = 1 ]; then
        return 1
    fi
}
source "$1"
ensure_portal_settings_blob acct portal-runtime-settings settings.json "$2"
"""
            result = subprocess.run(
                ["bash", "-c", script, "test", str(HELPER), str(ROOT / "portal/default-risk-settings.json")],
                env=env, capture_output=True, text=True,
            )
            return result, log.read_text()

    def test_new_deployment_creates_settings_without_overwrite(self):
        result, commands = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("storage container create", commands)
        self.assertIn("storage blob upload", commands)
        self.assertIn("--overwrite false", commands)

    def test_redeploy_preserves_settings(self):
        result, commands = self.run_helper(exists="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("storage blob upload", commands)

    def test_initialization_errors_fail_deployment(self):
        result, _ = self.run_helper(fail_upload=True)
        self.assertNotEqual(result.returncode, 0)
        result, _ = self.run_helper(exists="unexpected")
        self.assertNotEqual(result.returncode, 0)

    def test_defaults_are_explicit_demo_settings(self):
        defaults = json.loads((ROOT / "portal/default-risk-settings.json").read_text())
        self.assertEqual(defaults, [{"entra_signal_enabled": True, "risk_enforcement_enabled": False}])

    def test_teardown_and_rebuild_clear_settings_outputs(self):
        for path in ("scripts/teardown.sh", "scripts/rebuild-isp-exec.sh"):
            text = (ROOT / path).read_text()
            self.assertIn("PORTAL_RUNTIME_SETTINGS_CONTAINER", text)
            self.assertIn("PORTAL_RUNTIME_SETTINGS_BLOB_NAME", text)
        self.assertIn("azd down --force --purge", (ROOT / "scripts/teardown.sh").read_text())
        self.assertIn('az group delete -n "$RG" --yes', (ROOT / "scripts/rebuild-isp-exec.sh").read_text())
