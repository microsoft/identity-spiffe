import os
import sys
import unittest


SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from deployment_status import (  # noqa: E402
    blueprint_agents,
    evaluate_environment,
    missing_managed_identity_fics,
)


class DeploymentStatusTests(unittest.TestCase):
    def test_status_script_wires_health_evaluation_and_current_portal_key(self):
        script_path = os.path.join(SCRIPTS_DIR, "current-deployment.sh")
        with open(script_path, encoding="utf-8") as script_file:
            script = script_file.read()

        self.assertIn("SERVICE_ISP_PORTAL_ENDPOINT_URL", script)
        self.assertNotIn(
            'azd_env_get_from_blob "$AZD_ENV" "SERVICE_PORTAL_ENDPOINT_URL"',
            script,
        )
        self.assertIn("evaluate_environment", script)
        self.assertIn('exit "$DEPLOYMENT_STATUS"', script)

    def test_stale_environment_reports_all_fail_closed_findings(self):
        fics = [
            {
                "name": "isp-fic-report",
                "issuer": "https://login.microsoftonline.com/tenant/v2.0",
                "subject": "deleted-principal",
            },
            {
                "name": "github-reader",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:example/repo:ref:refs/heads/main",
            },
        ]

        missing_fics = missing_managed_identity_fics(fics, {"live-principal"})
        findings = evaluate_environment(
            resource_group_exists=False,
            endpoint_statuses={"portal": "unreachable"},
            graph_query_succeeded=False,
            missing_fic_names=missing_fics,
        )

        self.assertEqual(
            [finding.code for finding in findings],
            [
                "resource_group_missing",
                "endpoint_unreachable",
                "graph_query_failed",
                "fic_subject_missing",
            ],
        )
        self.assertEqual(missing_fics, ["isp-fic-report"])

    def test_healthy_environment_has_no_findings(self):
        fics = [
            {
                "name": "isp-fic-report",
                "issuer": "https://login.microsoftonline.com/tenant/v2.0",
                "subject": "live-principal",
            }
        ]

        findings = evaluate_environment(
            resource_group_exists=True,
            endpoint_statuses={"portal": "200"},
            graph_query_succeeded=True,
            missing_fic_names=missing_managed_identity_fics(
                fics, {"live-principal"}
            ),
        )

        self.assertEqual(findings, [])

    def test_blueprint_agents_excludes_unrelated_tenant_agents(self):
        principals = [
            {"id": "current", "agentIdentityBlueprintId": "current-blueprint"},
            {"id": "legacy", "agentIdentityBlueprintId": "legacy-blueprint"},
            {"id": "ordinary-service-principal"},
        ]

        self.assertEqual(
            blueprint_agents(principals, "current-blueprint"),
            [principals[0]],
        )


if __name__ == "__main__":
    unittest.main()
