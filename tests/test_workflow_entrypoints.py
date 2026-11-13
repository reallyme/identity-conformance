# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class WorkflowEntrypointTests(unittest.TestCase):
    def test_wallet_workflow_revalidates_the_exact_package_preflight(self) -> None:
        workflow = (WORKFLOWS / "eudi-wallet-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "Revalidate exact Wallet package preflight", workflow
        )
        self.assertIn("actions/runs/${PREFLIGHT_RUN_ID}/attempts/1/jobs?per_page=100", workflow)
        self.assertIn(
            "python3 identity-conformance/scripts/verify_wallet_package_preflight.py",
            workflow,
        )
        self.assertIn(".package_evidence.fuzz_run_id", workflow)
        self.assertIn(".package_evidence.protobuf_ci_run_id", workflow)
        self.assertIn(".package_evidence.rust_ci_run_id", workflow)
        self.assertNotIn("required_steps", workflow)

    def test_wallet_workflow_verifies_each_release_subject_provenance(self) -> None:
        workflow = (WORKFLOWS / "eudi-wallet-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("attestations: read", workflow)
        self.assertIn("materialize_wallet_attestation_subjects.py", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn(
            "--signer-workflow reallyme/wallet/.github/workflows/"
            "crates-package-preflight.yml",
            workflow,
        )
        self.assertIn('--source-digest "${TARGET_COMMIT}"', workflow)
        self.assertIn("--deny-self-hosted-runners", workflow)

    def test_identity_has_one_product_entrypoint_for_both_oidf_lanes(self) -> None:
        workflow = (WORKFLOWS / "identity-product-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("name: Product · Identity · OIDF", workflow)
        self.assertEqual(workflow.count("framework_commit:"), 3)
        self.assertIn(
            "uses: ./.github/workflows/oidf-openid4vci-certification.yml",
            workflow,
        )
        self.assertIn(
            "uses: ./.github/workflows/oidf-openid4vp-certification.yml",
            workflow,
        )
        self.assertEqual(workflow.count("secrets: inherit"), 2)

    def test_every_product_lane_uses_the_same_release_verifier(self) -> None:
        paths = (
            "eudi-relying-party-conformance.yml",
            "eudi-wallet-conformance.yml",
            "oidf-openid4vci-certification.yml",
            "oidf-openid4vp-certification.yml",
            "zk-conformance.yml",
        )
        for path in paths:
            with self.subTest(path=path):
                workflow = (WORKFLOWS / path).read_text(encoding="utf-8")
                self.assertEqual(
                    workflow.count("prepare_published_framework_release.sh"), 1
                )

    def test_oidf_lanes_use_the_framework_suite_pin_and_verify_wallet_scope(self) -> None:
        paths = (
            "oidf-openid4vci-certification.yml",
            "oidf-openid4vp-certification.yml",
        )
        for path in paths:
            with self.subTest(path=path):
                workflow = (WORKFLOWS / path).read_text(encoding="utf-8")
                self.assertIn(
                    "suite_commit=\"$(jq -er '.commit' "
                    "upstream/oidf/conformance-suite.lock.json)\"",
                    workflow,
                )
                self.assertIn("Verify complete official OIDF Wallet scope", workflow)
                self.assertIn(
                    "python3 scripts/verify_oidf_wallet_plan.py", workflow
                )
                self.assertNotIn("suite_commit=\"$(jq -er '.suite.commit'", workflow)

    def test_actions_names_distinguish_product_framework_and_internal_workflows(self) -> None:
        expected_prefixes = {
            "eudi-wallet-conformance.yml": "name: Product ·",
            "identity-product-conformance.yml": "name: Product ·",
            "zk-conformance.yml": "name: Product ·",
            "release-readiness.yml": "name: Framework ·",
            "eu-arf-normative.yml": "name: Framework ·",
            "oidf-openid4vci-certification.yml": "name: Internal ·",
        }
        for path, prefix in expected_prefixes.items():
            with self.subTest(path=path):
                workflow = (WORKFLOWS / path).read_text(encoding="utf-8")
                self.assertIn(prefix, workflow)


if __name__ == "__main__":
    unittest.main()
