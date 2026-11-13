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
            "eudi-identity-sdk-conformance.yml",
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

    def test_identity_eu_sdk_lane_executes_every_platform_boundary(self) -> None:
        workflow = (WORKFLOWS / "eudi-identity-sdk-conformance.yml").read_text(
            encoding="utf-8"
        )
        for expected in (
            "target_mode:",
            "target_commit:",
            "target_version:",
            "candidate_artifact_name:",
            "actions/download-artifact@",
            "verify_identity_candidate_bom.py",
            "verify_identity_release_dependencies.py",
            "audit_etsi_eaa_pid_trace.py",
            "reallyme-identity-oidf-openid4vci-wallet-host",
            "reallyme-identity-oidf-openid4vp-verifier-host",
            "test/eudi-catalogue.test.mjs",
            "packages/python/tests/test_eudi.py",
            "eudi-identity-sdk-python-requirements.lock",
            "--require-hashes",
            "go test ./...",
            "--tests '*EudiTest*'",
            "swift test --filter Eudi",
            "verify_eudi_identity_sdk_execution_result.py",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, workflow)
        self.assertNotIn("--all-features", workflow)
        self.assertNotIn("--test evidence", workflow)
        self.assertNotIn("for component in identity", workflow)
        self.assertNotIn("/releases/latest", workflow)

    def test_identity_eu_sdk_result_binds_candidate_components_and_workflow(self) -> None:
        workflow = (WORKFLOWS / "eudi-identity-sdk-conformance.yml").read_text(
            encoding="utf-8"
        )
        for expected in (
            "candidate_cargo_lock_sha256",
            "candidate_source_archive_sha256",
            "product_component_bom_sha256",
            "RELEASE_ID: ${{ inputs.release_id }}",
            'gh api "repos/reallyme/${component}/releases/${release_id}"',
            'git -C "${checkout}" archive --format=tar HEAD',
            "workflow_repository",
            "workflow_revision",
            "source_locks",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, workflow)
        self.assertNotIn("release_artifact_sha256", workflow)
        self.assertNotIn("component_attestation_sha256", workflow)

    def test_identity_eu_sdk_checks_out_verified_dependency_commits(self) -> None:
        workflow = (WORKFLOWS / "eudi-identity-sdk-conformance.yml").read_text(
            encoding="utf-8"
        )
        for component in ("ssi", "openid4vci", "openid4vp"):
            with self.subTest(component=component):
                self.assertIn(
                    f"ref: ${{{{ steps.revisions.outputs.{component}_commit }}}}",
                    workflow,
                )
                self.assertNotIn(
                    f"ref: ${{{{ steps.revisions.outputs.{component}_release_ref }}}}",
                    workflow,
                )

    def test_eudi_relying_party_caller_is_separate_from_component_under_test(self) -> None:
        workflow = (WORKFLOWS / "eudi-relying-party-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("candidate_repository:", workflow)
        self.assertIn("repository: ${{ inputs.candidate_repository }}", workflow)
        self.assertIn(
            '--candidate-repository "https://github.com/${CANDIDATE_REPOSITORY}"',
            workflow,
        )
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        self.assertNotIn("/releases/latest", workflow)

    def test_product_workflows_never_select_the_latest_caller_release(self) -> None:
        for path in (
            "eudi-identity-sdk-conformance.yml",
            "eudi-relying-party-conformance.yml",
            "eudi-wallet-conformance.yml",
            "oidf-openid4vci-certification.yml",
            "oidf-openid4vp-certification.yml",
            "zk-conformance.yml",
        ):
            with self.subTest(path=path):
                workflow = (WORKFLOWS / path).read_text(encoding="utf-8")
                self.assertNotIn("/releases/latest", workflow)

    def test_oidf_product_workflows_resolve_caller_release_ids(self) -> None:
        for path in (
            "oidf-openid4vci-certification.yml",
            "oidf-openid4vp-certification.yml",
        ):
            workflow = (WORKFLOWS / path).read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("release_id=", workflow)
                self.assertIn('/releases/${release_id}', workflow)
                self.assertIn(".draft == false and .prerelease == false", workflow)
                self.assertIn("done < <(jq -cer '.components[]'", workflow)
                self.assertIn(
                    "ref: ${{ steps.release-bom.outputs.adapter_commit }}", workflow
                )
                self.assertIn(
                    "ref: ${{ steps.release-bom.outputs.product_commit }}", workflow
                )
                self.assertNotIn(
                    "ref: ${{ steps.release-bom.outputs.adapter_release_ref }}",
                    workflow,
                )
                self.assertNotIn(
                    "ref: ${{ steps.release-bom.outputs.product_release_ref }}",
                    workflow,
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
                self.assertIn("Verify official OIDF Wallet inventory", workflow)
                self.assertIn(
                    "python3 scripts/verify_oidf_wallet_plan.py", workflow
                )
                self.assertNotIn("suite_commit=\"$(jq -er '.suite.commit'", workflow)

    def test_zk_engineering_lane_does_not_issue_a_pass_statement(self) -> None:
        workflow = (WORKFLOWS / "zk-conformance.yml").read_text(encoding="utf-8")
        self.assertIn("Report engineering-only coverage", workflow)
        self.assertIn("release_evidence_eligible", workflow)
        self.assertNotIn("Build product conformance statement", workflow)
        self.assertNotIn("product-conformance-statement.json", workflow)

    def test_zk_lane_resolves_the_caller_selected_release_id(self) -> None:
        workflow = (WORKFLOWS / "zk-conformance.yml").read_text(encoding="utf-8")
        self.assertIn("release_id=", workflow)
        self.assertIn('repos/reallyme/zk/releases/${release_id}', workflow)
        self.assertIn(".draft == false and .prerelease == false", workflow)
        self.assertIn("ref: ${{ steps.source.outputs.commit }}", workflow)
        self.assertNotIn("ref: ${{ steps.source.outputs.release_ref }}", workflow)

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
