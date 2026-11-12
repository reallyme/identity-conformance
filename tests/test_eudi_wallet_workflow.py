# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from pathlib import Path
import unittest


WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows/eudi-wallet-conformance.yml").read_text()


class HostedWalletWorkflowTests(unittest.TestCase):
    def test_hosted_execution_needs_no_private_runner_or_deployment_secret(self) -> None:
        self.assertIn("runs-on: ubuntu-26.04", WORKFLOW)
        for forbidden in (
            "self-hosted",
            "secrets:",
            "/protected-inputs/",
            "CARGO_REGISTRY_TOKEN",
            "release_artifact_path",
            "component_attestation_path",
            "EUDI_WALLET_DEPLOYMENT_MANIFEST_B64",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, WORKFLOW)

    def test_candidate_artifact_is_selected_from_the_same_workflow_run(self) -> None:
        self.assertIn("candidate_artifact_name:", WORKFLOW)
        self.assertIn("name: ${{ inputs.candidate_artifact_name }}", WORKFLOW)
        self.assertIn("actions/download-artifact@", WORKFLOW)
        self.assertIn("digest-mismatch: error", WORKFLOW)
        self.assertIn('test "${#entries[@]}" -eq 3', WORKFLOW)
        for forbidden in ("run-id:", "github-token:", "secrets: inherit"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, WORKFLOW)

    def test_candidate_validation_precedes_checkout_and_execution(self) -> None:
        validate = WORKFLOW.index("scripts/verify_eudi_wallet_deployment_manifest.py")
        checkout = WORKFLOW.index("- name: Checkout exact wallet source")
        verify_checkout = WORKFLOW.index("- name: Verify the selected Wallet checkout")
        execute = WORKFLOW.index("scripts/run_eudi_wallet_conformance.py")
        result = WORKFLOW.index("scripts/verify_eudi_wallet_execution_result.py")
        upload = WORKFLOW.index("- name: Upload validated EUDI Wallet result")
        self.assertLess(validate, checkout)
        self.assertLess(checkout, verify_checkout)
        self.assertLess(verify_checkout, execute)
        self.assertLess(execute, result)
        self.assertLess(result, upload)
        self.assertIn("ref: ${{ steps.source.outputs.release_ref }}", WORKFLOW)
        self.assertIn("repos/reallyme/wallet/releases/latest", WORKFLOW)
        self.assertIn("git -C components/wallet rev-parse HEAD", WORKFLOW)
        self.assertIn("--framework-revision", WORKFLOW)
        self.assertIn("--workflow-revision", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
