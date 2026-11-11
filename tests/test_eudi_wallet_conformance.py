# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, relative_path: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        name, REPOSITORY_ROOT / relative_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("test script module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


ADAPTER = load_script(
    "verify_eudi_wallet_adapter", "scripts/verify_eudi_wallet_adapter.py"
)
RUNNER = load_script(
    "run_eudi_wallet_conformance", "scripts/run_eudi_wallet_conformance.py"
)
RESULT = load_script(
    "verify_eudi_wallet_execution_result",
    "scripts/verify_eudi_wallet_execution_result.py",
)


def valid_deployment() -> dict[str, object]:
    _plan, adapter = ADAPTER.load_contract()
    requirement = adapter["component_requirement"]
    return {
        "schema": "reallyme.identity.eudi_wallet_deployment_manifest.v1",
        "plan_id": "eudi-wallet-engineering-v1",
        "component": {
            "component_id": requirement["component_id"],
            "repository": requirement["repository"],
            "commit": "1" * 40,
        },
        "release_artifact": {
            "artifact_id": "wallet-release-bundle",
            "kind": "archive",
            "sha256": "a" * 64,
        },
        "component_attestation_sha256": "b" * 64,
        "source_locks": {
            "eudi_sources_sha256": "c" * 64,
            "eudi_legal_sources_sha256": "d" * 64,
            "eudi_publications_sha256": "e" * 64,
        },
        "evidence_policy": ADAPTER.EXPECTED_POLICY,
    }


def valid_result() -> dict[str, object]:
    plan, adapter = ADAPTER.load_contract()
    kinds = RESULT.expected_check_kinds(adapter)
    deployment = valid_deployment()
    result = {
        "schema": "reallyme.identity.eudi_wallet_execution_result.v1",
        "plan_id": "eudi-wallet-engineering-v1",
        "result": "passed",
        "created_at": "2026-11-11T12:00:00Z",
        "framework_revision": "2" * 40,
        "workflow_revision": "3" * 40,
        "candidate_sha256": "0" * 64,
        "component": deployment["component"],
        "release_artifact_sha256": "a" * 64,
        "component_attestation_sha256": "b" * 64,
        "source_locks": {
            "eudi_sources_sha256": "c" * 64,
            "eudi_legal_sources_sha256": "d" * 64,
            "eudi_publications_sha256": "e" * 64,
        },
        "checks": [
            {"check_id": check_id, "kind": kind, "result": "passed"}
            for check_id, kind in sorted(kinds.items())
        ],
        "assertions": [
            {
                "assertion_id": assertion["assertion_id"],
                "check_ids": assertion["required_checks"],
                "result": "passed",
            }
            for assertion in plan["assertions"]
        ],
        "evidence_policy": ADAPTER.EXPECTED_POLICY,
    }
    candidate = {
        "plan_id": result["plan_id"],
        "component": result["component"],
        "release_artifact": deployment["release_artifact"],
        "component_attestation_sha256": result["component_attestation_sha256"],
        "source_locks": result["source_locks"],
    }
    result["candidate_sha256"] = RUNNER.candidate_digest(candidate)
    return result


class EudiWalletConformanceTests(unittest.TestCase):
    def test_checked_plan_and_adapter_are_valid(self) -> None:
        plan, adapter = ADAPTER.load_contract()
        self.assertEqual(
            plan["required_components"], [adapter["component_requirement"]]
        )

    def test_valid_deployment_is_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        artifact = RUNNER.validate_deployment(valid_deployment(), adapter)
        self.assertEqual(artifact["artifact_id"], "wallet-release-bundle")

    def test_two_caller_selected_wallet_commits_are_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        first = valid_deployment()
        second = copy.deepcopy(first)
        second["component"]["commit"] = "f" * 40
        RUNNER.validate_deployment(first, adapter)
        RUNNER.validate_deployment(second, adapter)

    def test_plan_cannot_add_an_undeclared_component(self) -> None:
        plan, _adapter = ADAPTER.load_contract()
        changed = copy.deepcopy(plan)
        changed["required_components"].append(
            {"component_id": "identity", "repository": "https://github.com/reallyme/identity"}
        )
        with self.assertRaises(ADAPTER.EudiWalletAdapterError) as raised:
            ADAPTER.validate_plan(changed)
        self.assertIs(
            raised.exception.reason, ADAPTER.EudiWalletAdapterErrorReason.INVALID_PLAN
        )

    def test_adapter_cannot_require_a_different_component(self) -> None:
        plan, adapter = ADAPTER.load_contract()
        changed = copy.deepcopy(adapter)
        changed["component_requirement"]["component_id"] = "identity"
        with self.assertRaises(ADAPTER.EudiWalletAdapterError) as raised:
            ADAPTER.validate_adapter(changed, plan)
        self.assertIs(
            raised.exception.reason, ADAPTER.EudiWalletAdapterErrorReason.INVALID_ADAPTER
        )

    def test_sensitive_evidence_policy_is_rejected(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        changed = valid_deployment()
        changed["evidence_policy"] = copy.deepcopy(changed["evidence_policy"])
        changed["evidence_policy"]["credential_payloads_retained"] = True
        with self.assertRaises(RUNNER.EudiWalletRunnerError):
            RUNNER.validate_deployment(changed, adapter)

    def test_incomplete_candidate_manifest_is_rejected(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        changed = valid_deployment()
        del changed["component"]["commit"]
        with self.assertRaises(RUNNER.EudiWalletRunnerError):
            RUNNER.validate_deployment(changed, adapter)

    def test_substituted_release_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "wallet.tar"
            artifact.write_bytes(b"substituted")
            expected = hashlib.sha256(b"intended").hexdigest()
            with self.assertRaises(RUNNER.EudiWalletRunnerError):
                RUNNER.verify_release_artifact(artifact, expected)

    def test_mismatched_attestation_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            attestation = Path(directory) / "attestation.json"
            attestation.write_bytes(b"{}")
            with self.assertRaises(RUNNER.EudiWalletRunnerError):
                RUNNER.verify_attestation(
                    attestation,
                    "0" * 64,
                    "1" * 64,
                    "2" * 40,
                )

    def test_valid_execution_result_is_accepted(self) -> None:
        RESULT.verify_result(valid_result())

    def test_result_rejects_mixed_candidate_inputs(self) -> None:
        changed = valid_result()
        changed["release_artifact_sha256"] = "f" * 64
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_failed_check_is_rejected(self) -> None:
        changed = valid_result()
        changed["checks"][0]["result"] = "failed"
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_assertion_cannot_drop_required_check(self) -> None:
        changed = valid_result()
        changed["assertions"][0]["check_ids"] = ["source.cargo-lock"]
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_unknown_upstream_source_is_rejected(self) -> None:
        plan, _adapter = ADAPTER.load_contract()
        changed = copy.deepcopy(plan)
        changed["upstream_source_ids"][0] = "unknown-source"
        with self.assertRaises(ADAPTER.EudiWalletAdapterError):
            ADAPTER.validate_plan(changed)


if __name__ == "__main__":
    unittest.main()
