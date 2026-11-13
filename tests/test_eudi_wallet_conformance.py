# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


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
        "schema": "reallyme.identity.eudi_wallet_deployment_manifest.v2",
        "plan_id": "eudi-wallet-engineering-v1",
        "component": {
            "component_id": requirement["component_id"],
            "repository": requirement["repository"],
            "commit": "1" * 40,
        },
        "target": {
            "mode": "candidate",
            "version": "1.0.0",
            "commit": "1" * 40,
            "preflight_run_id": 41,
        },
        "package_bundle": {
            "artifact_id": "wallet-package-bundle",
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
    crates = [
        {
            "name": name,
            "version": "1.0.0",
            "file": f"{name}-1.0.0.crate",
            "size": index,
            "sha256": f"{index:x}" * 64,
        }
        for index, name in enumerate(
            ("reallyme-wallet", "reallyme-wallet-types"), 1
        )
    ]
    crate_inventory_sha256 = RUNNER.wallet_package_bundle.digest_entries(
        [
            f"{crate['name']}|{crate['version']}|{crate['size']}|{crate['sha256']}"
            for crate in crates
        ]
    )
    result = {
        "schema": "reallyme.identity.eudi_wallet_execution_result.v3",
        "plan_id": "eudi-wallet-engineering-v1",
        "result": "passed",
        "created_at": "2026-11-11T12:00:00Z",
        "framework_version": RUNNER.framework_version(),
        "framework_revision": "2" * 40,
        "workflow_revision": "3" * 40,
        "candidate_sha256": "0" * 64,
        "component": deployment["component"],
        "target": deployment["target"],
        "package_bundle_sha256": "a" * 64,
        "component_attestation_sha256": "b" * 64,
        "package_evidence": {
            "preflight_run_id": 41,
            "preflight_job_id": 42,
            "fuzz_run_id": 31,
            "protobuf_ci_run_id": 32,
            "rust_ci_run_id": 33,
            "crate_count": len(crates),
            "crates": crates,
            "crate_inventory_sha256": crate_inventory_sha256,
            "evidence_count": 7,
            "evidence_inventory_sha256": "7" * 64,
            "cargo_lock_sha256": "8" * 64,
        },
        "source_locks": {
            "eudi_sources_sha256": "c" * 64,
            "eudi_legal_sources_sha256": "d" * 64,
            "eudi_publications_sha256": "e" * 64,
        },
        "normative_ledgers": RUNNER.normative_ledger_digests(),
        "coverage": {
            "authority": "internal_engineering",
            "certification_claim": False,
            "minimum_requirements": {
                "total": 14,
                "status_counts": {
                    "implemented": 6,
                    "partial": 5,
                    "operational_required": 1,
                    "delegated": 1,
                    "fixture_seeded": 1,
                },
                "incomplete": [
                    {
                        "minimum_id": f"minimum.incomplete-{index}",
                        "status": status,
                        "limitations": ["Not complete in this candidate."],
                    }
                    for index, status in enumerate(
                        [
                            "partial",
                            "partial",
                            "partial",
                            "partial",
                            "partial",
                            "operational_required",
                            "delegated",
                            "fixture_seeded",
                        ],
                        1,
                    )
                ],
            },
            "declared_cases": {
                "total": 18,
                "executable": 10,
                "non_executable": 8,
                "status_counts": {
                    "unit_covered": 9,
                    "implemented": 1,
                    "fixture_available": 2,
                    "fixture_seeded": 6,
                },
                "non_executable_cases": [
                    {
                        "case_id": f"wallet-core.fixture-{index}",
                        "status": "fixture_available" if index <= 2 else "fixture_seeded",
                    }
                    for index in range(1, 9)
                ],
            },
            "normative_boundaries": {"implemented": 2, "checks": 3},
        },
        "test_execution": {
            "command_id": RUNNER.TEST_COMMAND_ID,
            "discovered_test_count": 752,
            "test_inventory_sha256": "4" * 64,
            "executed_test_count": 752,
            "passed_test_count": 752,
            "failed_test_count": 0,
            "ignored_test_count": 0,
            "measured_test_count": 0,
            "filtered_test_count": 0,
            "declared_executable_case_count": 10,
            "declared_test_functions_sha256": "5" * 64,
            "result": "passed",
        },
        "framework_probes": [
            {
                "probe_id": probe["probe_id"],
                "command_id": probe["command_id"],
                "source_sha256": RUNNER.hash_regular_file(
                    REPOSITORY_ROOT / probe["source_path"]
                ),
                "executed_test_count": probe["expected_test_count"],
                "passed_test_count": probe["expected_test_count"],
                "failed_test_count": 0,
                "ignored_test_count": 0,
                "measured_test_count": 0,
                "filtered_test_count": 0,
                "result": "passed",
            }
            for probe in adapter["framework_probes"]
        ],
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
        "framework_version": result["framework_version"],
        "component": result["component"],
        "target": result["target"],
        "package_bundle": deployment["package_bundle"],
        "component_attestation_sha256": result["component_attestation_sha256"],
        "source_locks": result["source_locks"],
        "normative_ledgers": result["normative_ledgers"],
    }
    result["candidate_sha256"] = RUNNER.candidate_digest(candidate)
    return result


class EudiWalletConformanceTests(unittest.TestCase):
    def test_publishable_workspace_packages_are_discovered_from_cargo_metadata(
        self,
    ) -> None:
        metadata = {
            "workspace_members": ["public", "restricted", "private"],
            "packages": [
                {
                    "id": "public",
                    "name": "reallyme-wallet",
                    "version": "1.0.0",
                    "publish": None,
                },
                {
                    "id": "restricted",
                    "name": "reallyme-wallet-types",
                    "version": "1.0.0",
                    "publish": ["crates-io"],
                },
                {
                    "id": "private",
                    "name": "wallet-private-tests",
                    "version": "1.0.0",
                    "publish": [],
                },
            ],
        }
        output = RUNNER.CommandOutput(0, json.dumps(metadata).encode("utf-8"))
        with mock.patch.object(RUNNER, "capture_command_output", return_value=output):
            self.assertEqual(
                RUNNER.publishable_workspace_packages(Path("/unused")),
                {
                    "reallyme-wallet": "1.0.0",
                    "reallyme-wallet-types": "1.0.0",
                },
            )

    def test_publishable_workspace_discovery_rejects_missing_member_metadata(
        self,
    ) -> None:
        metadata = {
            "workspace_members": ["present", "missing"],
            "packages": [
                {
                    "id": "present",
                    "name": "reallyme-wallet",
                    "version": "1.0.0",
                    "publish": None,
                }
            ],
        }
        output = RUNNER.CommandOutput(0, json.dumps(metadata).encode("utf-8"))
        with mock.patch.object(RUNNER, "capture_command_output", return_value=output):
            with self.assertRaises(RUNNER.EudiWalletRunnerError):
                RUNNER.publishable_workspace_packages(Path("/unused"))

    def test_publishable_workspace_discovery_rejects_unrelated_public_package(
        self,
    ) -> None:
        metadata = {
            "workspace_members": ["unrelated"],
            "packages": [
                {
                    "id": "unrelated",
                    "name": "unrelated-package",
                    "version": "1.0.0",
                    "publish": None,
                }
            ],
        }
        output = RUNNER.CommandOutput(0, json.dumps(metadata).encode("utf-8"))
        with mock.patch.object(RUNNER, "capture_command_output", return_value=output):
            with self.assertRaises(RUNNER.EudiWalletRunnerError):
                RUNNER.publishable_workspace_packages(Path("/unused"))

    def test_checked_plan_and_adapter_are_valid(self) -> None:
        plan, adapter = ADAPTER.load_contract()
        self.assertEqual(
            plan["required_components"], [adapter["component_requirement"]]
        )

    def test_valid_deployment_is_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        artifact = RUNNER.validate_deployment(valid_deployment(), adapter)
        self.assertEqual(artifact["artifact_id"], "wallet-package-bundle")

    def test_two_caller_selected_wallet_commits_are_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        first = valid_deployment()
        second = copy.deepcopy(first)
        second["component"]["commit"] = "f" * 40
        second["target"]["commit"] = "f" * 40
        RUNNER.validate_deployment(first, adapter)
        RUNNER.validate_deployment(second, adapter)

    def test_component_and_target_commit_mismatch_is_rejected(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        changed = valid_deployment()
        changed["target"]["commit"] = "f" * 40
        with self.assertRaises(RUNNER.EudiWalletRunnerError):
            RUNNER.validate_deployment(changed, adapter)

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

    def test_substituted_package_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "wallet.tar"
            artifact.write_bytes(b"substituted")
            expected = hashlib.sha256(b"intended").hexdigest()
            with self.assertRaises(RUNNER.EudiWalletRunnerError):
                RUNNER.verify_package_bundle(artifact, expected)

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
                    valid_deployment()["target"],
                )

    def test_valid_execution_result_is_accepted(self) -> None:
        RESULT.verify_result(valid_result())

    def test_result_rejects_mixed_candidate_inputs(self) -> None:
        changed = valid_result()
        changed["package_bundle_sha256"] = "f" * 64
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_substituted_normative_ledger_digest(self) -> None:
        changed = valid_result()
        changed["normative_ledgers"]["eu_arf_sha256"] = "f" * 64
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_incomplete_package_evidence(self) -> None:
        changed = valid_result()
        changed["package_evidence"]["evidence_count"] = 6
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_coverage_that_hides_non_executable_cases(self) -> None:
        changed = valid_result()
        changed["coverage"]["declared_cases"]["non_executable"] = 0
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_coverage_promoted_to_certification(self) -> None:
        changed = valid_result()
        changed["coverage"]["certification_claim"] = True
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_coverage_that_omits_an_incomplete_minimum(self) -> None:
        changed = valid_result()
        changed["coverage"]["minimum_requirements"]["incomplete"].pop()
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_failed_check_is_rejected(self) -> None:
        changed = valid_result()
        changed["checks"][0]["result"] = "failed"
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_missing_workspace_test_inventory(self) -> None:
        changed = valid_result()
        changed["test_execution"]["discovered_test_count"] = 0
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_partially_executed_workspace_inventory(self) -> None:
        changed = valid_result()
        changed["test_execution"]["executed_test_count"] = 751
        changed["test_execution"]["passed_test_count"] = 751
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_missing_framework_probe_execution(self) -> None:
        changed = valid_result()
        changed["framework_probes"][0]["passed_test_count"] = 0
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_omitted_framework_probe(self) -> None:
        changed = valid_result()
        changed["framework_probes"].pop()
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_result_rejects_substituted_framework_probe_source(self) -> None:
        changed = valid_result()
        changed["framework_probes"][1]["source_sha256"] = "f" * 64
        with self.assertRaises(RESULT.runner.EudiWalletRunnerError):
            RESULT.verify_result(changed)

    def test_discovered_tests_rejects_empty_inventory(self) -> None:
        with self.assertRaises(RUNNER.EudiWalletRunnerError):
            RUNNER.discovered_tests(Path("/"), b"0 tests, 0 benchmarks\n", {}, {})

    def test_discovered_tests_extracts_complete_inventory(self) -> None:
        executable = Path("/bin/sh").resolve(strict=True)
        identity = "reallyme-wallet@1.0.0|test|wallet_tests"
        self.assertEqual(
            RUNNER.discovered_tests(
                Path("/"),
                (
                    f"     Running tests/wallet.rs ({executable})\n"
                    "issuance::accepts_valid_offer: test\n"
                    "presentation::rejects_bad_nonce: test\n"
                    "2 tests, 0 benchmarks\n"
                ).encode("utf-8"),
                {executable: identity},
                {},
            ),
            [
                f"{identity}|issuance::accepts_valid_offer",
                f"{identity}|presentation::rejects_bad_nonce",
            ],
        )

    def test_execution_counts_require_real_test_summaries(self) -> None:
        self.assertEqual(
            RUNNER.test_execution_counts(
                b"test result: ok. 4 passed; 0 failed; 0 ignored; "
                b"0 measured; 0 filtered out; finished in 0.01s\n"
                b"test result: ok. 3 passed; 0 failed; 0 ignored; "
                b"0 measured; 0 filtered out; finished in 0.01s\n"
            ),
            (7, 0, 0, 0, 0),
        )

    def test_command_capture_stops_oversized_output(self) -> None:
        command = (
            sys.executable,
            "-c",
            "import os\nwhile True: os.write(1, b'x' * 4096)",
        )
        with mock.patch.object(RUNNER, "MAX_COMMAND_OUTPUT_BYTES", 128):
            self.assertIsNone(RUNNER.capture_command_output(Path("/"), command))

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
