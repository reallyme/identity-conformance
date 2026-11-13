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
    path = REPOSITORY_ROOT / relative_path
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("test script module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


ADAPTER = load_script("verify_eudi_adapter", "scripts/verify_eudi_adapter.py")
RUNNER = load_script(
    "run_eudi_relying_party_conformance",
    "scripts/run_eudi_relying_party_conformance.py",
)
REQUIREMENT_RUNNER = load_script(
    "run_eudi_relying_party_requirement_tests",
    "scripts/run_eudi_relying_party_requirement_tests.py",
)
REQUIREMENT_RESULTS = load_script(
    "verify_eudi_relying_party_requirement_results",
    "scripts/verify_eudi_relying_party_requirement_results.py",
)
RESULT = load_script(
    "verify_eudi_execution_result",
    "scripts/verify_eudi_execution_result.py",
)
PUBLIC_EVIDENCE = load_script(
    "build_eudi_public_evidence",
    "scripts/build_eudi_public_evidence.py",
)


def valid_deployment() -> dict[str, object]:
    return {
        "schema_version": 1,
        "purpose": "eudi-relying-party-conformance-deployment",
        "plan_id": "eudi-relying-party-control-plane-v1",
        "mode": "engineering",
        "components": [
            {
                "component_id": "candidate",
                "repository": "https://github.com/reallyme/product",
                "commit": "a" * 40,
            },
            {
                "component_id": "platform",
                "repository": "https://github.com/reallyme/platform",
                "commit": "b" * 40,
            },
            {
                "component_id": "ssi",
                "repository": "https://github.com/reallyme/ssi",
                "commit": "c" * 40,
            },
        ],
        "artifact": {"kind": "binary", "sha256": "d" * 64},
        "trust_artifact": {"kind": "binary", "sha256": "f" * 64},
        "credential_authority_artifact": {
            "kind": "deployment_bundle",
            "sha256": "9" * 64,
        },
        "upstream_lock_sha256": "e" * 64,
        "legal_sources_lock_sha256": "8" * 64,
        "publications_lock_sha256": "6" * 64,
        "component_attestation_sha256": "7" * 64,
        "evidence_policy": {
            "raw_process_output_retained": False,
            "transaction_content_retained": False,
            "private_key_material_retained": False,
            "credentials_retained": False,
        },
    }


def valid_execution_result() -> dict[str, object]:
    bundle = ADAPTER.load_contract_bundle()
    assertion_ids = sorted(ADAPTER.plan_verifier.REQUIRED_ASSERTIONS)
    required_checks, _ = RUNNER.required_attestation_checks(
        bundle.plan, bundle.adapter
    )
    checks = [
        {
            "check_id": check_id,
            "kind": "attestation",
            "result": "passed",
        }
        for check_id in sorted(required_checks)
    ]
    checks.extend(
        {
            "check_id": check_id,
            "kind": "normative_source_binding",
            "result": "passed",
        }
        for check_id in sorted(
            RUNNER.required_normative_check_ids(bundle.adapter)
        )
    )
    families = {
        assertion["assertion_id"]: family["family_id"]
        for family in bundle.plan["assertion_families"]
        for assertion in family["assertions"]
    }
    return {
        "schema": "reallyme.identity.eudi_execution_result.v1",
        "plan_id": "eudi-relying-party-control-plane-v1",
        "mode": "engineering",
        "result": "passed",
        "created_at": "2026-11-11T12:00:00Z",
        "components": valid_deployment()["components"],
        "artifact_sha256": "d" * 64,
        "trust_artifact_sha256": "f" * 64,
        "credential_authority_artifact_sha256": "9" * 64,
        "component_attestation_sha256": "7" * 64,
        "source_locks": {
            "eudi_sources_sha256": "e" * 64,
            "eudi_legal_sources_sha256": "8" * 64,
            "eudi_publications_sha256": "6" * 64,
        },
        "upstream_sources": [
            {
                "source_id": source_id,
                "repository": bundle.upstream_sources[source_id]["repository"],
                "ref": bundle.upstream_sources[source_id]["ref"],
                "commit": bundle.upstream_sources[source_id]["commit"],
            }
            for source_id in sorted(ADAPTER.EXPECTED_EXECUTION_SOURCES)
        ],
        "checks": checks,
        "assertions": [
            {
                "family_id": families[assertion_id],
                "assertion_id": assertion_id,
                "result": "passed",
                "check_ids": [f"attestation.{assertion_id}"],
                "evidence_strength": "attestation_only",
            }
            for assertion_id in assertion_ids
        ],
        "evidence_policy": {
            "contains_sensitive_data": False,
            "raw_process_output_retained": False,
            "transaction_content_retained": False,
            "private_key_material_retained": False,
            "credentials_retained": False,
        },
    }


def valid_component_attestation(required_checks: set[str]) -> dict[str, object]:
    return {
        "schema": "reallyme.identity.component_attestation.v1",
        "classification": "internal",
        "component": {
            "component_id": "candidate",
            "repository": "https://github.com/reallyme/product",
            "source_commit": "a" * 40,
        },
        "release": {"version": "1.0.0", "source_ref": "v1.0.0"},
        "artifacts": [
            {"artifact_id": "candidate_binary", "kind": "binary", "sha256": "d" * 64},
            {"artifact_id": "trust_service", "kind": "binary", "sha256": "f" * 64},
            {"artifact_id": "credential_authority", "kind": "archive", "sha256": "9" * 64},
            {"artifact_id": "eudi_sources_lock", "kind": "metadata", "sha256": "e" * 64},
            {"artifact_id": "eudi_legal_sources_lock", "kind": "metadata", "sha256": "8" * 64},
        ],
        "dependency_lock": {"kind": "cargo", "sha256": "6" * 64},
        "toolchain": {"identifier": "rust", "version": "1.100.0"},
        "checks": [
            {
                "check_id": check_id,
                "category": "integration",
                "result": "passed",
                "evidence_sha256": "5" * 64,
            }
            for check_id in sorted(required_checks)
        ],
        "created_at": "2026-11-11T12:00:00Z",
        "evidence_policy": {
            "contains_sensitive_data": False,
            "raw_process_output_retained": False,
            "credentials_retained": False,
            "private_key_material_retained": False,
        },
    }


class EudiAdapterTests(unittest.TestCase):
    def test_checked_contract_bundle_is_valid(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        self.assertEqual(
            set(bundle.adapter["execution_sources"]),
            ADAPTER.EXPECTED_EXECUTION_SOURCES,
        )

    def test_plan_uses_opaque_attestation_contracts(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        contracts = {
            contract
            for family in bundle.plan["assertion_families"]
            for assertion in family["assertions"]
            for contract in assertion["evidence_contracts"]
        }
        self.assertEqual(len(contracts), len(ADAPTER.plan_verifier.REQUIRED_ASSERTIONS))
        self.assertTrue(all(contract.startswith("attestation.") for contract in contracts))
        self.assertEqual(
            bundle.plan["evidence_coverage"],
            {
                "assertion_count": 19,
                "independently_observed_assertion_count": 0,
                "attestation_only_assertion_count": 19,
                "badge_eligible": False,
            },
        )

    def test_valid_deployment_manifest_is_accepted(self) -> None:
        components = RUNNER.validate_deployment_manifest(valid_deployment())
        self.assertEqual(set(components), {"candidate", "platform", "ssi"})

    def test_substituted_component_repository_is_rejected(self) -> None:
        changed = valid_deployment()
        changed["components"][0]["repository"] = "https://github.com/example/eudi"
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_deployment_manifest(changed)

    def test_duplicate_component_is_rejected(self) -> None:
        changed = valid_deployment()
        changed["components"][2] = copy.deepcopy(changed["components"][0])
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_deployment_manifest(changed)

    def test_sensitive_output_policy_is_rejected(self) -> None:
        changed = valid_deployment()
        changed["evidence_policy"]["credentials_retained"] = True
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_deployment_manifest(changed)

    def test_complete_component_attestation_is_accepted(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        required_checks, _ = RUNNER.required_attestation_checks(
            bundle.plan, bundle.adapter
        )
        attestation = valid_component_attestation(required_checks)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attestation.json"
            payload = (json.dumps(attestation, sort_keys=True) + "\n").encode("utf-8")
            path.write_bytes(payload)
            observed = RUNNER.verify_attestation(
                path,
                hashlib.sha256(payload).hexdigest(),
                valid_deployment()["components"][0],
                {
                    "candidate_binary": "d" * 64,
                    "trust_service": "f" * 64,
                    "credential_authority": "9" * 64,
                    "eudi_sources_lock": "e" * 64,
                    "eudi_legal_sources_lock": "8" * 64,
                },
                required_checks,
            )
        self.assertEqual(observed, required_checks)

    def test_incomplete_component_attestation_is_rejected(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        required_checks, _ = RUNNER.required_attestation_checks(
            bundle.plan, bundle.adapter
        )
        attestation = valid_component_attestation(required_checks)
        attestation["checks"].pop()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attestation.json"
            payload = (json.dumps(attestation, sort_keys=True) + "\n").encode("utf-8")
            path.write_bytes(payload)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER.verify_attestation(
                    path,
                    hashlib.sha256(payload).hexdigest(),
                    valid_deployment()["components"][0],
                    {
                        "candidate_binary": "d" * 64,
                        "trust_service": "f" * 64,
                        "credential_authority": "9" * 64,
                        "eudi_sources_lock": "e" * 64,
                        "eudi_legal_sources_lock": "8" * 64,
                    },
                    required_checks,
                )

    def test_substituted_source_binding_attestation_is_rejected(self) -> None:
        adapter = ADAPTER.load_object(ADAPTER.ADAPTER_PATH)
        adapter["source_bindings"][0]["attestation_check_id"] = "invalid"
        with self.assertRaises(ADAPTER.AdapterError):
            ADAPTER.validate_adapter(adapter)

    def test_modified_normative_profile_contract_is_rejected(self) -> None:
        adapter = ADAPTER.load_object(ADAPTER.ADAPTER_PATH)
        adapter["normative_profiles"][0]["expected_version"] = "1.6"
        with self.assertRaises(ADAPTER.AdapterError):
            ADAPTER.validate_adapter(adapter)

    def test_requirement_test_plan_covers_complete_evidence_for_each_tranche(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        source_commit = bundle.upstream_sources[
            "eudi-technical-specifications"
        ]["commit"]
        ADAPTER.requirement_tests.verify_plan(
            bundle.requirement_test_plan,
            bundle.plan,
            source_commit,
        )
        self.assertFalse(bundle.requirement_test_plan["complete"])
        self.assertEqual(len(bundle.requirement_test_plan["tests"]), 7)

    def test_requirement_test_plan_rejects_partial_assertion_coverage(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        changed = copy.deepcopy(bundle.requirement_test_plan)
        changed["tests"].pop()
        with self.assertRaises(
            ADAPTER.requirement_tests.RequirementTestPlanError
        ):
            ADAPTER.requirement_tests.verify_plan(
                changed,
                bundle.plan,
                bundle.upstream_sources["eudi-technical-specifications"]["commit"],
            )

    def test_requirement_test_plan_rejects_target_path_mismatch(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        changed = copy.deepcopy(bundle.requirement_test_plan)
        changed["tests"][0]["test_target"] = "substituted_test_target"
        with self.assertRaises(
            ADAPTER.requirement_tests.RequirementTestPlanError
        ):
            ADAPTER.requirement_tests.verify_plan(
                changed,
                bundle.plan,
                bundle.upstream_sources["eudi-technical-specifications"]["commit"],
            )

    def test_normative_statement_normalization_matches_taxonomy_contract(self) -> None:
        source = "alpha  \r\n\tbéta\rignored\n".encode("utf-8")
        expected = hashlib.sha256("alpha  \n\tbéta\n".encode("utf-8")).hexdigest()
        self.assertEqual(
            REQUIREMENT_RUNNER.normalized_statement_sha256(source, 1, 2),
            expected,
        )

    def test_normative_statement_normalization_rejects_nul_and_bad_range(self) -> None:
        with self.assertRaises(REQUIREMENT_RUNNER.RequirementRunnerError):
            REQUIREMENT_RUNNER.normalized_statement_sha256(b"invalid\0text\n", 1, 1)
        with self.assertRaises(REQUIREMENT_RUNNER.RequirementRunnerError):
            REQUIREMENT_RUNNER.normalized_statement_sha256(b"one line\n", 1, 2)

    def test_exact_cargo_filter_cannot_pass_after_running_zero_tests(self) -> None:
        test = copy.deepcopy(
            ADAPTER.load_contract_bundle().requirement_test_plan["tests"][0]
        )

        def run_zero_tests(arguments: object, **kwargs: object) -> object:
            del arguments
            stdout = kwargs["stdout"]
            stderr = kwargs["stderr"]
            stdout.write(
                b"\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; "
                b"0 ignored; 0 measured; 12 filtered out; finished in 0.00s\n"
            )
            stderr.write(b"")
            return REQUIREMENT_RUNNER.subprocess.CompletedProcess([], 0)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                REQUIREMENT_RUNNER.subprocess,
                "run",
                side_effect=run_zero_tests,
            ):
                outcome = REQUIREMENT_RUNNER.execute_test(Path(directory), test)
        self.assertEqual(outcome.status, "failed")
        self.assertEqual(outcome.exit_code, 125)

    def test_taxonomy_observation_distinguishes_framework_and_subject(self) -> None:
        test = ADAPTER.load_contract_bundle().requirement_test_plan["tests"][0]
        outcome = REQUIREMENT_RUNNER.TestOutcome(
            "passed",
            0,
            "1" * 64,
            "2" * 64,
            "2026-11-13T12:00:00Z",
            "2026-11-13T12:00:01Z",
        )
        observation = REQUIREMENT_RUNNER.observation_document(
            test,
            "eudi.rp.association.behavior",
            "3" * 64,
            "4" * 64,
            "5" * 40,
            "6" * 40,
            "0.3.3",
            "7" * 64,
            "8" * 64,
            "1.100.0",
            "results/eudi/result.json",
            "9" * 64,
            outcome,
        )
        self.assertEqual(
            observation["producer"],
            {
                "repository": "reallyme/identity-conformance",
                "source_revision": "6" * 40,
            },
        )
        self.assertEqual(
            observation["subject"],
            {"repository": "reallyme/eudi", "source_revision": "5" * 40},
        )

    def test_taxonomy_requirement_rejects_unrelated_subject(self) -> None:
        test = ADAPTER.load_contract_bundle().requirement_test_plan["tests"][0]
        inventory = {
            "requirements": [
                {
                    "requirement_id": test["requirement_id"],
                    "requirement_sha256": "1" * 64,
                    "subject_repository": "reallyme/unrelated",
                    "required_evidence": [test["evidence_class"]],
                }
            ]
        }
        with self.assertRaises(REQUIREMENT_RUNNER.RequirementRunnerError):
            REQUIREMENT_RUNNER.requirement_from_inventory(
                inventory,
                test["requirement_id"],
                test["evidence_class"],
            )

    def test_taxonomy_receipt_binds_canonical_path_selector_and_auditor(self) -> None:
        test = ADAPTER.load_contract_bundle().requirement_test_plan["tests"][0]
        outcome = REQUIREMENT_RUNNER.TestOutcome(
            "passed",
            0,
            "1" * 64,
            "2" * 64,
            "2026-11-13T12:00:00Z",
            "2026-11-13T12:00:01Z",
        )
        result_sha256 = "3" * 64
        taxonomy_commit = "4" * 40
        observation = REQUIREMENT_RUNNER.observation_document(
            test,
            str(test["command_id"]),
            "5" * 64,
            "6" * 64,
            "7" * 40,
            "8" * 40,
            "0.3.3",
            "9" * 64,
            "a" * 64,
            "1.100.0",
            f"results/{test['command_id']}.json",
            result_sha256,
            outcome,
        )
        observation_bytes = (
            json.dumps(observation, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            taxonomy = Path(directory)
            entrypoint = taxonomy / "scripts/audit_conformance_execution_observation.rb"
            implementation = taxonomy / "scripts/conformance_execution_observation.rb"
            inventory = taxonomy / "conformance/inventory/requirements.json"
            entrypoint.parent.mkdir(parents=True)
            inventory.parent.mkdir(parents=True)
            entrypoint.write_bytes(b"entrypoint\n")
            implementation.write_bytes(b"implementation\n")
            inventory.write_bytes(b"{}\n")
            receipt = {
                "$comment": "test receipt",
                "schema": "reallyme.identity.conformance_execution_audit_receipt.v1",
                "audit_status": "passed",
                "observation_id": test["command_id"],
                "observation_path": (
                    f"conformance/observations/executions/{test['command_id']}.json"
                ),
                "observation_sha256": hashlib.sha256(observation_bytes).hexdigest(),
                "inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
                "taxonomy_source_sha256": observation["taxonomy_source_sha256"],
                "requirement_id": observation["requirement_id"],
                "requirement_sha256": observation["requirement_sha256"],
                "evidence_class": test["evidence_class"],
                "execution_status": "passed",
                "auditor": {
                    "repository": "reallyme/identity-taxonomy",
                    "source_revision": taxonomy_commit,
                    "entrypoint_path": "scripts/audit_conformance_execution_observation.rb",
                    "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
                    "implementation_path": "scripts/conformance_execution_observation.rb",
                    "implementation_sha256": hashlib.sha256(implementation.read_bytes()).hexdigest(),
                },
                "producer": observation["producer"],
                "subject": observation["subject"],
                "runner": {
                    "repository": observation["runner"]["repository"],
                    "source_revision": observation["runner"]["source_revision"],
                    "release_version": observation["runner"]["release_version"],
                },
                "test": observation["test"],
                "result_sha256": result_sha256,
                "completed_at": outcome.completed_at,
                "metadata_only": True,
            }
            REQUIREMENT_RESULTS.validate_receipt(
                receipt,
                observation,
                hashlib.sha256(observation_bytes).hexdigest(),
                test,
                result_sha256,
                taxonomy,
                taxonomy_commit,
            )
            changed = copy.deepcopy(receipt)
            changed["test"]["selector"] = "substituted_selector"
            with self.assertRaises(REQUIREMENT_RESULTS.RequirementResultError) as raised:
                REQUIREMENT_RESULTS.validate_receipt(
                    changed,
                    observation,
                    hashlib.sha256(observation_bytes).hexdigest(),
                    test,
                    result_sha256,
                    taxonomy,
                    taxonomy_commit,
                )
            self.assertIs(
                raised.exception.reason,
                REQUIREMENT_RESULTS.RequirementResultErrorReason.RECEIPT_INVALID,
            )

    def test_neutral_requirement_results_bind_caller_candidate(self) -> None:
        plan = ADAPTER.load_contract_bundle().requirement_test_plan
        candidate_commit = "a" * 40
        framework_commit = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            result_dir = root / "results"
            (result_dir / "results").mkdir(parents=True)
            symbols_by_path: dict[str, list[str]] = {}
            for test in plan["tests"]:
                symbols_by_path.setdefault(test["test_path"], []).append(test["symbol"])
            for relative_path, symbols in symbols_by_path.items():
                path = candidate / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "\n".join(f"fn {symbol}() {{}}" for symbol in symbols) + "\n",
                    encoding="utf-8",
                )
            records: list[dict[str, object]] = []
            outcome = REQUIREMENT_RUNNER.TestOutcome(
                "passed",
                0,
                "1" * 64,
                "2" * 64,
                "2026-11-13T12:00:00Z",
                "2026-11-13T12:00:01Z",
            )
            for test in plan["tests"]:
                document = REQUIREMENT_RUNNER.neutral_result_document(test, outcome)
                payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(
                    "utf-8"
                )
                (result_dir / "results" / f"{test['command_id']}.json").write_bytes(
                    payload
                )
                records.append(
                    {
                        "command_id": test["command_id"],
                        "assertion_id": test["assertion_id"],
                        "evidence_class": test["evidence_class"],
                        "status": "passed",
                        "test_source_sha256": hashlib.sha256(
                            (candidate / test["test_path"]).read_bytes()
                        ).hexdigest(),
                        "result_sha256": hashlib.sha256(payload).hexdigest(),
                        "observation_emitted": False,
                    }
                )
            manifest_path = (
                REPOSITORY_ROOT
                / "plans/eudi/relying-party-requirement-tests.json"
            )
            manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            index = {
                "$comment": REQUIREMENT_RUNNER.NOTICE,
                "schema": "reallyme.identity.eudi_requirement_test_execution.v1",
                "plan_id": plan["plan_id"],
                "framework_commit": framework_commit,
                "candidate_repository": "reallyme/eudi",
                "candidate_commit": candidate_commit,
                "command_manifest_sha256": manifest_sha256,
                "status": "passed",
                "records": records,
                "taxonomy_observations_emitted": False,
            }
            (result_dir / "index.json").write_text(
                json.dumps(index, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            REQUIREMENT_RESULTS.verify_results(
                result_dir,
                candidate,
                candidate_commit,
                framework_commit,
                "forbidden",
                "forbidden",
            )
            with self.assertRaises(REQUIREMENT_RESULTS.RequirementResultError):
                REQUIREMENT_RESULTS.verify_results(
                    result_dir,
                    candidate,
                    "c" * 40,
                    framework_commit,
                    "forbidden",
                    "forbidden",
                )

    def test_normative_profiles_bind_exact_candidate_and_framework_bytes(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        profile_fields = {
            "ts5_version": "1.6.1",
            "ts5_baseline_commit": "a" * 40,
            "ts6_version": "1.2.2",
            "ts6_baseline_commit": "b" * 40,
        }
        with tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as upstream_directory:
            candidate_root = Path(candidate_directory)
            upstream_root = Path(upstream_directory)
            for profile in bundle.adapter["normative_profiles"]:
                commit = profile_fields[profile["commit_field"]]
                for source_file in profile["files"]:
                    payload = (
                        f"{profile['profile_id']}:{source_file['artifact_id']}\n"
                    ).encode("utf-8")
                    candidate_path = (
                        candidate_root
                        / profile["candidate_root"]
                        / commit
                        / source_file["candidate_path"]
                    )
                    upstream_path = (
                        upstream_root
                        / profile["upstream_root"]
                        / source_file["upstream_path"]
                    )
                    candidate_path.parent.mkdir(parents=True, exist_ok=True)
                    upstream_path.parent.mkdir(parents=True, exist_ok=True)
                    candidate_path.write_bytes(payload)
                    upstream_path.write_bytes(payload)
            checks = RUNNER.evaluate_normative_profiles(
                profile_fields,
                candidate_root,
                upstream_root,
                bundle.adapter,
            )
        self.assertEqual(
            {check.check_id for check in checks},
            RUNNER.required_normative_check_ids(bundle.adapter),
        )
        self.assertTrue(all(check.result == "passed" for check in checks))

    def test_stale_normative_profile_version_fails_closed(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        profile_fields = {
            "ts5_version": "1.6",
            "ts5_baseline_commit": "a" * 40,
            "ts6_version": "1.2.2",
            "ts6_baseline_commit": "b" * 40,
        }
        with tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as upstream_directory:
            checks = RUNNER.evaluate_normative_profiles(
                profile_fields,
                Path(candidate_directory),
                Path(upstream_directory),
                bundle.adapter,
            )
        ts5_checks = [
            check for check in checks if check.check_id.startswith("normative_source.ts5.")
        ]
        self.assertEqual(len(ts5_checks), 3)
        self.assertTrue(all(check.result == "failed" for check in ts5_checks))

    def test_normative_profile_byte_substitution_fails_closed(self) -> None:
        bundle = ADAPTER.load_contract_bundle()
        profile = bundle.adapter["normative_profiles"][1]
        source_file = profile["files"][0]
        profile_fields = {
            "ts5_version": "1.6.1",
            "ts5_baseline_commit": "a" * 40,
            "ts6_version": "1.2.2",
            "ts6_baseline_commit": "b" * 40,
        }
        with tempfile.TemporaryDirectory() as candidate_directory, tempfile.TemporaryDirectory() as upstream_directory:
            candidate_root = Path(candidate_directory)
            upstream_root = Path(upstream_directory)
            candidate_path = (
                candidate_root
                / profile["candidate_root"]
                / profile_fields[profile["commit_field"]]
                / source_file["candidate_path"]
            )
            upstream_path = (
                upstream_root
                / profile["upstream_root"]
                / source_file["upstream_path"]
            )
            candidate_path.parent.mkdir(parents=True, exist_ok=True)
            upstream_path.parent.mkdir(parents=True, exist_ok=True)
            candidate_path.write_bytes(b"candidate\n")
            upstream_path.write_bytes(b"pinned\n")
            checks = RUNNER.evaluate_normative_profiles(
                profile_fields,
                candidate_root,
                upstream_root,
                {"normative_profiles": [profile]},
            )
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].result, "failed")

    def test_duplicate_deployment_json_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deployment.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(ADAPTER.AdapterError):
                ADAPTER.load_object(path)

    def test_new_schemas_are_valid_json(self) -> None:
        for name in (
            "eudi-deployment-manifest.schema.json",
            "eudi-execution-result.schema.json",
            "eudi-public-evidence.schema.json",
            "component-attestation.schema.json",
            "eudi-relying-party-requirement-test-plan.schema.json",
            "eudi-relying-party-requirement-test-result.schema.json",
            "eudi-relying-party-requirement-test-execution.schema.json",
        ):
            value = json.loads(
                (REPOSITORY_ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                value["$schema"], "https://json-schema.org/draft/2020-12/schema"
            )
        public_schema = json.loads(
            (REPOSITORY_ROOT / "schemas/eudi-public-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(public_schema["properties"]["execution"]["properties"]["mode"]["enum"]),
            RUNNER.EXECUTION_MODES,
        )

    def test_passed_execution_result_is_accepted(self) -> None:
        RESULT.verify_result(valid_execution_result())

    def test_failed_execution_result_is_rejected(self) -> None:
        changed = valid_execution_result()
        changed["checks"][0]["result"] = "failed"
        with self.assertRaises(RESULT.adapter_verifier.AdapterError):
            RESULT.verify_result(changed)

    def test_execution_result_without_normative_source_binding_is_rejected(self) -> None:
        changed = valid_execution_result()
        changed["checks"] = [
            check
            for check in changed["checks"]
            if check["kind"] != "normative_source_binding"
        ]
        with self.assertRaises(RESULT.adapter_verifier.AdapterError):
            RESULT.verify_result(changed)

    def test_attestation_only_assertion_cannot_claim_stronger_evidence(self) -> None:
        changed = valid_execution_result()
        changed["assertions"][0]["evidence_strength"] = "framework_probe"
        with self.assertRaises(RESULT.adapter_verifier.AdapterError):
            RESULT.verify_result(changed)

    def test_live_result_requires_live_probe(self) -> None:
        changed = valid_execution_result()
        changed["mode"] = "live_ts5"
        with self.assertRaises(RESULT.adapter_verifier.AdapterError):
            RESULT.verify_result(changed)

    def test_public_evidence_omits_private_repository_metadata(self) -> None:
        framework_manifest = PUBLIC_EVIDENCE.framework_release.build_manifest(
            "a" * 40
        )
        evidence = PUBLIC_EVIDENCE.build_evidence(
            valid_execution_result(),
            "1" * 64,
            framework_manifest,
            "2" * 64,
            "3" * 64,
            PUBLIC_EVIDENCE.require_review(
                "security_reviewer", "2026-11-11T12:00:00Z"
            ),
            PUBLIC_EVIDENCE.require_review(
                "disclosure_reviewer", "2026-11-11T12:01:00Z"
            ),
        )
        encoded = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("https://github.com/reallyme/", encoded)
        self.assertNotIn("component_id", encoded)
        self.assertEqual(evidence["classification"], "public")

    def test_public_evidence_rejects_an_incomplete_framework_manifest(self) -> None:
        with self.assertRaises(PUBLIC_EVIDENCE.runner.RunnerError):
            PUBLIC_EVIDENCE.build_evidence(
                valid_execution_result(),
                "1" * 64,
                {
                    "schema": "reallyme.identity.conformance_framework_release.v1",
                    "release_kind": "framework",
                    "release_version": "1.0.0",
                },
                "2" * 64,
                "3" * 64,
                PUBLIC_EVIDENCE.require_review(
                    "security_reviewer", "2026-11-11T12:00:00Z"
                ),
                PUBLIC_EVIDENCE.require_review(
                    "disclosure_reviewer", "2026-11-11T12:01:00Z"
                ),
            )

    def test_deployment_manifest_binds_the_expected_candidate_repository(self) -> None:
        RUNNER.validate_deployment_manifest(
            valid_deployment(), "https://github.com/reallyme/product"
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_deployment_manifest(
                valid_deployment(), "https://github.com/reallyme/substituted"
            )

    def test_credential_authority_artifact_is_required(self) -> None:
        changed = valid_deployment()
        del changed["credential_authority_artifact"]
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_deployment_manifest(changed)

    def test_service_endpoint_rejects_plain_http(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_service_endpoint("http://127.0.0.1:8443/healthz")

    def test_service_endpoint_rejects_embedded_credentials(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_service_endpoint(
                "https://user:secret@127.0.0.1:8443/healthz"
            )

    def test_service_probe_contract_is_closed(self) -> None:
        services = RUNNER.service_probe_contract(ADAPTER.load_contract_bundle().adapter)
        self.assertEqual(
            set(services),
            {"trust_service", "credential_authority"},
        )


if __name__ == "__main__":
    unittest.main()
