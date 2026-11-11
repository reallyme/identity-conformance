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
        "toolchain": {"identifier": "rust", "version": "1.99.1"},
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
        ):
            value = json.loads((REPOSITORY_ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
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

    def test_live_result_requires_live_probe(self) -> None:
        changed = valid_execution_result()
        changed["mode"] = "live_ts5"
        with self.assertRaises(RESULT.adapter_verifier.AdapterError):
            RESULT.verify_result(changed)

    def test_public_evidence_omits_private_repository_metadata(self) -> None:
        framework_manifest = PUBLIC_EVIDENCE.framework_release.build_manifest(
            "1.0.0", "a" * 40
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
