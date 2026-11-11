# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import ModuleType, SimpleNamespace


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


MANIFESTS = load_script("verify_oidf_manifests", "scripts/verify_oidf_manifests.py")
PARAMETERS = load_script(
    "verify_oidf_certification_parameters",
    "scripts/verify_oidf_certification_parameters.py",
)
NORMATIVE_SOURCES = load_script(
    "verify_normative_sources", "scripts/verify_normative_sources.py"
)
COMPONENT_LOCK = load_script(
    "verify_component_lock", "scripts/verify_component_lock.py"
)
EVIDENCE_INDEX = load_script(
    "build_oidf_evidence_index", "scripts/build_oidf_evidence_index.py"
)
VCI_EVIDENCE_INDEX = load_script(
    "build_oidf_openid4vci_evidence_index",
    "scripts/build_oidf_openid4vci_evidence_index.py",
)
VCI_PRE_SUBMISSION = load_script(
    "assert_oidf_openid4vci_pre_submission",
    "scripts/assert_oidf_openid4vci_pre_submission.py",
)
VP_PRE_SUBMISSION = load_script(
    "assert_oidf_openid4vp_pre_submission",
    "scripts/assert_oidf_openid4vp_pre_submission.py",
)
LOCAL_ENDPOINTS = load_script(
    "verify_oidf_local_endpoints", "scripts/verify_oidf_local_endpoints.py"
)
DEPLOYMENT_MANIFEST = load_script(
    "verify_oidf_deployment_manifest",
    "scripts/verify_oidf_deployment_manifest.py",
)
INPUT_FINGERPRINT = load_script(
    "hash_oidf_input", "scripts/hash_oidf_input.py"
)


def valid_deployment_manifest() -> dict[str, object]:
    component_lock = json.loads(
        (REPOSITORY_ROOT / "components.lock.json").read_text(encoding="utf-8")
    )
    components = {
        item["component_id"]: item for item in component_lock["repositories"]
    }

    def deployment(
        component_id: str, endpoints: dict[str, str], digest_character: str
    ) -> dict[str, object]:
        component = components[component_id]
        return {
            "source_repository": component["repository"],
            "source_commit": component["commit"],
            "artifact": {
                "kind": "oci_image",
                "identifier": (
                    "registry.reallyme.com/identity@sha256:"
                    f"{digest_character * 64}"
                ),
                "sha256": digest_character * 64,
            },
            "endpoints": endpoints,
        }

    return {
        "schema_version": 4,
        "purpose": "oidf-certification-deployment-bom",
        "legal_entity": "ReallyMe Technologies Limited",
        "product_name": "ReallyMe Identity",
        "product_version": "1.0.0-rc.1",
        "environment": "preproduction",
        "roles": {
            "openid4vci_issuer": deployment(
                "openid4vci",
                {"issuer_base_url": "https://issuer.reallyme.com/"}, "a"
            ),
            "openid4vci_wallet": deployment(
                "identity",
                {
                    "wallet_harness_endpoint": "https://wallet.reallyme.com/oidf/vci",
                    "wallet_harness_health_endpoint": (
                        "https://wallet.reallyme.com/healthz"
                    ),
                },
                "b",
            ),
            "openid4vp_verifier": deployment(
                "identity",
                {
                    "verifier_base_url": "https://verifier.reallyme.com",
                    "verifier_launch_endpoint": (
                        "https://verifier.reallyme.com/oidf/launch"
                    ),
                    "verifier_evidence_endpoint": (
                        "https://verifier.reallyme.com/oidf/evidence"
                    ),
                    "verifier_health_endpoint": (
                        "https://verifier.reallyme.com/healthz"
                    ),
                },
                "c",
            ),
            "openid4vp_wallet": deployment(
                "identity",
                {
                    "wallet_harness_endpoint": "https://wallet.reallyme.com/oidf/vp",
                    "wallet_harness_health_endpoint": (
                        "https://wallet.reallyme.com/healthz"
                    ),
                },
                "d",
            ),
        },
        "capabilities": {"zk_presentations": {"enabled": False}},
    }


class ManifestContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.suite_lock = MANIFESTS.load_object(MANIFESTS.SUITE_LOCK_PATH)
        self.certification = MANIFESTS.load_object(
            MANIFESTS.PLANS_ROOT / "certification.json"
        )
        self.engineering = MANIFESTS.load_object(
            MANIFESTS.PLANS_ROOT / "engineering.json"
        )
        self.adapters = MANIFESTS.load_object(MANIFESTS.ADAPTER_REGISTRY_PATH)
        self.component_lock = MANIFESTS.load_object(MANIFESTS.COMPONENT_LOCK_PATH)

    def assert_rejected(self, operation: object) -> None:
        if not callable(operation):
            self.fail("test operation must be callable")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                operation()
        self.assertEqual(raised.exception.code, MANIFESTS.EXIT_INVALID_INPUT)

    def test_checked_repository_contract_is_valid(self) -> None:
        self.assertEqual(MANIFESTS.main(), 0)

    def test_current_master_engineering_target_matches_its_own_lock(self) -> None:
        lock_path = "upstream/oidf/engineering-master.lock.json"
        lock = MANIFESTS.load_object(REPOSITORY_ROOT / lock_path)
        manifest = MANIFESTS.load_object(
            MANIFESTS.PLANS_ROOT / "engineering-master.json"
        )
        MANIFESTS.verify_engineering_manifest(manifest, lock, lock_path)
        self.assertEqual(
            PARAMETERS.verify_target_matches_lock(manifest, lock, lock_path),
            lock["commit"],
        )

    def test_certification_rejects_the_engineering_master_pin(self) -> None:
        lock_path = "upstream/oidf/engineering-master.lock.json"
        lock = MANIFESTS.load_object(REPOSITORY_ROOT / lock_path)
        changed = copy.deepcopy(self.certification)
        changed["suite_target"].update(
            lock_file=lock_path, pinned_ref=lock["pinned_ref"], commit=lock["commit"]
        )
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                PARAMETERS.verify_target_matches_lock(changed, lock)
        self.assertEqual(raised.exception.code, PARAMETERS.EXIT_INVALID_INPUT)

    def test_master_assessment_rejects_a_substituted_commit(self) -> None:
        lock_path = "upstream/oidf/engineering-master.lock.json"
        lock = MANIFESTS.load_object(REPOSITORY_ROOT / lock_path)
        manifest = MANIFESTS.load_object(
            MANIFESTS.PLANS_ROOT / "engineering-master.json"
        )
        manifest["suite_target"]["commit"] = "0" * 40
        self.assert_rejected(
            lambda: MANIFESTS.verify_engineering_manifest(manifest, lock, lock_path)
        )

    def test_plan_cannot_change_the_canonical_suite_pin(self) -> None:
        changed = copy.deepcopy(self.certification)
        changed["suite_target"]["commit"] = "0" * 40
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )

    def test_certification_requires_official_production_endpoints(self) -> None:
        changed = copy.deepcopy(self.certification)
        changed["execution_contract"]["production_endpoints"]["api"] = (
            "https://lookalike.example/"
        )
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )

        changed = copy.deepcopy(self.certification)
        changed["execution_contract"]["production_endpoints"]["mtls"] = (
            "https://mtls.certification.openid.net/"
        )
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )

    def test_vp_wallet_certification_requires_format_credential_type_pair(self) -> None:
        changed = copy.deepcopy(self.certification)
        wallet_plan = next(
            plan
            for plan in changed["plans"]
            if plan["plan_id"] == "oid4vp-1final-wallet-haip-test-plan"
        )
        wallet_plan["certification_runs"][0]["credential_type"] = "mdl"
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )

    def test_vp_wallet_engineering_expression_requires_credential_type(self) -> None:
        changed = copy.deepcopy(self.engineering)
        wallet_plan = next(
            plan
            for plan in changed["plans"]
            if plan["plan_id"] == "oid4vp-1final-wallet-test-plan"
        )
        wallet_plan["engineering_runs"][0]["expression"] = wallet_plan[
            "engineering_runs"
        ][0]["expression"].replace("[credential_type=eudi_pid]", "")
        self.assert_rejected(
            lambda: MANIFESTS.verify_engineering_manifest(changed, self.suite_lock)
        )

    def test_plan_cannot_select_only_part_of_a_module_inventory(self) -> None:
        changed = copy.deepcopy(self.certification)
        changed["plans"][0]["certification_runs"][0]["expression"] += ":one-module"
        self.assert_rejected(
            lambda: MANIFESTS.verify_certification_manifest(changed, self.suite_lock)
        )

    def test_adapter_plan_must_have_exactly_one_owner(self) -> None:
        changed = copy.deepcopy(self.adapters)
        duplicated_plan = changed["adapters"][0]["plan_ids"][0]
        changed["adapters"][1]["plan_ids"].append(duplicated_plan)
        owners = MANIFESTS.plan_owners(self.certification, self.engineering)
        self.assert_rejected(
            lambda: MANIFESTS.verify_adapter_registry(changed, owners)
        )

    def test_adapter_boundary_rejects_path_traversal(self) -> None:
        changed = copy.deepcopy(self.adapters)
        changed["adapters"][0]["contract_path"] = "adapters/../upstream"
        owners = MANIFESTS.plan_owners(self.certification, self.engineering)
        self.assert_rejected(
            lambda: MANIFESTS.verify_adapter_registry(changed, owners)
        )

    def test_adapter_rejects_external_component_repository(self) -> None:
        changed = copy.deepcopy(self.adapters)
        changed["adapters"][0]["component_repositories"] = [
            "https://example.invalid/unreviewed/component"
        ]
        owners = MANIFESTS.plan_owners(self.certification, self.engineering)
        self.assert_rejected(
            lambda: MANIFESTS.verify_adapter_registry(changed, owners)
        )

    def test_adapter_components_must_match_release_bom(self) -> None:
        changed = copy.deepcopy(self.adapters)
        changed["adapters"][1]["component_repositories"].remove(
            "https://github.com/reallyme/ssi"
        )
        owners = MANIFESTS.plan_owners(self.certification, self.engineering)
        components = MANIFESTS.component_repositories_by_role(self.component_lock)
        self.assert_rejected(
            lambda: MANIFESTS.verify_adapter_registry(changed, owners, components)
        )

    def test_component_lock_rejects_invalid_commit(self) -> None:
        changed = copy.deepcopy(self.component_lock)
        changed["repositories"][0]["commit"] = "not-a-commit"
        self.assert_rejected(
            lambda: MANIFESTS.component_repositories_by_role(changed)
        )

    def test_component_lock_requires_exact_public_crate_releases(self) -> None:
        lock = COMPONENT_LOCK.load_lock()
        packages, overrides = COMPONENT_LOCK.package_policy(lock)
        self.assertEqual(packages, lock["required_cargo_packages"])
        self.assertEqual(overrides, {})
        self.assertEqual(
            set(COMPONENT_LOCK.verify_lock(lock)),
            set(COMPONENT_LOCK.EXPECTED_COMPONENTS),
        )

    def test_evidence_component_lock_requires_every_release_reference(self) -> None:
        lock = COMPONENT_LOCK.load_lock()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                COMPONENT_LOCK.verify_lock(lock, require_release_refs=True)
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_INVALID_INPUT)

    def test_reference_candidate_rejects_a_false_evidence_claim(self) -> None:
        lock = COMPONENT_LOCK.load_lock()
        lock["claim_status"] = "certified"
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                COMPONENT_LOCK.verify_lock(lock)
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_INVALID_INPUT)

    def test_component_dependency_check_rejects_other_jose_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            (checkout / "Cargo.lock").write_text(
                (
                    'version = 4\n\n[[package]]\nname = "reallyme-jose"\n'
                    'version = "0.3.0"\n'
                ),
                encoding="utf-8",
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    COMPONENT_LOCK.verify_cargo_lock(checkout / "Cargo.lock", "test")
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_CONFIGURATION)

    def test_component_dependency_check_rejects_other_cose_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            (checkout / "Cargo.lock").write_text(
                (
                    'version = 4\n\n[[package]]\nname = "reallyme-cose"\n'
                    'version = "0.2.3"\n'
                ),
                encoding="utf-8",
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    COMPONENT_LOCK.verify_cargo_lock(checkout / "Cargo.lock", "test")
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_CONFIGURATION)

    def test_component_dependency_check_rejects_git_source_for_published_crate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            (checkout / "Cargo.lock").write_text(
                (
                    'version = 4\n\n[[package]]\nname = "reallyme-openid4vp-types"\n'
                    'version = "0.1.0"\n'
                    'source = "git+https://github.com/reallyme/openid4vp"\n'
                ),
                encoding="utf-8",
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    COMPONENT_LOCK.verify_cargo_lock(
                        checkout / "Cargo.lock", "test", "identity"
                    )
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_CONFIGURATION)

    def test_component_dependency_check_rejects_wrong_registry_checksum(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            (checkout / "Cargo.lock").write_text(
                (
                    'version = 4\n\n[[package]]\nname = "reallyme-openid4vp-types"\n'
                    'version = "0.1.0"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    f'checksum = "{"0" * 64}"\n'
                ),
                encoding="utf-8",
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    COMPONENT_LOCK.verify_cargo_lock(
                        checkout / "Cargo.lock", "test", "identity"
                    )
        self.assertEqual(raised.exception.code, COMPONENT_LOCK.EXIT_CONFIGURATION)

    def test_component_dependency_check_accepts_exact_registry_release(self) -> None:
        packages, _overrides = COMPONENT_LOCK.package_policy()
        package = packages["reallyme-openid4vp-types"]
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            (checkout / "Cargo.lock").write_text(
                (
                    'version = 4\n\n[[package]]\nname = "reallyme-openid4vp-types"\n'
                    f'version = "{package["version"]}"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    f'checksum = "{package["checksum"]}"\n'
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                COMPONENT_LOCK.verify_cargo_lock(
                    checkout / "Cargo.lock", "test", "identity"
                )
            )

    def test_component_dependency_check_allows_unrelated_nested_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cargo_lock = Path(temporary_directory) / "Cargo.lock"
            cargo_lock.write_text(
                'version = 4\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            self.assertFalse(COMPONENT_LOCK.verify_cargo_lock(cargo_lock, "test"))

    def test_openid4vp_execution_wrapper_requires_all_six_profiles(self) -> None:
        runner = (
            REPOSITORY_ROOT / "scripts" / "run_oidf_openid4vp_certification.sh"
        ).read_text(encoding="utf-8")
        expected_profiles = {
            "verifier-sd-jwt-vc-direct-post-jwt",
            "verifier-iso-mdl-direct-post-jwt",
            "wallet-sd-jwt-vc-direct-post-jwt",
            "wallet-iso-mdl-direct-post-jwt",
            "wallet-sd-jwt-vc-dc-api-jwt",
            "wallet-iso-mdl-dc-api-jwt",
        }
        certification_plan = (
            REPOSITORY_ROOT / "plans" / "oidf" / "certification.json"
        ).read_text(encoding="utf-8")
        for profile_id in expected_profiles:
            self.assertIn(profile_id, certification_plan)
        self.assertIn(
            "verify_component_lock.py --evidence-release --verify-checkouts",
            runner,
        )
        self.assertIn("OIDF_VERIFIER_FLOW_DRIVER_MODE=execute", runner)
        self.assertIn("OIDF_WALLET_FLOW_DRIVER_MODE=execute", runner)
        self.assertIn("OIDF_WALLET_SD_JWT_CONFIG_FILE", runner)
        self.assertIn("OIDF_WALLET_MDOC_CONFIG_FILE", runner)
        self.assertIn("wallet_sd_jwt_config_fingerprint", runner)
        self.assertIn("wallet_mdoc_config_fingerprint", runner)
        self.assertIn(".status == \"validated\"", runner)
        self.assertIn("build_oidf_evidence_index.py", runner)
        self.assertIn("assert_oidf_openid4vp_pre_submission.py", runner)
        self.assertIn('OIDF_PROFILE_ID="${profile_id}"', runner)
        self.assertIn('OIDF_PROFILE_MATRIX="${openid_profile_matrix}"', runner)
        self.assertIn("verify_oidf_deployment_manifest.py", runner)
        self.assertIn("OIDF_DEPLOYMENT_MANIFEST", runner)
        self.assertIn("--component-lock", runner)
        self.assertIn("OIDF_VERIFIER_HEALTH_ENDPOINT", runner)
        self.assertIn("OIDF_VERIFIER_EVIDENCE_ENDPOINT", runner)
        self.assertIn("OIDF_VERIFIER_LAUNCH_TOKEN", runner)
        self.assertIn("OIDF_VERIFIER_EVIDENCE_TOKEN", runner)
        self.assertIn("OIDF_WALLET_HARNESS_HEALTH_ENDPOINT", runner)
        self.assertIn("OIDF_WALLET_HARNESS_TOKEN", runner)
        self.assertIn("production_endpoints.api", runner)
        self.assertIn("production_endpoints.mtls", runner)
        self.assertIn("official OIDF production server", runner)
        self.assertNotIn("--rerun", runner)
        retained_lock_copy = (
            'cp "${repository_root}/components.lock.json" '
            '"${result_root}/components.lock.json"'
        )
        retained_lock_binding = (
            '--component-lock "${result_root}/components.lock.json"'
        )
        self.assertLess(
            runner.index(retained_lock_copy), runner.index(retained_lock_binding)
        )

    def test_direct_matrix_runner_marks_outputs_non_certification(self) -> None:
        runner = (
            REPOSITORY_ROOT / "scripts" / "run_oidf_final_matrix.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('"certification_evidence":false', runner)
        self.assertIn("interactive_product_and_deployment_evidence_not_collected", runner)
        self.assertIn("result directory already exists", runner)

    def test_openid4vp_local_rehearsal_is_complete_and_non_certifying(self) -> None:
        runner = (
            REPOSITORY_ROOT / "scripts" / "run_oidf_openid4vp_local_rehearsal.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('"certification_evidence":false', runner)
        self.assertIn('"submission_authorized":false', runner)
        self.assertIn("OIDF_LOCAL_REHEARSAL must be enabled", runner)
        self.assertIn("CONFORMANCE_DEV_MODE must be unset", runner)
        self.assertIn("CONFORMANCE_VERIFY_SSL must be explicitly enabled", runner)
        self.assertIn("CONFORMANCE_TOKEN must be unset", runner)
        self.assertIn("local conformance API token creation failed", runner)
        self.assertIn("--request DELETE", runner)
        self.assertIn("local conformance API is not anonymously reachable", runner)
        self.assertIn('--ca-cert "${SSL_CERT_FILE}"', runner)
        self.assertIn('"${#verifier_profiles[@]}" -eq 2', runner)
        self.assertIn('"${#wallet_profiles[@]}" -eq 4', runner)
        self.assertIn("OIDF_VERIFIER_FLOW_DRIVER_MODE=execute", runner)
        self.assertIn("OIDF_WALLET_FLOW_DRIVER_MODE=execute", runner)
        self.assertIn("archive_verifier_preflight", runner)
        self.assertIn("preflight/${profile_id}.json", runner)
        self.assertIn("assert_oidf_openid4vp_local_rehearsal.py", runner)
        self.assertIn(
            "verify_component_lock.py --verify-checkouts",
            runner,
        )
        self.assertIn("OIDF_LOOPBACK_HTTP_ORIGIN is required", runner)
        self.assertIn("verify_oidf_loopback_crl.py", runner)
        self.assertIn('--credential-format sd_jwt_vc', runner)
        self.assertIn('--credential-format iso_mdl', runner)
        self.assertLess(runner.index('--credential-format iso_mdl'), runner.index('for profile_id in "${verifier_profiles[@]}"'))
        self.assertNotIn("build_oidf_evidence_index.py", runner)
        self.assertNotIn("OIDF_DEPLOYMENT_MANIFEST", runner)
        self.assertNotIn("--rerun", runner)

    def test_local_oidf_endpoint_policy_requires_loopback_only_https(self) -> None:
        accepted = (
            "https://127.0.0.1:8443/",
            "https://[::1]:8444/",
            "https://localhost:8443/",
        )
        for endpoint in accepted:
            validated = LOCAL_ENDPOINTS.validate_endpoint(endpoint)
            self.assertTrue(validated.port >= 1024)
        rejected = (
            "https://localhost.emobix.co.uk:8443/",
            "http://127.0.0.1:8080/",
            "https://127.0.0.1/",
            "https://127.0.0.1:8443/api/runner/available",
            "https://localhost.attacker.example/",
            "https://127.example/",
            "https://192.0.2.1/",
            "https://user@localhost:8443/",
            "https://localhost:8443/?token=secret",
        )
        for endpoint in rejected:
            with self.assertRaises(LOCAL_ENDPOINTS.EndpointError):
                LOCAL_ENDPOINTS.validate_endpoint(endpoint)

    def test_local_oidf_ca_bundle_rejects_empty_symlink_and_writable_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "ca.crt"
            bundle.write_bytes(b"certificate")
            bundle.chmod(0o644)
            self.assertEqual(LOCAL_ENDPOINTS.require_ca_bundle(bundle), bundle)

            bundle.chmod(0o666)
            with self.assertRaises(LOCAL_ENDPOINTS.EndpointError):
                LOCAL_ENDPOINTS.require_ca_bundle(bundle)

            bundle.chmod(0o644)
            link = root / "ca-link.crt"
            link.symlink_to(bundle)
            with self.assertRaises(LOCAL_ENDPOINTS.EndpointError):
                LOCAL_ENDPOINTS.require_ca_bundle(link)

            empty = root / "empty.crt"
            empty.touch()
            with self.assertRaises(LOCAL_ENDPOINTS.EndpointError):
                LOCAL_ENDPOINTS.require_ca_bundle(empty)

    def test_openid4vp_composed_plan_matches_public_profile_contract(self) -> None:
        plan = json.loads(
            (REPOSITORY_ROOT / "plans" / "oidf" / "certification.json").read_text(
                encoding="utf-8"
            )
        )
        matrix = json.loads(
            (
                REPOSITORY_ROOT.parent
                / "openid4vp"
                / "conformance"
                / "oidf"
                / "profile-matrix.json"
            ).read_text(encoding="utf-8")
        )
        selected = VP_PRE_SUBMISSION.selected_profiles(plan)
        supported = VP_PRE_SUBMISSION.supported_profiles(matrix)
        self.assertEqual(len(selected), 6)
        self.assertTrue(set(selected).issubset(supported))
        for profile_id, (role, plan_id, expression) in selected.items():
            profile = supported[profile_id]
            self.assertEqual(profile["role"], role)
            self.assertEqual(profile["plan_id"], plan_id)
            self.assertEqual(profile["expression"], expression)
        self.assertNotIn("product_name", matrix)
        self.assertNotIn("product_version", matrix)

    def test_openid4vp_pre_submission_rejects_duplicate_profile_ids(self) -> None:
        plan = json.loads(
            (REPOSITORY_ROOT / "plans" / "oidf" / "certification.json").read_text(
                encoding="utf-8"
            )
        )
        vp_plan = next(item for item in plan["plans"] if item["protocol"] == "openid4vp")
        vp_plan["certification_runs"].append(
            copy.deepcopy(vp_plan["certification_runs"][0])
        )
        with self.assertRaises(VP_PRE_SUBMISSION.EvidenceError):
            VP_PRE_SUBMISSION.selected_profiles(plan)

    def test_openid4vci_execution_wrapper_requires_all_ten_profiles(self) -> None:
        runner = (
            REPOSITORY_ROOT / "scripts" / "run_oidf_openid4vci_certification.sh"
        ).read_text(encoding="utf-8")
        expected_profiles = {
            "issuer-sd-jwt-vc-wallet-initiated",
            "issuer-sd-jwt-vc-issuer-initiated",
            "issuer-mdoc-wallet-initiated",
            "issuer-mdoc-issuer-initiated",
            "wallet-sd-jwt-vc-wallet-initiated",
            "wallet-sd-jwt-vc-issuer-initiated-by-value",
            "wallet-sd-jwt-vc-issuer-initiated-by-reference",
            "wallet-mdoc-wallet-initiated",
            "wallet-mdoc-issuer-initiated-by-value",
            "wallet-mdoc-issuer-initiated-by-reference",
        }
        certification_plan = (
            REPOSITORY_ROOT / "plans" / "oidf" / "certification.json"
        ).read_text(encoding="utf-8")
        for profile_id in expected_profiles:
            self.assertIn(profile_id, certification_plan)
        self.assertIn(
            "verify_component_lock.py --evidence-release --verify-checkouts",
            runner,
        )
        self.assertEqual(runner.count("OIDF_CONFORMANCE_MODE=hosted"), 2)
        self.assertIn('.result == "passed"', runner)
        self.assertIn("build_oidf_openid4vci_evidence_index.py", runner)
        self.assertIn("assert_oidf_openid4vci_pre_submission.py", runner)
        self.assertIn("verify_oidf_deployment_manifest.py", runner)
        self.assertIn("OIDF_DEPLOYMENT_MANIFEST", runner)
        self.assertIn("--component-lock", runner)
        self.assertIn("OPENID4VCI_WALLET_HARNESS_TOKEN", runner)
        self.assertIn("production_endpoints.api", runner)
        self.assertIn("production_endpoints.mtls", runner)
        self.assertIn("official OIDF production server", runner)
        self.assertNotIn("--rerun", runner)
        retained_lock_copy = (
            'cp "${repository_root}/components.lock.json" '
            '"${result_root}/components.lock.json"'
        )
        retained_lock_binding = (
            '--component-lock "${result_root}/components.lock.json"'
        )
        self.assertLess(
            runner.index(retained_lock_copy), runner.index(retained_lock_binding)
        )

    def test_openid4vci_composed_plan_matches_public_profile_contract(self) -> None:
        plan = json.loads(
            (REPOSITORY_ROOT / "plans" / "oidf" / "certification.json").read_text(
                encoding="utf-8"
            )
        )
        matrix_path = (
            REPOSITORY_ROOT.parent
            / "openid4vci"
            / "conformance"
            / "oidf"
            / "profile-matrix.json"
        )
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        selected = VCI_PRE_SUBMISSION.selected_profiles(plan)
        supported = VCI_PRE_SUBMISSION.supported_profiles(matrix)
        self.assertEqual(len(selected), 10)
        self.assertTrue(set(selected).issubset(supported))
        self.assertNotIn("product_name", matrix)
        self.assertNotIn("product_version", matrix)

    def test_openid4vci_pre_submission_rejects_unredacted_secrets(self) -> None:
        with self.assertRaises(VCI_PRE_SUBMISSION.EvidenceError):
            VCI_PRE_SUBMISSION.assert_redacted(
                {"nested": {"client_secret": "must-not-be-retained"}}
            )

    def test_openid4vci_pre_submission_rejects_duplicate_profile_ids(self) -> None:
        plan = json.loads(
            (REPOSITORY_ROOT / "plans" / "oidf" / "certification.json").read_text(
                encoding="utf-8"
            )
        )
        duplicate = copy.deepcopy(plan["plans"][0]["certification_runs"][0])
        plan["plans"][0]["certification_runs"].append(duplicate)
        with self.assertRaises(VCI_PRE_SUBMISSION.EvidenceError):
            VCI_PRE_SUBMISSION.selected_profiles(plan)

    def test_openid4vci_pre_submission_validates_composed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            result_root = root / "results"
            result_root.mkdir()

            def create_repository(path: Path, content: str) -> str:
                # Fixture repositories require their own index even when the
                # outer release gate uses a disposable index for an uncommitted
                # candidate tree.
                git_environment = os.environ.copy()
                git_environment.pop("GIT_INDEX_FILE", None)
                path.mkdir()
                subprocess.run(
                    ["git", "-C", path, "init", "-q"],
                    check=True,
                    env=git_environment,
                )
                subprocess.run(
                    ["git", "-C", path, "config", "user.name", "ReallyMe Test"],
                    check=True,
                    env=git_environment,
                )
                subprocess.run(
                    ["git", "-C", path, "config", "user.email", "test@really.me"],
                    check=True,
                    env=git_environment,
                )
                (path / "tracked.txt").write_text(content, encoding="utf-8")
                subprocess.run(
                    ["git", "-C", path, "add", "tracked.txt"],
                    check=True,
                    env=git_environment,
                )
                subprocess.run(
                    ["git", "-C", path, "commit", "-q", "-m", "Create fixture"],
                    check=True,
                    env=git_environment,
                )
                completed = subprocess.run(
                    ["git", "-C", path, "rev-parse", "HEAD"],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=git_environment,
                )
                return completed.stdout.strip()

            openid_source = root / "openid4vci"
            wallet_source = root / "identity"
            openid_commit = create_repository(openid_source, "openid4vci")
            wallet_commit = create_repository(wallet_source, "identity")
            issuer_binary = root / "issuer-bin"
            wallet_binary = root / "wallet-bin"
            issuer_binary.write_bytes(b"issuer binary")
            wallet_binary.write_bytes(b"wallet binary")
            issuer_digest = hashlib.sha256(issuer_binary.read_bytes()).hexdigest()
            wallet_digest = hashlib.sha256(wallet_binary.read_bytes()).hexdigest()
            issuer_deployment_artifact = root / "issuer-image.tar"
            wallet_deployment_artifact = root / "wallet-image.tar"
            issuer_deployment_artifact.write_bytes(b"issuer image")
            wallet_deployment_artifact.write_bytes(b"wallet image")
            issuer_deployment_digest = hashlib.sha256(
                issuer_deployment_artifact.read_bytes()
            ).hexdigest()
            wallet_deployment_digest = hashlib.sha256(
                wallet_deployment_artifact.read_bytes()
            ).hexdigest()

            certification_plan = root / "certification-plan.json"
            certification_plan.write_bytes(
                (REPOSITORY_ROOT / "plans" / "oidf" / "certification.json").read_bytes()
            )
            profile_matrix = root / "profile-matrix.json"
            profile_matrix.write_bytes(
                (
                    REPOSITORY_ROOT.parent
                    / "openid4vci"
                    / "conformance"
                    / "oidf"
                    / "profile-matrix.json"
                ).read_bytes()
            )
            suite_contract = root / "suite-contract.json"
            suite_contract.write_bytes(
                (
                    REPOSITORY_ROOT.parent
                    / "openid4vci"
                    / "conformance"
                    / "oidf"
                    / "suite-contract.json"
                ).read_bytes()
            )
            suite_commit = json.loads(suite_contract.read_text(encoding="utf-8"))[
                "commit"
            ]
            component_lock = root / "components.lock.json"
            component_lock.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {
                                "component_id": "openid4vci",
                                "repository": "https://github.com/reallyme/openid4vci",
                                "commit": openid_commit,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            issuer_endpoint = "https://issuer.reallyme.com/"
            wallet_endpoint = "https://wallet.reallyme.com/oidf/vci"
            wallet_health_endpoint = "https://wallet.reallyme.com/healthz"
            deployment_manifest = root / "deployment-manifest.json"
            deployment_manifest.write_text(
                json.dumps(
                    {
                        "product_name": "ReallyMe Identity",
                        "product_version": "1.0.0-rc.1",
                        "roles": {
                            "openid4vci_issuer": {
                                "source_repository": "https://github.com/reallyme/openid4vci",
                                "source_commit": openid_commit,
                                "artifact": {
                                    "kind": "oci_image",
                                    "sha256": issuer_deployment_digest,
                                },
                                "endpoints": {"issuer_base_url": issuer_endpoint},
                            },
                            "openid4vci_wallet": {
                                "source_repository": "https://github.com/reallyme/identity",
                                "source_commit": wallet_commit,
                                "artifact": {
                                    "kind": "oci_image",
                                    "sha256": wallet_deployment_digest,
                                },
                                "endpoints": {
                                    "wallet_harness_endpoint": wallet_endpoint,
                                    "wallet_harness_health_endpoint": wallet_health_endpoint,
                                },
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            result_assertion = root / "assert-results.sh"
            result_assertion.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(result_assertion, 0o700)
            wallet_assertion = root / "assert-wallet.py"
            wallet_assertion.write_text("raise SystemExit(0)\n", encoding="utf-8")
            module_inventory = root / "module-inventory.json"
            module_inventory.write_text("{}\n", encoding="utf-8")

            plan = json.loads(certification_plan.read_text(encoding="utf-8"))
            selections = VCI_PRE_SUBMISSION.selected_profiles(plan)
            for profile_id, (role, plan_id, expression) in selections.items():
                profile_dir = result_root / role / profile_id
                export_dir = profile_dir / "suite-export"
                export_dir.mkdir(parents=True)
                export_file = export_dir / "result.zip"
                export_file.write_bytes(profile_id.encode("utf-8"))
                export_digest = hashlib.sha256(export_file.read_bytes()).hexdigest()
                config_name = f"oid4vci-{role}-config.redacted.json"
                (profile_dir / config_name).write_text(
                    json.dumps({"alias": f"test-{profile_id}"}), encoding="utf-8"
                )
                (profile_dir / "oidf-suite-revision.txt").write_text(
                    f"{suite_commit}\n", encoding="ascii"
                )
                summary: dict[str, object] = {
                    "schema_version": 3,
                    "source_repository": "https://github.com/reallyme/openid4vci",
                    "source_commit": openid_commit,
                    "source_worktree_clean": True,
                    "profile_id": profile_id,
                    "plan_id": plan_id,
                    "plan_expression": expression,
                    "suite_commit": suite_commit,
                    "suite_export_sha256": export_digest,
                    "result": "passed",
                }
                if role == "issuer":
                    summary.update(
                        {
                            "issuer_config": config_name,
                            "issuer_binary_sha256": issuer_digest,
                            "issuer_base_url": issuer_endpoint,
                        }
                    )
                else:
                    implementation_dir = profile_dir / "wallet-implementation-evidence"
                    implementation_dir.mkdir()
                    (implementation_dir / "module.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                    summary.update(
                        {
                            "wallet_config": config_name,
                            "wallet_harness_endpoint": wallet_endpoint,
                            "wallet_harness_health_endpoint": wallet_health_endpoint,
                            "implementation_source_repository": (
                                "https://github.com/reallyme/identity"
                            ),
                            "implementation_source_commit": wallet_commit,
                            "implementation_source_worktree_clean": True,
                            "implementation_binary_sha256": wallet_digest,
                            "implementation_evidence_count": 1,
                        }
                    )
                (profile_dir / "summary.json").write_text(
                    json.dumps(summary), encoding="utf-8"
                )

            arguments = SimpleNamespace(
                result_root=result_root,
                certification_plan=certification_plan,
                profile_matrix=profile_matrix,
                suite_contract=suite_contract,
                component_lock=component_lock,
                deployment_manifest=deployment_manifest,
                openid4vci_source_dir=openid_source,
                wallet_source_dir=wallet_source,
                issuer_binary=issuer_binary,
                wallet_binary=wallet_binary,
                issuer_deployment_artifact=issuer_deployment_artifact,
                wallet_deployment_artifact=wallet_deployment_artifact,
                result_assertion=result_assertion,
                wallet_assertion=wallet_assertion,
                module_inventory=module_inventory,
            )
            VCI_PRE_SUBMISSION.validate(arguments)

            issuer_deployment_artifact.write_bytes(b"tampered issuer image")
            with self.assertRaises(VCI_PRE_SUBMISSION.EvidenceError):
                VCI_PRE_SUBMISSION.validate(arguments)
            issuer_deployment_artifact.write_bytes(b"issuer image")

            first_profile = next(iter(selections))
            first_role = selections[first_profile][0]
            summary_path = result_root / first_role / first_profile / "summary.json"
            changed_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            changed_summary["suite_export_sha256"] = "0" * 64
            summary_path.write_text(json.dumps(changed_summary), encoding="utf-8")
            with self.assertRaises(VCI_PRE_SUBMISSION.EvidenceError):
                VCI_PRE_SUBMISSION.validate(arguments)

    def test_evidence_index_hashes_artifacts_and_sensitive_configs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = root / "results"
            results.mkdir()
            artifact = results / "profile.json"
            artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
            component_lock = results / "components.lock.json"
            component_lock.write_text('{"name":"components.lock.json"}\n', encoding="utf-8")
            inputs = []
            for name in (
                "certification-plan.json",
                "profile-matrix.json",
                "verifier.json",
                "wallet-sd-jwt.json",
                "wallet-mdoc.json",
            ):
                path = root / name
                path.write_text(f'{{"name":"{name}"}}\n', encoding="utf-8")
                inputs.append(path)
            deployment_manifest = results / "deployment-manifest.json"
            deployment_manifest.write_text("{}\n", encoding="utf-8")

            EVIDENCE_INDEX.write_index(
                results,
                "a" * 40,
                component_lock,
                deployment_manifest,
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                inputs[4],
                "https://verifier.example.test",
                "https://verifier.example.test/oidf/launch",
                "https://verifier.example.test/oidf/evidence",
                "https://verifier.example.test/healthz",
                "https://wallet.example.test/oidf/wallet/authorize",
                "https://wallet.example.test/healthz",
            )

            index = json.loads(
                (results / EVIDENCE_INDEX.INDEX_FILENAME).read_text(encoding="utf-8")
            )
            self.assertEqual(index["protocol"], "openid4vp")
            self.assertEqual(index["suite_revision"], "a" * 40)
            self.assertEqual(
                {artifact["path"] for artifact in index["artifacts"]},
                {"components.lock.json", "deployment-manifest.json", "profile.json"},
            )
            self.assertEqual(
                len(index["inputs"]["wallet_sd_jwt_config"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["wallet_mdoc_config"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["certification_plan"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["openid4vp_profile_matrix"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["deployment_manifest"]["sha256"]), 64
            )
            self.assertEqual(
                index["deployment"]["wallet_harness_endpoint"],
                "https://wallet.example.test/oidf/wallet/authorize",
            )
            self.assertEqual(
                index["deployment"]["verifier_evidence_endpoint"],
                "https://verifier.example.test/oidf/evidence",
            )
            self.assertEqual(
                index["deployment"]["verifier_health_endpoint"],
                "https://verifier.example.test/healthz",
            )

    def test_input_fingerprint_is_content_and_size_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "input.json"
            input_path.write_bytes(b'{"value":1}\n')
            first = INPUT_FINGERPRINT.fingerprint(input_path)
            self.assertRegex(first, r"^[0-9a-f]{64}:12$")
            input_path.write_bytes(b'{"value":2}\n')
            self.assertNotEqual(first, INPUT_FINGERPRINT.fingerprint(input_path))

    def test_input_fingerprint_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "input.json"
            link.symlink_to(target)
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    INPUT_FINGERPRINT.fingerprint(link)
        self.assertEqual(raised.exception.code, 65)

    def test_evidence_index_rejects_noncanonical_endpoints(self) -> None:
        invalid_endpoints = (
            "https://user:secret@verifier.example.test/oidf/launch",
            "https://verifier.example.test:invalid/oidf/launch",
            "https://verifier.example.test/oidf/launch\n",
            "HTTPS://verifier.example.test/oidf/launch",
            "https://verifier.example.test\\@attacker.invalid/oidf/launch",
            "https://verifier%2eexample.test/oidf/launch",
            "https://verifier.example.test.:443/oidf/launch",
            "https://verifier.example.test:0/oidf/launch",
            "https://verifier.example.test/oidf/launch?secret=value",
            "https://verifier.example.test/oidf/launch#fragment",
            "https://verifiér.example.test/oidf/launch",
        )
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    EVIDENCE_INDEX.deployment_endpoint(endpoint)
                self.assertEqual(raised.exception.code, 65)

    def test_evidence_index_rejects_symlinked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = root / "results"
            results.mkdir()
            target = root / "outside.json"
            target.write_text("{}\n", encoding="utf-8")
            (results / "linked.json").symlink_to(target)

            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    EVIDENCE_INDEX.collect_artifacts(results)
        self.assertEqual(raised.exception.code, 65)

    def test_evidence_index_requires_retained_deployment_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = root / "results"
            results.mkdir()
            (results / "profile.json").write_text("{}\n", encoding="utf-8")
            outside = root / "deployment-manifest.json"
            outside.write_text("{}\n", encoding="utf-8")
            artifacts = EVIDENCE_INDEX.collect_artifacts(results)
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    EVIDENCE_INDEX.retained_deployment_digest(
                        results, outside, artifacts
                    )
        self.assertEqual(raised.exception.code, 65)

    def test_evidence_index_requires_retained_component_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = root / "results"
            results.mkdir()
            (results / "profile.json").write_text("{}\n", encoding="utf-8")
            outside = root / "components.lock.json"
            outside.write_text("{}\n", encoding="utf-8")
            artifacts = EVIDENCE_INDEX.collect_artifacts(results)
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    EVIDENCE_INDEX.retained_component_lock_digest(
                        results, outside, artifacts
                    )
        self.assertEqual(raised.exception.code, 65)

    def test_openid4vci_evidence_index_binds_binary_and_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = root / "results"
            results.mkdir()
            (results / "profile.json").write_text(
                '{"result":"passed"}\n', encoding="utf-8"
            )
            component_lock = results / "components.lock.json"
            component_lock.write_bytes(b"components.lock.json")
            inputs = []
            for name in (
                "certification-plan.json",
                "profile-matrix.json",
                "issuer.json",
                "wallet.json",
                "issuer-bin",
                "wallet-bin",
            ):
                path = root / name
                path.write_bytes(name.encode("utf-8"))
                inputs.append(path)
            deployment_manifest = results / "deployment-manifest.json"
            deployment_manifest.write_text("{}\n", encoding="utf-8")

            VCI_EVIDENCE_INDEX.write_index(
                results,
                "b" * 40,
                component_lock,
                deployment_manifest,
                inputs[0],
                inputs[1],
                inputs[2],
                inputs[3],
                inputs[4],
                inputs[5],
                inputs[4],
                inputs[5],
                "https://issuer.example.test/",
                "https://wallet.example.test/oidf/wallet/credential-offer",
                "https://wallet.example.test/healthz",
            )

            index = json.loads(
                (results / EVIDENCE_INDEX.INDEX_FILENAME).read_text(encoding="utf-8")
            )
            self.assertEqual(index["protocol"], "openid4vci")
            self.assertEqual(len(index["inputs"]["issuer_binary"]["sha256"]), 64)
            self.assertEqual(len(index["inputs"]["wallet_binary"]["sha256"]), 64)
            self.assertEqual(
                len(index["inputs"]["issuer_deployment_artifact"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["wallet_deployment_artifact"]["sha256"]), 64
            )
            self.assertEqual(
                len(index["inputs"]["deployment_manifest"]["sha256"]), 64
            )
            self.assertEqual(
                index["deployment"]["issuer_base_url"],
                "https://issuer.example.test/",
            )

    def test_deployment_manifest_binds_all_four_roles(self) -> None:
        manifest = valid_deployment_manifest()
        endpoints = DEPLOYMENT_MANIFEST.validate_manifest(manifest)
        DEPLOYMENT_MANIFEST.verify_component_bindings(manifest, self.component_lock)
        DEPLOYMENT_MANIFEST.verify_bindings(
            endpoints,
            [
                (
                    "openid4vp_verifier.verifier_launch_endpoint",
                    "https://verifier.reallyme.com/oidf/launch",
                )
            ],
        )
        self.assertEqual(set(endpoints), set(DEPLOYMENT_MANIFEST.ROLE_ENDPOINTS))

    def test_deployment_manifest_rejects_source_commit_outside_release_lock(self) -> None:
        manifest = valid_deployment_manifest()
        manifest["roles"]["openid4vp_verifier"]["source_commit"] = "0" * 40
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.verify_component_bindings(
                    manifest, self.component_lock
                )
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_repository_without_role_ownership(self) -> None:
        manifest = valid_deployment_manifest()
        openid4vci = next(
            item
            for item in self.component_lock["repositories"]
            if item["component_id"] == "openid4vci"
        )
        verifier = manifest["roles"]["openid4vp_verifier"]
        verifier["source_repository"] = openid4vci["repository"]
        verifier["source_commit"] = openid4vci["commit"]
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.verify_component_bindings(
                    manifest, self.component_lock
                )
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_endpoint_mismatch(self) -> None:
        endpoints = DEPLOYMENT_MANIFEST.validate_manifest(valid_deployment_manifest())
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.verify_bindings(
                    endpoints,
                    [
                        (
                            "openid4vci_issuer.issuer_base_url",
                            "https://other.reallyme.com/",
                        )
                    ],
                )
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_private_ip_endpoint(self) -> None:
        changed = valid_deployment_manifest()
        changed["roles"]["openid4vci_issuer"]["endpoints"][
            "issuer_base_url"
        ] = "https://127.0.0.1/"
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.validate_manifest(changed)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_noncanonical_endpoints(self) -> None:
        invalid_endpoints = (
            "HTTPS://issuer.reallyme.com/",
            "https://issuer.reallyme.com\\@attacker.invalid/",
            "https://issuer%2ereallyme.com/",
            "https://issuer.reallyme.com./",
            "https://issuer.reallyme.com:0/",
            "https://0177.0.0.1/",
            "https://0x7f.0.0.1/",
            "https://issuer.reallyme.com/?secret=value",
            "https://issuer.reallyme.com/#fragment",
            "https://issuér.reallyme.com/",
        )
        for endpoint in invalid_endpoints:
            changed = valid_deployment_manifest()
            changed["roles"]["openid4vci_issuer"]["endpoints"][
                "issuer_base_url"
            ] = endpoint
            with self.subTest(endpoint=endpoint), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    DEPLOYMENT_MANIFEST.validate_manifest(changed)
                self.assertEqual(
                    raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT
                )

    def test_deployment_manifest_rejects_missing_role(self) -> None:
        changed = valid_deployment_manifest()
        del changed["roles"]["openid4vp_wallet"]
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.validate_manifest(changed)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_obsolete_schema_version(self) -> None:
        changed = valid_deployment_manifest()
        changed["schema_version"] = 2
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.validate_manifest(changed)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_accepts_bound_zk_capability(self) -> None:
        changed = valid_deployment_manifest()
        _plan, adapter = DEPLOYMENT_MANIFEST.zk_adapter_validator.load_contract()
        component = adapter["component"]
        changed["capabilities"]["zk_presentations"] = {
            "enabled": True,
            "plan_id": "zk-presentation-proofs-v1",
            "source_repository": component["repository"],
            "source_commit": component["commit"],
            "release_artifact": {
                "artifact_id": "zk-release-bundle",
                "kind": "archive",
                "sha256": "8" * 64,
            },
            "component_attestation_sha256": "9" * 64,
        }
        DEPLOYMENT_MANIFEST.validate_manifest(changed)

    def test_deployment_manifest_rejects_unbound_zk_commit(self) -> None:
        changed = valid_deployment_manifest()
        changed["capabilities"]["zk_presentations"] = {
            "enabled": True,
            "plan_id": "zk-presentation-proofs-v1",
            "source_repository": "https://github.com/reallyme/zk",
            "source_commit": "f" * 40,
            "release_artifact": {
                "artifact_id": "zk-release-bundle",
                "kind": "archive",
                "sha256": "8" * 64,
            },
            "component_attestation_sha256": "9" * 64,
        }
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                DEPLOYMENT_MANIFEST.validate_manifest(changed)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_duplicate_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "deployment.json"
            manifest.write_text(
                '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    DEPLOYMENT_MANIFEST.load_manifest(manifest)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_deployment_manifest_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target.json"
            target.write_text(
                json.dumps(valid_deployment_manifest()), encoding="utf-8"
            )
            manifest = root / "deployment.json"
            manifest.symlink_to(target)
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    DEPLOYMENT_MANIFEST.load_manifest(manifest)
        self.assertEqual(raised.exception.code, DEPLOYMENT_MANIFEST.EXIT_INVALID_INPUT)

    def test_source_assertion_cannot_escape_upstream_checkout(self) -> None:
        suite_directory = MANIFESTS.REPOSITORY_ROOT / "upstream" / "oidf" / "openid-conformance-suite"
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                PARAMETERS.resolve_source(suite_directory, "../conformance-suite.lock.json")
        self.assertEqual(raised.exception.code, PARAMETERS.EXIT_INVALID_INPUT)

    def test_normative_source_reference_is_valid(self) -> None:
        self.assertEqual(NORMATIVE_SOURCES.main(), 0)

    def test_normative_source_rejects_invalid_digest(self) -> None:
        ledger = NORMATIVE_SOURCES.load_object(NORMATIVE_SOURCES.SOURCE_LOCK_PATH)
        changed = copy.deepcopy(ledger)
        changed["sources"][0]["sha256"] = "0" * 63
        self.assert_rejected_normative(lambda: NORMATIVE_SOURCES.verify_ledger(changed))

    def test_normative_source_rejects_evidence_path_traversal(self) -> None:
        ledger = NORMATIVE_SOURCES.load_object(NORMATIVE_SOURCES.SOURCE_LOCK_PATH)
        changed = copy.deepcopy(ledger)
        changed["sources"][0]["implementation_evidence"][0]["path"] = "../ssi"
        self.assert_rejected_normative(lambda: NORMATIVE_SOURCES.verify_ledger(changed))

    def test_normative_source_rejects_non_string_clause_without_crashing(self) -> None:
        ledger = NORMATIVE_SOURCES.load_object(NORMATIVE_SOURCES.SOURCE_LOCK_PATH)
        changed = copy.deepcopy(ledger)
        changed["sources"][0]["reviewed_clauses"][0] = {"unexpected": "shape"}
        self.assert_rejected_normative(lambda: NORMATIVE_SOURCES.verify_ledger(changed))

    def assert_rejected_normative(self, operation: object) -> None:
        if not callable(operation):
            self.fail("test operation must be callable")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                operation()
        self.assertEqual(raised.exception.code, NORMATIVE_SOURCES.EXIT_INVALID_INPUT)


if __name__ == "__main__":
    unittest.main()
