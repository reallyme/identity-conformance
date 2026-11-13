#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the ZK plan, adapter, source baseline, and immutable source files."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPOSITORY_ROOT / "plans" / "zk" / "presentation-proofs.json"
ADAPTER_PATH = REPOSITORY_ROOT / "adapters" / "zk" / "adapter.json"
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_ARTIFACT_BYTES = 16 * 1024 * 1024
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
EXPECTED_ASSERTIONS = {
    "toolchain_identity",
    "artifact_identity",
    "canonical_vectors",
    "malicious_proof_rejection",
    "request_binding",
    "artifact_substitution_rejection",
    "provider_release_quality",
}
EXPECTED_PACKAGES = [
    "reallyme-zk-api",
    "reallyme-zk-artifacts",
    "reallyme-zk-proto",
    "reallyme-zk-proto-codec",
    "reallyme-zk-conformance",
]
EXPECTED_ATTESTATION_CATEGORIES = {
    "format",
    "lint",
    "integration",
    "vector",
    "security",
    "build",
}
EXPECTED_POLICY = {
    "contains_sensitive_data": False,
    "raw_process_output_retained": False,
    "witness_material_retained": False,
    "private_key_material_retained": False,
}
EXPECTED_LINKED_PROBES = {
    "probe.zk.fresh-proof-matrix.v1": (
        "zk_provider",
        "scripts/test-persona-credential-evidence-linked-proofs.py",
    ),
    "probe.zk.witness-parity.current-state.v1": (
        "zk_provider",
        "circuits::persona_credential_evidence_v1_current_state::tests::compiled_prepared_status_witness_matches_noir_in_both_lanes",
    ),
    "probe.zk.witness-parity.issuer-envelope.v1": (
        "zk_provider",
        "circuits::persona_credential_evidence_v1_issuer_envelope::tests::compiled_issuer_envelope_witness_matches_noir_in_both_lanes",
    ),
    "probe.zk.witness-parity.claim-root.v1": (
        "zk_provider",
        "circuits::persona_credential_evidence_v1_claim_root::tests::compiled_claim_root_witness_matches_noir_in_both_lanes",
    ),
    "probe.zk.witness-parity.signed-validity.v1": (
        "zk_provider",
        "circuits::persona_credential_evidence_v1_signed_validity::tests::compiled_signed_validity_witness_matches_noir_in_both_lanes",
    ),
    "probe.zk.witness-parity.selected-claim.v1": (
        "zk_provider",
        "circuits::persona_credential_evidence_v1_claim::tests::compiled_prepared_claim_witness_matches_noir_in_both_lanes",
    ),
    "probe.zk.frozen-mobile-request-parity.v1": (
        "zk_provider",
        "demo_prepared_requests_match_current_noir_witnesses",
    ),
    "probe.zk.native-linked-backend.v1": (
        "zk_provider",
        "fresh_prepared_proofs_verify_through_linked_library",
    ),
    "probe.identity.openid4vp-prepared-boundary.v1": (
        "identity_product",
        "linked_tests::fresh_linked_proofs_cross_openid4vp_prepared_boundary",
    ),
    "probe.identity.wallet-record-presentation.v1": (
        "identity_product",
        "select_inventory_presentations::mixed_record_tests::prepared_live_source::selected_ssi_vci_record_builds_signed_native_persona_credential_evidence_presentation",
    ),
    "probe.zk.mobile-ffi-exact-candidate.v1": (
        "zk_provider",
        "dispatch::tests::mobile_package_verifies_prepared_proofs_from_exact_candidate",
    ),
}
EXPECTED_PROBE_TOOLCHAINS = {
    "probe.zk.fresh-proof-matrix.v1": {"rustc", "nargo", "bb", "libbb_external", "bn254_g1", "bn254_g2"},
    "probe.zk.witness-parity.current-state.v1": {"rustc", "nargo"},
    "probe.zk.witness-parity.issuer-envelope.v1": {"rustc", "nargo"},
    "probe.zk.witness-parity.claim-root.v1": {"rustc", "nargo"},
    "probe.zk.witness-parity.signed-validity.v1": {"rustc", "nargo"},
    "probe.zk.witness-parity.selected-claim.v1": {"rustc", "nargo"},
    "probe.zk.frozen-mobile-request-parity.v1": {"rustc", "nargo"},
    "probe.zk.native-linked-backend.v1": {"rustc", "bb", "libbb_external", "bn254_g1", "bn254_g2"},
    "probe.identity.openid4vp-prepared-boundary.v1": {"rustc", "bb", "libbb_external", "bn254_g1", "bn254_g2"},
    "probe.identity.wallet-record-presentation.v1": {"rustc", "bb", "libbb_external", "bn254_g1", "bn254_g2"},
    "probe.zk.mobile-ffi-exact-candidate.v1": {"rustc", "bb", "libbb_external", "bn254_g1", "bn254_g2"},
}
EXPECTED_PROBE_INPUTS = {
    "probe.zk.fresh-proof-matrix.v1": {"proof_matrix_manifest", "zk_candidate_tree"},
    "probe.zk.witness-parity.current-state.v1": {"zk_candidate_tree"},
    "probe.zk.witness-parity.issuer-envelope.v1": {"zk_candidate_tree"},
    "probe.zk.witness-parity.claim-root.v1": {"zk_candidate_tree"},
    "probe.zk.witness-parity.signed-validity.v1": {"zk_candidate_tree"},
    "probe.zk.witness-parity.selected-claim.v1": {"zk_candidate_tree"},
    "probe.zk.frozen-mobile-request-parity.v1": {"frozen_request_manifest", "zk_candidate_tree"},
    "probe.zk.native-linked-backend.v1": {"proof_matrix_manifest", "zk_candidate_tree"},
    "probe.identity.openid4vp-prepared-boundary.v1": {"identity_candidate_tree", "proof_matrix_manifest"},
    "probe.identity.wallet-record-presentation.v1": {"identity_candidate_tree", "proof_matrix_manifest"},
    "probe.zk.mobile-ffi-exact-candidate.v1": {"proof_matrix_manifest", "release_index", "zk_candidate_tree"},
}
EXPECTED_ASSERTION_PROBES = {
    "toolchain_identity": {"probe.zk.fresh-proof-matrix.v1"},
    "artifact_identity": {
        "probe.zk.fresh-proof-matrix.v1",
        "probe.zk.mobile-ffi-exact-candidate.v1",
    },
    "canonical_vectors": {
        "probe.zk.witness-parity.current-state.v1",
        "probe.zk.witness-parity.issuer-envelope.v1",
        "probe.zk.witness-parity.claim-root.v1",
        "probe.zk.witness-parity.signed-validity.v1",
        "probe.zk.witness-parity.selected-claim.v1",
        "probe.zk.frozen-mobile-request-parity.v1",
    },
    "malicious_proof_rejection": {
        "probe.zk.fresh-proof-matrix.v1",
        "probe.zk.native-linked-backend.v1",
        "probe.zk.mobile-ffi-exact-candidate.v1",
    },
    "request_binding": {
        "probe.zk.native-linked-backend.v1",
        "probe.identity.openid4vp-prepared-boundary.v1",
        "probe.identity.wallet-record-presentation.v1",
    },
    "artifact_substitution_rejection": {
        "probe.zk.fresh-proof-matrix.v1",
        "probe.zk.mobile-ffi-exact-candidate.v1",
    },
    "provider_release_quality": {
        "probe.zk.native-linked-backend.v1",
        "probe.zk.mobile-ffi-exact-candidate.v1",
        "probe.identity.openid4vp-prepared-boundary.v1",
        "probe.identity.wallet-record-presentation.v1",
    },
}


class ZkAdapterErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_PLAN = "invalid_plan"
    INVALID_ADAPTER = "invalid_adapter"
    INVALID_CHECKOUT = "invalid_checkout"
    DIRTY_CHECKOUT = "dirty_checkout"
    REVISION_MISMATCH = "revision_mismatch"
    SOURCE_ARTIFACT_MISMATCH = "source_artifact_mismatch"


@dataclass(frozen=True)
class ZkAdapterError(Exception):
    reason: ZkAdapterErrorReason


def fail(reason: ZkAdapterErrorReason) -> NoReturn:
    print(f"ZK adapter validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: ZkAdapterErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ZkAdapterError(reason)
    return value


def load_object(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_JSON_BYTES:
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_JSON)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(MAX_JSON_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(opened.st_mode)
            or len(raw) != before.st_size
            or any(
                getattr(before, field) != getattr(opened, field)
                or getattr(before, field) != getattr(after_open, field)
                or getattr(before, field) != getattr(after_path, field)
                for field in stable_fields
            )
        ):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_JSON)
        value = strict_json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_JSON)
    return value


def validate_plan(plan: dict[str, object]) -> None:
    exact_object(
        plan,
        {
            "$comment",
            "schema_version",
            "plan_id",
            "execution_status",
            "certification_claim",
            "required_components",
            "assertions",
            "evidence_coverage",
            "linked_observation_contract",
            "evidence_policy",
        },
        ZkAdapterErrorReason.INVALID_PLAN,
    )
    if (
        plan["schema_version"] != 1
        or plan["plan_id"] != "zk-presentation-proofs-v1"
        or plan["execution_status"] != "executable_with_attestation_gaps"
        or plan["certification_claim"] is not False
        or plan["evidence_coverage"]
        != {
            "assertion_count": 7,
            "exact_assertion_binding_count": 0,
            "candidate_test_inventory_assertion_count": 7,
            "badge_eligible": False,
        }
        or plan["evidence_policy"] != EXPECTED_POLICY
    ):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    if plan["required_components"] != [
        {"component_id": "zk", "repository": "https://github.com/reallyme/zk"}
    ]:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    validate_linked_observation_contract(plan["linked_observation_contract"])
    assertions = plan["assertions"]
    if not isinstance(assertions, list) or len(assertions) != len(EXPECTED_ASSERTIONS):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    observed: set[str] = set()
    for raw_assertion in assertions:
        assertion = exact_object(
            raw_assertion,
            {"assertion_id", "required_checks"},
            ZkAdapterErrorReason.INVALID_PLAN,
        )
        assertion_id = assertion["assertion_id"]
        checks = assertion["required_checks"]
        if (
            not isinstance(assertion_id, str)
            or assertion_id in observed
            or assertion_id not in EXPECTED_ASSERTIONS
            or not isinstance(checks, list)
            or not checks
            or len(checks) != len(set(checks))
            or not all(
                isinstance(check, str) and IDENTIFIER.fullmatch(check) is not None
                for check in checks
            )
        ):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
        observed.add(assertion_id)
    if observed != EXPECTED_ASSERTIONS:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)


def validate_linked_observation_contract(value: object) -> None:
    contract = exact_object(
        value,
        {
            "profile_id",
            "component_roles",
            "proof_matrix",
            "required_toolchain_bindings",
            "probes",
            "assertion_bindings",
        },
        ZkAdapterErrorReason.INVALID_PLAN,
    )
    if contract["profile_id"] != "identity-zk-linked-presentation-proofs-v1":
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    roles = contract["component_roles"]
    if roles != [
        {"component_role": "zk_provider", "selection": "zk_adapter_contract"},
        {"component_role": "identity_product", "selection": "product_component_id"},
    ]:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    if contract["proof_matrix"] != {
        "lanes": ["sha256", "poseidon2"],
        "modes": ["public", "private"],
        "stages": [
            "issuer_envelope",
            "claim_root",
            "signed_validity",
            "selected_claim",
            "current_state",
        ],
        "row_count": 20,
    }:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    if contract["required_toolchain_bindings"] != [
        "rustc",
        "nargo",
        "bb",
        "libbb_external",
        "bn254_g1",
        "bn254_g2",
    ]:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    raw_probes = contract["probes"]
    if not isinstance(raw_probes, list) or len(raw_probes) != len(
        EXPECTED_LINKED_PROBES
    ):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    observed_probes: set[str] = set()
    for raw_probe in raw_probes:
        probe = exact_object(
            raw_probe,
            {
                "probe_id",
                "component_role",
                "test_selector",
                "required_toolchain_binding_ids",
                "required_input_binding_ids",
            },
            ZkAdapterErrorReason.INVALID_PLAN,
        )
        probe_id = probe["probe_id"]
        toolchain_ids = probe["required_toolchain_binding_ids"]
        input_ids = probe["required_input_binding_ids"]
        if (
            not isinstance(probe_id, str)
            or probe_id in observed_probes
            or (probe["component_role"], probe["test_selector"])
            != EXPECTED_LINKED_PROBES.get(probe_id)
            or not isinstance(toolchain_ids, list)
            or len(toolchain_ids) != len(set(toolchain_ids))
            or set(toolchain_ids) != EXPECTED_PROBE_TOOLCHAINS.get(probe_id)
            or not isinstance(input_ids, list)
            or len(input_ids) != len(set(input_ids))
            or set(input_ids) != EXPECTED_PROBE_INPUTS.get(probe_id)
        ):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
        observed_probes.add(probe_id)
    if observed_probes != set(EXPECTED_LINKED_PROBES):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    raw_bindings = contract["assertion_bindings"]
    if not isinstance(raw_bindings, list) or len(raw_bindings) != len(
        EXPECTED_ASSERTION_PROBES
    ):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    observed_assertions: set[str] = set()
    for raw_binding in raw_bindings:
        binding = exact_object(
            raw_binding,
            {"assertion_id", "required_probe_ids"},
            ZkAdapterErrorReason.INVALID_PLAN,
        )
        assertion_id = binding["assertion_id"]
        probe_ids = binding["required_probe_ids"]
        if (
            not isinstance(assertion_id, str)
            or assertion_id in observed_assertions
            or not isinstance(probe_ids, list)
            or len(probe_ids) != len(set(probe_ids))
            or set(probe_ids) != EXPECTED_ASSERTION_PROBES.get(assertion_id)
        ):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
        observed_assertions.add(assertion_id)
    if observed_assertions != set(EXPECTED_ASSERTION_PROBES):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)


def validate_adapter(adapter: dict[str, object], plan: dict[str, object]) -> None:
    exact_object(
        adapter,
        {
            "$comment",
            "schema_version",
            "adapter_id",
            "plan_path",
            "component_requirement",
            "source_artifacts",
            "cargo_packages",
            "required_attestation_categories",
            "evidence_policy",
        },
        ZkAdapterErrorReason.INVALID_ADAPTER,
    )
    if (
        adapter["schema_version"] != 1
        or adapter["adapter_id"] != "zk_presentation_proofs"
        or adapter["plan_path"] != "plans/zk/presentation-proofs.json"
        or adapter["component_requirement"] != plan["required_components"][0]
        or adapter["cargo_packages"] != EXPECTED_PACKAGES
        or set(adapter["required_attestation_categories"])
        != EXPECTED_ATTESTATION_CATEGORIES
        or adapter["evidence_policy"] != EXPECTED_POLICY
    ):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)
    source_artifacts = adapter["source_artifacts"]
    if not isinstance(source_artifacts, list) or len(source_artifacts) != 3:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)
    expected_paths = {
        "toolchain-lock": "circuits/toolchain-lock.json",
        "provider-manifest": "provider_manifest.json",
        "cargo-lock": "Cargo.lock",
    }
    observed: set[str] = set()
    for raw_artifact in source_artifacts:
        artifact = exact_object(
            raw_artifact,
            {"artifact_id", "path"},
            ZkAdapterErrorReason.INVALID_ADAPTER,
        )
        artifact_id = artifact["artifact_id"]
        if (
            not isinstance(artifact_id, str)
            or artifact_id in observed
            or artifact["path"] != expected_paths.get(artifact_id)
        ):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)
        observed.add(artifact_id)
    if observed != set(expected_paths):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)


def git_output(checkout: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_CHECKOUT) from error
    if completed.returncode != 0:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_CHECKOUT)
    return completed.stdout.strip()


def verify_source_file(source: Path, relative_path: str) -> None:
    candidate = source / relative_path
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(source.resolve(strict=True))
        if candidate.is_symlink() or not candidate.is_file():
            raise ZkAdapterError(ZkAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
        if not 1 <= metadata.st_size <= MAX_SOURCE_ARTIFACT_BYTES:
            raise ZkAdapterError(ZkAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
    except (OSError, ValueError) as error:
        raise ZkAdapterError(ZkAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH) from error
    if not git_output(source, "ls-files", "--error-unmatch", "--", relative_path):
        raise ZkAdapterError(ZkAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
    return None


def verify_checkout(
    source: Path, adapter: dict[str, object], expected_commit: str, expected_ref: str
) -> None:
    if GIT_COMMIT.fullmatch(expected_commit) is None:
        raise ZkAdapterError(ZkAdapterErrorReason.REVISION_MISMATCH)
    if git_output(source, "rev-parse", "HEAD") != expected_commit:
        raise ZkAdapterError(ZkAdapterErrorReason.REVISION_MISMATCH)
    if git_output(source, "rev-list", "-n", "1", expected_ref) != expected_commit:
        raise ZkAdapterError(ZkAdapterErrorReason.REVISION_MISMATCH)
    if git_output(source, "status", "--porcelain"):
        raise ZkAdapterError(ZkAdapterErrorReason.DIRTY_CHECKOUT)
    source_artifacts = adapter["source_artifacts"]
    if not isinstance(source_artifacts, list):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)
    for raw_artifact in source_artifacts:
        if not isinstance(raw_artifact, dict):
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_ADAPTER)
        path = raw_artifact.get("path")
        if not isinstance(path, str):
            raise ZkAdapterError(ZkAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
        verify_source_file(source, path)


def load_contract() -> tuple[dict[str, object], dict[str, object]]:
    plan = load_object(PLAN_PATH)
    adapter = load_object(ADAPTER_PATH)
    validate_plan(plan)
    validate_adapter(adapter, plan)
    return plan, adapter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-ref")
    args = parser.parse_args()
    try:
        _plan, adapter = load_contract()
        if args.source is not None:
            if args.expected_commit is None or args.expected_ref is None:
                raise ZkAdapterError(ZkAdapterErrorReason.REVISION_MISMATCH)
            verify_checkout(args.source, adapter, args.expected_commit, args.expected_ref)
    except ZkAdapterError as error:
        fail(error.reason)
    print("ZK presentation-proof adapter valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
