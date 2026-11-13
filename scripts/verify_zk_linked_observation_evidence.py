#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate exact linked ZK observations without retaining proof material."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_product_component_bom as bom_verifier  # noqa: E402
import verify_zk_adapter as zk_adapter  # noqa: E402


SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY = re.compile(
    r"^https://github\.com/reallyme/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)
PROBE_ID = re.compile(r"^probe\.[a-z0-9_.-]+\.v[1-9][0-9]*$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
COMPONENT_ROLES = frozenset({"zk_provider", "identity_product"})
CANDIDATE_BINDINGS = frozenset({"working_tree_observation", "immutable_release"})
REQUIRED_HASHED_TOOLCHAINS = frozenset(
    {"nargo", "bb", "libbb_external", "bn254_g1", "bn254_g2"}
)
EXPECTED_POLICY = {
    "contains_sensitive_data": False,
    "raw_process_output_retained": False,
    "witness_material_retained": False,
    "private_key_material_retained": False,
    "raw_proof_material_retained": False,
    "machine_local_paths_retained": False,
}


class LinkedObservationErrorReason(Enum):
    INVALID_EVIDENCE = "invalid_evidence"
    INVALID_COMPONENT_BINDING = "invalid_component_binding"
    INVALID_TOOLCHAIN_BINDING = "invalid_toolchain_binding"
    INVALID_PROBE_INVENTORY = "invalid_probe_inventory"
    INVALID_PROOF_MATRIX = "invalid_proof_matrix"
    INVALID_CANDIDATE_BINDING = "invalid_candidate_binding"
    REVISION_MISMATCH = "revision_mismatch"


@dataclass(frozen=True)
class LinkedObservationError(Exception):
    reason: LinkedObservationErrorReason


@dataclass(frozen=True)
class LinkedObservationSummary:
    candidate_binding: str
    evidence_sha256: str
    product_component_bom_sha256: str | None
    probe_ids: tuple[str, ...]
    proof_row_count: int


def fail(reason: LinkedObservationErrorReason) -> NoReturn:
    raise LinkedObservationError(reason)


def exact_object(
    value: object,
    keys: set[str],
    reason: LinkedObservationErrorReason,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(reason)
    return value


def bounded_string(
    value: object,
    maximum: int,
    reason: LinkedObservationErrorReason,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        fail(reason)
    return value


def require_sha256(value: object, reason: LinkedObservationErrorReason) -> str:
    digest = bounded_string(value, 64, reason)
    if SHA256.fullmatch(digest) is None or digest == "0" * 64:
        fail(reason)
    return digest


def canonical_sha256(value: dict[str, object]) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_components(
    raw_components: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(raw_components, list) or len(raw_components) != 2:
        fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
    components: dict[str, dict[str, object]] = {}
    repositories: set[str] = set()
    for raw_component in raw_components:
        component = exact_object(
            raw_component,
            {
                "component_role",
                "component_id",
                "repository",
                "source_commit",
                "source_tree",
                "source_state",
                "working_tree_diff_sha256",
                "release_id",
                "release_ref",
                "release_artifact_sha256",
                "component_attestation_sha256",
            },
            LinkedObservationErrorReason.INVALID_COMPONENT_BINDING,
        )
        role = component["component_role"]
        component_id = component["component_id"]
        repository = component["repository"]
        source_commit = component["source_commit"]
        source_tree = component["source_tree"]
        source_state = component["source_state"]
        if (
            not isinstance(role, str)
            or role not in COMPONENT_ROLES
            or role in components
            or not isinstance(component_id, str)
            or COMPONENT_ID.fullmatch(component_id) is None
            or not isinstance(repository, str)
            or REPOSITORY.fullmatch(repository) is None
            or repository in repositories
            or not isinstance(source_commit, str)
            or GIT_COMMIT.fullmatch(source_commit) is None
            or not isinstance(source_tree, str)
            or GIT_COMMIT.fullmatch(source_tree) is None
            or source_state not in {"clean", "dirty"}
        ):
            fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
        diff_digest = component["working_tree_diff_sha256"]
        if source_state == "clean":
            if diff_digest is not None:
                fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
        elif diff_digest is None:
            fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
        else:
            require_sha256(
                diff_digest, LinkedObservationErrorReason.INVALID_COMPONENT_BINDING
            )
        for field in ("release_artifact_sha256", "component_attestation_sha256"):
            digest = component[field]
            if digest is not None:
                require_sha256(
                    digest, LinkedObservationErrorReason.INVALID_COMPONENT_BINDING
                )
        release_id = component["release_id"]
        release_ref = component["release_ref"]
        if (release_id is None) != (release_ref is None):
            fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
        if release_id is not None and (
            not isinstance(release_id, int)
            or isinstance(release_id, bool)
            or not 1 <= release_id <= 9_223_372_036_854_775_807
            or not isinstance(release_ref, str)
            or bom_verifier.RELEASE_REF.fullmatch(release_ref) is None
        ):
            fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
        components[role] = component
        repositories.add(repository)
    if set(components) != COMPONENT_ROLES:
        fail(LinkedObservationErrorReason.INVALID_COMPONENT_BINDING)
    return components


def validate_toolchains(raw_bindings: object, plan: dict[str, object]) -> set[str]:
    contract = plan["linked_observation_contract"]
    if not isinstance(contract, dict):
        fail(LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING)
    expected_ids = contract["required_toolchain_bindings"]
    if not isinstance(expected_ids, list):
        fail(LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING)
    if not isinstance(raw_bindings, list) or len(raw_bindings) != len(expected_ids):
        fail(LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING)
    observed: set[str] = set()
    for raw_binding in raw_bindings:
        binding = exact_object(
            raw_binding,
            {"binding_id", "version", "sha256"},
            LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING,
        )
        binding_id = binding["binding_id"]
        if (
            not isinstance(binding_id, str)
            or binding_id in observed
            or binding_id not in expected_ids
        ):
            fail(LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING)
        bounded_string(
            binding["version"],
            128,
            LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING,
        )
        digest = binding["sha256"]
        if binding_id in REQUIRED_HASHED_TOOLCHAINS:
            require_sha256(
                digest, LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING
            )
        elif digest is not None:
            require_sha256(
                digest, LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING
            )
        observed.add(binding_id)
    if observed != set(expected_ids):
        fail(LinkedObservationErrorReason.INVALID_TOOLCHAIN_BINDING)
    return observed


def validate_digest_bindings(value: object) -> set[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
    observed: set[str] = set()
    for raw_binding in value:
        binding = exact_object(
            raw_binding,
            {"binding_id", "sha256"},
            LinkedObservationErrorReason.INVALID_PROBE_INVENTORY,
        )
        binding_id = binding["binding_id"]
        if (
            not isinstance(binding_id, str)
            or IDENTIFIER.fullmatch(binding_id) is None
            or binding_id in observed
        ):
            fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
        require_sha256(
            binding["sha256"], LinkedObservationErrorReason.INVALID_PROBE_INVENTORY
        )
        observed.add(binding_id)
    return observed


def validate_probes(
    raw_probes: object,
    plan: dict[str, object],
    components: dict[str, dict[str, object]],
    toolchain_ids: set[str],
) -> tuple[str, ...]:
    contract = plan["linked_observation_contract"]
    if not isinstance(contract, dict) or not isinstance(contract.get("probes"), list):
        fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
    expected = {
        probe["probe_id"]: probe
        for probe in contract["probes"]
        if isinstance(probe, dict) and isinstance(probe.get("probe_id"), str)
    }
    if not isinstance(raw_probes, list) or len(raw_probes) != len(expected):
        fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
    observed: set[str] = set()
    for raw_probe in raw_probes:
        probe = exact_object(
            raw_probe,
            {
                "probe_id",
                "component_role",
                "test_selector",
                "source_commit",
                "source_tree",
                "toolchain_binding_ids",
                "input_digests",
                "result",
            },
            LinkedObservationErrorReason.INVALID_PROBE_INVENTORY,
        )
        probe_id = probe["probe_id"]
        role = probe["component_role"]
        expected_probe = expected.get(probe_id) if isinstance(probe_id, str) else None
        component = components.get(role) if isinstance(role, str) else None
        raw_toolchains = probe["toolchain_binding_ids"]
        expected_toolchains = expected_probe.get("required_toolchain_binding_ids") if expected_probe is not None else None
        expected_inputs = expected_probe.get("required_input_binding_ids") if expected_probe is not None else None
        if (
            not isinstance(probe_id, str)
            or PROBE_ID.fullmatch(probe_id) is None
            or probe_id in observed
            or expected_probe is None
            or role != expected_probe.get("component_role")
            or probe["test_selector"] != expected_probe.get("test_selector")
            or component is None
            or probe["source_commit"] != component["source_commit"]
            or probe["source_tree"] != component["source_tree"]
            or not isinstance(raw_toolchains, list)
            or not raw_toolchains
            or len(raw_toolchains) != len(set(raw_toolchains))
            or not set(raw_toolchains).issubset(toolchain_ids)
            or not isinstance(expected_toolchains, list)
            or set(raw_toolchains) != set(expected_toolchains)
            or not isinstance(expected_inputs, list)
            or probe["result"] != "passed"
        ):
            fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
        if validate_digest_bindings(probe["input_digests"]) != set(expected_inputs):
            fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
        observed.add(probe_id)
    if observed != set(expected):
        fail(LinkedObservationErrorReason.INVALID_PROBE_INVENTORY)
    return tuple(sorted(observed))


def validate_proof_rows(raw_rows: object, plan: dict[str, object]) -> int:
    contract = plan["linked_observation_contract"]
    if not isinstance(contract, dict) or not isinstance(
        contract.get("proof_matrix"), dict
    ):
        fail(LinkedObservationErrorReason.INVALID_PROOF_MATRIX)
    matrix = contract["proof_matrix"]
    lanes = matrix.get("lanes")
    modes = matrix.get("modes")
    stages = matrix.get("stages")
    if not isinstance(lanes, list) or not isinstance(modes, list) or not isinstance(stages, list):
        fail(LinkedObservationErrorReason.INVALID_PROOF_MATRIX)
    expected = {
        (lane, mode, stage)
        for lane in lanes
        for mode in modes
        for stage in stages
    }
    if not isinstance(raw_rows, list) or len(raw_rows) != len(expected):
        fail(LinkedObservationErrorReason.INVALID_PROOF_MATRIX)
    observed: set[tuple[str, str, str]] = set()
    for raw_row in raw_rows:
        row = exact_object(
            raw_row,
            {
                "lane",
                "mode",
                "stage",
                "circuit_ref",
                "artifact_sha256",
                "verification_key_sha256",
                "proof_sha256",
                "public_inputs_sha256",
                "frozen_request_sha256",
                "result",
                "tampered_proof_rejected",
                "tampered_public_inputs_rejected",
            },
            LinkedObservationErrorReason.INVALID_PROOF_MATRIX,
        )
        key = (row["lane"], row["mode"], row["stage"])
        if (
            not all(isinstance(item, str) for item in key)
            or key not in expected
            or key in observed
            or row["result"] != "passed"
            or row["tampered_proof_rejected"] is not True
            or row["tampered_public_inputs_rejected"] is not True
        ):
            fail(LinkedObservationErrorReason.INVALID_PROOF_MATRIX)
        bounded_string(
            row["circuit_ref"], 128, LinkedObservationErrorReason.INVALID_PROOF_MATRIX
        )
        for field in (
            "artifact_sha256",
            "verification_key_sha256",
            "proof_sha256",
            "public_inputs_sha256",
            "frozen_request_sha256",
        ):
            require_sha256(
                row[field], LinkedObservationErrorReason.INVALID_PROOF_MATRIX
            )
        observed.add(key)
    if observed != expected:
        fail(LinkedObservationErrorReason.INVALID_PROOF_MATRIX)
    return len(observed)


def validate_candidate_binding(
    evidence: dict[str, object],
    components: dict[str, dict[str, object]],
    bom: dict[str, object] | None,
) -> str | None:
    binding = evidence["candidate_binding"]
    bom_digest = evidence["product_component_bom_sha256"]
    if binding == "working_tree_observation":
        if bom is not None or bom_digest is not None:
            fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
        if all(component["source_state"] == "clean" for component in components.values()):
            fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
        return None
    if binding != "immutable_release" or bom is None:
        fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
    try:
        bom_components = bom_verifier.validate_bom(bom, require_release_refs=True)
    except SystemExit as error:
        raise LinkedObservationError(
            LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING
        ) from error
    expected_digest = bom_verifier.canonical_digest(bom)
    if bom_digest != expected_digest:
        fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
    product_id = bom.get("product_component_id")
    product = bom_components.get(product_id) if isinstance(product_id, str) else None
    providers = [
        component
        for component in bom_components.values()
        if "zk" in component.adapter_contracts
    ]
    if product is None or len(providers) != 1:
        fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
    expected_components = {
        "identity_product": product,
        "zk_provider": providers[0],
    }
    for role, component in components.items():
        expected = expected_components[role]
        if (
            component["component_id"] != expected.component_id
            or component["repository"] != expected.repository
            or component["source_commit"] != expected.commit
            or component["source_state"] != "clean"
            or component["working_tree_diff_sha256"] is not None
            or component["release_id"] != expected.release_id
            or component["release_ref"] != expected.release_ref
            or component["release_artifact_sha256"] is None
            or component["component_attestation_sha256"] is None
        ):
            fail(LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING)
    return expected_digest


def validate_evidence(
    evidence: dict[str, object],
    plan: dict[str, object],
    *,
    bom: dict[str, object] | None = None,
    expected_framework_revision: str | None = None,
    expected_workflow_revision: str | None = None,
) -> LinkedObservationSummary:
    exact_object(
        evidence,
        {
            "schema",
            "plan_id",
            "profile_id",
            "candidate_binding",
            "framework_revision",
            "workflow_revision",
            "product_component_bom_sha256",
            "components",
            "toolchain_bindings",
            "probes",
            "proof_rows",
            "evidence_policy",
        },
        LinkedObservationErrorReason.INVALID_EVIDENCE,
    )
    if (
        evidence["schema"]
        != "reallyme.identity.zk_linked_observation_evidence.v1"
        or evidence["plan_id"] != "zk-presentation-proofs-v1"
        or evidence["profile_id"] != "identity-zk-linked-presentation-proofs-v1"
        or evidence["candidate_binding"] not in CANDIDATE_BINDINGS
        or evidence["evidence_policy"] != EXPECTED_POLICY
    ):
        fail(LinkedObservationErrorReason.INVALID_EVIDENCE)
    framework_revision = evidence["framework_revision"]
    workflow_revision = evidence["workflow_revision"]
    if (
        not isinstance(framework_revision, str)
        or GIT_COMMIT.fullmatch(framework_revision) is None
        or not isinstance(workflow_revision, str)
        or GIT_COMMIT.fullmatch(workflow_revision) is None
        or expected_framework_revision is not None
        and framework_revision != expected_framework_revision
        or expected_workflow_revision is not None
        and workflow_revision != expected_workflow_revision
    ):
        fail(LinkedObservationErrorReason.REVISION_MISMATCH)
    components = validate_components(evidence["components"])
    toolchains = validate_toolchains(evidence["toolchain_bindings"], plan)
    probes = validate_probes(evidence["probes"], plan, components, toolchains)
    proof_row_count = validate_proof_rows(evidence["proof_rows"], plan)
    bom_digest = validate_candidate_binding(evidence, components, bom)
    return LinkedObservationSummary(
        candidate_binding=str(evidence["candidate_binding"]),
        evidence_sha256=canonical_sha256(evidence),
        product_component_bom_sha256=bom_digest,
        probe_ids=probes,
        proof_row_count=proof_row_count,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--product-component-bom", type=Path)
    parser.add_argument("--framework-revision")
    parser.add_argument("--workflow-revision")
    arguments = parser.parse_args()
    try:
        plan, _adapter = zk_adapter.load_contract()
        evidence = zk_adapter.load_object(arguments.evidence)
        bom = (
            bom_verifier.load_bom(arguments.product_component_bom)
            if arguments.product_component_bom is not None
            else None
        )
        summary = validate_evidence(
            evidence,
            plan,
            bom=bom,
            expected_framework_revision=arguments.framework_revision,
            expected_workflow_revision=arguments.workflow_revision,
        )
    except zk_adapter.ZkAdapterError as error:
        zk_adapter.fail(error.reason)
    except LinkedObservationError as error:
        print(
            f"linked ZK observation evidence invalid: {error.reason.value}",
            file=sys.stderr,
        )
        return 65
    print(
        json.dumps(
            {
                "candidate_binding": summary.candidate_binding,
                "evidence_sha256": summary.evidence_sha256,
                "probe_count": len(summary.probe_ids),
                "proof_row_count": summary.proof_row_count,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
