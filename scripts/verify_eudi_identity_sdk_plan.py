#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the closed EUDI Identity SDK conformance plan."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


PLAN_PATH = REPOSITORY_ROOT / "plans/eudi/identity-sdk.json"
LEGAL_SOURCES_PATH = REPOSITORY_ROOT / "upstream/eudi/legal-sources.lock.json"
NORMATIVE_SOURCES_PATH = REPOSITORY_ROOT / "references/normative-sources.lock.json"
EUDI_SOURCES_PATH = REPOSITORY_ROOT / "upstream/eudi/sources.lock.json"
MAX_JSON_BYTES = 512 * 1024

EXPECTED_OPERATIONS = frozenset(
    {
        "resolve_requirement",
        "validate_catalogue",
        "validate_legal_person_pid",
        "validate_natural_person_pid",
        "validate_pid_allocation",
        "validate_pid_issuance",
        "validate_pid_revocation",
        "validate_requirement_registry",
    }
)
EXPECTED_LANES = {
    "normative_trace": ("framework", "executable"),
    "rust_product_boundary": ("github_hosted_linux", "executable"),
    "eudi_openid_composition": ("github_hosted_linux", "executable"),
    "typescript_sdk": ("github_hosted_linux", "executable"),
    "python_sdk": ("github_hosted_linux", "executable"),
    "go_sdk": ("github_hosted_linux", "executable"),
    "kotlin_sdk": ("github_hosted_linux", "executable"),
    "swift_sdk": ("github_hosted_macos", "executable"),
}
EXPECTED_LEGAL_SOURCES = frozenset(
    {"cir-2024-2977", "cir-2024-2979", "cir-2024-2982", "cir-2026-1731"}
)
EXPECTED_STANDARDS = frozenset(
    {
        "etsi-ts-119-472-1-v1.2.1",
        "etsi-ts-119-472-2-v1.3.1",
        "etsi-ts-119-472-3-v1.1.1",
    }
)
EXPECTED_TECHNICAL_SOURCES = frozenset({"eudi-attestation-rulebooks"})
EXPECTED_COMPONENT_ROLES = frozenset({"openid4vci", "openid4vp", "ssi"})
EXPECTED_CANDIDATE_COMPONENTS = {
    "identity": "https://github.com/reallyme/identity",
    "ssi": "https://github.com/reallyme/ssi",
    "openid4vci": "https://github.com/reallyme/openid4vci",
    "openid4vp": "https://github.com/reallyme/openid4vp",
}


class PlanErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    PLAN_INVALID = "plan_invalid"
    SOURCE_BINDING_INVALID = "source_binding_invalid"


@dataclass(frozen=True)
class PlanError(Exception):
    reason: PlanErrorReason


def fail(reason: PlanErrorReason) -> NoReturn:
    raise PlanError(reason)


def load_object(path: Path, reason: PlanErrorReason) -> dict[str, object]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAX_JSON_BYTES
        ):
            fail(reason)
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
            fail(reason)
        value = strict_json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(reason)
    if not isinstance(value, dict):
        fail(reason)
    return value


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(PlanErrorReason.PLAN_INVALID)
    return value


def unique_strings(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        fail(PlanErrorReason.PLAN_INVALID)
    return tuple(value)


def source_ids(lock: dict[str, object]) -> frozenset[str]:
    sources = lock.get("sources")
    if not isinstance(sources, list):
        fail(PlanErrorReason.SOURCE_BINDING_INVALID)
    observed: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            fail(PlanErrorReason.SOURCE_BINDING_INVALID)
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or not source_id or source_id in observed:
            fail(PlanErrorReason.SOURCE_BINDING_INVALID)
        observed.add(source_id)
    return frozenset(observed)


def normative_source_ids(lock: dict[str, object]) -> frozenset[str]:
    sources = lock.get("sources")
    if not isinstance(sources, list):
        fail(PlanErrorReason.SOURCE_BINDING_INVALID)
    observed: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            fail(PlanErrorReason.SOURCE_BINDING_INVALID)
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id or source_id in observed:
            fail(PlanErrorReason.SOURCE_BINDING_INVALID)
        observed.add(source_id)
    return frozenset(observed)


def validate_plan(
    plan: dict[str, object],
    legal_sources: frozenset[str],
    standards: frozenset[str],
    eudi_sources: frozenset[str],
) -> None:
    expected_top_level = {
        "$comment",
        "schema_version",
        "plan_id",
        "authority",
        "certification_claim",
        "execution_status",
        "system_under_test",
        "candidate_contract",
        "ownership",
        "sources",
        "requirement_registry",
        "operations",
        "execution_lanes",
        "evidence_classes",
        "evidence_policy",
        "evidence_coverage",
    }
    if (
        set(plan) != expected_top_level
        or plan.get("schema_version") != 1
        or plan.get("plan_id") != "eudi-identity-sdk-v1"
        or plan.get("authority") != "internal_non_certification_evidence"
        or plan.get("certification_claim") is not False
        or plan.get("execution_status")
        != "executable"
    ):
        fail(PlanErrorReason.PLAN_INVALID)

    system = exact_object(
        plan.get("system_under_test"),
        {"component_id", "repository", "adapter_contract"},
    )
    if system != {
        "component_id": "identity",
        "repository": "https://github.com/reallyme/identity",
        "adapter_contract": "candidate-owned-identity-operation-boundary",
    }:
        fail(PlanErrorReason.PLAN_INVALID)

    candidate_contract = exact_object(
        plan.get("candidate_contract"),
        {
            "selection",
            "reference_baseline_fallback",
            "dependency_release_ids_required",
            "dependency_release_refs_required",
            "required_components",
        },
    )
    raw_required_components = candidate_contract.get("required_components")
    if (
        candidate_contract.get("selection") != "caller_product_component_bom"
        or candidate_contract.get("reference_baseline_fallback") is not False
        or candidate_contract.get("dependency_release_ids_required") is not True
        or candidate_contract.get("dependency_release_refs_required") is not True
        or not isinstance(raw_required_components, list)
        or len(raw_required_components) != len(EXPECTED_CANDIDATE_COMPONENTS)
    ):
        fail(PlanErrorReason.PLAN_INVALID)
    required_components: dict[str, str] = {}
    for raw_component in raw_required_components:
        component = exact_object(raw_component, {"component_id", "repository"})
        component_id = component.get("component_id")
        repository = component.get("repository")
        if (
            not isinstance(component_id, str)
            or not isinstance(repository, str)
            or component_id in required_components
        ):
            fail(PlanErrorReason.PLAN_INVALID)
        required_components[component_id] = repository
    if required_components != EXPECTED_CANDIDATE_COMPONENTS:
        fail(PlanErrorReason.PLAN_INVALID)

    ownership = exact_object(
        plan.get("ownership"),
        {
            "identity_responsibility",
            "semantic_component_roles",
            "hosted_lifecycle_profile",
        },
    )
    if (
        ownership.get("identity_responsibility")
        != "product_composition_dispatch_wire_and_sdk_parity"
        or frozenset(unique_strings(ownership.get("semantic_component_roles")))
        != EXPECTED_COMPONENT_ROLES
        or ownership.get("hosted_lifecycle_profile")
        != "eudi-relying-party-control-plane-v1"
    ):
        fail(PlanErrorReason.PLAN_INVALID)

    sources = exact_object(
        plan.get("sources"), {"legal", "standards", "technical_specifications"}
    )
    selected_legal = frozenset(unique_strings(sources.get("legal")))
    selected_standards = frozenset(unique_strings(sources.get("standards")))
    selected_technical = frozenset(
        unique_strings(sources.get("technical_specifications"))
    )
    if (
        selected_legal != EXPECTED_LEGAL_SOURCES
        or selected_standards != EXPECTED_STANDARDS
        or selected_technical != EXPECTED_TECHNICAL_SOURCES
        or not selected_legal.issubset(legal_sources)
        or not selected_standards.issubset(standards)
        or not selected_technical.issubset(eudi_sources)
    ):
        fail(PlanErrorReason.SOURCE_BINDING_INVALID)

    registry = exact_object(
        plan.get("requirement_registry"),
        {
            "etsi_rows",
            "eu_rows",
            "code_and_composed_evidence_rows",
            "external_evidence_rows",
            "not_applicable_rows",
            "framework_audit",
        },
    )
    if registry != {
        "etsi_rows": 740,
        "eu_rows": 229,
        "code_and_composed_evidence_rows": 898,
        "external_evidence_rows": 53,
        "not_applicable_rows": 18,
        "framework_audit": "scripts/audit_etsi_eaa_pid_trace.py",
    }:
        fail(PlanErrorReason.PLAN_INVALID)
    if (
        registry["code_and_composed_evidence_rows"]
        + registry["external_evidence_rows"]
        + registry["not_applicable_rows"]
        != registry["etsi_rows"] + registry["eu_rows"]
    ):
        fail(PlanErrorReason.PLAN_INVALID)

    operations = plan.get("operations")
    if not isinstance(operations, list) or len(operations) != len(EXPECTED_OPERATIONS):
        fail(PlanErrorReason.PLAN_INVALID)
    observed_operations: set[str] = set()
    allowed_sources = selected_legal | selected_standards | selected_technical
    for raw_operation in operations:
        operation = exact_object(
            raw_operation, {"operation_id", "semantic_owner_role", "source_refs"}
        )
        operation_id = operation.get("operation_id")
        if (
            not isinstance(operation_id, str)
            or operation_id not in EXPECTED_OPERATIONS
            or operation_id in observed_operations
            or operation.get("semantic_owner_role") not in EXPECTED_COMPONENT_ROLES
            or not frozenset(unique_strings(operation.get("source_refs"))).issubset(
                allowed_sources
            )
        ):
            fail(PlanErrorReason.PLAN_INVALID)
        observed_operations.add(operation_id)
    if observed_operations != EXPECTED_OPERATIONS:
        fail(PlanErrorReason.PLAN_INVALID)

    lanes = plan.get("execution_lanes")
    if not isinstance(lanes, list) or len(lanes) != len(EXPECTED_LANES):
        fail(PlanErrorReason.PLAN_INVALID)
    observed_lanes: set[str] = set()
    for raw_lane in lanes:
        lane = exact_object(raw_lane, {"lane_id", "runner", "required", "state"})
        lane_id = lane.get("lane_id")
        if (
            not isinstance(lane_id, str)
            or lane_id not in EXPECTED_LANES
            or lane_id in observed_lanes
            or lane.get("required") is not True
            or (lane.get("runner"), lane.get("state")) != EXPECTED_LANES[lane_id]
        ):
            fail(PlanErrorReason.PLAN_INVALID)
        observed_lanes.add(lane_id)
    if observed_lanes != set(EXPECTED_LANES):
        fail(PlanErrorReason.PLAN_INVALID)

    evidence_classes = exact_object(
        plan.get("evidence_classes"),
        {
            "normative_specifications",
            "reference_implementation_parity",
            "external_legal_and_certification",
        },
    )
    normative = exact_object(
        evidence_classes.get("normative_specifications"),
        {"status", "required_for_engineering_pass", "evidence"},
    )
    if normative != {
        "status": "executed",
        "required_for_engineering_pass": True,
        "evidence": [
            "normative_trace",
            "rust_product_boundary",
            "eudi_openid_composition",
        ],
    }:
        fail(PlanErrorReason.PLAN_INVALID)
    reference_parity = exact_object(
        evidence_classes.get("reference_implementation_parity"),
        {"status", "required_for_engineering_pass", "reason", "targets"},
    )
    expected_reference_targets = [
        {
            "scope_id": "identity_eudi_operations",
            "status": "not_applicable",
            "source_refs": [],
            "reason": "no_official_executable_oracle_for_catalogue_requirement_or_pid_validation",
        },
        {
            "scope_id": "openid4vci_composition",
            "status": "external_runner_required",
            "source_refs": ["eudi-pid-issuer", "eudi-issuer-wallet-tester", "eudi-itb"],
            "reason": "deployed_reference_issuer_and_test_services_required",
        },
        {
            "scope_id": "openid4vp_verifier_composition",
            "status": "external_runner_required",
            "source_refs": ["eudi-verifier-endpoint", "eudi-web-verifier", "eudi-itb"],
            "reason": "deployed_reference_verifier_and_test_services_required",
        },
        {
            "scope_id": "openid4vp_wallet_composition",
            "status": "not_applicable",
            "source_refs": [
                "eudi-android-wallet-core",
                "eudi-android-wallet-ui",
                "eudi-ios-wallet-kit",
                "eudi-ios-wallet-ui",
            ],
            "reason": "identity_sdk_candidate_contains_no_android_or_ios_wallet_application",
        },
    ]
    if reference_parity != {
        "status": "separate_deployed_interoperability_profile",
        "required_for_engineering_pass": False,
        "reason": "no_equivalent_eu_identity_sdk_boundary",
        "targets": expected_reference_targets,
    }:
        fail(PlanErrorReason.PLAN_INVALID)
    for target in expected_reference_targets:
        if not set(target["source_refs"]).issubset(eudi_sources):
            fail(PlanErrorReason.SOURCE_BINDING_INVALID)
    external = exact_object(
        evidence_classes.get("external_legal_and_certification"),
        {
            "status",
            "required_for_engineering_pass",
            "external_evidence_rows",
            "legal_conformity_claim",
            "certification_claim",
        },
    )
    if external != {
        "status": "external_evidence_required",
        "required_for_engineering_pass": False,
        "external_evidence_rows": 53,
        "legal_conformity_claim": False,
        "certification_claim": False,
    }:
        fail(PlanErrorReason.PLAN_INVALID)

    policy = exact_object(
        plan.get("evidence_policy"),
        {
            "immutable_candidate_required_for_badge",
            "exact_component_revisions_required",
            "framework_executes_tests",
            "attestations_satisfy_behavior",
            "external_evidence_rows_are_code_passes",
            "legal_conformity_claim",
            "certification_claim",
        },
    )
    if policy != {
        "immutable_candidate_required_for_badge": True,
        "exact_component_revisions_required": True,
        "framework_executes_tests": True,
        "attestations_satisfy_behavior": False,
        "external_evidence_rows_are_code_passes": False,
        "legal_conformity_claim": False,
        "certification_claim": False,
    }:
        fail(PlanErrorReason.PLAN_INVALID)

    coverage = exact_object(
        plan.get("evidence_coverage"),
        {
            "identity_operation_count",
            "required_lane_count",
            "executable_lane_count",
            "pending_lane_count",
            "badge_eligible",
        },
    )
    if coverage != {
        "identity_operation_count": 8,
        "required_lane_count": 8,
        "executable_lane_count": 8,
        "pending_lane_count": 0,
        "badge_eligible": True,
    }:
        fail(PlanErrorReason.PLAN_INVALID)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=PLAN_PATH)
    arguments = parser.parse_args()
    try:
        validate_plan(
            load_object(arguments.plan, PlanErrorReason.INPUT_INVALID),
            source_ids(load_object(LEGAL_SOURCES_PATH, PlanErrorReason.SOURCE_BINDING_INVALID)),
            normative_source_ids(
                load_object(NORMATIVE_SOURCES_PATH, PlanErrorReason.SOURCE_BINDING_INVALID)
            ),
            source_ids(load_object(EUDI_SOURCES_PATH, PlanErrorReason.SOURCE_BINDING_INVALID)),
        )
    except PlanError as error:
        print(f"error: EUDI Identity SDK plan is invalid ({error.reason.value})", file=sys.stderr)
        return 65
    print("EUDI Identity SDK plan valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
