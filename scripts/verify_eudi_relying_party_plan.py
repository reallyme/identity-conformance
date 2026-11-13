#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Fail-closed validation for the EUDI relying-party control-plane plan."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPOSITORY_ROOT / "plans" / "eudi" / "relying-party-control-plane.json"
MAX_PLAN_BYTES = 256 * 1024
EXIT_INVALID_INPUT = 2
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_CONTRACT = re.compile(r"^attestation\.[a-z][a-z0-9_]{0,95}$")

REQUIRED_SOURCES = {
    "eu_regulation_910_2014",
    "cir_2025_848",
    "cir_2026_1730",
    "ec_ts5_wallet_relying_party_registration",
    "ec_ts6_wallet_relying_party_information",
    "etsi_ts_119_411_8",
    "etsi_ts_119_475",
}
REQUIRED_EXECUTION_SOURCES = {
    "eudi-arf": "requirements_baseline",
    "eudi-fcaf": "assessment_methodology",
    "eudi-technical-specifications": "ts5_ts6_wire_contracts",
    "eudi-relying-party-registration-service": "explicit_compatibility_profile",
}
REQUIRED_FAMILIES = {
    "regulatory_identity_and_representation",
    "service_level_intermediary_association",
    "authenticated_and_trusted_registry_observation",
    "recoverable_registration_mutation",
    "independent_wrpac_and_wrprc_lifecycle",
    "transaction_content_non_retention",
}
REQUIRED_ASSERTIONS = {
    "customer_regulatory_identity_preserved",
    "representative_mandate_is_scoped",
    "technical_intermediary_is_distinct",
    "association_is_service_to_service",
    "wrpac_binds_association_and_register_reference",
    "current_ts5_signed_envelope_is_strict",
    "signer_trust_is_exactly_bound",
    "legacy_profile_cannot_synthesize_current_claims",
    "reconciliation_is_revision_bound",
    "deletion_requires_authoritative_absence",
    "dispatch_intent_precedes_non_idempotent_io",
    "unknown_outcome_forbids_blind_retry",
    "legacy_administration_is_not_normative_ts5",
    "wrprc_is_bound_per_service_and_intended_use",
    "legacy_wrprc_shape_cannot_satisfy_strict_profile",
    "wrpac_lifecycle_is_separate_from_registration",
    "private_key_material_remains_external",
    "transaction_content_is_outside_control_plane_storage",
    "retained_evidence_is_control_plane_only",
}
ALLOWED_EVIDENCE = {
    "architecture_test",
    "authorization_test",
    "behavior_test",
    "boundary_test",
    "concurrency_test",
    "crash_recovery_test",
    "downgrade_test",
    "invalid_input_test",
    "oversized_input_test",
    "redaction_test",
    "round_trip_test",
    "state_transition_test",
    "storage_policy_test",
    "substitution_test",
    "telemetry_policy_test",
    "trust_test",
    "unsupported_operation_test",
}


class PlanError(Exception):
    """Typed validation failure without echoing repository-controlled values."""


def fail(reason: str) -> NoReturn:
    print(f"EUDI relying-party plan validation failed: {reason}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID_INPUT)


def load_plan(path: Path = PLAN_PATH) -> dict[str, object]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_PLAN_BYTES:
            raise PlanError("invalid_plan_size")
        parsed = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise PlanError("unreadable_plan") from error
    if not isinstance(parsed, dict):
        raise PlanError("invalid_root")
    return parsed


def exact_keys(value: object, expected: set[str], reason: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PlanError(reason)
    return value


def require_identifier(value: object, reason: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise PlanError(reason)
    return value


def require_string_list(value: object, reason: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise PlanError(reason)
    strings = list(value)
    if len(strings) != len(set(strings)):
        raise PlanError(reason)
    return strings


def verify_plan(plan: dict[str, object]) -> None:
    exact_keys(
        plan,
        {"schema_version", "plan_id", "authority", "certification_claim", "execution_status", "taxonomy_program", "system_under_test", "sources", "evidence_policy", "evidence_coverage", "assertion_families"},
        "invalid_plan_shape",
    )
    if plan["schema_version"] != 1 or plan["plan_id"] != "eudi-relying-party-control-plane-v1":
        raise PlanError("invalid_plan_identity")
    if plan["authority"] != "internal_non_certification_evidence" or plan["certification_claim"] is not False:
        raise PlanError("invalid_authority")
    if plan["execution_status"] != "executable_with_attestation_gaps":
        raise PlanError("invalid_execution_status")
    if plan["taxonomy_program"] != "eudi_relying_party_control_plane":
        raise PlanError("invalid_taxonomy_program")

    system = exact_keys(
        plan["system_under_test"],
        {"component_id", "adapter_contract"},
        "invalid_system_under_test",
    )
    if system != {
        "component_id": "eudi-relying-party-control-plane",
        "adapter_contract": "adapters/eudi-relying-party/README.md",
    }:
        raise PlanError("invalid_system_under_test")

    sources = exact_keys(
        plan["sources"],
        {"required", "execution_sources", "legacy_reference"},
        "invalid_sources",
    )
    if set(require_string_list(sources["required"], "invalid_required_sources")) != REQUIRED_SOURCES:
        raise PlanError("invalid_required_sources")
    execution_sources = sources["execution_sources"]
    if not isinstance(execution_sources, list) or len(execution_sources) != len(REQUIRED_EXECUTION_SOURCES):
        raise PlanError("invalid_execution_sources")
    observed_execution_sources: dict[str, str] = {}
    for execution_source_value in execution_sources:
        execution_source = exact_keys(
            execution_source_value,
            {"source_id", "use", "required_checkout"},
            "invalid_execution_source",
        )
        source_id = execution_source["source_id"]
        use = execution_source["use"]
        if (
            not isinstance(source_id, str)
            or not isinstance(use, str)
            or execution_source["required_checkout"] is not True
            or source_id in observed_execution_sources
        ):
            raise PlanError("invalid_execution_source")
        observed_execution_sources[source_id] = use
    if observed_execution_sources != REQUIRED_EXECUTION_SOURCES:
        raise PlanError("invalid_execution_sources")
    legacy = exact_keys(sources["legacy_reference"], {"repository", "commit", "profile"}, "invalid_legacy_reference")
    if legacy["repository"] != "eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py":
        raise PlanError("invalid_legacy_reference")
    if not isinstance(legacy["commit"], str) or HEX_COMMIT.fullmatch(legacy["commit"]) is None:
        raise PlanError("invalid_legacy_reference")
    if legacy["profile"] != "explicit_compatibility_only":
        raise PlanError("invalid_legacy_reference")

    policy = exact_keys(
        plan["evidence_policy"],
        {"plan_is_evidence", "production_code_under_test_required", "exact_repository_revisions_required", "negative_input_evidence_required", "oversized_input_evidence_required", "reviewed_redacted_results_required", "transaction_content_prohibited"},
        "invalid_evidence_policy",
    )
    if policy["plan_is_evidence"] is not False or any(policy[key] is not True for key in policy if key != "plan_is_evidence"):
        raise PlanError("invalid_evidence_policy")

    coverage = exact_keys(
        plan["evidence_coverage"],
        {"assertion_count", "independently_observed_assertion_count", "attestation_only_assertion_count", "badge_eligible"},
        "invalid_evidence_coverage",
    )
    if coverage != {
        "assertion_count": 19,
        "independently_observed_assertion_count": 0,
        "attestation_only_assertion_count": 19,
        "badge_eligible": False,
    }:
        raise PlanError("invalid_evidence_coverage")

    families = plan["assertion_families"]
    if not isinstance(families, list) or not families:
        raise PlanError("invalid_assertion_families")
    family_ids: set[str] = set()
    assertion_ids: set[str] = set()
    for family_value in families:
        family = exact_keys(family_value, {"family_id", "assertions"}, "invalid_family")
        family_id = require_identifier(family["family_id"], "invalid_family_id")
        if family_id in family_ids:
            raise PlanError("duplicate_family_id")
        family_ids.add(family_id)
        assertions = family["assertions"]
        if not isinstance(assertions, list) or not assertions:
            raise PlanError("empty_family")
        for assertion_value in assertions:
            assertion = exact_keys(
                assertion_value,
                {"assertion_id", "taxonomy_refs", "source_refs", "required_evidence", "evidence_contracts"},
                "invalid_assertion",
            )
            assertion_id = require_identifier(assertion["assertion_id"], "invalid_assertion_id")
            if assertion_id in assertion_ids:
                raise PlanError("duplicate_assertion_id")
            assertion_ids.add(assertion_id)
            taxonomy_refs = require_string_list(assertion["taxonomy_refs"], "invalid_taxonomy_refs")
            if any(not reference.startswith("identity.") for reference in taxonomy_refs):
                raise PlanError("invalid_taxonomy_refs")
            if not set(require_string_list(assertion["source_refs"], "invalid_source_refs")).issubset(REQUIRED_SOURCES):
                raise PlanError("invalid_source_refs")
            evidence = set(require_string_list(assertion["required_evidence"], "invalid_required_evidence"))
            if not evidence.issubset(ALLOWED_EVIDENCE):
                raise PlanError("invalid_required_evidence")
            contracts = require_string_list(
                assertion["evidence_contracts"], "invalid_evidence_contracts"
            )
            if contracts != [f"attestation.{assertion_id}"] or any(
                EVIDENCE_CONTRACT.fullmatch(contract) is None
                for contract in contracts
            ):
                raise PlanError("invalid_evidence_contracts")

    if family_ids != REQUIRED_FAMILIES:
        raise PlanError("incomplete_family_set")
    if assertion_ids != REQUIRED_ASSERTIONS:
        raise PlanError("incomplete_assertion_set")


def main() -> int:
    try:
        verify_plan(load_plan())
    except PlanError as error:
        fail(str(error))
    print("EUDI relying-party control-plane plan valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
