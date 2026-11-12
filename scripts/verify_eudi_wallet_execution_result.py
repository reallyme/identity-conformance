#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a passing EUDI Wallet execution result and its closed contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_eudi_wallet_conformance as runner  # noqa: E402
import verify_eu_wallet_boundaries as normative_boundaries  # noqa: E402
import verify_eudi_wallet_adapter as adapter_verifier  # noqa: E402


TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


def expected_check_kinds(adapter: dict[str, object]) -> dict[str, str]:
    artifacts = adapter["source_artifacts"]
    test_execution = adapter["test_execution"]
    if not isinstance(artifacts, list) or not isinstance(test_execution, dict):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    source_checks: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("artifact_id"), str):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        source_checks[f"source.{artifact['artifact_id']}"] = "source"
    test_check_id = test_execution.get("check_id")
    framework_probes = adapter.get("framework_probes")
    if (
        not isinstance(test_check_id, str)
        or not isinstance(framework_probes, list)
        or not framework_probes
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    probe_checks: dict[str, str] = {}
    for probe in framework_probes:
        if not isinstance(probe, dict) or not isinstance(probe.get("check_id"), str):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        check_id = probe["check_id"]
        if check_id in probe_checks:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        probe_checks[check_id] = "probe"
    boundary_adapter = normative_boundaries.load_adapter()
    raw_boundaries = boundary_adapter.get("implemented_boundaries")
    if not isinstance(raw_boundaries, list):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    normative_checks: dict[str, str] = {}
    for raw_boundary in raw_boundaries:
        if not isinstance(raw_boundary, dict):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        checks = raw_boundary.get("normative_checks")
        if not isinstance(checks, dict):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        for check_id in checks.values():
            if not isinstance(check_id, str) or check_id in normative_checks:
                raise runner.EudiWalletRunnerError(
                    runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            normative_checks[check_id] = "normative"
    return {
        **source_checks,
        "artifact.wallet-release-bundle": "artifact",
        "framework.eudi-source-lock": "source",
        "framework.eudi-legal-source-lock": "source",
        "framework.eudi-publications-lock": "source",
        **normative_checks,
        **{
            f"attestation.{category}": "attestation"
            for category in adapter_verifier.EXPECTED_ATTESTATION_CATEGORIES
        },
        test_check_id: "cargo",
        **probe_checks,
    }


def verify_test_execution(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "command_id",
        "discovered_test_count",
        "test_inventory_sha256",
        "executed_test_count",
        "passed_test_count",
        "failed_test_count",
        "ignored_test_count",
        "measured_test_count",
        "filtered_test_count",
        "declared_executable_case_count",
        "declared_test_functions_sha256",
        "result",
    }:
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    if (
        value["command_id"] != runner.TEST_COMMAND_ID
        or not isinstance(value["discovered_test_count"], int)
        or isinstance(value["discovered_test_count"], bool)
        or not 1 <= value["discovered_test_count"] <= runner.MAX_DISCOVERED_TESTS
        or not isinstance(value["test_inventory_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["test_inventory_sha256"]) is None
        or not isinstance(value["executed_test_count"], int)
        or isinstance(value["executed_test_count"], bool)
        or value["executed_test_count"] != value["discovered_test_count"]
        or not isinstance(value["passed_test_count"], int)
        or isinstance(value["passed_test_count"], bool)
        or value["passed_test_count"] != value["discovered_test_count"]
        or type(value["failed_test_count"]) is not int
        or value["failed_test_count"] != 0
        or type(value["ignored_test_count"]) is not int
        or value["ignored_test_count"] != 0
        or type(value["measured_test_count"]) is not int
        or value["measured_test_count"] != 0
        or type(value["filtered_test_count"]) is not int
        or value["filtered_test_count"] != 0
        or not isinstance(value["declared_executable_case_count"], int)
        or isinstance(value["declared_executable_case_count"], bool)
        or not 1 <= value["declared_executable_case_count"] <= 10_000
        or not isinstance(value["declared_test_functions_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["declared_test_functions_sha256"])
        is None
        or value["result"] != "passed"
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )


def verify_framework_probes(value: object, adapter: dict[str, object]) -> None:
    contracts = adapter.get("framework_probes")
    if (
        not isinstance(contracts, list)
        or not isinstance(value, list)
        or len(value) != len(contracts)
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    for probe, contract in zip(value, contracts, strict=True):
        if not isinstance(probe, dict) or not isinstance(contract, dict):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        if set(probe) != {
            "probe_id",
            "command_id",
            "source_sha256",
            "executed_test_count",
            "passed_test_count",
            "failed_test_count",
            "ignored_test_count",
            "measured_test_count",
            "filtered_test_count",
            "result",
        }:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        source_path = contract.get("source_path")
        expected_test_count = contract.get("expected_test_count")
        if (
            not isinstance(source_path, str)
            or type(expected_test_count) is not int
            or probe["probe_id"] != contract.get("probe_id")
            or probe["command_id"] != contract.get("command_id")
            or probe["source_sha256"]
            != runner.hash_regular_file(adapter_verifier.REPOSITORY_ROOT / source_path)
            or type(probe["executed_test_count"]) is not int
            or probe["executed_test_count"] != expected_test_count
            or type(probe["passed_test_count"]) is not int
            or probe["passed_test_count"] != expected_test_count
            or type(probe["failed_test_count"]) is not int
            or probe["failed_test_count"] != 0
            or type(probe["ignored_test_count"]) is not int
            or probe["ignored_test_count"] != 0
            or type(probe["measured_test_count"]) is not int
            or probe["measured_test_count"] != 0
            or type(probe["filtered_test_count"]) is not int
            or probe["filtered_test_count"] != 0
            or probe["result"] != "passed"
        ):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )


def verify_release_evidence(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "preflight_run_id",
        "preflight_job_id",
        "fuzz_run_id",
        "protobuf_ci_run_id",
        "rust_ci_run_id",
        "crate_count",
        "crate_inventory_sha256",
        "evidence_count",
        "evidence_inventory_sha256",
        "cargo_lock_sha256",
    }:
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    if (
        type(value["preflight_run_id"]) is not int
        or value["preflight_run_id"] < 1
        or type(value["preflight_job_id"]) is not int
        or value["preflight_job_id"] < 1
        or type(value["fuzz_run_id"]) is not int
        or value["fuzz_run_id"] < 1
        or type(value["protobuf_ci_run_id"]) is not int
        or value["protobuf_ci_run_id"] < 1
        or type(value["rust_ci_run_id"]) is not int
        or value["rust_ci_run_id"] < 1
        or len(
            {
                value["preflight_run_id"],
                value["fuzz_run_id"],
                value["protobuf_ci_run_id"],
                value["rust_ci_run_id"],
            }
        )
        != 4
        or type(value["crate_count"]) is not int
        or not 1 <= value["crate_count"] <= 128
        or not isinstance(value["crate_inventory_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["crate_inventory_sha256"])
        is None
        or value["evidence_count"] != 7
        or not isinstance(value["evidence_inventory_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["evidence_inventory_sha256"])
        is None
        or not isinstance(value["cargo_lock_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["cargo_lock_sha256"]) is None
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )


def verify_coverage(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "authority",
        "certification_claim",
        "minimum_requirements",
        "declared_cases",
        "normative_boundaries",
    }:
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    minimums = value["minimum_requirements"]
    cases = value["declared_cases"]
    boundaries = value["normative_boundaries"]
    minimum_statuses = {
        "implemented",
        "partial",
        "operational_required",
        "delegated",
        "fixture_seeded",
    }
    case_statuses = {
        "unit_covered",
        "implemented",
        "fixture_available",
        "fixture_seeded",
    }
    if (
        value["authority"] != "internal_engineering"
        or value["certification_claim"] is not False
        or not isinstance(minimums, dict)
        or set(minimums) != {"total", "status_counts", "incomplete"}
        or type(minimums["total"]) is not int
        or not 1 <= minimums["total"] <= 256
        or not isinstance(minimums["status_counts"], dict)
        or set(minimums["status_counts"]) != minimum_statuses
        or any(
            type(count) is not int or count < 0
            for count in minimums["status_counts"].values()
        )
        or sum(minimums["status_counts"].values()) != minimums["total"]
        or not isinstance(minimums["incomplete"], list)
        or len(minimums["incomplete"])
        != minimums["total"] - minimums["status_counts"]["implemented"]
        or not isinstance(cases, dict)
        or set(cases)
        != {
            "total",
            "executable",
            "non_executable",
            "status_counts",
            "non_executable_cases",
        }
        or type(cases["total"]) is not int
        or not 1 <= cases["total"] <= 10_000
        or type(cases["executable"]) is not int
        or not 1 <= cases["executable"] <= cases["total"]
        or type(cases["non_executable"]) is not int
        or cases["non_executable"] != cases["total"] - cases["executable"]
        or not isinstance(cases["status_counts"], dict)
        or set(cases["status_counts"]) != case_statuses
        or any(
            type(count) is not int or count < 0
            for count in cases["status_counts"].values()
        )
        or sum(cases["status_counts"].values()) != cases["total"]
        or cases["status_counts"]["unit_covered"]
        + cases["status_counts"]["implemented"]
        != cases["executable"]
        or not isinstance(cases["non_executable_cases"], list)
        or len(cases["non_executable_cases"]) != cases["non_executable"]
        or not isinstance(boundaries, dict)
        or set(boundaries) != {"implemented", "checks"}
        or type(boundaries["implemented"]) is not int
        or boundaries["implemented"] < 1
        or type(boundaries["checks"]) is not int
        or boundaries["checks"] < boundaries["implemented"]
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    incomplete_ids: set[str] = set()
    incomplete_status_counts = {
        status: 0 for status in minimum_statuses if status != "implemented"
    }
    for raw_minimum in minimums["incomplete"]:
        if not isinstance(raw_minimum, dict) or set(raw_minimum) != {
            "minimum_id",
            "status",
            "limitations",
        }:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        minimum_id = raw_minimum["minimum_id"]
        status = raw_minimum["status"]
        limitations = raw_minimum["limitations"]
        if (
            not isinstance(minimum_id, str)
            or adapter_verifier.IDENTIFIER.fullmatch(minimum_id) is None
            or minimum_id in incomplete_ids
            or status not in incomplete_status_counts
            or not isinstance(limitations, list)
            or not limitations
            or not all(isinstance(item, str) and item for item in limitations)
        ):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        incomplete_ids.add(minimum_id)
        incomplete_status_counts[status] += 1
    if any(
        incomplete_status_counts[status] != minimums["status_counts"][status]
        for status in incomplete_status_counts
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    non_executable_ids: set[str] = set()
    non_executable_status_counts = {"fixture_available": 0, "fixture_seeded": 0}
    for raw_case in cases["non_executable_cases"]:
        if not isinstance(raw_case, dict) or set(raw_case) != {"case_id", "status"}:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        case_id = raw_case["case_id"]
        status = raw_case["status"]
        if (
            not isinstance(case_id, str)
            or adapter_verifier.IDENTIFIER.fullmatch(case_id) is None
            or case_id in non_executable_ids
            or status not in non_executable_status_counts
        ):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        non_executable_ids.add(case_id)
        non_executable_status_counts[status] += 1
    if any(
        non_executable_status_counts[status] != cases["status_counts"][status]
        for status in non_executable_status_counts
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )


def verify_result(value: dict[str, object]) -> None:
    if set(value) != {
        "schema",
        "plan_id",
        "result",
        "created_at",
        "framework_version",
        "framework_revision",
        "workflow_revision",
        "candidate_sha256",
        "component",
        "release_artifact_sha256",
        "component_attestation_sha256",
        "release_evidence",
        "source_locks",
        "normative_ledgers",
        "coverage",
        "test_execution",
        "framework_probes",
        "checks",
        "assertions",
        "evidence_policy",
    }:
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    plan, adapter = adapter_verifier.load_contract()
    if (
        value["schema"] != "reallyme.identity.eudi_wallet_execution_result.v2"
        or value["plan_id"] != "eudi-wallet-engineering-v1"
        or value["result"] != "passed"
        or not isinstance(value["created_at"], str)
        or TIMESTAMP.fullmatch(value["created_at"]) is None
        or value["framework_version"] != runner.framework_version()
        or not isinstance(value["framework_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", value["framework_revision"]) is None
        or not isinstance(value["workflow_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", value["workflow_revision"]) is None
        or not isinstance(value["candidate_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["candidate_sha256"]) is None
        or value["evidence_policy"] != adapter_verifier.EXPECTED_POLICY
        or not isinstance(value["release_artifact_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["release_artifact_sha256"]) is None
        or not isinstance(value["component_attestation_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["component_attestation_sha256"])
        is None
        or not isinstance(value["source_locks"], dict)
        or set(value["source_locks"])
        != {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
        }
        or not all(
            isinstance(digest, str)
            and adapter_verifier.SHA256.fullmatch(digest) is not None
            for digest in value["source_locks"].values()
        )
        or value["normative_ledgers"] != runner.normative_ledger_digests()
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    verify_test_execution(value["test_execution"])
    verify_framework_probes(value["framework_probes"], adapter)
    verify_release_evidence(value["release_evidence"])
    verify_coverage(value["coverage"])
    test_execution = value["test_execution"]
    coverage = value["coverage"]
    if (
        not isinstance(test_execution, dict)
        or not isinstance(coverage, dict)
        or not isinstance(coverage.get("declared_cases"), dict)
        or coverage["declared_cases"].get("executable")
        != test_execution.get("declared_executable_case_count")
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    component = value["component"]
    requirement = adapter.get("component_requirement")
    if (
        not isinstance(component, dict)
        or set(component) != {"component_id", "repository", "release_ref", "commit"}
        or not isinstance(requirement, dict)
        or component.get("component_id") != requirement.get("component_id")
        or component.get("repository") != requirement.get("repository")
        or not isinstance(component.get("release_ref"), str)
        or re.fullmatch(
            r"reallyme-wallet-v(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
            component["release_ref"],
        )
        is None
        or not isinstance(component.get("commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", component["commit"]) is None
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    candidate = {
        "plan_id": value["plan_id"],
        "framework_version": value["framework_version"],
        "component": component,
        "release_artifact": {
            "artifact_id": "wallet-release-bundle",
            "kind": "archive",
            "sha256": value["release_artifact_sha256"],
        },
        "component_attestation_sha256": value["component_attestation_sha256"],
        "source_locks": value["source_locks"],
        "normative_ledgers": value["normative_ledgers"],
    }
    if value["candidate_sha256"] != runner.candidate_digest(candidate):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    expected_checks = expected_check_kinds(adapter)
    checks = value["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    observed_checks: set[str] = set()
    for raw_check in checks:
        if not isinstance(raw_check, dict) or set(raw_check) != {
            "check_id",
            "kind",
            "result",
        }:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        check_id = raw_check["check_id"]
        if (
            not isinstance(check_id, str)
            or check_id in observed_checks
            or raw_check["kind"] != expected_checks.get(check_id)
            or raw_check["result"] != "passed"
        ):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        observed_checks.add(check_id)
    if observed_checks != set(expected_checks):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    raw_plan_assertions = plan["assertions"]
    assertions = value["assertions"]
    if not isinstance(raw_plan_assertions, list) or not isinstance(assertions, list):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    expected_assertions = {
        assertion["assertion_id"]: assertion["required_checks"]
        for assertion in raw_plan_assertions
        if isinstance(assertion, dict)
    }
    if len(assertions) != len(expected_assertions):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    observed_assertions: set[str] = set()
    for raw_assertion in assertions:
        if not isinstance(raw_assertion, dict) or set(raw_assertion) != {
            "assertion_id",
            "check_ids",
            "result",
        }:
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        assertion_id = raw_assertion["assertion_id"]
        if (
            not isinstance(assertion_id, str)
            or assertion_id in observed_assertions
            or raw_assertion["check_ids"] != expected_assertions.get(assertion_id)
            or raw_assertion["result"] != "passed"
        ):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        observed_assertions.add(assertion_id)
    if observed_assertions != set(expected_assertions):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_result(adapter_verifier.load_object(args.result))
    except adapter_verifier.EudiWalletAdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.EudiWalletRunnerError as error:
        runner.fail(error.reason)
    print("EUDI Wallet execution result valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
