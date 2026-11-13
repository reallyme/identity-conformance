#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the closed shape and pass semantics of a ZK execution result."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_zk_conformance as runner  # noqa: E402
import verify_zk_adapter as adapter_verifier  # noqa: E402


TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


def verify_result(value: dict[str, object]) -> None:
    if set(value) != {
        "schema",
        "plan_id",
        "result",
        "created_at",
        "framework_revision",
        "workflow_revision",
        "candidate_sha256",
        "component",
        "release_artifact_sha256",
        "component_attestation_sha256",
        "linked_observation",
        "coverage",
        "checks",
        "assertions",
        "evidence_policy",
    }:
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    plan, adapter = adapter_verifier.load_contract()
    if (
        value["schema"] != "reallyme.identity.zk_execution_result.v2"
        or value["plan_id"] != "zk-presentation-proofs-v1"
        or value["result"] != "passed"
        or not isinstance(value["created_at"], str)
        or TIMESTAMP.fullmatch(value["created_at"]) is None
        or not isinstance(value["framework_revision"], str)
        or adapter_verifier.GIT_COMMIT.fullmatch(value["framework_revision"]) is None
        or not isinstance(value["workflow_revision"], str)
        or adapter_verifier.GIT_COMMIT.fullmatch(value["workflow_revision"]) is None
        or not isinstance(value["candidate_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["candidate_sha256"]) is None
        or value["evidence_policy"] != adapter_verifier.EXPECTED_POLICY
        or not isinstance(value["release_artifact_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(value["release_artifact_sha256"])
        is None
        or not isinstance(value["component_attestation_sha256"], str)
        or adapter_verifier.SHA256.fullmatch(
            value["component_attestation_sha256"]
        )
        is None
    ):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    component = value["component"]
    requirement = adapter.get("component_requirement")
    if (
        not isinstance(component, dict)
        or set(component)
        != {"component_id", "repository", "release_id", "release_ref", "commit"}
        or not isinstance(requirement, dict)
        or component.get("component_id") != requirement.get("component_id")
        or component.get("repository") != requirement.get("repository")
        or not isinstance(component.get("release_id"), int)
        or isinstance(component.get("release_id"), bool)
        or not 1 <= component["release_id"] <= 9_223_372_036_854_775_807
        or not isinstance(component.get("release_ref"), str)
        or re.fullmatch(
            r"reallyme-zk-v(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
            component["release_ref"],
        )
        is None
        or not isinstance(component.get("commit"), str)
        or adapter_verifier.GIT_COMMIT.fullmatch(component["commit"]) is None
    ):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    candidate = {
        "plan_id": value["plan_id"],
        "component": component,
        "release_artifact": {
            "artifact_id": "zk-release-bundle",
            "kind": "archive",
            "sha256": value["release_artifact_sha256"],
        },
        "component_attestation_sha256": value["component_attestation_sha256"],
    }
    if value["candidate_sha256"] != runner.candidate_digest(candidate):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    linked = value["linked_observation"]
    linked_enabled = linked is not None
    immutable_candidate_bound = False
    if linked_enabled:
        if not isinstance(linked, dict) or set(linked) != {
            "candidate_binding",
            "evidence_sha256",
            "product_component_bom_sha256",
            "probe_count",
            "proof_row_count",
        }:
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        candidate_binding = linked["candidate_binding"]
        bom_digest = linked["product_component_bom_sha256"]
        immutable_candidate_bound = candidate_binding == "immutable_release"
        if (
            candidate_binding not in {"working_tree_observation", "immutable_release"}
            or not isinstance(linked["evidence_sha256"], str)
            or adapter_verifier.SHA256.fullmatch(linked["evidence_sha256"]) is None
            or linked["probe_count"] != 11
            or linked["proof_row_count"] != 20
            or immutable_candidate_bound
            and (
                not isinstance(bom_digest, str)
                or adapter_verifier.SHA256.fullmatch(bom_digest) is None
            )
            or not immutable_candidate_bound
            and bom_digest is not None
        ):
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    coverage = value["coverage"]
    expected_coverage = {
        "assertion_count": 7,
        "independently_observed_assertion_count": 7 if linked_enabled else 0,
        "candidate_test_inventory_assertion_count": 0 if linked_enabled else 7,
        "immutable_candidate_bound": immutable_candidate_bound,
        "release_evidence_eligible": immutable_candidate_bound,
    }
    if coverage != expected_coverage:
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    expected_check_kinds = {
        "source.toolchain-lock": "source",
        "source.provider-manifest": "source",
        "source.cargo-lock": "source",
        "artifact.release-bundle": "artifact",
        **{
            f"attestation.{category}": "attestation"
            for category in adapter_verifier.EXPECTED_ATTESTATION_CATEGORIES
        },
        **{
            f"cargo.{package}": "cargo"
            for package in adapter_verifier.EXPECTED_PACKAGES
        },
    }
    if linked_enabled:
        expected_check_kinds.update(
            {
                probe_id: "observation"
                for probe_id in adapter_verifier.EXPECTED_LINKED_PROBES
            }
        )
    checks = value["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_check_kinds):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    observed_checks: set[str] = set()
    for raw_check in checks:
        if not isinstance(raw_check, dict) or set(raw_check) != {
            "check_id",
            "kind",
            "result",
        }:
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        check_id = raw_check["check_id"]
        if (
            not isinstance(check_id, str)
            or check_id in observed_checks
            or raw_check["kind"] != expected_check_kinds.get(check_id)
            or raw_check["result"] != "passed"
        ):
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        observed_checks.add(check_id)
    if observed_checks != set(expected_check_kinds):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    raw_plan_assertions = plan["assertions"]
    assertions = value["assertions"]
    if not isinstance(raw_plan_assertions, list) or not isinstance(assertions, list):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    expected_assertions = {
        assertion["assertion_id"]: list(assertion["required_checks"])
        for assertion in raw_plan_assertions
        if isinstance(assertion, dict)
    }
    if linked_enabled:
        for assertion_id, probe_ids in adapter_verifier.EXPECTED_ASSERTION_PROBES.items():
            expected_assertions[assertion_id].extend(sorted(probe_ids))
    if len(assertions) != len(expected_assertions):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    observed_assertions: set[str] = set()
    for raw_assertion in assertions:
        if not isinstance(raw_assertion, dict) or set(raw_assertion) != {
            "assertion_id",
            "check_ids",
            "evidence_strength",
            "result",
        }:
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        assertion_id = raw_assertion["assertion_id"]
        expected_strength = (
            "independently_observed_behavior"
            if linked_enabled
            else "candidate_test_inventory"
        )
        if (
            not isinstance(assertion_id, str)
            or assertion_id in observed_assertions
            or raw_assertion["check_ids"] != expected_assertions.get(assertion_id)
            or raw_assertion["evidence_strength"] != expected_strength
            or raw_assertion["result"] != "passed"
        ):
            raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        observed_assertions.add(assertion_id)
    if observed_assertions != set(expected_assertions):
        raise runner.ZkRunnerError(runner.ZkRunnerErrorReason.INVALID_DEPLOYMENT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_result(adapter_verifier.load_object(args.result))
    except adapter_verifier.ZkAdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.ZkRunnerError as error:
        runner.fail(error.reason)
    print("ZK execution result valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
