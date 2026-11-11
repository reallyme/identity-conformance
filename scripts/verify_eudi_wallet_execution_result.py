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
import verify_eudi_wallet_adapter as adapter_verifier  # noqa: E402


TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


def expected_check_kinds(adapter: dict[str, object]) -> dict[str, str]:
    artifacts = adapter["source_artifacts"]
    packages = adapter["cargo_packages"]
    if not isinstance(artifacts, list) or not isinstance(packages, list):
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
    package_checks: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, str):
            raise runner.EudiWalletRunnerError(
                runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        package_checks[f"cargo.{package}"] = "cargo"
    return {
        **source_checks,
        "artifact.wallet-release-bundle": "artifact",
        "framework.eudi-source-lock": "source",
        "framework.eudi-legal-source-lock": "source",
        "framework.eudi-publications-lock": "source",
        **{
            f"attestation.{category}": "attestation"
            for category in adapter_verifier.EXPECTED_ATTESTATION_CATEGORIES
        },
        **package_checks,
    }


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
        "source_locks",
        "checks",
        "assertions",
        "evidence_policy",
    }:
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    plan, adapter = adapter_verifier.load_contract()
    if (
        value["schema"] != "reallyme.identity.eudi_wallet_execution_result.v1"
        or value["plan_id"] != "eudi-wallet-engineering-v1"
        or value["result"] != "passed"
        or not isinstance(value["created_at"], str)
        or TIMESTAMP.fullmatch(value["created_at"]) is None
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
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    component = value["component"]
    requirement = adapter.get("component_requirement")
    if (
        not isinstance(component, dict)
        or set(component) != {"component_id", "repository", "commit"}
        or not isinstance(requirement, dict)
        or component.get("component_id") != requirement.get("component_id")
        or component.get("repository") != requirement.get("repository")
        or not isinstance(component.get("commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", component["commit"]) is None
    ):
        raise runner.EudiWalletRunnerError(
            runner.EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        )
    candidate = {
        "plan_id": value["plan_id"],
        "component": component,
        "release_artifact": {
            "artifact_id": "wallet-release-bundle",
            "kind": "archive",
            "sha256": value["release_artifact_sha256"],
        },
        "component_attestation_sha256": value["component_attestation_sha256"],
        "source_locks": value["source_locks"],
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
