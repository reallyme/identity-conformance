#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the digest-bound EUDI Wallet engineering conformance lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_component_attestation as component_attestation  # noqa: E402
import verify_eudi_wallet_adapter as wallet_adapter  # noqa: E402


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 3_600


class EudiWalletRunnerErrorReason(Enum):
    INVALID_DEPLOYMENT = "invalid_deployment"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_ATTESTATION = "invalid_attestation"
    RESULT_PATH_EXISTS = "result_path_exists"
    RESULT_WRITE_FAILED = "result_write_failed"


@dataclass(frozen=True)
class EudiWalletRunnerError(Exception):
    reason: EudiWalletRunnerErrorReason


@dataclass(frozen=True)
class Check:
    check_id: str
    kind: str
    result: str


def fail(reason: EudiWalletRunnerErrorReason) -> NoReturn:
    print(f"EUDI Wallet conformance runner failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: EudiWalletRunnerErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EudiWalletRunnerError(reason)
    return value


def validate_deployment(
    value: dict[str, object], adapter: dict[str, object]
) -> dict[str, object]:
    exact_object(
        value,
        {
            "schema",
            "plan_id",
            "component",
            "release_artifact",
            "component_attestation_sha256",
            "source_locks",
            "evidence_policy",
        },
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        value["schema"] != "reallyme.identity.eudi_wallet_deployment_manifest.v1"
        or value["plan_id"] != "eudi-wallet-engineering-v1"
        or value["evidence_policy"] != wallet_adapter.EXPECTED_POLICY
        or not isinstance(value["component_attestation_sha256"], str)
        or wallet_adapter.SHA256.fullmatch(value["component_attestation_sha256"])
        is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    component = exact_object(
        value["component"],
        {"component_id", "repository", "commit"},
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    requirement = adapter.get("component_requirement")
    if (
        not isinstance(requirement, dict)
        or component.get("component_id") != requirement.get("component_id")
        or component.get("repository") != requirement.get("repository")
        or not isinstance(component.get("commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", component["commit"]) is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    artifact = exact_object(
        value["release_artifact"],
        {"artifact_id", "kind", "sha256"},
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        artifact["artifact_id"] != "wallet-release-bundle"
        or artifact["kind"] != "archive"
        or not isinstance(artifact["sha256"], str)
        or wallet_adapter.SHA256.fullmatch(artifact["sha256"]) is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    source_locks = exact_object(
        value["source_locks"],
        {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
        },
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if not all(
        isinstance(digest, str)
        and wallet_adapter.SHA256.fullmatch(digest) is not None
        for digest in source_locks.values()
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return artifact


def candidate_digest(deployment: dict[str, object]) -> str:
    candidate = {
        "plan_id": deployment["plan_id"],
        "component": deployment["component"],
        "release_artifact": deployment["release_artifact"],
        "component_attestation_sha256": deployment["component_attestation_sha256"],
        "source_locks": deployment["source_locks"],
    }
    encoded = json.dumps(
        candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hash_regular_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
        if not 1 <= metadata.st_size <= MAX_ARTIFACT_BYTES:
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT) from error


def verify_release_artifact(path: Path, expected_digest: str) -> str:
    observed_digest = hash_regular_file(path)
    if observed_digest != expected_digest:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
    return observed_digest


def verify_attestation(
    path: Path,
    expected_digest: str,
    expected_artifact_digest: str,
    expected_commit: str,
) -> set[str]:
    if hash_regular_file(path) != expected_digest:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    try:
        attestation = component_attestation.load_attestation(path)
        component_attestation.verify_attestation(attestation)
    except component_attestation.AttestationError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_ATTESTATION
        ) from error
    component = attestation["component"]
    artifacts = attestation["artifacts"]
    checks = attestation["checks"]
    if (
        component
        != {
            "component_id": "wallet",
            "repository": "https://github.com/reallyme/wallet",
            "source_commit": expected_commit,
        }
        or not isinstance(artifacts, list)
        or not any(
            isinstance(artifact, dict)
            and artifact.get("artifact_id") == "wallet-release-bundle"
            and artifact.get("sha256") == expected_artifact_digest
            for artifact in artifacts
        )
        or not isinstance(checks, list)
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    categories = {
        check["category"]
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("category"), str)
    }
    if not wallet_adapter.EXPECTED_ATTESTATION_CATEGORIES.issubset(categories):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    return categories


def execute_package(source: Path, package: str) -> bool:
    try:
        completed = subprocess.run(
            ["cargo", "test", "--locked", "-p", package, "--all-features"],
            cwd=source,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def write_result(output: Path, result: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".eudi-wallet-result-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.RESULT_WRITE_FAILED
        ) from error


def build_assertions(
    plan: dict[str, object], checks: list[Check]
) -> list[dict[str, object]]:
    check_results = {check.check_id: check.result for check in checks}
    raw_assertions = plan["assertions"]
    if not isinstance(raw_assertions, list):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    assertions: list[dict[str, object]] = []
    for raw_assertion in raw_assertions:
        if not isinstance(raw_assertion, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        assertion_id = raw_assertion.get("assertion_id")
        required_checks = raw_assertion.get("required_checks")
        if not isinstance(assertion_id, str) or not isinstance(required_checks, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        assertions.append(
            {
                "assertion_id": assertion_id,
                "check_ids": required_checks,
                "result": "passed"
                if all(check_results.get(check) == "passed" for check in required_checks)
                else "failed",
            }
        )
    return assertions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--release-artifact", required=True, type=Path)
    parser.add_argument("--component-attestation", required=True, type=Path)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan, adapter = wallet_adapter.load_contract()
        deployment = wallet_adapter.load_object(args.deployment_manifest)
        artifact = validate_deployment(deployment, adapter)
        source_locks = deployment["source_locks"]
        if not isinstance(source_locks, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        if (
            hash_regular_file(wallet_adapter.UPSTREAM_LOCK_PATH)
            != source_locks["eudi_sources_sha256"]
            or hash_regular_file(wallet_adapter.LEGAL_SOURCES_LOCK_PATH)
            != source_locks["eudi_legal_sources_sha256"]
            or hash_regular_file(wallet_adapter.PUBLICATIONS_LOCK_PATH)
            != source_locks["eudi_publications_sha256"]
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        if (
            re.fullmatch(r"[0-9a-f]{40}", args.framework_revision) is None
            or re.fullmatch(r"[0-9a-f]{40}", args.workflow_revision) is None
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        artifact_digest = verify_release_artifact(
            args.release_artifact, artifact["sha256"]
        )
        component = deployment["component"]
        if not isinstance(component, dict) or not isinstance(component.get("commit"), str):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        wallet_adapter.verify_checkout(args.source, adapter, component["commit"])
        categories = verify_attestation(
            args.component_attestation,
            deployment["component_attestation_sha256"],
            artifact_digest,
            component["commit"],
        )
        source_artifacts = adapter["source_artifacts"]
        if not isinstance(source_artifacts, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        checks = [
            Check(f"source.{artifact['artifact_id']}", "source", "passed")
            for artifact in source_artifacts
            if isinstance(artifact, dict) and isinstance(artifact.get("artifact_id"), str)
        ]
        if len(checks) != len(source_artifacts):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        checks.append(Check("artifact.wallet-release-bundle", "artifact", "passed"))
        checks.append(Check("framework.eudi-source-lock", "source", "passed"))
        checks.append(Check("framework.eudi-legal-source-lock", "source", "passed"))
        checks.append(Check("framework.eudi-publications-lock", "source", "passed"))
        for category in sorted(wallet_adapter.EXPECTED_ATTESTATION_CATEGORIES):
            checks.append(
                Check(
                    f"attestation.{category}",
                    "attestation",
                    "passed" if category in categories else "failed",
                )
            )
        packages = adapter["cargo_packages"]
        if not isinstance(packages, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        for package in packages:
            if not isinstance(package, str):
                raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
            checks.append(
                Check(
                    f"cargo.{package}",
                    "cargo",
                    "passed" if execute_package(args.source, package) else "failed",
                )
            )
        assertions = build_assertions(plan, checks)
        passed = all(check.result == "passed" for check in checks) and all(
            assertion["result"] == "passed" for assertion in assertions
        )
        result = {
            "schema": "reallyme.identity.eudi_wallet_execution_result.v1",
            "plan_id": "eudi-wallet-engineering-v1",
            "result": "passed" if passed else "failed",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "framework_revision": args.framework_revision,
            "workflow_revision": args.workflow_revision,
            "candidate_sha256": candidate_digest(deployment),
            "component": component,
            "release_artifact_sha256": artifact_digest,
            "component_attestation_sha256": deployment["component_attestation_sha256"],
            "source_locks": source_locks,
            "checks": [check.__dict__ for check in sorted(checks, key=lambda item: item.check_id)],
            "assertions": sorted(assertions, key=lambda item: str(item["assertion_id"])),
            "evidence_policy": wallet_adapter.EXPECTED_POLICY,
        }
        write_result(args.output, result)
        return 0 if passed else 1
    except wallet_adapter.EudiWalletAdapterError as error:
        wallet_adapter.fail(error.reason)
    except EudiWalletRunnerError as error:
        fail(error.reason)


if __name__ == "__main__":
    raise SystemExit(main())
