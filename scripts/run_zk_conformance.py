#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the digest-bound ZK presentation-proof conformance lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
import verify_zk_adapter as zk_adapter  # noqa: E402


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 3_600


class ZkRunnerErrorReason(Enum):
    INVALID_DEPLOYMENT = "invalid_deployment"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_ATTESTATION = "invalid_attestation"
    RESULT_PATH_EXISTS = "result_path_exists"
    RESULT_WRITE_FAILED = "result_write_failed"


@dataclass(frozen=True)
class ZkRunnerError(Exception):
    reason: ZkRunnerErrorReason


@dataclass(frozen=True)
class Check:
    check_id: str
    kind: str
    result: str


def fail(reason: ZkRunnerErrorReason) -> NoReturn:
    print(f"ZK conformance runner failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: ZkRunnerErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ZkRunnerError(reason)
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
            "evidence_policy",
        },
        ZkRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        value["schema"] != "reallyme.identity.zk_deployment_manifest.v1"
        or value["plan_id"] != "zk-presentation-proofs-v1"
        or value["component"] != adapter["component"]
        or value["evidence_policy"] != zk_adapter.EXPECTED_POLICY
        or not isinstance(value["component_attestation_sha256"], str)
        or zk_adapter.SHA256.fullmatch(value["component_attestation_sha256"])
        is None
    ):
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    artifact = exact_object(
        value["release_artifact"],
        {"artifact_id", "kind", "sha256"},
        ZkRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        artifact["artifact_id"] != "zk-release-bundle"
        or artifact["kind"] != "archive"
        or not isinstance(artifact["sha256"], str)
        or zk_adapter.SHA256.fullmatch(artifact["sha256"]) is None
    ):
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
    return artifact


def hash_regular_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ARTIFACT)
        if not 1 <= metadata.st_size <= MAX_ARTIFACT_BYTES:
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ARTIFACT)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ARTIFACT) from error


def verify_attestation(
    path: Path,
    expected_digest: str,
    expected_artifact_digest: str,
    expected_commit: str,
) -> set[str]:
    if hash_regular_file(path) != expected_digest:
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ATTESTATION)
    try:
        attestation = component_attestation.load_attestation(path)
        component_attestation.verify_attestation(attestation)
    except component_attestation.AttestationError as error:
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ATTESTATION) from error
    component = attestation["component"]
    artifacts = attestation["artifacts"]
    checks = attestation["checks"]
    if (
        not isinstance(component, dict)
        or component
        != {
            "component_id": "zk",
            "repository": "https://github.com/reallyme/zk",
            "source_commit": expected_commit,
        }
        or not isinstance(artifacts, list)
        or not any(
            isinstance(artifact, dict)
            and artifact.get("artifact_id") == "zk-release-bundle"
            and artifact.get("sha256") == expected_artifact_digest
            for artifact in artifacts
        )
        or not isinstance(checks, list)
    ):
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ATTESTATION)
    categories = {
        check["category"]
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("category"), str)
    }
    if not zk_adapter.EXPECTED_ATTESTATION_CATEGORIES.issubset(categories):
        raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ATTESTATION)
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
        raise ZkRunnerError(ZkRunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".zk-result-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise ZkRunnerError(ZkRunnerErrorReason.RESULT_WRITE_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--release-artifact", required=True, type=Path)
    parser.add_argument("--component-attestation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan, adapter = zk_adapter.load_contract()
        deployment = zk_adapter.load_object(args.deployment_manifest)
        artifact = validate_deployment(deployment, adapter)
        zk_adapter.verify_checkout(args.source, adapter)
        artifact_digest = hash_regular_file(args.release_artifact)
        if artifact_digest != artifact["sha256"]:
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_ARTIFACT)
        component = deployment["component"]
        if not isinstance(component, dict) or not isinstance(component.get("commit"), str):
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        categories = verify_attestation(
            args.component_attestation,
            deployment["component_attestation_sha256"],
            artifact_digest,
            component["commit"],
        )
        checks = [
            Check("source.toolchain-lock", "source", "passed"),
            Check("source.provider-manifest", "source", "passed"),
            Check("source.cargo-lock", "source", "passed"),
            Check("artifact.release-bundle", "artifact", "passed"),
        ]
        for category in sorted(zk_adapter.EXPECTED_ATTESTATION_CATEGORIES):
            checks.append(
                Check(
                    f"attestation.{category}",
                    "attestation",
                    "passed" if category in categories else "failed",
                )
            )
        packages = adapter["cargo_packages"]
        if not isinstance(packages, list):
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        for package in packages:
            if not isinstance(package, str):
                raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
            checks.append(
                Check(
                    f"cargo.{package}",
                    "cargo",
                    "passed" if execute_package(args.source, package) else "failed",
                )
            )
        check_results = {check.check_id: check.result for check in checks}
        raw_assertions = plan["assertions"]
        if not isinstance(raw_assertions, list):
            raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
        assertions: list[dict[str, object]] = []
        for raw_assertion in raw_assertions:
            if not isinstance(raw_assertion, dict):
                raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
            required_checks = raw_assertion.get("required_checks")
            assertion_id = raw_assertion.get("assertion_id")
            if not isinstance(required_checks, list) or not isinstance(assertion_id, str):
                raise ZkRunnerError(ZkRunnerErrorReason.INVALID_DEPLOYMENT)
            assertions.append(
                {
                    "assertion_id": assertion_id,
                    "check_ids": required_checks,
                    "result": "passed"
                    if all(check_results.get(check) == "passed" for check in required_checks)
                    else "failed",
                }
            )
        passed = all(check.result == "passed" for check in checks) and all(
            assertion["result"] == "passed" for assertion in assertions
        )
        result = {
            "schema": "reallyme.identity.zk_execution_result.v1",
            "plan_id": "zk-presentation-proofs-v1",
            "result": "passed" if passed else "failed",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "component": component,
            "release_artifact_sha256": artifact_digest,
            "component_attestation_sha256": deployment[
                "component_attestation_sha256"
            ],
            "checks": [check.__dict__ for check in sorted(checks, key=lambda item: item.check_id)],
            "assertions": sorted(assertions, key=lambda item: str(item["assertion_id"])),
            "evidence_policy": zk_adapter.EXPECTED_POLICY,
        }
        write_result(args.output, result)
        return 0 if passed else 1
    except zk_adapter.ZkAdapterError as error:
        zk_adapter.fail(error.reason)
    except ZkRunnerError as error:
        fail(error.reason)


if __name__ == "__main__":
    raise SystemExit(main())
