#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the ZK plan, adapter, source baseline, and immutable source files."""

from __future__ import annotations

import argparse
import re
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
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise ZkAdapterError(ZkAdapterErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
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
            "evidence_policy",
        },
        ZkAdapterErrorReason.INVALID_PLAN,
    )
    if (
        plan["schema_version"] != 1
        or plan["plan_id"] != "zk-presentation-proofs-v1"
        or plan["execution_status"] != "executable"
        or plan["certification_claim"] is not False
        or plan["evidence_policy"] != EXPECTED_POLICY
    ):
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
    if plan["required_components"] != [
        {"component_id": "zk", "repository": "https://github.com/reallyme/zk"}
    ]:
        raise ZkAdapterError(ZkAdapterErrorReason.INVALID_PLAN)
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
