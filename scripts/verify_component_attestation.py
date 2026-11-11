#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a component attestation before it enters a composed release run."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"
)
SOURCE_REF = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
TOOLCHAIN_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
REPOSITORY = re.compile(r"^https://github\.com/reallyme/[A-Za-z0-9_.-]+$")
ARTIFACT_KINDS = {
    "binary",
    "oci_image",
    "archive",
    "package",
    "circuit_artifact",
    "metadata",
}
LOCK_KINDS = {"cargo", "npm", "mixed", "other"}
CHECK_CATEGORIES = {
    "format",
    "lint",
    "unit",
    "integration",
    "property",
    "fuzz",
    "vector",
    "security",
    "build",
}
MAX_ATTESTATION_BYTES = 256 * 1024


class AttestationErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_COMPONENT = "invalid_component"
    INVALID_RELEASE = "invalid_release"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_DEPENDENCY_LOCK = "invalid_dependency_lock"
    INVALID_TOOLCHAIN = "invalid_toolchain"
    INVALID_CHECK = "invalid_check"
    INVALID_EVIDENCE_POLICY = "invalid_evidence_policy"


@dataclass(frozen=True)
class AttestationError(Exception):
    reason: AttestationErrorReason


def fail(reason: AttestationErrorReason) -> NoReturn:
    print(f"component attestation invalid: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: AttestationErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AttestationError(reason)
    return value


def verify_attestation(value: dict[str, object]) -> None:
    exact_object(
        value,
        {
            "schema",
            "classification",
            "component",
            "release",
            "artifacts",
            "dependency_lock",
            "toolchain",
            "checks",
            "created_at",
            "evidence_policy",
        },
        AttestationErrorReason.INVALID_JSON,
    )
    if (
        value["schema"] != "reallyme.identity.component_attestation.v1"
        or value["classification"] != "internal"
        or not isinstance(value["created_at"], str)
        or TIMESTAMP.fullmatch(value["created_at"]) is None
    ):
        raise AttestationError(AttestationErrorReason.INVALID_JSON)
    component = exact_object(
        value["component"],
        {"component_id", "repository", "source_commit"},
        AttestationErrorReason.INVALID_COMPONENT,
    )
    if (
        not isinstance(component["component_id"], str)
        or IDENTIFIER.fullmatch(component["component_id"]) is None
        or not isinstance(component["repository"], str)
        or REPOSITORY.fullmatch(component["repository"]) is None
        or not isinstance(component["source_commit"], str)
        or GIT_COMMIT.fullmatch(component["source_commit"]) is None
    ):
        raise AttestationError(AttestationErrorReason.INVALID_COMPONENT)
    release = exact_object(
        value["release"],
        {"version", "source_ref"},
        AttestationErrorReason.INVALID_RELEASE,
    )
    if (
        not isinstance(release["version"], str)
        or SEMVER.fullmatch(release["version"]) is None
        or not isinstance(release["source_ref"], str)
        or SOURCE_REF.fullmatch(release["source_ref"]) is None
        or ".." in release["source_ref"]
        or release["source_ref"].startswith("/")
        or release["source_ref"].endswith("/")
        or "//" in release["source_ref"]
    ):
        raise AttestationError(AttestationErrorReason.INVALID_RELEASE)
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
        raise AttestationError(AttestationErrorReason.INVALID_ARTIFACT)
    artifact_ids: set[str] = set()
    for raw_artifact in artifacts:
        artifact = exact_object(
            raw_artifact,
            {"artifact_id", "kind", "sha256"},
            AttestationErrorReason.INVALID_ARTIFACT,
        )
        artifact_id = artifact["artifact_id"]
        if (
            not isinstance(artifact_id, str)
            or IDENTIFIER.fullmatch(artifact_id) is None
            or artifact_id in artifact_ids
            or artifact["kind"] not in ARTIFACT_KINDS
            or not isinstance(artifact["sha256"], str)
            or SHA256.fullmatch(artifact["sha256"]) is None
        ):
            raise AttestationError(AttestationErrorReason.INVALID_ARTIFACT)
        artifact_ids.add(artifact_id)
    dependency_lock = exact_object(
        value["dependency_lock"],
        {"kind", "sha256"},
        AttestationErrorReason.INVALID_DEPENDENCY_LOCK,
    )
    if (
        dependency_lock["kind"] not in LOCK_KINDS
        or not isinstance(dependency_lock["sha256"], str)
        or SHA256.fullmatch(dependency_lock["sha256"]) is None
    ):
        raise AttestationError(AttestationErrorReason.INVALID_DEPENDENCY_LOCK)
    toolchain = exact_object(
        value["toolchain"],
        {"identifier", "version"},
        AttestationErrorReason.INVALID_TOOLCHAIN,
    )
    if (
        not isinstance(toolchain["identifier"], str)
        or IDENTIFIER.fullmatch(toolchain["identifier"]) is None
        or not isinstance(toolchain["version"], str)
        or TOOLCHAIN_VERSION.fullmatch(toolchain["version"]) is None
    ):
        raise AttestationError(AttestationErrorReason.INVALID_TOOLCHAIN)
    checks = value["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 256:
        raise AttestationError(AttestationErrorReason.INVALID_CHECK)
    check_ids: set[str] = set()
    for raw_check in checks:
        check = exact_object(
            raw_check,
            {"check_id", "category", "result", "evidence_sha256"},
            AttestationErrorReason.INVALID_CHECK,
        )
        check_id = check["check_id"]
        if (
            not isinstance(check_id, str)
            or IDENTIFIER.fullmatch(check_id) is None
            or check_id in check_ids
            or check["category"] not in CHECK_CATEGORIES
            or check["result"] != "passed"
            or not isinstance(check["evidence_sha256"], str)
            or SHA256.fullmatch(check["evidence_sha256"]) is None
        ):
            raise AttestationError(AttestationErrorReason.INVALID_CHECK)
        check_ids.add(check_id)
    policy = exact_object(
        value["evidence_policy"],
        {
            "contains_sensitive_data",
            "raw_process_output_retained",
            "credentials_retained",
            "private_key_material_retained",
        },
        AttestationErrorReason.INVALID_EVIDENCE_POLICY,
    )
    if any(item is not False for item in policy.values()):
        raise AttestationError(AttestationErrorReason.INVALID_EVIDENCE_POLICY)


def load_attestation(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= MAX_ATTESTATION_BYTES
        ):
            raise AttestationError(AttestationErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise AttestationError(AttestationErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise AttestationError(AttestationErrorReason.INVALID_JSON)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_attestation(load_attestation(args.attestation))
    except AttestationError as error:
        fail(error.reason)
    print("component attestation valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
