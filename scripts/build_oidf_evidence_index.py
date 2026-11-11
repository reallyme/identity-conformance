#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Create a bounded, content-addressed index for retained OIDF run evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit


MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARTIFACTS = 4096
READ_CHUNK_BYTES = 64 * 1024
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
INDEX_FILENAME = "evidence-index.json"
COMPONENT_LOCK_FILENAME = "components.lock.json"
DEPLOYMENT_MANIFEST_FILENAME = "deployment-manifest.json"


def fail(reason: str) -> NoReturn:
    print(reason, file=sys.stderr)
    raise SystemExit(65)


def hash_file(path: Path, maximum_bytes: int) -> tuple[str, int]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            fail("evidence_input_invalid")
        size = before.st_size
        if size < 0 or size > maximum_bytes:
            fail("evidence_input_size_invalid")
        digest = hashlib.sha256()
        observed = 0
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            handle = os.fdopen(descriptor, "rb")
        except OSError:
            os.close(descriptor)
            raise
        with handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or not stat.S_ISREG(opened.st_mode)
            ):
                fail("evidence_input_changed_while_hashing")
            while True:
                chunk = handle.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    fail("evidence_input_size_invalid")
                digest.update(chunk)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError:
        fail("evidence_input_unreadable")
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if observed != size or any(
        getattr(before, field) != getattr(after_open, field)
        or getattr(before, field) != getattr(after_path, field)
        for field in stable_fields
    ):
        fail("evidence_input_changed_while_hashing")
    return digest.hexdigest(), size


def collect_artifacts(result_root: Path) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    total_bytes = 0
    try:
        candidates = sorted(result_root.rglob("*"))
    except OSError:
        fail("evidence_directory_unreadable")
    for path in candidates:
        if path.name == INDEX_FILENAME and path.parent == result_root:
            continue
        if path.is_symlink():
            fail("evidence_symlink_rejected")
        if not path.is_file():
            continue
        if len(artifacts) >= MAX_ARTIFACTS:
            fail("evidence_artifact_count_exceeded")
        digest, size = hash_file(path, MAX_ARTIFACT_BYTES)
        total_bytes += size
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            fail("evidence_total_size_exceeded")
        artifacts.append(
            {
                "path": path.relative_to(result_root).as_posix(),
                "sha256": digest,
                "size_bytes": size,
            }
        )
    if not artifacts:
        fail("evidence_artifacts_missing")
    return artifacts


def input_digest(path: Path) -> dict[str, object]:
    digest, size = hash_file(path, MAX_INPUT_BYTES)
    return {"sha256": digest, "size_bytes": size}


def retained_artifact_digest(
    result_root: Path,
    input_path: Path,
    expected_filename: str,
    artifacts: list[dict[str, object]],
    failure_reason: str,
) -> dict[str, object]:
    expected = result_root / expected_filename
    try:
        if input_path.resolve(strict=True) != expected.resolve(strict=True):
            fail(failure_reason)
    except OSError:
        fail(failure_reason)
    matches = [
        artifact
        for artifact in artifacts
        if artifact.get("path") == expected_filename
    ]
    if len(matches) != 1:
        fail(failure_reason)
    return {
        "sha256": matches[0]["sha256"],
        "size_bytes": matches[0]["size_bytes"],
    }


def retained_deployment_digest(
    result_root: Path,
    deployment_manifest: Path,
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    return retained_artifact_digest(
        result_root,
        deployment_manifest,
        DEPLOYMENT_MANIFEST_FILENAME,
        artifacts,
        "deployment_manifest_not_retained",
    )


def retained_component_lock_digest(
    result_root: Path,
    component_lock: Path,
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    return retained_artifact_digest(
        result_root,
        component_lock,
        COMPONENT_LOCK_FILENAME,
        artifacts,
        "component_lock_not_retained",
    )


def deployment_endpoint(value: str) -> str:
    if (
        not value.isascii()
        or not value.startswith("https://")
        or len(value) > 2048
        or any(character.isspace() for character in value)
        or "\\" in value
    ):
        fail("deployment_endpoint_invalid")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        fail("deployment_endpoint_invalid")
    if (
        parsed.scheme != "https"
        or hostname is None
        or "@" in parsed.netloc
        or "%" in parsed.netloc
        or hostname.endswith(".")
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query != ""
        or parsed.fragment != ""
    ):
        fail("deployment_endpoint_invalid")
    return value


def write_new_index(index_path: Path, value: dict[str, object]) -> None:
    if index_path.exists() or index_path.is_symlink():
        fail("evidence_index_already_exists")
    try:
        descriptor = os.open(
            index_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        fail("evidence_index_write_failed")


def write_index(
    result_root: Path,
    suite_revision: str,
    component_lock: Path,
    deployment_manifest: Path,
    certification_plan: Path,
    profile_matrix: Path,
    verifier_config: Path,
    wallet_sd_jwt_config: Path,
    wallet_mdoc_config: Path,
    verifier_base_url: str,
    verifier_launch_endpoint: str,
    verifier_evidence_endpoint: str,
    verifier_health_endpoint: str,
    wallet_harness_endpoint: str,
    wallet_harness_health_endpoint: str,
) -> None:
    if GIT_COMMIT.fullmatch(suite_revision) is None:
        fail("suite_revision_invalid")
    index_path = result_root / INDEX_FILENAME
    artifacts = collect_artifacts(result_root)
    deployment_digest = retained_deployment_digest(
        result_root, deployment_manifest, artifacts
    )
    component_lock_digest = retained_component_lock_digest(
        result_root, component_lock, artifacts
    )
    value = {
        "schema_version": 1,
        "protocol": "openid4vp",
        "suite_revision": suite_revision,
        "inputs": {
            "component_lock": component_lock_digest,
            "deployment_manifest": deployment_digest,
            "certification_plan": input_digest(certification_plan),
            "openid4vp_profile_matrix": input_digest(profile_matrix),
            "verifier_config": input_digest(verifier_config),
            "wallet_sd_jwt_config": input_digest(wallet_sd_jwt_config),
            "wallet_mdoc_config": input_digest(wallet_mdoc_config),
        },
        "deployment": {
            "verifier_base_url": deployment_endpoint(verifier_base_url),
            "verifier_launch_endpoint": deployment_endpoint(verifier_launch_endpoint),
            "verifier_evidence_endpoint": deployment_endpoint(
                verifier_evidence_endpoint
            ),
            "verifier_health_endpoint": deployment_endpoint(verifier_health_endpoint),
            "wallet_harness_endpoint": deployment_endpoint(wallet_harness_endpoint),
            "wallet_harness_health_endpoint": deployment_endpoint(
                wallet_harness_health_endpoint
            ),
        },
        "artifacts": artifacts,
    }
    write_new_index(index_path, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", required=True, type=Path)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--component-lock", required=True, type=Path)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--certification-plan", required=True, type=Path)
    parser.add_argument("--profile-matrix", required=True, type=Path)
    parser.add_argument("--verifier-config", required=True, type=Path)
    parser.add_argument("--wallet-sd-jwt-config", required=True, type=Path)
    parser.add_argument("--wallet-mdoc-config", required=True, type=Path)
    parser.add_argument("--verifier-base-url", required=True)
    parser.add_argument("--verifier-launch-endpoint", required=True)
    parser.add_argument("--verifier-evidence-endpoint", required=True)
    parser.add_argument("--verifier-health-endpoint", required=True)
    parser.add_argument("--wallet-harness-endpoint", required=True)
    parser.add_argument("--wallet-harness-health-endpoint", required=True)
    args = parser.parse_args()
    if not args.result_root.is_dir() or args.result_root.is_symlink():
        fail("evidence_directory_invalid")
    write_index(
        args.result_root,
        args.suite_revision,
        args.component_lock,
        args.deployment_manifest,
        args.certification_plan,
        args.profile_matrix,
        args.verifier_config,
        args.wallet_sd_jwt_config,
        args.wallet_mdoc_config,
        args.verifier_base_url,
        args.verifier_launch_endpoint,
        args.verifier_evidence_endpoint,
        args.verifier_health_endpoint,
        args.wallet_harness_endpoint,
        args.wallet_harness_health_endpoint,
    )
    print("OIDF evidence index created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
