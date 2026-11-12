#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify that a framework checkout is an exact published release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import build_release_manifest as release_manifest  # noqa: E402
import strict_json  # noqa: E402


MAX_INPUT_BYTES = 16 * 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PublishedReleaseErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    CHECKOUT_MISMATCH = "checkout_mismatch"
    RELEASE_METADATA_INVALID = "release_metadata_invalid"
    RELEASE_TAG_MISMATCH = "release_tag_mismatch"
    RELEASE_MANIFEST_INVALID = "release_manifest_invalid"
    OUTPUT_FAILED = "output_failed"


@dataclass(frozen=True)
class PublishedReleaseError(Exception):
    reason: PublishedReleaseErrorReason


def fail(reason: PublishedReleaseErrorReason) -> NoReturn:
    print(f"published framework release verification failed: {reason.value}", file=sys.stderr)
    raise SystemExit(65)


def read_regular_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
        if not 1 <= before.st_size <= MAX_INPUT_BYTES:
            raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
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
                raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
            content = handle.read(MAX_INPUT_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as error:
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID) from error
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        len(content) != before.st_size
        or len(content) > MAX_INPUT_BYTES
        or any(
            getattr(before, field) != getattr(after_open, field)
            or getattr(before, field) != getattr(after_path, field)
            for field in stable_fields
        )
    ):
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
    return content


def read_object(path: Path) -> dict[str, object]:
    try:
        value = strict_json.loads(read_regular_bytes(path).decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID) from error
    if not isinstance(value, dict):
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
    return value


def verify_release(
    framework_root: Path,
    expected_commit: str,
    release_metadata_path: Path,
    tag_commit: str,
    manifest_path: Path,
) -> dict[str, object]:
    if COMMIT.fullmatch(expected_commit) is None or COMMIT.fullmatch(tag_commit) is None:
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
    try:
        root_metadata = framework_root.lstat()
        if framework_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID)
        version = release_manifest.read_release_version(framework_root)
    except (OSError, release_manifest.ManifestError) as error:
        raise PublishedReleaseError(PublishedReleaseErrorReason.INPUT_INVALID) from error

    release = read_object(release_metadata_path)
    expected_tag = f"v{version}"
    if (
        release.get("tag_name") != expected_tag
        or release.get("target_commitish") != expected_commit
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("html_url"), str)
        or release.get("html_url")
        != f"https://github.com/reallyme/identity-conformance/releases/tag/{expected_tag}"
    ):
        raise PublishedReleaseError(
            PublishedReleaseErrorReason.RELEASE_METADATA_INVALID
        )
    if tag_commit != expected_commit:
        raise PublishedReleaseError(PublishedReleaseErrorReason.RELEASE_TAG_MISMATCH)

    manifest_bytes = read_regular_bytes(manifest_path)
    try:
        raw_manifest = strict_json.loads(manifest_bytes.decode("utf-8"))
        manifest = release_manifest.validate_manifest(raw_manifest, framework_root)
        rebuilt = release_manifest.build_manifest(expected_commit, framework_root)
    except (
        UnicodeError,
        strict_json.StrictJsonError,
        release_manifest.ManifestError,
    ) as error:
        raise PublishedReleaseError(
            PublishedReleaseErrorReason.RELEASE_MANIFEST_INVALID
        ) from error
    if (
        manifest != rebuilt
        or manifest.get("release_version") != version
        or manifest.get("repository_commit") != expected_commit
        or not isinstance(manifest.get("input_set_sha256"), str)
        or SHA256.fullmatch(manifest["input_set_sha256"]) is None
    ):
        raise PublishedReleaseError(
            PublishedReleaseErrorReason.RELEASE_MANIFEST_INVALID
        )

    return {
        "schema": "reallyme.identity.published_framework_selection.v1",
        "release_version": version,
        "release_tag": expected_tag,
        "release_url": release["html_url"],
        "repository_commit": expected_commit,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "input_set_sha256": manifest["input_set_sha256"],
    }


def write_output(path: Path, value: dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".framework-selection-", delete=False
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as error:
        raise PublishedReleaseError(PublishedReleaseErrorReason.OUTPUT_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--release-metadata", required=True, type=Path)
    parser.add_argument("--tag-commit", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        selection = verify_release(
            args.framework_root,
            args.expected_commit,
            args.release_metadata,
            args.tag_commit,
            args.manifest,
        )
        write_output(args.output, selection)
    except PublishedReleaseError as error:
        fail(error.reason)
    print("published Identity Conformance release verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
