#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a deterministic digest manifest for a conformance release candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 16 * 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
FIXED_INPUTS = (
    "references/reallyme/trace-sources.lock.json",
    "references/normative-sources.lock.json",
    "references/eudi-publications.lock.json",
    "references/pin-policy.json",
    "references/etsi-eaa-pid/requirement-trace.json",
    "upstream/eudi/sources.lock.json",
    "upstream/eudi/legal-sources.lock.json",
    "upstream/oidf/conformance-suite.lock.json",
    "upstream/oidf/engineering-master.lock.json",
    "upstream/oidf/specifications.lock.json",
    "scripts/oidf-maven.Dockerfile",
    "scripts/oidf-runner-requirements.lock",
)
INPUT_GLOBS = (
    ".github/workflows/*.yml",
    "adapters/**/*",
    "plans/**/*.json",
    "schemas/*.json",
    "scripts/**/*",
    "upstream/oidf/snapshots/*.json",
)
IGNORED_INPUT_PARTS = {"__pycache__"}
IGNORED_INPUT_SUFFIXES = {".pyc", ".pyo"}


class ManifestError(Exception):
    """Raised when release inputs cannot be bound safely."""


@dataclass(frozen=True)
class InputDigest:
    path: str
    sha256: str
    size: int


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(65)


def release_inputs(root: Path = REPOSITORY_ROOT) -> list[Path]:
    paths = {root / relative_path for relative_path in FIXED_INPUTS}
    for pattern in INPUT_GLOBS:
        paths.update(
            candidate
            for candidate in root.glob(pattern)
            if (candidate.is_file() or candidate.is_symlink())
            and not IGNORED_INPUT_PARTS.intersection(candidate.relative_to(root).parts)
            and candidate.suffix not in IGNORED_INPUT_SUFFIXES
            and candidate.name != ".DS_Store"
        )
    if not paths:
        raise ManifestError("release input set is empty")
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def digest_input(path: Path, root: Path = REPOSITORY_ROOT) -> InputDigest:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise ManifestError("release input must be a regular file")
        if metadata.st_size < 1 or metadata.st_size > MAX_INPUT_BYTES:
            raise ManifestError("release input has an invalid size")
        content = path.read_bytes()
    except (OSError, ValueError) as error:
        raise ManifestError("release input is unavailable or unsafe") from error
    return InputDigest(
        path=path.relative_to(root).as_posix(),
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def aggregate_digest(inputs: list[InputDigest]) -> str:
    digest = hashlib.sha256()
    for item in inputs:
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(item.size).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_manifest(
    version: str, repository_commit: str, root: Path = REPOSITORY_ROOT
) -> dict[str, object]:
    if VERSION.fullmatch(version) is None:
        raise ManifestError("release version must be stable semantic versioning")
    if COMMIT.fullmatch(repository_commit) is None:
        raise ManifestError("repository commit must be a full lowercase Git commit")
    inputs = [digest_input(path, root) for path in release_inputs(root)]
    return {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.conformance_framework_release.v1",
        "release_kind": "framework",
        "release_version": version,
        "repository_commit": repository_commit,
        "input_set_sha256": aggregate_digest(inputs),
        "inputs": [asdict(item) for item in inputs],
    }


def validate_manifest(
    value: object,
    root: Path = REPOSITORY_ROOT,
    *,
    verify_repository_inputs: bool = True,
) -> dict[str, object]:
    expected_keys = {
        "$comment",
        "schema",
        "release_kind",
        "release_version",
        "repository_commit",
        "input_set_sha256",
        "inputs",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ManifestError("release manifest has an invalid shape")
    version = value["release_version"]
    repository_commit = value["repository_commit"]
    input_set_sha256 = value["input_set_sha256"]
    if (
        value["schema"] != "reallyme.identity.conformance_framework_release.v1"
        or value["release_kind"] != "framework"
        or not isinstance(value["$comment"], str)
        or not isinstance(version, str)
        or VERSION.fullmatch(version) is None
        or not isinstance(repository_commit, str)
        or COMMIT.fullmatch(repository_commit) is None
        or not isinstance(input_set_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", input_set_sha256) is None
        or not isinstance(value["inputs"], list)
        or not value["inputs"]
    ):
        raise ManifestError("release manifest metadata is invalid")

    inputs: list[InputDigest] = []
    observed_paths: set[str] = set()
    for raw_input in value["inputs"]:
        if not isinstance(raw_input, dict) or set(raw_input) != {"path", "sha256", "size"}:
            raise ManifestError("release manifest input has an invalid shape")
        path = raw_input["path"]
        sha256 = raw_input["sha256"]
        size = raw_input["size"]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or path in observed_paths
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= MAX_INPUT_BYTES
        ):
            raise ManifestError("release manifest input is invalid")
        observed_paths.add(path)
        inputs.append(InputDigest(path=path, sha256=sha256, size=size))
    if [item.path for item in inputs] != sorted(observed_paths):
        raise ManifestError("release manifest inputs are not canonical")
    if aggregate_digest(inputs) != input_set_sha256:
        raise ManifestError("release manifest aggregate digest is invalid")
    if verify_repository_inputs:
        expected = [digest_input(path, root) for path in release_inputs(root)]
        if inputs != expected:
            raise ManifestError("release manifest does not bind this framework checkout")
    return value


def write_manifest(output: Path, manifest: dict[str, object]) -> None:
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        content = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".release-manifest-", delete=False
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise ManifestError("release manifest could not be written") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.version, args.repository_commit)
        write_manifest(args.output, manifest)
    except ManifestError as error:
        fail(str(error))
    print(f"wrote conformance release manifest to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
