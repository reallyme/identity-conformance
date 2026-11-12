#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify the contents and source binding of a Wallet release-evidence bundle."""

from __future__ import annotations

import hashlib
import io
import os
import re
import sys
import tarfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_MEMBERS = 256
MAX_MANIFEST_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_CRATE_BYTES = 64 * 1024 * 1024
MAX_CRATE_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_CRATE_MEMBERS = 20_000
MAX_CRATE_MEMBER_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CRATE_NAME = re.compile(r"^reallyme-wallet(?:-[a-z0-9][a-z0-9-]{0,63})?$")
CRATE_FILE_NAME = re.compile(
    r"^reallyme-wallet(?:-[a-z0-9][a-z0-9-]{0,63})?-"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.crate$"
)
EXPECTED_EVIDENCE_STEPS: dict[str, tuple[str, ...]] = {
    "format": ("Check formatting",),
    "lint": ("Clippy",),
    "unit": ("Test all features",),
    "integration": ("Test all features",),
    "vector": (
        "Check protobuf boundaries and generated source",
        "Test all features",
    ),
    "security": ("Check dependency policy", "Security advisory audit"),
    "build": (
        "Inspect normalized crate tarballs and dry-run publication",
        "Check Identity Wasm participant lane",
    ),
}


class WalletReleaseBundleErrorReason(Enum):
    INVALID_BUNDLE = "invalid_bundle"
    INVALID_MANIFEST = "invalid_manifest"
    INVALID_EVIDENCE = "invalid_evidence"
    INVALID_CRATE = "invalid_crate"
    SOURCE_MISMATCH = "source_mismatch"


@dataclass(frozen=True)
class WalletReleaseBundleError(Exception):
    reason: WalletReleaseBundleErrorReason


@dataclass(frozen=True)
class VerifiedWalletReleaseBundle:
    preflight_run_id: int
    preflight_job_id: int
    fuzz_run_id: int
    protobuf_ci_run_id: int
    rust_ci_run_id: int
    crate_count: int
    crate_inventory_sha256: str
    evidence_count: int
    evidence_inventory_sha256: str
    cargo_lock_sha256: str


def exact_object(
    value: object, keys: set[str], reason: WalletReleaseBundleErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WalletReleaseBundleError(reason)
    return value


def digest_entries(entries: list[str]) -> str:
    payload = "".join(f"{entry}\n" for entry in sorted(entries)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def regular_file_digest(path: Path, maximum: int) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= maximum:
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.INVALID_BUNDLE
            )
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_BUNDLE
        ) from error


def safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and "\\" not in name
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def read_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    maximum: int,
    reason: WalletReleaseBundleErrorReason,
) -> bytes:
    if not member.isreg() or not 1 <= member.size <= maximum:
        raise WalletReleaseBundleError(reason)
    try:
        extracted = archive.extractfile(member)
        if extracted is None:
            raise WalletReleaseBundleError(reason)
        with extracted:
            content = extracted.read(maximum + 1)
    except (OSError, tarfile.TarError) as error:
        raise WalletReleaseBundleError(reason) from error
    if len(content) != member.size:
        raise WalletReleaseBundleError(reason)
    return content


def parse_json(content: bytes, reason: WalletReleaseBundleErrorReason) -> object:
    try:
        return strict_json.loads(content.decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise WalletReleaseBundleError(reason) from error


def materialize_attestation_subjects(
    path: Path, output_directory: Path, expected_crate_count: int
) -> list[Path]:
    """Write only the preflight manifest and crate subjects for provenance checks."""
    if not 1 <= expected_crate_count <= 128:
        raise WalletReleaseBundleError(WalletReleaseBundleErrorReason.INVALID_BUNDLE)
    regular_file_digest(path, MAX_BUNDLE_BYTES)
    if output_directory.exists() or output_directory.is_symlink():
        raise WalletReleaseBundleError(WalletReleaseBundleErrorReason.INVALID_BUNDLE)
    created: list[Path] = []
    try:
        output_directory.mkdir(mode=0o700, parents=False)
        with tarfile.open(path, mode="r:") as archive:
            members: list[tarfile.TarInfo] = []
            for member in archive:
                if len(members) >= MAX_BUNDLE_MEMBERS:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_BUNDLE
                    )
                members.append(member)
            names: set[str] = set()
            subjects: list[tuple[str, bytes]] = []
            evidence_names = {
                f"evidence-{category}.json" for category in EXPECTED_EVIDENCE_STEPS
            }
            for member in members:
                if (
                    not safe_member_name(member.name)
                    or member.name in names
                    or not member.isreg()
                ):
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_BUNDLE
                    )
                names.add(member.name)
                if member.name == "crates-preflight.json":
                    subjects.append(
                        (
                            member.name,
                            read_member(
                                archive,
                                member,
                                MAX_MANIFEST_BYTES,
                                WalletReleaseBundleErrorReason.INVALID_BUNDLE,
                            ),
                        )
                    )
                elif CRATE_FILE_NAME.fullmatch(member.name) is not None:
                    subjects.append(
                        (
                            member.name,
                            read_member(
                                archive,
                                member,
                                MAX_CRATE_BYTES,
                                WalletReleaseBundleErrorReason.INVALID_BUNDLE,
                            ),
                        )
                    )
                elif member.name not in evidence_names:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_BUNDLE
                    )
            subject_names = {name for name, _content in subjects}
            crate_names = {
                name
                for name in subject_names
                if CRATE_FILE_NAME.fullmatch(name) is not None
            }
            if (
                len(subject_names) != len(subjects)
                or "crates-preflight.json" not in subject_names
                or len(crate_names) != expected_crate_count
                or names
                != subject_names.union(evidence_names)
            ):
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_BUNDLE
                )
            for name, content in sorted(subjects):
                destination = output_directory / name
                descriptor = os.open(
                    destination,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                created.append(destination)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                except BaseException:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    raise
        return created
    except WalletReleaseBundleError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_BUNDLE
        ) from error
    finally:
        if sys.exc_info()[0] is not None:
            for created_path in created:
                try:
                    created_path.unlink()
                except OSError:
                    pass
            try:
                output_directory.rmdir()
            except OSError:
                pass


def verify_crate_source_binding(
    content: bytes, crate_name: str, version: str, expected_commit: str
) -> None:
    expected_root = f"{crate_name}-{version}"
    vcs_name = f"{expected_root}/.cargo_vcs_info.json"
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            members: list[tarfile.TarInfo] = []
            for member in archive:
                if len(members) >= MAX_CRATE_MEMBERS:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_CRATE
                    )
                members.append(member)
            if not members:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_CRATE
                )
            names: set[str] = set()
            unpacked = 0
            vcs_member: tarfile.TarInfo | None = None
            for member in members:
                if (
                    not safe_member_name(member.name)
                    or member.name in names
                    or PurePosixPath(member.name).parts[0] != expected_root
                    or not (member.isdir() or member.isreg())
                ):
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_CRATE
                    )
                names.add(member.name)
                if member.isreg():
                    if not 0 <= member.size <= MAX_CRATE_MEMBER_BYTES:
                        raise WalletReleaseBundleError(
                            WalletReleaseBundleErrorReason.INVALID_CRATE
                        )
                    unpacked += member.size
                    if unpacked > MAX_CRATE_UNPACKED_BYTES:
                        raise WalletReleaseBundleError(
                            WalletReleaseBundleErrorReason.INVALID_CRATE
                        )
                if member.name == vcs_name:
                    vcs_member = member
            if vcs_member is None:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.SOURCE_MISMATCH
                )
            vcs = exact_object(
                parse_json(
                    read_member(
                        archive,
                        vcs_member,
                        MAX_EVIDENCE_BYTES,
                        WalletReleaseBundleErrorReason.INVALID_CRATE,
                    ),
                    WalletReleaseBundleErrorReason.INVALID_CRATE,
                ),
                {"git", "path_in_vcs"},
                WalletReleaseBundleErrorReason.INVALID_CRATE,
            )
            git = exact_object(
                vcs["git"],
                {"sha1"},
                WalletReleaseBundleErrorReason.INVALID_CRATE,
            )
            if git["sha1"] != expected_commit or not isinstance(vcs["path_in_vcs"], str):
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.SOURCE_MISMATCH
                )
    except WalletReleaseBundleError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_CRATE
        ) from error


def verify_manifest(
    value: object,
    expected_commit: str,
    expected_version: str,
    expected_packages: dict[str, str],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    manifest = exact_object(
        value,
        {
            "schema",
            "repository",
            "workflow",
            "run_id",
            "run_attempt",
            "release_sha",
            "version",
            "crates",
            "prerequisites",
        },
        WalletReleaseBundleErrorReason.INVALID_MANIFEST,
    )
    if (
        manifest["schema"] != "reallyme.wallet.crates_preflight.v3"
        or manifest["repository"] != "reallyme/wallet"
        or manifest["workflow"] != "crates-package-preflight.yml"
        or type(manifest["run_id"]) is not int
        or manifest["run_id"] < 1
        or manifest["run_attempt"] != 1
        or manifest["release_sha"] != expected_commit
        or manifest["version"] != expected_version
    ):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_MANIFEST
        )
    prerequisites = exact_object(
        manifest["prerequisites"],
        {"fuzz", "protobuf_ci", "rust_ci"},
        WalletReleaseBundleErrorReason.INVALID_MANIFEST,
    )
    if any(type(run_id) is not int or run_id < 1 for run_id in prerequisites.values()):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_MANIFEST
        )
    crates = manifest["crates"]
    if not isinstance(crates, list) or len(crates) != len(expected_packages):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )
    expected_names = sorted(expected_packages)
    observed_names: list[str] = []
    validated: list[dict[str, object]] = []
    for raw_crate in crates:
        crate = exact_object(
            raw_crate,
            {"file", "sha256", "size"},
            WalletReleaseBundleErrorReason.INVALID_MANIFEST,
        )
        file_name = crate["file"]
        suffix = f"-{expected_version}.crate"
        if (
            not isinstance(file_name, str)
            or not file_name.endswith(suffix)
            or "/" in file_name
            or "\\" in file_name
            or not isinstance(crate["sha256"], str)
            or SHA256.fullmatch(crate["sha256"]) is None
            or type(crate["size"]) is not int
            or not 1 <= crate["size"] <= MAX_CRATE_BYTES
        ):
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.INVALID_MANIFEST
            )
        name = file_name[: -len(suffix)]
        if CRATE_NAME.fullmatch(name) is None or expected_packages.get(name) != expected_version:
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.SOURCE_MISMATCH
            )
        observed_names.append(name)
        validated.append(crate)
    if observed_names != expected_names or len(set(observed_names)) != len(observed_names):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )
    return manifest, validated


def verify_evidence(
    value: object,
    category: str,
    expected_commit: str,
    expected_run_id: int,
    expected_digest: str,
    content: bytes,
) -> int:
    evidence = exact_object(
        value,
        {
            "schema",
            "repository",
            "release_sha",
            "run_id",
            "run_attempt",
            "job_id",
            "category",
            "steps",
        },
        WalletReleaseBundleErrorReason.INVALID_EVIDENCE,
    )
    if (
        hashlib.sha256(content).hexdigest() != expected_digest
        or evidence["schema"] != "reallyme.wallet.eudi_release_check_evidence.v1"
        or evidence["repository"] != "reallyme/wallet"
        or evidence["release_sha"] != expected_commit
        or evidence["run_id"] != expected_run_id
        or evidence["run_attempt"] != 1
        or type(evidence["job_id"]) is not int
        or evidence["job_id"] < 1
        or evidence["category"] != category
        or not isinstance(evidence["steps"], list)
        or len(evidence["steps"]) != len(EXPECTED_EVIDENCE_STEPS[category])
    ):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_EVIDENCE
        )
    observed_names: list[str] = []
    observed_numbers: set[int] = set()
    for raw_step in evidence["steps"]:
        step = exact_object(
            raw_step,
            {"name", "number", "status", "conclusion"},
            WalletReleaseBundleErrorReason.INVALID_EVIDENCE,
        )
        if (
            not isinstance(step["name"], str)
            or type(step["number"]) is not int
            or step["number"] < 1
            or step["number"] in observed_numbers
            or step["status"] != "completed"
            or step["conclusion"] != "success"
        ):
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.INVALID_EVIDENCE
            )
        observed_names.append(step["name"])
        observed_numbers.add(step["number"])
    if tuple(observed_names) != EXPECTED_EVIDENCE_STEPS[category]:
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_EVIDENCE
        )
    return evidence["job_id"]


def verify_bundle(
    path: Path,
    attestation: dict[str, object],
    expected_commit: str,
    expected_release_ref: str,
    expected_packages: dict[str, str],
    source_cargo_lock: Path,
) -> VerifiedWalletReleaseBundle:
    if GIT_COMMIT.fullmatch(expected_commit) is None:
        raise WalletReleaseBundleError(WalletReleaseBundleErrorReason.SOURCE_MISMATCH)
    release = attestation.get("release")
    dependency_lock = attestation.get("dependency_lock")
    checks = attestation.get("checks")
    if (
        not isinstance(release, dict)
        or set(release) != {"version", "source_ref"}
        or not isinstance(release.get("version"), str)
        or SEMVER.fullmatch(release["version"]) is None
        or release.get("source_ref") != expected_release_ref
        or expected_release_ref != f"reallyme-wallet-v{release['version']}"
        or not isinstance(dependency_lock, dict)
        or dependency_lock.get("kind") != "cargo"
        or not isinstance(dependency_lock.get("sha256"), str)
        or SHA256.fullmatch(dependency_lock["sha256"]) is None
        or not isinstance(checks, list)
    ):
        raise WalletReleaseBundleError(WalletReleaseBundleErrorReason.SOURCE_MISMATCH)
    cargo_lock_sha256 = regular_file_digest(source_cargo_lock, MAX_MANIFEST_BYTES * 64)
    if cargo_lock_sha256 != dependency_lock["sha256"]:
        raise WalletReleaseBundleError(WalletReleaseBundleErrorReason.SOURCE_MISMATCH)
    expected_evidence: dict[str, str] = {}
    for raw_check in checks:
        if not isinstance(raw_check, dict):
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.INVALID_EVIDENCE
            )
        category = raw_check.get("category")
        if (
            category not in EXPECTED_EVIDENCE_STEPS
            or raw_check.get("check_id") != f"release-preflight-{category}"
            or raw_check.get("result") != "passed"
            or not isinstance(raw_check.get("evidence_sha256"), str)
            or SHA256.fullmatch(raw_check["evidence_sha256"]) is None
            or category in expected_evidence
        ):
            raise WalletReleaseBundleError(
                WalletReleaseBundleErrorReason.INVALID_EVIDENCE
            )
        expected_evidence[category] = raw_check["evidence_sha256"]
    if set(expected_evidence) != set(EXPECTED_EVIDENCE_STEPS):
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_EVIDENCE
        )
    regular_file_digest(path, MAX_BUNDLE_BYTES)
    try:
        with tarfile.open(path, mode="r:") as archive:
            members: list[tarfile.TarInfo] = []
            for member in archive:
                if len(members) >= MAX_BUNDLE_MEMBERS:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_BUNDLE
                    )
                members.append(member)
            if not members:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_BUNDLE
                )
            member_map: dict[str, tarfile.TarInfo] = {}
            for member in members:
                if (
                    not safe_member_name(member.name)
                    or member.name in member_map
                    or not member.isreg()
                ):
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_BUNDLE
                    )
                member_map[member.name] = member
            manifest_member = member_map.get("crates-preflight.json")
            if manifest_member is None:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_MANIFEST
                )
            manifest, crates = verify_manifest(
                parse_json(
                    read_member(
                        archive,
                        manifest_member,
                        MAX_MANIFEST_BYTES,
                        WalletReleaseBundleErrorReason.INVALID_MANIFEST,
                    ),
                    WalletReleaseBundleErrorReason.INVALID_MANIFEST,
                ),
                expected_commit,
                release["version"],
                expected_packages,
            )
            expected_names = {"crates-preflight.json"}
            crate_inventory: list[str] = []
            for crate in crates:
                file_name = crate["file"]
                if not isinstance(file_name, str):
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_MANIFEST
                    )
                member = member_map.get(file_name)
                if member is None or member.size != crate["size"]:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_CRATE
                    )
                content = read_member(
                    archive,
                    member,
                    MAX_CRATE_BYTES,
                    WalletReleaseBundleErrorReason.INVALID_CRATE,
                )
                if hashlib.sha256(content).hexdigest() != crate["sha256"]:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_CRATE
                    )
                suffix = f"-{release['version']}.crate"
                crate_name = file_name[: -len(suffix)]
                verify_crate_source_binding(
                    content, crate_name, release["version"], expected_commit
                )
                expected_names.add(file_name)
                crate_inventory.append(
                    f"{crate_name}|{release['version']}|{crate['size']}|{crate['sha256']}"
                )
            run_id = manifest["run_id"]
            if type(run_id) is not int:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_MANIFEST
                )
            prerequisites = manifest["prerequisites"]
            if not isinstance(prerequisites, dict):
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_MANIFEST
                )
            prerequisite_run_ids = (
                prerequisites["fuzz"],
                prerequisites["protobuf_ci"],
                prerequisites["rust_ci"],
            )
            if len({run_id, *prerequisite_run_ids}) != 4:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_MANIFEST
                )
            job_id: int | None = None
            evidence_inventory: list[str] = []
            for category, digest in sorted(expected_evidence.items()):
                file_name = f"evidence-{category}.json"
                member = member_map.get(file_name)
                if member is None:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_EVIDENCE
                    )
                content = read_member(
                    archive,
                    member,
                    MAX_EVIDENCE_BYTES,
                    WalletReleaseBundleErrorReason.INVALID_EVIDENCE,
                )
                observed_job_id = verify_evidence(
                    parse_json(content, WalletReleaseBundleErrorReason.INVALID_EVIDENCE),
                    category,
                    expected_commit,
                    run_id,
                    digest,
                    content,
                )
                if job_id is None:
                    job_id = observed_job_id
                elif job_id != observed_job_id:
                    raise WalletReleaseBundleError(
                        WalletReleaseBundleErrorReason.INVALID_EVIDENCE
                    )
                expected_names.add(file_name)
                evidence_inventory.append(f"{category}|{digest}")
            if set(member_map) != expected_names or job_id is None:
                raise WalletReleaseBundleError(
                    WalletReleaseBundleErrorReason.INVALID_BUNDLE
                )
            return VerifiedWalletReleaseBundle(
                preflight_run_id=run_id,
                preflight_job_id=job_id,
                fuzz_run_id=prerequisites["fuzz"],
                protobuf_ci_run_id=prerequisites["protobuf_ci"],
                rust_ci_run_id=prerequisites["rust_ci"],
                crate_count=len(crates),
                crate_inventory_sha256=digest_entries(crate_inventory),
                evidence_count=len(evidence_inventory),
                evidence_inventory_sha256=digest_entries(evidence_inventory),
                cargo_lock_sha256=cargo_lock_sha256,
            )
    except WalletReleaseBundleError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise WalletReleaseBundleError(
            WalletReleaseBundleErrorReason.INVALID_BUNDLE
        ) from error
