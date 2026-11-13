#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify one frozen Wallet GitHub release and crates.io publication inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_eudi_wallet_execution_result as result_verifier  # noqa: E402
import verify_wallet_package_bundle as package_bundle  # noqa: E402


MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = package_bundle.MAX_CRATE_BYTES
SHA256_PREFIX = re.compile(r"^sha256:([0-9a-f]{64})$")
PUBLICATION_STATES = {"published", "verified_existing"}


class PublishedTargetErrorReason(Enum):
    INVALID_INPUT = "invalid_input"
    TARGET_MISMATCH = "target_mismatch"
    RELEASE_MISMATCH = "release_mismatch"
    ASSET_MISMATCH = "asset_mismatch"
    LEDGER_MISMATCH = "ledger_mismatch"
    REGISTRY_MISMATCH = "registry_mismatch"
    OUTPUT_EXISTS = "output_exists"
    OUTPUT_FAILED = "output_failed"


@dataclass(frozen=True)
class PublishedTargetError(Exception):
    reason: PublishedTargetErrorReason


def fail(reason: PublishedTargetErrorReason) -> NoReturn:
    print(f"Wallet published target invalid: {reason.value}", file=sys.stderr)
    raise SystemExit(65)


def read_json(path: Path, reason: PublishedTargetErrorReason) -> object:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise PublishedTargetError(reason)
        return strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise PublishedTargetError(reason) from error


def file_identity(path: Path) -> tuple[int, str]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_ASSET_BYTES:
            raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
        return metadata.st_size, digest.hexdigest()
    except OSError as error:
        raise PublishedTargetError(
            PublishedTargetErrorReason.ASSET_MISMATCH
        ) from error


def canonical_inventory_digest(value: list[dict[str, object]]) -> str:
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(payload).hexdigest()


def verify_release_assets(
    release: dict[str, object],
    assets_directory: Path,
    expected_crates: list[dict[str, object]],
) -> list[dict[str, object]]:
    expected_names = {
        "crates-preflight.json",
        "crates-publication-ledger.json",
        *(
            crate["file"]
            for crate in expected_crates
            if isinstance(crate.get("file"), str)
        ),
    }
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list) or len(raw_assets) != len(expected_names):
        raise PublishedTargetError(PublishedTargetErrorReason.RELEASE_MISMATCH)
    try:
        entries = list(assets_directory.iterdir())
    except OSError as error:
        raise PublishedTargetError(
            PublishedTargetErrorReason.ASSET_MISMATCH
        ) from error
    if {entry.name for entry in entries} != expected_names:
        raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
    inventory: list[dict[str, object]] = []
    observed_names: set[str] = set()
    for raw_asset in raw_assets:
        if not isinstance(raw_asset, dict):
            raise PublishedTargetError(PublishedTargetErrorReason.RELEASE_MISMATCH)
        name = raw_asset.get("name")
        size = raw_asset.get("size")
        digest_value = raw_asset.get("digest")
        digest_match = (
            SHA256_PREFIX.fullmatch(digest_value)
            if isinstance(digest_value, str)
            else None
        )
        if (
            not isinstance(name, str)
            or name not in expected_names
            or name in observed_names
            or type(size) is not int
            or size < 1
            or digest_match is None
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.RELEASE_MISMATCH)
        local_size, local_digest = file_identity(assets_directory / name)
        if local_size != size or local_digest != digest_match.group(1):
            raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
        observed_names.add(name)
        inventory.append({"name": name, "size": size, "sha256": local_digest})
    return sorted(inventory, key=lambda item: str(item["name"]))


def verify_manifest_asset(
    assets_directory: Path,
    expected_commit: str,
    expected_version: str,
    expected_run_id: int,
    expected_crates: list[dict[str, object]],
) -> None:
    packages = {
        crate["name"]: crate["version"]
        for crate in expected_crates
        if isinstance(crate.get("name"), str)
        and isinstance(crate.get("version"), str)
    }
    manifest = read_json(
        assets_directory / "crates-preflight.json",
        PublishedTargetErrorReason.ASSET_MISMATCH,
    )
    try:
        validated, crates = package_bundle.verify_manifest(
            manifest, expected_commit, expected_version, packages
        )
    except package_bundle.WalletPackageBundleError as error:
        raise PublishedTargetError(
            PublishedTargetErrorReason.ASSET_MISMATCH
        ) from error
    if validated.get("run_id") != expected_run_id or crates != [
        {"file": crate["file"], "sha256": crate["sha256"], "size": crate["size"]}
        for crate in expected_crates
    ]:
        raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)


def verify_ledger(
    assets_directory: Path,
    expected_commit: str,
    expected_version: str,
    expected_crates: list[dict[str, object]],
) -> None:
    ledger = read_json(
        assets_directory / "crates-publication-ledger.json",
        PublishedTargetErrorReason.LEDGER_MISMATCH,
    )
    if (
        not isinstance(ledger, dict)
        or set(ledger)
        != {
            "schema",
            "repository",
            "source_commit",
            "release_version",
            "state",
            "crates",
        }
        or ledger.get("schema") != "reallyme.wallet.crates-publication-ledger.v1"
        or ledger.get("repository") != "reallyme/wallet"
        or ledger.get("source_commit") != expected_commit
        or ledger.get("release_version") != expected_version
        or ledger.get("state") != "completed"
        or not isinstance(ledger.get("crates"), list)
        or len(ledger["crates"]) != len(expected_crates)
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.LEDGER_MISMATCH)
    expected_by_name = {crate["name"]: crate for crate in expected_crates}
    observed: set[str] = set()
    for publish_order, raw_entry in enumerate(ledger["crates"]):
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "name",
            "version",
            "publish_order",
            "state",
            "archive_sha256",
        }:
            raise PublishedTargetError(PublishedTargetErrorReason.LEDGER_MISMATCH)
        name = raw_entry["name"]
        expected = expected_by_name.get(name) if isinstance(name, str) else None
        if (
            expected is None
            or name in observed
            or raw_entry["version"] != expected_version
            or raw_entry["publish_order"] != publish_order
            or raw_entry["state"] not in PUBLICATION_STATES
            or raw_entry["archive_sha256"] != expected["sha256"]
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.LEDGER_MISMATCH)
        observed.add(name)
    if observed != set(expected_by_name):
        raise PublishedTargetError(PublishedTargetErrorReason.LEDGER_MISMATCH)


def verify_registry(
    value: object,
    expected_version: str,
    expected_crates: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(expected_crates):
        raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
    expected_by_name = {crate["name"]: crate for crate in expected_crates}
    inventory: list[dict[str, object]] = []
    observed: set[str] = set()
    for raw_entry in value:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "name",
            "version",
            "checksum",
            "yanked",
        }:
            raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
        name = raw_entry["name"]
        expected = expected_by_name.get(name) if isinstance(name, str) else None
        if (
            expected is None
            or name in observed
            or raw_entry["version"] != expected_version
            or raw_entry["checksum"] != expected["sha256"]
            or raw_entry["yanked"] is not False
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
        observed.add(name)
        inventory.append(
            {
                "name": name,
                "version": expected_version,
                "checksum": raw_entry["checksum"],
                "yanked": False,
            }
        )
    if observed != set(expected_by_name):
        raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
    return sorted(inventory, key=lambda item: str(item["name"]))


def validate_publication_evidence(
    value: object,
    target: dict[str, object],
    expected_crates: list[dict[str, object]],
) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "release",
            "release_assets",
            "release_asset_inventory_sha256",
            "registry_packages",
            "registry_package_inventory_sha256",
        }
        or value.get("schema")
        != "reallyme.identity.wallet_publication_evidence.v1"
        or target.get("mode") != "published"
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.INVALID_INPUT)
    release = value.get("release")
    if (
        not isinstance(release, dict)
        or set(release) != {"id", "ref", "version", "commit"}
        or release.get("id") != target.get("release_id")
        or release.get("ref") != target.get("release_ref")
        or release.get("version") != target.get("version")
        or release.get("commit") != target.get("commit")
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.TARGET_MISMATCH)

    expected_by_file = {
        crate["file"]: crate
        for crate in expected_crates
        if isinstance(crate.get("file"), str)
    }
    expected_asset_names = {
        "crates-preflight.json",
        "crates-publication-ledger.json",
        *expected_by_file,
    }
    release_assets = value.get("release_assets")
    if (
        not isinstance(release_assets, list)
        or len(release_assets) != len(expected_asset_names)
        or release_assets
        != sorted(
            release_assets,
            key=lambda item: (
                str(item.get("name")) if isinstance(item, dict) else ""
            ),
        )
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
    observed_assets: set[str] = set()
    for raw_asset in release_assets:
        if not isinstance(raw_asset, dict) or set(raw_asset) != {"name", "size", "sha256"}:
            raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
        name = raw_asset.get("name")
        size = raw_asset.get("size")
        digest = raw_asset.get("sha256")
        if (
            not isinstance(name, str)
            or name not in expected_asset_names
            or name in observed_assets
            or type(size) is not int
            or size < 1
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
        expected_crate = expected_by_file.get(name)
        if expected_crate is not None and (
            size != expected_crate.get("size") or digest != expected_crate.get("sha256")
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)
        observed_assets.add(name)
    if (
        observed_assets != expected_asset_names
        or value.get("release_asset_inventory_sha256")
        != canonical_inventory_digest(release_assets)
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.ASSET_MISMATCH)

    expected_by_name = {
        crate["name"]: crate
        for crate in expected_crates
        if isinstance(crate.get("name"), str)
    }
    registry_packages = value.get("registry_packages")
    if (
        not isinstance(registry_packages, list)
        or len(registry_packages) != len(expected_by_name)
        or registry_packages
        != sorted(
            registry_packages,
            key=lambda item: (
                str(item.get("name")) if isinstance(item, dict) else ""
            ),
        )
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
    observed_packages: set[str] = set()
    for raw_package in registry_packages:
        if not isinstance(raw_package, dict) or set(raw_package) != {
            "name",
            "version",
            "checksum",
            "yanked",
        }:
            raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
        name = raw_package.get("name")
        expected_crate = expected_by_name.get(name) if isinstance(name, str) else None
        if (
            expected_crate is None
            or name in observed_packages
            or raw_package.get("version") != target.get("version")
            or raw_package.get("checksum") != expected_crate.get("sha256")
            or raw_package.get("yanked") is not False
        ):
            raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)
        observed_packages.add(name)
    if (
        observed_packages != set(expected_by_name)
        or value.get("registry_package_inventory_sha256")
        != canonical_inventory_digest(registry_packages)
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.REGISTRY_MISMATCH)


def build_publication_evidence(
    result: dict[str, object],
    release: dict[str, object],
    assets_directory: Path,
    registry_records: object,
) -> dict[str, object]:
    try:
        result_verifier.verify_result(result)
    except result_verifier.runner.EudiWalletRunnerError as error:
        raise PublishedTargetError(PublishedTargetErrorReason.INVALID_INPUT) from error
    target = result.get("target")
    package_evidence = result.get("package_evidence")
    component = result.get("component")
    if (
        not isinstance(target, dict)
        or target.get("mode") != "published"
        or not isinstance(package_evidence, dict)
        or not isinstance(package_evidence.get("crates"), list)
        or not isinstance(component, dict)
        or component.get("commit") != target.get("commit")
        or release.get("id") != target.get("release_id")
        or release.get("tag_name") != target.get("release_ref")
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise PublishedTargetError(PublishedTargetErrorReason.TARGET_MISMATCH)
    crates = package_evidence["crates"]
    release_assets = verify_release_assets(release, assets_directory, crates)
    verify_manifest_asset(
        assets_directory,
        target["commit"],
        target["version"],
        target["preflight_run_id"],
        crates,
    )
    verify_ledger(
        assets_directory,
        target["commit"],
        target["version"],
        crates,
    )
    registry_packages = verify_registry(
        registry_records, target["version"], crates
    )
    evidence = {
        "schema": "reallyme.identity.wallet_publication_evidence.v1",
        "release": {
            "id": target["release_id"],
            "ref": target["release_ref"],
            "version": target["version"],
            "commit": target["commit"],
        },
        "release_assets": release_assets,
        "release_asset_inventory_sha256": canonical_inventory_digest(release_assets),
        "registry_packages": registry_packages,
        "registry_package_inventory_sha256": canonical_inventory_digest(
            registry_packages
        ),
    }
    validate_publication_evidence(evidence, target, crates)
    return evidence


def write_output(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise PublishedTargetError(PublishedTargetErrorReason.OUTPUT_EXISTS)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".wallet-publication-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as error:
        raise PublishedTargetError(PublishedTargetErrorReason.OUTPUT_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--release-record", required=True, type=Path)
    parser.add_argument("--assets-directory", required=True, type=Path)
    parser.add_argument("--registry-records", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = read_json(args.result, PublishedTargetErrorReason.INVALID_INPUT)
        release = read_json(
            args.release_record, PublishedTargetErrorReason.INVALID_INPUT
        )
        registry = read_json(
            args.registry_records, PublishedTargetErrorReason.INVALID_INPUT
        )
        if not isinstance(result, dict) or not isinstance(release, dict):
            raise PublishedTargetError(PublishedTargetErrorReason.INVALID_INPUT)
        evidence = build_publication_evidence(
            result, release, args.assets_directory, registry
        )
        write_output(args.output, evidence)
    except PublishedTargetError as error:
        fail(error.reason)
    print("Wallet published target evidence valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
