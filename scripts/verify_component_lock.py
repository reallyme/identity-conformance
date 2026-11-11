#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the exact cross-repository OIDF release bill of materials."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = REPOSITORY_ROOT / "components.lock.json"
MAX_LOCK_BYTES = 64_000
MAX_CARGO_LOCK_BYTES = 16 * 1024 * 1024
EXIT_INVALID_INPUT = 65
EXIT_CONFIGURATION = 78
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_COMPONENTS = {
    "openid4vci": (
        "https://github.com/reallyme/openid4vci",
        "../openid4vci",
        {"openid4vci_issuer", "openid4vci_wallet"},
    ),
    "openid4vp": (
        "https://github.com/reallyme/openid4vp",
        "../openid4vp",
        {"openid4vp_verifier", "openid4vp_wallet"},
    ),
    "wallet": (
        "https://github.com/reallyme/wallet",
        "../wallet",
        {"openid4vci_wallet", "openid4vp_wallet"},
    ),
    "ssi": (
        "https://github.com/reallyme/ssi",
        "../ssi",
        {
            "openid4vci_issuer",
            "openid4vci_wallet",
            "openid4vp_verifier",
            "openid4vp_wallet",
        },
    ),
    "identity": (
        "https://github.com/reallyme/identity",
        "../identity",
        {"openid4vci_wallet", "openid4vp_verifier", "openid4vp_wallet"},
    ),
    "cose": (
        "https://github.com/reallyme/cose",
        "../cose",
        {
            "openid4vci_issuer",
            "openid4vci_wallet",
            "openid4vp_verifier",
            "openid4vp_wallet",
        },
    ),
}
EXPECTED_PACKAGE_NAMES = {
    "openid4vci-attestation",
    "openid4vci-http",
    "openid4vci-issuer",
    "openid4vci-profiles",
    "openid4vci-proto-codec",
    "reallyme-crypto",
    "reallyme-cose",
    "reallyme-jose",
    "reallyme-openid4vci",
    "reallyme-openid4vci-proto",
    "reallyme-openid4vci-types",
    "reallyme-openid4vci-wallet",
    "reallyme-openid4vp",
    "reallyme-openid4vp-dc-api",
    "reallyme-openid4vp-dcql",
    "reallyme-openid4vp-formats",
    "reallyme-openid4vp-http",
    "reallyme-openid4vp-profiles",
    "reallyme-openid4vp-proto",
    "reallyme-openid4vp-proto-codec",
    "reallyme-openid4vp-runtime",
    "reallyme-openid4vp-types",
    "reallyme-openid4vp-verifier",
    "reallyme-openid4vp-wallet",
    "reallyme-ssi-core",
    "reallyme-ssi-proto",
    "reallyme-ssi-proto-codec",
}
WORKSPACE_PACKAGE_OWNERS = {
    "openid4vci-attestation": "openid4vci",
    "openid4vci-http": "openid4vci",
    "openid4vci-issuer": "openid4vci",
    "openid4vci-profiles": "openid4vci",
    "openid4vci-proto-codec": "openid4vci",
    "reallyme-cose": "cose",
    "reallyme-openid4vci": "openid4vci",
    "reallyme-openid4vci-proto": "openid4vci",
    "reallyme-openid4vci-types": "openid4vci",
    "reallyme-openid4vci-wallet": "openid4vci",
    "reallyme-openid4vp": "openid4vp",
    "reallyme-openid4vp-dc-api": "openid4vp",
    "reallyme-openid4vp-dcql": "openid4vp",
    "reallyme-openid4vp-formats": "openid4vp",
    "reallyme-openid4vp-http": "openid4vp",
    "reallyme-openid4vp-profiles": "openid4vp",
    "reallyme-openid4vp-proto": "openid4vp",
    "reallyme-openid4vp-proto-codec": "openid4vp",
    "reallyme-openid4vp-runtime": "openid4vp",
    "reallyme-openid4vp-types": "openid4vp",
    "reallyme-openid4vp-verifier": "openid4vp",
    "reallyme-openid4vp-wallet": "openid4vp",
    "reallyme-ssi-core": "ssi",
    "reallyme-ssi-proto": "ssi",
    "reallyme-ssi-proto-codec": "ssi",
}
OWNER_REQUIRED_PACKAGES = {
    component_id: {
        package_name
        for package_name, owner in WORKSPACE_PACKAGE_OWNERS.items()
        if owner == component_id
    }
    for component_id in {"openid4vci", "openid4vp", "ssi"}
}
RELEASE_PREFIXES = {
    "openid4vci": "reallyme-openid4vci-v",
    "openid4vp": "reallyme-openid4vp-v",
    "wallet": "reallyme-wallet-v",
    "ssi": "reallyme-ssi-v",
    "identity": "reallyme-identity-v",
    "cose": "reallyme-cose-v",
}
def fail(message: str, exit_code: int = EXIT_INVALID_INPUT) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def load_lock(path: Path = LOCK_PATH) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_LOCK_BYTES:
            fail("component lock exceeds the accepted size")
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("component lock is unavailable or invalid JSON")
    if not isinstance(value, dict):
        fail("component lock must contain an object")
    return value


def required_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty string")
    return value


def validate_package_map(value: object, context: str) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != EXPECTED_PACKAGE_NAMES:
        fail(f"{context} must contain the complete approved package set")
    validated: dict[str, dict[str, str]] = {}
    for package_name, raw_metadata in value.items():
        if not isinstance(package_name, str) or not isinstance(raw_metadata, dict):
            fail(f"{context} contains an invalid package entry")
        if set(raw_metadata) != {"version", "checksum"}:
            fail(f"{context}.{package_name} has unsupported fields")
        version = required_string(
            raw_metadata.get("version"), f"{context}.{package_name}.version"
        )
        checksum = required_string(
            raw_metadata.get("checksum"), f"{context}.{package_name}.checksum"
        )
        if SEMVER.fullmatch(version) is None:
            fail(f"{context}.{package_name}.version must be stable semantic versioning")
        if SHA256.fullmatch(checksum) is None:
            fail(f"{context}.{package_name}.checksum must be lowercase SHA-256")
        validated[package_name] = {"version": version, "checksum": checksum}
    return validated


def package_policy(
    value: dict[str, object] | None = None,
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, dict[str, str]]]]:
    lock = load_lock() if value is None else value
    packages = validate_package_map(
        lock.get("required_cargo_packages"), "required_cargo_packages"
    )
    raw_overrides = lock.get("component_cargo_package_overrides")
    if not isinstance(raw_overrides, dict):
        fail("component_cargo_package_overrides must be an object")
    overrides: dict[str, dict[str, dict[str, str]]] = {}
    for component_id, raw_package_map in raw_overrides.items():
        if component_id not in EXPECTED_COMPONENTS or not isinstance(
            raw_package_map, dict
        ):
            fail("component Cargo package overrides contain an invalid component")
        component_packages: dict[str, dict[str, str]] = {}
        for package_name, raw_metadata in raw_package_map.items():
            if package_name not in EXPECTED_PACKAGE_NAMES or not isinstance(
                raw_metadata, dict
            ):
                fail("component Cargo package overrides contain an invalid package")
            if set(raw_metadata) != {"version", "checksum"}:
                fail("component Cargo package override has unsupported fields")
            version = required_string(
                raw_metadata.get("version"), "component package override version"
            )
            checksum = required_string(
                raw_metadata.get("checksum"), "component package override checksum"
            )
            if SEMVER.fullmatch(version) is None or SHA256.fullmatch(checksum) is None:
                fail("component Cargo package override is invalid")
            component_packages[package_name] = {
                "version": version,
                "checksum": checksum,
            }
        overrides[component_id] = component_packages
    return packages, overrides


def verify_lock(
    value: dict[str, object], *, require_release_refs: bool = False
) -> dict[str, tuple[str, str]]:
    if value.get("schema_version") != 1:
        fail("component lock has an unsupported schema version")
    if value.get("purpose") != "oidf-cross-repository-release-bom":
        fail("component lock has an invalid purpose")
    if value.get("claim_status") != "reference_candidate_not_conformance_evidence":
        fail("component lock has an invalid claim status")
    package_policy(value)
    if "retained_conformance_evidence" in value:
        fail("component lock contains an unsupported field")
    repositories = value.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != len(EXPECTED_COMPONENTS):
        fail("component lock must contain the complete repository set")

    observed: dict[str, tuple[str, str]] = {}
    for item in repositories:
        if not isinstance(item, dict):
            fail("component lock repository entry must be an object")
        component_id = required_string(item.get("component_id"), "component_id")
        if component_id in observed:
            fail("component lock repeats a component")
        expected = EXPECTED_COMPONENTS.get(component_id)
        if expected is None:
            fail("component lock contains an unknown component")
        repository = required_string(item.get("repository"), f"{component_id}.repository")
        checkout = required_string(item.get("local_checkout"), f"{component_id}.local_checkout")
        commit = required_string(item.get("commit"), f"{component_id}.commit")
        release_ref = item.get("release_ref")
        roles = item.get("roles")
        if repository != expected[0] or checkout != expected[1]:
            fail(f"{component_id} repository identity is invalid")
        if GIT_COMMIT.fullmatch(commit) is None:
            fail(f"{component_id} commit must be a full lowercase Git commit")
        expected_release_prefix = RELEASE_PREFIXES[component_id]
        if release_ref is not None:
            release_ref = required_string(
                release_ref, f"{component_id}.release_ref"
            )
            if not release_ref.startswith(expected_release_prefix):
                fail(f"{component_id} release reference is invalid")
        elif require_release_refs:
            fail(f"{component_id} requires an immutable release reference for evidence")
        if (
            not isinstance(roles, list)
            or set(roles) != expected[2]
            or len(roles) != len(expected[2])
        ):
            fail(f"{component_id} role coverage is invalid")
        observed[component_id] = (checkout, commit)
    if set(observed) != set(EXPECTED_COMPONENTS):
        fail("component lock does not cover the approved repository set")
    return observed


def git_output(checkout: Path, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        fail("unable to inspect a component checkout", EXIT_CONFIGURATION)
    if result.returncode != 0:
        fail("unable to inspect a component checkout", EXIT_CONFIGURATION)
    return result.stdout.strip()


def verify_cargo_lock(
    cargo_lock: Path, context: str, component_id: str | None = None
) -> set[str]:
    required_packages, component_overrides = package_policy()
    try:
        metadata = cargo_lock.lstat()
        if cargo_lock.is_symlink() or not cargo_lock.is_file():
            fail(
                f"{context} must be a regular file",
                EXIT_CONFIGURATION,
            )
        if metadata.st_size < 1 or metadata.st_size > MAX_CARGO_LOCK_BYTES:
            fail(f"{context} has an invalid size", EXIT_CONFIGURATION)
        value = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        fail(f"{context} is unavailable or invalid", EXIT_CONFIGURATION)
    packages = value.get("package")
    if not isinstance(packages, list):
        fail(f"{context} has no package inventory", EXIT_CONFIGURATION)
    for package_name, required in required_packages.items():
        selected_overrides = component_overrides.get(
            component_id or "", {}
        )
        expected = selected_overrides.get(package_name, required)
        matches = [
            package
            for package in packages
            if isinstance(package, dict) and package.get("name") == package_name
        ]
        if not matches:
            continue
        if len(matches) != 1 or matches[0].get("version") != expected["version"]:
            fail(
                f"{context} must resolve exactly {package_name} {expected['version']}",
                EXIT_CONFIGURATION,
            )
        package = matches[0]
        if package.get("source") is None:
            if WORKSPACE_PACKAGE_OWNERS.get(package_name) != component_id:
                fail(
                    f"{context} contains an unapproved workspace package source",
                    EXIT_CONFIGURATION,
                )
            continue
        if (
            package.get("source") != CRATES_IO_SOURCE
            or package.get("checksum") != expected["checksum"]
        ):
            fail(
                f"{context} does not match the approved crates.io package",
                EXIT_CONFIGURATION,
            )
    return {
        package["name"]
        for package in packages
        if isinstance(package, dict)
        and isinstance(package.get("name"), str)
        and package.get("name") in required_packages
    }


def verify_cargo_dependencies(checkout: Path, component_id: str) -> None:
    tracked = git_output(
        checkout,
        ["ls-files", "--cached", "--", "Cargo.lock", ":(glob)**/Cargo.lock"],
    ).splitlines()
    relative_paths = sorted(set(path for path in tracked if path))
    if not relative_paths:
        fail(f"{component_id} has no tracked Cargo.lock", EXIT_CONFIGURATION)
    found_required_packages: set[str] = set()
    for relative_path in relative_paths:
        cargo_lock = (checkout / relative_path).resolve()
        try:
            cargo_lock.relative_to(checkout)
        except ValueError:
            fail(f"{component_id} Cargo.lock escapes its checkout", EXIT_CONFIGURATION)
        found_required_packages.update(
            verify_cargo_lock(
                cargo_lock, f"{component_id}/{relative_path}", component_id
            )
        )
    if not found_required_packages:
        fail(
            f"{component_id} does not resolve the required Cargo package set",
            EXIT_CONFIGURATION,
        )
    missing_owner_packages = OWNER_REQUIRED_PACKAGES.get(component_id, set()).difference(
        found_required_packages
    )
    if missing_owner_packages:
        fail(
            f"{component_id} omits an approved public package from its Cargo lock",
            EXIT_CONFIGURATION,
        )


def verify_checkouts(components: dict[str, tuple[str, str]]) -> None:
    for component_id, (relative_checkout, expected_commit) in components.items():
        checkout = (REPOSITORY_ROOT / relative_checkout).resolve()
        if not (checkout / ".git").exists():
            fail(f"{component_id} checkout is unavailable", EXIT_CONFIGURATION)
        if git_output(checkout, ["rev-parse", "HEAD"]) != expected_commit:
            fail(f"{component_id} checkout is not at the locked commit", EXIT_CONFIGURATION)
        if git_output(checkout, ["status", "--porcelain"]):
            fail(f"{component_id} checkout contains uncommitted changes", EXIT_CONFIGURATION)
        verify_cargo_dependencies(checkout, component_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-checkouts",
        action="store_true",
        help="also require every sibling checkout to be clean and at its locked commit",
    )
    parser.add_argument(
        "--evidence-release",
        action="store_true",
        help="require immutable release references for every evidence component",
    )
    args = parser.parse_args()
    components = verify_lock(
        load_lock(), require_release_refs=args.evidence_release
    )
    if args.verify_checkouts:
        verify_checkouts(components)
    scope = "evidence release" if args.evidence_release else "reference candidate"
    print(f"component lock covers six repositories and four OIDF roles ({scope})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
