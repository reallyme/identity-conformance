#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify that Identity uses the selected released component versions exactly."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


MAX_TOML_BYTES = 1024 * 1024
STABLE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
RELEASE_REF = re.compile(
    r"^reallyme-(ssi|openid4vci|openid4vp)-v"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
PYTHON_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
    r"(?:\[[A-Za-z0-9_,.-]+\])?(?P<specifier>.*)$"
)
PYTHON_SPECIFIER_START = re.compile(r"^(?:===|==|~=|!=|<=|>=|<|>)")
REQUIRED_PYTHON_RUNTIME_PACKAGES = frozenset({"protobuf"})
REQUIRED_PYTHON_TEST_PACKAGES = frozenset({"cryptography", "pytest"})
REQUIRED_COMPONENT_PACKAGES = {
    "ssi": frozenset(
        {
            "reallyme-credential",
            "reallyme-did-api",
            "reallyme-etsi-eaa-conformance",
            "reallyme-mdoc",
            "reallyme-sd-jwt",
            "reallyme-ssi-proto",
            "reallyme-ssi-proto-codec",
            "reallyme-trust",
            "reallyme-trust-core",
            "reallyme-trust-x509",
        }
    ),
    "openid4vci": frozenset(
        {
            "reallyme-openid4vci",
            "reallyme-openid4vci-proto",
            "reallyme-openid4vci-wallet",
        }
    ),
    "openid4vp": frozenset(
        {
            "reallyme-openid4vp",
            "reallyme-openid4vp-proto",
            "reallyme-openid4vp-runtime",
            "reallyme-openid4vp-verifier",
            "reallyme-openid4vp-wallet",
        }
    ),
}


class DependencyErrorReason(Enum):
    INPUT_UNAVAILABLE = "input_unavailable"
    INPUT_TOO_LARGE = "input_too_large"
    TOML_INVALID = "toml_invalid"
    RELEASE_REF_INVALID = "release_ref_invalid"
    RELEASE_COMPONENT_MISMATCH = "release_component_mismatch"
    WORKSPACE_DEPENDENCIES_INVALID = "workspace_dependencies_invalid"
    REQUIRED_PACKAGE_MISSING = "required_package_missing"
    VERSION_REQUIREMENT_INVALID = "version_requirement_invalid"
    VERSION_MISMATCH = "version_mismatch"
    PYTHON_DEPENDENCIES_INVALID = "python_dependencies_invalid"


@dataclass(frozen=True)
class DependencyError(Exception):
    reason: DependencyErrorReason


def fail(reason: DependencyErrorReason) -> NoReturn:
    raise DependencyError(reason)


def parse_release_ref(value: str, component: str) -> str:
    match = RELEASE_REF.fullmatch(value)
    if match is None:
        fail(DependencyErrorReason.RELEASE_REF_INVALID)
    if match.group(1) != component:
        fail(DependencyErrorReason.RELEASE_COMPONENT_MISMATCH)
    version = ".".join(match.groups()[1:])
    if STABLE_VERSION.fullmatch(version) is None:
        fail(DependencyErrorReason.RELEASE_REF_INVALID)
    return version


def load_workspace_dependencies(path: Path) -> dict[str, object]:
    try:
        metadata = path.stat()
        if not path.is_file() or path.is_symlink() or metadata.st_size < 1:
            fail(DependencyErrorReason.INPUT_UNAVAILABLE)
        if metadata.st_size > MAX_TOML_BYTES:
            fail(DependencyErrorReason.INPUT_TOO_LARGE)
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except DependencyError:
        raise
    except (OSError, tomllib.TOMLDecodeError):
        fail(DependencyErrorReason.TOML_INVALID)
    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
    dependencies = workspace.get("dependencies")
    if not isinstance(dependencies, dict):
        fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
    return dependencies


def verify_identity_version(path: Path, selected_version: str) -> None:
    try:
        metadata = path.stat()
        if not path.is_file() or path.is_symlink() or metadata.st_size < 1:
            fail(DependencyErrorReason.INPUT_UNAVAILABLE)
        if metadata.st_size > MAX_TOML_BYTES:
            fail(DependencyErrorReason.INPUT_TOO_LARGE)
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except DependencyError:
        raise
    except (OSError, tomllib.TOMLDecodeError):
        fail(DependencyErrorReason.TOML_INVALID)
    package = document.get("package")
    if (
        not isinstance(package, dict)
        or package.get("name") != "reallyme-identity"
        or package.get("version") != selected_version
    ):
        fail(DependencyErrorReason.VERSION_MISMATCH)


def verify_python_dependencies(path: Path, selected_version: str) -> None:
    try:
        metadata = path.stat()
        if not path.is_file() or path.is_symlink() or metadata.st_size < 1:
            fail(DependencyErrorReason.INPUT_UNAVAILABLE)
        if metadata.st_size > MAX_TOML_BYTES:
            fail(DependencyErrorReason.INPUT_TOO_LARGE)
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except DependencyError:
        raise
    except (OSError, tomllib.TOMLDecodeError):
        fail(DependencyErrorReason.TOML_INVALID)
    project = document.get("project")
    if not isinstance(project, dict):
        fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)
    runtime = project.get("dependencies")
    optional = project.get("optional-dependencies")
    if (
        project.get("name") != "reallyme-identity"
        or project.get("version") != selected_version
        or not isinstance(runtime, list)
        or not 1 <= len(runtime) <= 64
        or not isinstance(optional, dict)
        or not isinstance(optional.get("test"), list)
        or not 1 <= len(optional["test"]) <= 64
    ):
        fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)
    runtime_names = python_requirement_names(runtime)
    test_names = python_requirement_names(optional["test"])
    if (
        not REQUIRED_PYTHON_RUNTIME_PACKAGES.issubset(runtime_names)
        or not REQUIRED_PYTHON_TEST_PACKAGES.issubset(test_names)
    ):
        fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)


def python_requirement_names(requirements: list[object]) -> set[str]:
    names: set[str] = set()
    for requirement in requirements:
        if (
            not isinstance(requirement, str)
            or not 1 <= len(requirement) <= 512
            or not requirement.isprintable()
            or any(token in requirement for token in ("@", "://", "/", "\\"))
        ):
            fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)
        match = PYTHON_REQUIREMENT.fullmatch(requirement)
        if (
            match is None
            or PYTHON_SPECIFIER_START.match(match.group("specifier").lstrip()) is None
        ):
            fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)
        name = match.group("name").lower().replace("_", "-").replace(".", "-")
        if name in names:
            fail(DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID)
        names.add(name)
    return names


def package_name(key: str, value: object) -> str:
    if isinstance(value, str):
        return key
    if not isinstance(value, dict):
        fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
    explicit = value.get("package", key)
    if not isinstance(explicit, str) or not explicit:
        fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
    return explicit


def version_requirement(value: object) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
    version = value.get("version")
    if not isinstance(version, str):
        fail(DependencyErrorReason.VERSION_REQUIREMENT_INVALID)
    return version


def component_for_package(key: str, package: str) -> str | None:
    # Identity's own composition crates contain protocol names but are not
    # artifacts from the protocol component releases.
    if package.startswith("reallyme-identity-"):
        return None
    combined = f"{key}\n{package}"
    if "openid4vci" in combined:
        return "openid4vci"
    if "openid4vp" in combined:
        return "openid4vp"
    ssi_prefixes = (
        "reallyme-credential",
        "reallyme-did",
        "reallyme-disclosure-policy",
        "reallyme-etsi-eaa-conformance",
        "reallyme-mdoc",
        "reallyme-openid-oauth",
        "reallyme-revocation",
        "reallyme-sd-jwt",
        "reallyme-ssi",
        "reallyme-trust",
        "reallyme-vp",
    )
    if package.startswith(ssi_prefixes):
        return "ssi"
    return None


def verify_dependencies(
    dependencies: dict[str, object], selected_versions: dict[str, str]
) -> None:
    observed: dict[str, set[str]] = {component: set() for component in selected_versions}
    for key, value in dependencies.items():
        if not isinstance(key, str) or not key:
            fail(DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID)
        package = package_name(key, value)
        component = component_for_package(key, package)
        if component is None:
            continue
        requirement = version_requirement(value)
        expected = f"={selected_versions[component]}"
        if requirement != expected:
            fail(DependencyErrorReason.VERSION_MISMATCH)
        observed[component].add(package)
    for component, required in REQUIRED_COMPONENT_PACKAGES.items():
        if not required.issubset(observed[component]):
            fail(DependencyErrorReason.REQUIRED_PACKAGE_MISSING)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-toml", required=True, type=Path)
    parser.add_argument("--identity-package-toml", required=True, type=Path)
    parser.add_argument("--python-pyproject", required=True, type=Path)
    parser.add_argument("--identity-version", required=True)
    parser.add_argument("--ssi-release-ref", required=True)
    parser.add_argument("--openid4vci-release-ref", required=True)
    parser.add_argument("--openid4vp-release-ref", required=True)
    arguments = parser.parse_args()
    try:
        if STABLE_VERSION.fullmatch(arguments.identity_version) is None:
            fail(DependencyErrorReason.VERSION_REQUIREMENT_INVALID)
        selected_versions = {
            "ssi": parse_release_ref(arguments.ssi_release_ref, "ssi"),
            "openid4vci": parse_release_ref(
                arguments.openid4vci_release_ref, "openid4vci"
            ),
            "openid4vp": parse_release_ref(
                arguments.openid4vp_release_ref, "openid4vp"
            ),
        }
        verify_dependencies(
            load_workspace_dependencies(arguments.cargo_toml), selected_versions
        )
        verify_identity_version(
            arguments.identity_package_toml, arguments.identity_version
        )
        verify_python_dependencies(
            arguments.python_pyproject, arguments.identity_version
        )
    except DependencyError as error:
        print(
            f"error: Identity release dependencies are invalid ({error.reason.value})",
            file=sys.stderr,
        )
        return 65
    print("Identity dependencies match the selected component releases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
