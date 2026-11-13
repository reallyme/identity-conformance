# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = ROOT / "scripts/verify_identity_release_dependencies.py"
    specification = importlib.util.spec_from_file_location(
        "verify_identity_release_dependencies", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("dependency verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


def dependency(version: str, package: str | None = None) -> dict[str, object]:
    value: dict[str, object] = {"version": version}
    if package is not None:
        value["package"] = package
    return value


def complete_dependencies() -> dict[str, object]:
    dependencies: dict[str, object] = {}
    versions = {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"}
    for component, packages in VERIFIER.REQUIRED_COMPONENT_PACKAGES.items():
        for index, package in enumerate(sorted(packages)):
            dependencies[f"{component}-alias-{index}"] = dependency(
                f"={versions[component]}", package
            )
    return dependencies


class IdentityReleaseDependencyTests(unittest.TestCase):
    def test_complete_exact_dependency_set_passes(self) -> None:
        VERIFIER.verify_dependencies(
            complete_dependencies(),
            {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"},
        )

    def test_release_ref_parsing_is_component_specific(self) -> None:
        self.assertEqual(
            VERIFIER.parse_release_ref("reallyme-openid4vci-v0.3.2", "openid4vci"),
            "0.3.2",
        )
        with self.assertRaises(VERIFIER.DependencyError) as raised:
            VERIFIER.parse_release_ref("reallyme-openid4vp-v0.3.1", "openid4vci")
        self.assertIs(
            raised.exception.reason,
            VERIFIER.DependencyErrorReason.RELEASE_COMPONENT_MISMATCH,
        )

    def test_non_exact_requirement_is_rejected(self) -> None:
        dependencies = complete_dependencies()
        dependencies["openid4vci-alias-0"]["version"] = "0.3.2"
        with self.assertRaises(VERIFIER.DependencyError) as raised:
            VERIFIER.verify_dependencies(
                dependencies,
                {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"},
            )
        self.assertIs(
            raised.exception.reason, VERIFIER.DependencyErrorReason.VERSION_MISMATCH
        )

    def test_mixed_component_version_is_rejected(self) -> None:
        dependencies = complete_dependencies()
        dependencies["openid4vp-alias-0"]["version"] = "=0.3.0"
        with self.assertRaises(VERIFIER.DependencyError) as raised:
            VERIFIER.verify_dependencies(
                dependencies,
                {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"},
            )
        self.assertIs(
            raised.exception.reason, VERIFIER.DependencyErrorReason.VERSION_MISMATCH
        )

    def test_missing_required_package_is_rejected(self) -> None:
        dependencies = complete_dependencies()
        dependencies.pop("ssi-alias-0")
        with self.assertRaises(VERIFIER.DependencyError) as raised:
            VERIFIER.verify_dependencies(
                dependencies,
                {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"},
            )
        self.assertIs(
            raised.exception.reason,
            VERIFIER.DependencyErrorReason.REQUIRED_PACKAGE_MISSING,
        )

    def test_invalid_dependency_shape_is_rejected(self) -> None:
        dependencies = complete_dependencies()
        dependencies["reallyme-openid4vci"] = ["=0.3.2"]
        with self.assertRaises(VERIFIER.DependencyError) as raised:
            VERIFIER.verify_dependencies(
                dependencies,
                {"ssi": "0.6.2", "openid4vci": "0.3.2", "openid4vp": "0.3.1"},
            )
        self.assertIs(
            raised.exception.reason,
            VERIFIER.DependencyErrorReason.WORKSPACE_DEPENDENCIES_INVALID,
        )

    def test_identity_composition_crates_are_not_component_dependencies(self) -> None:
        self.assertIsNone(
            VERIFIER.component_for_package(
                "reallyme-identity-openid4vp-product",
                "reallyme-identity-openid4vp-product",
            )
        )

    def test_identity_version_must_match_the_primary_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(
                '[package]\nname = "reallyme-identity"\nversion = "0.1.1"\n',
                encoding="utf-8",
            )
            VERIFIER.verify_identity_version(path, "0.1.1")
            with self.assertRaises(VERIFIER.DependencyError) as raised:
                VERIFIER.verify_identity_version(path, "0.1.2")
        self.assertIs(
            raised.exception.reason, VERIFIER.DependencyErrorReason.VERSION_MISMATCH
        )

    def test_python_dependency_ranges_are_owned_by_the_candidate(self) -> None:
        valid = (
            '[project]\nname = "reallyme-identity"\nversion = "0.1.1"\n'
            'dependencies = ["protobuf>=7.36.2,<8", "certifi>=2026.1"]\n'
            '[project.optional-dependencies]\n'
            'test = ["cryptography>=50.0.2,<51", "pytest>=8,<10", '
            '"hypothesis>=6"]\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(valid, encoding="utf-8")
            VERIFIER.verify_python_dependencies(path, "0.1.1")
            path.write_text(
                valid.replace("cryptography>=50.0.2,<51", "cryptography>=45,<47"),
                encoding="utf-8",
            )
            VERIFIER.verify_python_dependencies(path, "0.1.1")

    def test_python_dependencies_reject_remote_requirement(self) -> None:
        invalid = (
            '[project]\nname = "reallyme-identity"\nversion = "0.1.1"\n'
            'dependencies = ["protobuf @ https://example.invalid/package.whl"]\n'
            '[project.optional-dependencies]\n'
            'test = ["cryptography>=50", "pytest>=9"]\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(invalid, encoding="utf-8")
            with self.assertRaises(VERIFIER.DependencyError) as raised:
                VERIFIER.verify_python_dependencies(path, "0.1.1")
        self.assertIs(
            raised.exception.reason,
            VERIFIER.DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID,
        )

    def test_python_dependencies_require_boundary_packages(self) -> None:
        invalid = (
            '[project]\nname = "reallyme-identity"\nversion = "0.1.1"\n'
            'dependencies = ["protobuf>=7"]\n'
            '[project.optional-dependencies]\n'
            'test = ["pytest>=9"]\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(invalid, encoding="utf-8")
            with self.assertRaises(VERIFIER.DependencyError) as raised:
                VERIFIER.verify_python_dependencies(path, "0.1.1")
        self.assertIs(
            raised.exception.reason,
            VERIFIER.DependencyErrorReason.PYTHON_DEPENDENCIES_INVALID,
        )


if __name__ == "__main__":
    unittest.main()
