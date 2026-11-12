#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate pinned EU test assets without claiming product execution."""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_eudi_upstream_coverage as coverage_verifier  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPOSITORY_ROOT / "plans/eudi/upstream-assets.json"
SOURCE_LOCK_PATH = REPOSITORY_ROOT / "upstream/eudi/sources.lock.json"
MAX_JSON_BYTES = 1_000_000
MAX_TEXT_BYTES = 4_000_000
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$")
HEADING = re.compile(r"^#{1,6} .+", re.MULTILINE)
FEATURE = re.compile(r"^\s*Feature:\s*\S", re.MULTILINE)
SCENARIO = re.compile(r"^\s*Scenario(?: Outline)?:\s*\S", re.MULTILINE)
GITB_NAMESPACE = "{http://www.gitb.com/tdl/v1/}"
EXPECTED_ASSETS = {
    "fcaf-wallet-methodology": ("eudi-fcaf", "fcaf_methodology"),
    "wallet-ui-tests": ("eudi-functional-tests", "gherkin_inventory"),
    "interoperability-testbed": ("eudi-itb", "gitb_inventory"),
    "age-verification-profile": (
        "eudi-age-verification-specification",
        "age_verification_documents",
    ),
    "rqes-wallet-driven-tester": (
        "eudi-rqes-wallet-driven-tester",
        "python_service_inventory",
    ),
}
ALLOWED_EXECUTION_STATES = {"not_executable", "external_environment_required"}


class AssetErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_PLAN = "invalid_plan"
    SOURCE_LOCK_MISMATCH = "source_lock_mismatch"
    INVALID_CHECKOUT = "invalid_checkout"
    SOURCE_COMMIT_MISMATCH = "source_commit_mismatch"
    UNSAFE_PATH = "unsafe_path"
    REQUIRED_FILE_MISSING = "required_file_missing"
    INVENTORY_MISMATCH = "inventory_mismatch"
    INVALID_GHERKIN = "invalid_gherkin"
    INVALID_XML = "invalid_xml"
    INVALID_PYTHON = "invalid_python"
    INVALID_ENVIRONMENT_TEMPLATE = "invalid_environment_template"
    INVALID_REQUIREMENTS = "invalid_requirements"


@dataclass(frozen=True)
class AssetError(Exception):
    reason: AssetErrorReason


def fail(reason: AssetErrorReason) -> NoReturn:
    print(f"EUDI upstream asset validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: AssetErrorReason = AssetErrorReason.INVALID_PLAN
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AssetError(reason)
    return value


def required_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
    ):
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    return value


def required_count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    return value


def relative_path(value: object) -> str:
    text = required_text(value)
    path = PurePosixPath(text)
    if path.is_absolute() or path.parts[0] in {".", ".."} or ".." in path.parts:
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    return text


def unique_text_list(value: object, *, paths: bool = False) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    items = [relative_path(item) if paths else required_text(item) for item in value]
    if len(items) != len(set(items)):
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    return items


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise AssetError(AssetErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise AssetError(AssetErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise AssetError(AssetErrorReason.INVALID_JSON)
    return value


def validate_plan(
    plan: dict[str, object], sources: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    exact_object(
        plan,
        {
            "$comment",
            "schema",
            "source_lock_path",
            "product_execution_claim",
            "assets",
        },
    )
    if (
        not isinstance(plan["$comment"], str)
        or plan["schema"] != "reallyme.identity.eudi_upstream_assets.v1"
        or plan["source_lock_path"] != "upstream/eudi/sources.lock.json"
        or plan["product_execution_claim"] is not False
        or not isinstance(plan["assets"], list)
    ):
        raise AssetError(AssetErrorReason.INVALID_PLAN)

    assets: dict[str, dict[str, object]] = {}
    for raw_asset in plan["assets"]:
        asset = exact_object(
            raw_asset,
            {
                "asset_id",
                "source_id",
                "validation_kind",
                "validation_scope",
                "execution_state",
                "conformance_claim",
                "expected",
            },
        )
        asset_id = required_text(asset["asset_id"])
        source_id = required_text(asset["source_id"])
        validation_kind = required_text(asset["validation_kind"])
        expected_identity = EXPECTED_ASSETS.get(asset_id)
        if (
            IDENTIFIER.fullmatch(asset_id) is None
            or expected_identity != (source_id, validation_kind)
            or asset_id in assets
            or source_id not in sources
            or asset["validation_scope"]
            not in {
                "source_structure_and_methodology_inventory",
                "source_structure_and_test_inventory",
                "source_structure_and_normative_document_inventory",
                "source_structure_and_deployable_service_inventory",
            }
            or asset["execution_state"] not in ALLOWED_EXECUTION_STATES
            or asset["conformance_claim"] is not False
            or not isinstance(asset["expected"], dict)
        ):
            raise AssetError(AssetErrorReason.INVALID_PLAN)
        assets[asset_id] = asset
    if set(assets) != set(EXPECTED_ASSETS):
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    validate_expectations(assets)
    return assets


def validate_expectations(assets: dict[str, dict[str, object]]) -> None:
    fcaf = exact_object(
        assets["fcaf-wallet-methodology"]["expected"],
        {"markdown_document_count", "wallet_sut_documents"},
    )
    required_count(fcaf["markdown_document_count"])
    unique_text_list(fcaf["wallet_sut_documents"], paths=True)

    ui = exact_object(
        assets["wallet-ui-tests"]["expected"], {"required_files", "platforms"}
    )
    unique_text_list(ui["required_files"], paths=True)
    platforms = ui["platforms"]
    if not isinstance(platforms, list) or len(platforms) != 2:
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    platform_names: set[str] = set()
    for raw_platform in platforms:
        platform = exact_object(
            raw_platform,
            {"name", "root", "feature_file_count", "scenario_count"},
        )
        name = required_text(platform["name"])
        if name not in {"android", "ios"} or name in platform_names:
            raise AssetError(AssetErrorReason.INVALID_PLAN)
        platform_names.add(name)
        relative_path(platform["root"])
        required_count(platform["feature_file_count"])
        required_count(platform["scenario_count"])
    if platform_names != {"android", "ios"}:
        raise AssetError(AssetErrorReason.INVALID_PLAN)

    itb = exact_object(
        assets["interoperability-testbed"]["expected"],
        {"required_files", "suites"},
    )
    unique_text_list(itb["required_files"], paths=True)
    suites = itb["suites"]
    if not isinstance(suites, list) or len(suites) != 5:
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    suite_paths: set[str] = set()
    for raw_suite in suites:
        suite = exact_object(
            raw_suite, {"path", "suite_id", "test_case_ids"}
        )
        path = relative_path(suite["path"])
        if path in suite_paths:
            raise AssetError(AssetErrorReason.INVALID_PLAN)
        suite_paths.add(path)
        required_text(suite["suite_id"])
        unique_text_list(suite["test_case_ids"])

    age = exact_object(
        assets["age-verification-profile"]["expected"],
        {"heading_count", "documents"},
    )
    required_count(age["heading_count"])
    unique_text_list(age["documents"], paths=True)

    rqes = exact_object(
        assets["rqes-wallet-driven-tester"]["expected"],
        {
            "dependency_installation",
            "python_file_count",
            "route_count",
            "required_files",
            "required_environment_keys",
            "requirements_entries",
        },
    )
    if rqes["dependency_installation"] != "prohibited":
        raise AssetError(AssetErrorReason.INVALID_PLAN)
    required_count(rqes["python_file_count"])
    required_count(rqes["route_count"])
    unique_text_list(rqes["required_files"], paths=True)
    unique_text_list(rqes["required_environment_keys"])
    unique_text_list(rqes["requirements_entries"])


def safe_file(root: Path, relative: str) -> Path:
    reject_symlink_components(root, relative)
    try:
        resolved_root = root.resolve(strict=True)
        path = root / relative
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise AssetError(AssetErrorReason.REQUIRED_FILE_MISSING) from error
    if (
        root.is_symlink()
        or path.is_symlink()
        or not path.is_file()
        or not 1 <= metadata.st_size <= MAX_TEXT_BYTES
    ):
        raise AssetError(AssetErrorReason.UNSAFE_PATH)
    return path


def reject_symlink_components(root: Path, relative: str) -> None:
    current = root
    try:
        if current.is_symlink():
            raise AssetError(AssetErrorReason.UNSAFE_PATH)
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise AssetError(AssetErrorReason.UNSAFE_PATH)
    except OSError as error:
        raise AssetError(AssetErrorReason.UNSAFE_PATH) from error


def read_text(root: Path, relative: str) -> str:
    try:
        return safe_file(root, relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AssetError(AssetErrorReason.UNSAFE_PATH) from error


def regular_files(root: Path, relative: str, suffix: str) -> list[Path]:
    reject_symlink_components(root, relative)
    try:
        resolved_root = root.resolve(strict=True)
        directory = (root / relative).resolve(strict=True)
        directory.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise AssetError(AssetErrorReason.REQUIRED_FILE_MISSING) from error
    if root.is_symlink() or not directory.is_dir():
        raise AssetError(AssetErrorReason.UNSAFE_PATH)
    files: list[Path] = []
    for path in sorted(directory.rglob(f"*{suffix}")):
        try:
            metadata = path.lstat()
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise AssetError(AssetErrorReason.UNSAFE_PATH) from error
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_TEXT_BYTES:
            raise AssetError(AssetErrorReason.UNSAFE_PATH)
        files.append(path)
    return files


def verify_checkout_commit(root: Path, expected_commit: str) -> None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AssetError(AssetErrorReason.INVALID_CHECKOUT) from error
    if result.returncode != 0:
        raise AssetError(AssetErrorReason.INVALID_CHECKOUT)
    if result.stdout.strip() != expected_commit:
        raise AssetError(AssetErrorReason.SOURCE_COMMIT_MISMATCH)
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AssetError(AssetErrorReason.INVALID_CHECKOUT) from error
    if status.returncode != 0 or status.stdout:
        raise AssetError(AssetErrorReason.INVALID_CHECKOUT)


def verify_fcaf(root: Path, expected: dict[str, object]) -> None:
    documents = regular_files(root, "docs/fcaf", ".md")
    if len(documents) != expected["markdown_document_count"]:
        raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)
    for relative in expected["wallet_sut_documents"]:
        content = read_text(root, relative)
        if HEADING.search(content) is None:
            raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)


def verify_gherkin(root: Path, expected: dict[str, object]) -> None:
    for relative in expected["required_files"]:
        safe_file(root, relative)
    for platform in expected["platforms"]:
        files = regular_files(root, platform["root"], ".feature")
        scenario_count = 0
        for path in files:
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise AssetError(AssetErrorReason.INVALID_GHERKIN) from error
            scenarios = len(SCENARIO.findall(content))
            if FEATURE.search(content) is None or scenarios < 1:
                raise AssetError(AssetErrorReason.INVALID_GHERKIN)
            scenario_count += scenarios
        if (
            len(files) != platform["feature_file_count"]
            or scenario_count != platform["scenario_count"]
        ):
            raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)


def parse_xml(root: Path, relative: str) -> ElementTree.Element:
    content = read_text(root, relative)
    if "<!DOCTYPE" in content or "<!ENTITY" in content:
        raise AssetError(AssetErrorReason.INVALID_XML)
    try:
        return ElementTree.fromstring(content)
    except ElementTree.ParseError as error:
        raise AssetError(AssetErrorReason.INVALID_XML) from error


def verify_gitb(root: Path, expected: dict[str, object]) -> None:
    for relative in expected["required_files"]:
        safe_file(root, relative)
    for suite in expected["suites"]:
        suite_root = parse_xml(root, suite["path"])
        if (
            suite_root.tag != f"{GITB_NAMESPACE}testsuite"
            or suite_root.attrib.get("id") != suite["suite_id"]
        ):
            raise AssetError(AssetErrorReason.INVALID_XML)
        references = [
            element.attrib.get("id")
            for element in suite_root.findall(f"{GITB_NAMESPACE}testcase")
        ]
        if references != suite["test_case_ids"] or None in references:
            raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)
        suite_directory = PurePosixPath(suite["path"]).parent
        case_directory = suite_directory / "tests"
        case_files = regular_files(root, case_directory.as_posix(), ".xml")
        case_ids: list[str] = []
        for case_file in case_files:
            relative = case_file.relative_to(root.resolve(strict=True)).as_posix()
            case_root = parse_xml(root, relative)
            case_id = case_root.attrib.get("id")
            if case_root.tag != f"{GITB_NAMESPACE}testcase" or case_id is None:
                raise AssetError(AssetErrorReason.INVALID_XML)
            case_ids.append(case_id)
        if len(case_ids) != len(set(case_ids)) or set(case_ids) != set(references):
            raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)


def verify_age_verification(root: Path, expected: dict[str, object]) -> None:
    heading_count = 0
    for relative in expected["documents"]:
        content = read_text(root, relative)
        count = len(HEADING.findall(content))
        if count < 1:
            raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)
        heading_count += count
    if heading_count != expected["heading_count"]:
        raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)


def environment_keys(content: str) -> set[str]:
    keys: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, _value = stripped.partition("=")
        if separator != "=" or re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None or key in keys:
            raise AssetError(AssetErrorReason.INVALID_ENVIRONMENT_TEMPLATE)
        keys.add(key)
    return keys


def verify_requirements(content: str, expected: list[str]) -> None:
    requirements = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    requirement = re.compile(
        r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:==[A-Za-z0-9][A-Za-z0-9_.+-]*)?"
    )
    if (
        not requirements
        or len(requirements) != len(set(requirements))
        or any(requirement.fullmatch(item) is None for item in requirements)
        or requirements != expected
    ):
        raise AssetError(AssetErrorReason.INVALID_REQUIREMENTS)


def verify_python_service(root: Path, expected: dict[str, object]) -> None:
    for relative in expected["required_files"]:
        safe_file(root, relative)
    python_files = regular_files(root, "app", ".py")
    route_count = 0
    for path in python_files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        except (OSError, UnicodeError, SyntaxError) as error:
            raise AssetError(AssetErrorReason.INVALID_PYTHON) from error
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):
                    route_count += 1
    if (
        len(python_files) != expected["python_file_count"]
        or route_count != expected["route_count"]
    ):
        raise AssetError(AssetErrorReason.INVENTORY_MISMATCH)
    keys = environment_keys(read_text(root, ".env.sample"))
    if not set(expected["required_environment_keys"]).issubset(keys):
        raise AssetError(AssetErrorReason.INVALID_ENVIRONMENT_TEMPLATE)
    verify_requirements(
        read_text(root, "requirements.txt"), expected["requirements_entries"]
    )


def verify_assets(
    plan: dict[str, object],
    source_lock: dict[str, object],
    checkouts: dict[str, Path],
    *,
    verify_commits: bool,
) -> None:
    try:
        sources = coverage_verifier.validate_source_lock(source_lock)
    except coverage_verifier.CoverageError as error:
        raise AssetError(AssetErrorReason.SOURCE_LOCK_MISMATCH) from error
    assets = validate_plan(plan, sources)
    expected_sources = {identity[0] for identity in EXPECTED_ASSETS.values()}
    if set(checkouts) != expected_sources:
        raise AssetError(AssetErrorReason.INVALID_CHECKOUT)

    validators = {
        "fcaf_methodology": verify_fcaf,
        "gherkin_inventory": verify_gherkin,
        "gitb_inventory": verify_gitb,
        "age_verification_documents": verify_age_verification,
        "python_service_inventory": verify_python_service,
    }
    for asset in assets.values():
        source_id = asset["source_id"]
        checkout = checkouts[source_id]
        if verify_commits:
            verify_checkout_commit(checkout, sources[source_id]["commit"])
        validator = validators[asset["validation_kind"]]
        validator(checkout, asset["expected"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--fcaf", type=Path)
    parser.add_argument("--functional-tests", type=Path)
    parser.add_argument("--itb", type=Path)
    parser.add_argument("--age-verification", type=Path)
    parser.add_argument("--rqes", type=Path)
    args = parser.parse_args()
    plan = load_object(PLAN_PATH)
    source_lock = load_object(SOURCE_LOCK_PATH)
    if args.plan_only:
        if any(
            value is not None
            for value in (
                args.fcaf,
                args.functional_tests,
                args.itb,
                args.age_verification,
                args.rqes,
            )
        ):
            fail(AssetErrorReason.INVALID_CHECKOUT)
        try:
            sources = coverage_verifier.validate_source_lock(source_lock)
            validate_plan(plan, sources)
        except coverage_verifier.CoverageError:
            fail(AssetErrorReason.SOURCE_LOCK_MISMATCH)
        except AssetError as error:
            fail(error.reason)
        print("EUDI upstream test asset plan matches the reviewed source lock")
        return 0
    if any(
        value is None
        for value in (
            args.fcaf,
            args.functional_tests,
            args.itb,
            args.age_verification,
            args.rqes,
        )
    ):
        fail(AssetErrorReason.INVALID_CHECKOUT)
    checkouts = {
        "eudi-fcaf": args.fcaf,
        "eudi-functional-tests": args.functional_tests,
        "eudi-itb": args.itb,
        "eudi-age-verification-specification": args.age_verification,
        "eudi-rqes-wallet-driven-tester": args.rqes,
    }
    try:
        verify_assets(
            plan,
            source_lock,
            checkouts,
            verify_commits=True,
        )
    except AssetError as error:
        fail(error.reason)
    print("EUDI upstream test assets match the reviewed source inventory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
