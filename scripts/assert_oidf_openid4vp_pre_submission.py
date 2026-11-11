#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate composed OpenID4VP self-assessment evidence before submission."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


MAX_JSON_BYTES = 2 * 1024 * 1024
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class EvidenceError(Exception):
    """A stable, non-sensitive evidence validation failure."""


def fail(reason: str) -> NoReturn:
    raise EvidenceError(reason)


def load_object(path: Path, reason: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 1
            or metadata.st_size > MAX_JSON_BYTES
        ):
            fail(reason)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(reason)
    if not isinstance(value, dict):
        fail(reason)
    return value


def require_string(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value or any(ord(item) < 32 for item in value):
        fail(reason)
    return value


def require_object(value: object, reason: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def require_array(value: object, reason: str) -> list[object]:
    if not isinstance(value, list):
        fail(reason)
    return value


def selected_profiles(
    plan: dict[str, object],
) -> dict[str, tuple[str, str, str]]:
    profiles: dict[str, tuple[str, str, str]] = {}
    for raw_plan in require_array(plan.get("plans"), "certification_plan_invalid"):
        item = require_object(raw_plan, "certification_plan_invalid")
        if item.get("protocol") != "openid4vp":
            continue
        role = require_string(item.get("role"), "certification_plan_invalid")
        plan_id = require_string(item.get("plan_id"), "certification_plan_invalid")
        if role not in {"verifier", "wallet"}:
            fail("certification_plan_invalid")
        for raw_run in require_array(
            item.get("certification_runs"), "certification_plan_invalid"
        ):
            run = require_object(raw_run, "certification_plan_invalid")
            profile_id = require_string(run.get("profile_id"), "profile_id_invalid")
            expression = require_string(run.get("expression"), "plan_expression_invalid")
            if PROFILE_ID.fullmatch(profile_id) is None or profile_id in profiles:
                fail("profile_id_invalid")
            profiles[profile_id] = (role, plan_id, expression)
    if len(profiles) != 6:
        fail("certification_profile_count_invalid")
    return profiles


def supported_profiles(matrix: dict[str, object]) -> dict[str, dict[str, object]]:
    supported: dict[str, dict[str, object]] = {}
    for raw_profile in require_array(matrix.get("profiles"), "profile_matrix_invalid"):
        profile = require_object(raw_profile, "profile_matrix_invalid")
        profile_id = require_string(profile.get("id"), "profile_matrix_invalid")
        if PROFILE_ID.fullmatch(profile_id) is None or profile_id in supported:
            fail("profile_matrix_invalid")
        supported[profile_id] = profile
    return supported


def expected_module_count(profile: dict[str, object]) -> int:
    total = 0
    for raw_group in require_array(profile.get("expected_groups"), "profile_matrix_invalid"):
        group = require_object(raw_group, "profile_matrix_invalid")
        modules = require_array(group.get("modules"), "profile_matrix_invalid")
        if not modules:
            fail("profile_matrix_invalid")
        for module in modules:
            require_string(module, "profile_matrix_invalid")
        total += len(modules)
    return total


def locked_component(product_bom: dict[str, object]) -> tuple[str, str]:
    matches: list[tuple[str, str]] = []
    for raw_item in require_array(product_bom.get("components"), "product_bom_invalid"):
        item = require_object(raw_item, "product_bom_invalid")
        if item.get("component_id") != "openid4vp":
            continue
        repository = require_string(item.get("repository"), "product_bom_invalid")
        commit = require_string(item.get("commit"), "product_bom_invalid")
        if GIT_COMMIT.fullmatch(commit) is None:
            fail("product_bom_invalid")
        matches.append((repository, commit))
    if len(matches) != 1:
        fail("product_bom_invalid")
    return matches[0]


def git_output(repository: Path, arguments: list[str], reason: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(reason)
    if completed.returncode != 0:
        fail(reason)
    return completed.stdout.strip()


def assert_checkout(repository: Path, expected_commit: str) -> None:
    if not repository.is_dir() or repository.is_symlink():
        fail("openid4vp_checkout_mismatch")
    if (
        git_output(
            repository,
            ["rev-parse", "--verify", "HEAD^{commit}"],
            "openid4vp_checkout_mismatch",
        )
        != expected_commit
    ):
        fail("openid4vp_checkout_mismatch")
    if git_output(
        repository,
        ["status", "--porcelain", "--untracked-files=normal"],
        "openid4vp_checkout_mismatch",
    ):
        fail("openid4vp_checkout_mismatch")


def plan_instance_id(result_root: Path, role: str, profile_id: str) -> str:
    if role == "verifier":
        index = load_object(
            result_root
            / "control"
            / role
            / "implementation-evidence"
            / profile_id
            / "index.json",
            "implementation_evidence_invalid",
        )
        driver = load_object(
            result_root / "control" / role / "oidf-verifier-flow-drivers" / f"{profile_id}.json",
            "flow_driver_evidence_invalid",
        )
        expected = require_string(index.get("plan_instance_id"), "implementation_evidence_invalid")
        if driver.get("plan_instance_id") != expected:
            fail("plan_instance_binding_mismatch")
        return expected
    driver = load_object(
        result_root / "control" / role / f"oidf-wallet-flow-driver-{profile_id}.json",
        "flow_driver_evidence_invalid",
    )
    return require_string(driver.get("plan_instance_id"), "flow_driver_evidence_invalid")


def assert_profile(
    result_root: Path,
    profile_id: str,
    selection: tuple[str, str, str],
    profile: dict[str, object],
    result_assertion: Path,
    profile_matrix: Path,
) -> None:
    role, plan_id, expression = selection
    if (
        profile.get("role") != role
        or profile.get("plan_id") != plan_id
        or profile.get("expression") != expression
    ):
        fail("selected_profile_not_supported")
    module_count = expected_module_count(profile)
    result = load_object(
        result_root / "control" / role / f"{profile_id}.json",
        "profile_result_invalid",
    )
    if (
        result.get("profile_id") != profile_id
        or result.get("plan_id") != plan_id
        or result.get("status") != "validated"
        or result.get("triggered_modules") != module_count
    ):
        fail("profile_result_invalid")
    export_dir = result_root / "exports" / role / profile_id
    if not export_dir.is_dir() or export_dir.is_symlink():
        fail("profile_export_invalid")
    instance_id = plan_instance_id(result_root, role, profile_id)
    try:
        completed = subprocess.run(
            [
                os.fspath(result_assertion),
                os.fspath(export_dir),
                "--matrix",
                os.fspath(profile_matrix),
                "--profile",
                profile_id,
                "--expected-plan-instance-id",
                instance_id,
            ],
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("suite_result_assertion_failed")
    if completed.returncode != 0:
        fail("suite_result_assertion_failed")


def validate(args: argparse.Namespace) -> None:
    result_root = args.result_root.resolve(strict=True)
    if not result_root.is_dir() or result_root.is_symlink():
        fail("result_root_invalid")
    plan = load_object(args.certification_plan, "certification_plan_invalid")
    matrix = load_object(args.profile_matrix, "profile_matrix_invalid")
    product_bom = load_object(args.product_component_bom, "product_bom_invalid")
    deployment = load_object(args.deployment_manifest, "deployment_manifest_invalid")
    require_string(deployment.get("product_name"), "deployment_manifest_invalid")
    require_string(deployment.get("product_version"), "deployment_manifest_invalid")
    selected = selected_profiles(plan)
    supported = supported_profiles(matrix)
    suite = require_object(matrix.get("suite"), "profile_matrix_invalid")
    suite_commit = require_string(suite.get("commit"), "profile_matrix_invalid")
    if GIT_COMMIT.fullmatch(suite_commit) is None:
        fail("profile_matrix_invalid")
    suite_revision_path = result_root / "oidf-suite-revision.txt"
    try:
        suite_revision_metadata = suite_revision_path.lstat()
        if (
            not stat.S_ISREG(suite_revision_metadata.st_mode)
            or suite_revision_metadata.st_size != 41
        ):
            fail("suite_revision_evidence_invalid")
        suite_revision = suite_revision_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        fail("suite_revision_evidence_invalid")
    if suite_revision != suite_commit:
        fail("suite_revision_evidence_invalid")
    repository, commit = locked_component(product_bom)
    if matrix.get("source_repository") != repository:
        fail("profile_matrix_source_mismatch")
    assert_checkout(args.openid4vp_source_dir, commit)
    if not args.result_assertion.is_file() or args.result_assertion.is_symlink():
        fail("result_assertion_unavailable")
    for profile_id, selection in selected.items():
        profile = supported.get(profile_id)
        if profile is None:
            fail("selected_profile_not_supported")
        assert_profile(
            result_root,
            profile_id,
            selection,
            profile,
            args.result_assertion,
            args.profile_matrix,
        )
    expected_by_role = {
        role: {
            profile_id
            for profile_id, (item_role, _, _) in selected.items()
            if item_role == role
        }
        for role in ("verifier", "wallet")
    }
    for role, expected in expected_by_role.items():
        export_root = result_root / "exports" / role
        try:
            observed = {
                item.name
                for item in export_root.iterdir()
                if item.is_dir() and not item.is_symlink()
            }
        except OSError:
            fail("profile_export_inventory_invalid")
        if observed != expected:
            fail("profile_export_inventory_invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", required=True, type=Path)
    parser.add_argument("--certification-plan", required=True, type=Path)
    parser.add_argument("--profile-matrix", required=True, type=Path)
    parser.add_argument("--product-component-bom", required=True, type=Path)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--openid4vp-source-dir", required=True, type=Path)
    parser.add_argument("--result-assertion", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate(args)
    except (EvidenceError, OSError) as error:
        reason = str(error) if isinstance(error, EvidenceError) else "evidence_io_failure"
        print(f"OpenID4VP pre-submission evidence invalid: {reason}", file=sys.stderr)
        return 70
    print("OpenID4VP pre-submission evidence covers all six composed profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
