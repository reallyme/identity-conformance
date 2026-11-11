#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate composed OpenID4VCI self-assessment evidence before submission."""

from __future__ import annotations

import argparse
import hashlib
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


MAX_JSON_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SENSITIVE_KEY = re.compile(
    r"^(?:d|p|q|dp|dq|qi|oth|k|client_?secret|password|private_?key|"
    r"private_?key_?pem|api_?key|access_?token|refresh_?token|tx_?code|pin)$",
    re.IGNORECASE,
)


class EvidenceError(Exception):
    """A stable, non-sensitive evidence validation failure."""


def fail(reason: str) -> NoReturn:
    raise EvidenceError(reason)


def require_regular_file(path: Path, reason: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError:
        fail(reason)
    if not stat.S_ISREG(metadata.st_mode):
        fail(reason)
    return metadata


def load_object(path: Path, reason: str) -> dict[str, object]:
    before = require_regular_file(path, reason)
    if before.st_size < 1 or before.st_size > MAX_JSON_BYTES:
        fail(reason)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(MAX_JSON_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(opened.st_mode)
            or len(raw) != before.st_size
            or any(
                getattr(before, field) != getattr(opened, field)
                or getattr(before, field) != getattr(after_open, field)
                or getattr(before, field) != getattr(after_path, field)
                for field in stable_fields
            )
        ):
            fail(reason)
        value = strict_json.loads(raw.decode("utf-8"))
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


def sha256_file(path: Path) -> str:
    before = require_regular_file(path, "artifact_unavailable")
    if before.st_size > MAX_ARTIFACT_BYTES:
        fail("artifact_too_large")
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError:
        fail("artifact_unavailable")
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if not stat.S_ISREG(opened.st_mode) or any(
        getattr(before, field) != getattr(opened, field)
        or getattr(before, field) != getattr(after_open, field)
        or getattr(before, field) != getattr(after_path, field)
        for field in stable_fields
    ):
        fail("artifact_changed_while_reading")
    return digest.hexdigest()


def git_output(repository: Path, arguments: list[str], reason: str) -> str:
    # Repository-specific verification must not inherit plumbing variables from
    # a parent release process; those variables can redirect Git to another
    # index or work tree and invalidate the cleanliness decision.
    git_environment = os.environ.copy()
    for variable in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"):
        git_environment.pop(variable, None)
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=git_environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(reason)
    if completed.returncode != 0:
        fail(reason)
    return completed.stdout.strip()


def assert_checkout(repository: Path, expected_commit: str, reason: str) -> None:
    if not repository.is_dir() or repository.is_symlink():
        fail(reason)
    actual_commit = git_output(
        repository, ["rev-parse", "--verify", "HEAD^{commit}"], reason
    )
    if actual_commit != expected_commit:
        fail(reason)
    status = git_output(
        repository, ["status", "--porcelain", "--untracked-files=normal"], reason
    )
    if status:
        fail(reason)


def assert_redacted(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                fail("redacted_configuration_invalid")
            if SENSITIVE_KEY.fullmatch(key) is not None and item != "<redacted>":
                fail("sensitive_configuration_value_retained")
            assert_redacted(item)
    elif isinstance(value, list):
        for item in value:
            assert_redacted(item)


def selected_profiles(plan: dict[str, object]) -> dict[str, tuple[str, str, str]]:
    profiles: dict[str, tuple[str, str, str]] = {}
    for raw_plan in require_array(plan.get("plans"), "certification_plan_invalid"):
        item = require_object(raw_plan, "certification_plan_invalid")
        if item.get("protocol") != "openid4vci":
            continue
        role = require_string(item.get("role"), "certification_plan_invalid")
        plan_id = require_string(item.get("plan_id"), "certification_plan_invalid")
        if role not in {"issuer", "wallet"}:
            fail("certification_plan_invalid")
        for raw_run in require_array(
            item.get("certification_runs"), "certification_plan_invalid"
        ):
            run = require_object(raw_run, "certification_plan_invalid")
            profile_id = require_string(run.get("profile_id"), "profile_id_invalid")
            expression = require_string(
                run.get("expression"), "plan_expression_invalid"
            )
            if PROFILE_ID.fullmatch(profile_id) is None or profile_id in profiles:
                fail("profile_id_invalid")
            profiles[profile_id] = (role, plan_id, expression)
    if len(profiles) != 10:
        fail("certification_profile_count_invalid")
    return profiles


def supported_profiles(matrix: dict[str, object]) -> dict[str, dict[str, object]]:
    supported: dict[str, dict[str, object]] = {}
    for raw_profile in require_array(
        matrix.get("profiles"), "profile_matrix_invalid"
    ):
        profile = require_object(raw_profile, "profile_matrix_invalid")
        profile_id = require_string(
            profile.get("profile_id"), "profile_matrix_invalid"
        )
        if PROFILE_ID.fullmatch(profile_id) is None or profile_id in supported:
            fail("profile_matrix_invalid")
        supported[profile_id] = profile
    return supported


def component(
    product_bom: dict[str, object], component_id: str
) -> tuple[str, str]:
    matches: list[tuple[str, str]] = []
    for raw_item in require_array(product_bom.get("components"), "product_bom_invalid"):
        item = require_object(raw_item, "product_bom_invalid")
        if item.get("component_id") == component_id:
            repository = require_string(
                item.get("repository"), "product_bom_invalid"
            )
            commit = require_string(item.get("commit"), "product_bom_invalid")
            if GIT_COMMIT.fullmatch(commit) is None:
                fail("product_bom_invalid")
            matches.append((repository, commit))
    if len(matches) != 1:
        fail("product_bom_invalid")
    return matches[0]


def deployment_role(
    manifest: dict[str, object], role: str
) -> dict[str, object]:
    roles = require_object(manifest.get("roles"), "deployment_manifest_invalid")
    return require_object(roles.get(role), "deployment_manifest_invalid")


def run_assertion(arguments: list[str], reason: str) -> None:
    try:
        completed = subprocess.run(arguments, check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        fail(reason)
    if completed.returncode != 0:
        fail(reason)


def validate_profile(
    *,
    result_root: Path,
    profile_id: str,
    selection: tuple[str, str, str],
    supported: dict[str, object],
    suite_commit: str,
    source_repository: str,
    source_commit: str,
    issuer_deployment: dict[str, object],
    wallet_deployment: dict[str, object],
    issuer_binary_digest: str,
    wallet_binary_digest: str,
    issuer_deployment_artifact_digest: str,
    wallet_deployment_artifact_digest: str,
    result_assertion: Path,
    module_inventory: Path,
    wallet_assertion: Path,
) -> None:
    role, plan_id, expression = selection
    expected_entity = "credential_issuer" if role == "issuer" else "wallet"
    if (
        supported.get("entity_under_test") != expected_entity
        or supported.get("plan_id") != plan_id
        or supported.get("plan_expression") != expression
    ):
        fail("selected_profile_not_supported")
    expected_count = supported.get("expected_module_count")
    if (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or expected_count < 1
    ):
        fail("profile_module_count_invalid")

    profile_dir = result_root / role / profile_id
    if not profile_dir.is_dir() or profile_dir.is_symlink():
        fail("profile_evidence_missing")
    summary = load_object(profile_dir / "summary.json", "profile_summary_invalid")
    if (
        summary.get("schema_version") != 3
        or summary.get("source_repository") != source_repository
        or summary.get("source_commit") != source_commit
        or summary.get("source_worktree_clean") is not True
        or summary.get("profile_id") != profile_id
        or summary.get("plan_id") != plan_id
        or summary.get("plan_expression") != expression
        or summary.get("suite_commit") != suite_commit
        or summary.get("result") != "passed"
    ):
        fail("profile_summary_invalid")

    revision = require_regular_file(
        profile_dir / "oidf-suite-revision.txt", "suite_revision_evidence_invalid"
    )
    if revision.st_size > 128:
        fail("suite_revision_evidence_invalid")
    try:
        retained_revision = (profile_dir / "oidf-suite-revision.txt").read_text(
            encoding="ascii"
        ).strip()
    except (OSError, UnicodeError):
        fail("suite_revision_evidence_invalid")
    if retained_revision != suite_commit:
        fail("suite_revision_evidence_invalid")

    export_dir = profile_dir / "suite-export"
    if not export_dir.is_dir() or export_dir.is_symlink():
        fail("suite_export_invalid")
    exports = [item for item in export_dir.iterdir() if item.suffix == ".zip"]
    if len(exports) != 1 or any(item.is_symlink() for item in exports):
        fail("suite_export_invalid")
    export_digest = sha256_file(exports[0])
    if summary.get("suite_export_sha256") != export_digest:
        fail("suite_export_digest_mismatch")

    config_field = "issuer_config" if role == "issuer" else "wallet_config"
    config_name = require_string(
        summary.get(config_field), "redacted_configuration_invalid"
    )
    if Path(config_name).name != config_name or not config_name.endswith(
        ".redacted.json"
    ):
        fail("redacted_configuration_invalid")
    config = load_object(profile_dir / config_name, "redacted_configuration_invalid")
    assert_redacted(config)
    alias = require_string(config.get("alias"), "redacted_configuration_invalid")

    run_assertion(
        [
            os.fspath(result_assertion),
            os.fspath(export_dir),
            str(expected_count),
            os.fspath(module_inventory),
            expression,
            alias,
        ],
        "suite_result_assertion_failed",
    )

    if role == "issuer":
        artifact = require_object(
            issuer_deployment.get("artifact"), "deployment_manifest_invalid"
        )
        endpoints = require_object(
            issuer_deployment.get("endpoints"), "deployment_manifest_invalid"
        )
        if (
            summary.get("issuer_binary_sha256") != issuer_binary_digest
            or artifact.get("sha256") != issuer_deployment_artifact_digest
            or summary.get("issuer_base_url") != endpoints.get("issuer_base_url")
        ):
            fail("issuer_deployment_provenance_mismatch")
        return

    artifact = require_object(
        wallet_deployment.get("artifact"), "deployment_manifest_invalid"
    )
    endpoints = require_object(
        wallet_deployment.get("endpoints"), "deployment_manifest_invalid"
    )
    wallet_repository = require_string(
        wallet_deployment.get("source_repository"), "deployment_manifest_invalid"
    )
    wallet_commit = require_string(
        wallet_deployment.get("source_commit"), "deployment_manifest_invalid"
    )
    if (
        summary.get("implementation_source_repository") != wallet_repository
        or summary.get("implementation_source_commit") != wallet_commit
        or summary.get("implementation_source_worktree_clean") is not True
        or summary.get("implementation_binary_sha256") != wallet_binary_digest
        or artifact.get("sha256") != wallet_deployment_artifact_digest
        or summary.get("wallet_harness_endpoint")
        != endpoints.get("wallet_harness_endpoint")
        or summary.get("wallet_harness_health_endpoint")
        != endpoints.get("wallet_harness_health_endpoint")
    ):
        fail("wallet_deployment_provenance_mismatch")
    implementation_evidence = profile_dir / "wallet-implementation-evidence"
    expected_evidence_count = summary.get("implementation_evidence_count")
    if (
        not implementation_evidence.is_dir()
        or implementation_evidence.is_symlink()
        or not isinstance(expected_evidence_count, int)
        or isinstance(expected_evidence_count, bool)
        or expected_evidence_count < 1
        or len(list(implementation_evidence.glob("*.json")))
        != expected_evidence_count
    ):
        fail("wallet_implementation_evidence_invalid")
    launch_mode = (
        "issuer_initiated"
        if "[vci_authorization_code_flow_variant=issuer_initiated]" in expression
        else "wallet_initiated"
    )
    run_assertion(
        [
            sys.executable,
            os.fspath(wallet_assertion),
            os.fspath(export_dir),
            os.fspath(implementation_evidence),
            launch_mode,
        ],
        "wallet_implementation_evidence_invalid",
    )


def validate(args: argparse.Namespace) -> None:
    if args.result_root.is_symlink():
        fail("result_root_invalid")
    result_root = args.result_root.resolve(strict=True)
    if not result_root.is_dir() or result_root.is_symlink():
        fail("result_root_invalid")
    plan = load_object(args.certification_plan, "certification_plan_invalid")
    matrix = load_object(args.profile_matrix, "profile_matrix_invalid")
    suite_contract = load_object(args.suite_contract, "suite_contract_invalid")
    product_bom = load_object(args.product_component_bom, "product_bom_invalid")
    deployment = load_object(
        args.deployment_manifest, "deployment_manifest_invalid"
    )
    require_string(deployment.get("product_name"), "deployment_manifest_invalid")
    require_string(deployment.get("product_version"), "deployment_manifest_invalid")

    suite_commit = require_string(
        suite_contract.get("commit"), "suite_contract_invalid"
    )
    if GIT_COMMIT.fullmatch(suite_commit) is None:
        fail("suite_contract_invalid")
    selected = selected_profiles(plan)
    supported = supported_profiles(matrix)
    source_repository, source_commit = component(product_bom, "openid4vci")
    if matrix.get("source_repository") != source_repository:
        fail("profile_matrix_source_mismatch")
    issuer_deployment = deployment_role(deployment, "openid4vci_issuer")
    wallet_deployment = deployment_role(deployment, "openid4vci_wallet")
    if (
        issuer_deployment.get("source_repository") != source_repository
        or issuer_deployment.get("source_commit") != source_commit
    ):
        fail("issuer_source_binding_mismatch")
    require_string(
        wallet_deployment.get("source_repository"), "deployment_manifest_invalid"
    )
    wallet_commit = require_string(
        wallet_deployment.get("source_commit"), "deployment_manifest_invalid"
    )
    if GIT_COMMIT.fullmatch(wallet_commit) is None:
        fail("deployment_manifest_invalid")

    assert_checkout(
        args.openid4vci_source_dir, source_commit, "openid4vci_checkout_mismatch"
    )
    assert_checkout(args.wallet_source_dir, wallet_commit, "wallet_checkout_mismatch")
    issuer_binary_digest = sha256_file(args.issuer_binary)
    wallet_binary_digest = sha256_file(args.wallet_binary)
    issuer_deployment_artifact_digest = sha256_file(
        args.issuer_deployment_artifact
    )
    wallet_deployment_artifact_digest = sha256_file(
        args.wallet_deployment_artifact
    )
    require_regular_file(args.result_assertion, "result_assertion_unavailable")
    require_regular_file(args.wallet_assertion, "wallet_assertion_unavailable")
    require_regular_file(args.module_inventory, "module_inventory_unavailable")

    for profile_id, selection in selected.items():
        profile = supported.get(profile_id)
        if profile is None:
            fail("selected_profile_not_supported")
        validate_profile(
            result_root=result_root,
            profile_id=profile_id,
            selection=selection,
            supported=profile,
            suite_commit=suite_commit,
            source_repository=source_repository,
            source_commit=source_commit,
            issuer_deployment=issuer_deployment,
            wallet_deployment=wallet_deployment,
            issuer_binary_digest=issuer_binary_digest,
            wallet_binary_digest=wallet_binary_digest,
            issuer_deployment_artifact_digest=issuer_deployment_artifact_digest,
            wallet_deployment_artifact_digest=wallet_deployment_artifact_digest,
            result_assertion=args.result_assertion,
            module_inventory=args.module_inventory,
            wallet_assertion=args.wallet_assertion,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", required=True, type=Path)
    parser.add_argument("--certification-plan", required=True, type=Path)
    parser.add_argument("--profile-matrix", required=True, type=Path)
    parser.add_argument("--suite-contract", required=True, type=Path)
    parser.add_argument("--product-component-bom", required=True, type=Path)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--openid4vci-source-dir", required=True, type=Path)
    parser.add_argument("--wallet-source-dir", required=True, type=Path)
    parser.add_argument("--issuer-binary", required=True, type=Path)
    parser.add_argument("--wallet-binary", required=True, type=Path)
    parser.add_argument("--issuer-deployment-artifact", required=True, type=Path)
    parser.add_argument("--wallet-deployment-artifact", required=True, type=Path)
    parser.add_argument("--result-assertion", required=True, type=Path)
    parser.add_argument("--wallet-assertion", required=True, type=Path)
    parser.add_argument("--module-inventory", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate(args)
    except (EvidenceError, OSError) as error:
        reason = (
            str(error)
            if isinstance(error, EvidenceError)
            else "evidence_io_failure"
        )
        print(f"OpenID4VCI pre-submission evidence invalid: {reason}", file=sys.stderr)
        return 70
    print("OpenID4VCI pre-submission evidence covers all ten composed profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
