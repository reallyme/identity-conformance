#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a disclosure-safe statement for one passing product execution."""

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

import strict_json  # noqa: E402
import verify_eudi_wallet_execution_result as wallet_result_validator  # noqa: E402
import verify_product_component_bom as product_bom_validator  # noqa: E402


MAX_INPUT_BYTES = 16 * 1024 * 1024
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent
OIDF_CERTIFICATION_PLAN_PATH = REPOSITORY_ROOT / "plans/oidf/certification.json"
OIDF_MODULE_SNAPSHOT_PATH = (
    REPOSITORY_ROOT / "upstream/oidf/snapshots/certification-modules.json"
)
OIDF_SUITE_LOCK_PATH = REPOSITORY_ROOT / "upstream/oidf/conformance-suite.lock.json"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RELEASE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
RELEASE_REF = re.compile(
    r"^reallyme-[a-z0-9-]+-v"
    r"(?P<version>(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$"
)
REPOSITORY = re.compile(r"^https://github\.com/reallyme/[A-Za-z0-9_.-]+$")
WORKFLOW_REPOSITORY = re.compile(r"^reallyme/[A-Za-z0-9_.-]+$")


class StatementErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    FRAMEWORK_SELECTION_INVALID = "framework_selection_invalid"
    PRODUCT_RELEASE_INVALID = "product_release_invalid"
    EXECUTION_IDENTITY_INVALID = "execution_identity_invalid"
    RESULT_INVALID = "result_invalid"
    OUTPUT_FAILED = "output_failed"


@dataclass(frozen=True)
class StatementError(Exception):
    reason: StatementErrorReason


def fail(reason: StatementErrorReason) -> NoReturn:
    print(f"product conformance statement failed: {reason.value}", file=sys.stderr)
    raise SystemExit(65)


def read_regular_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise StatementError(StatementErrorReason.INPUT_INVALID)
        if not 1 <= before.st_size <= MAX_INPUT_BYTES:
            raise StatementError(StatementErrorReason.INPUT_INVALID)
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
                raise StatementError(StatementErrorReason.INPUT_INVALID)
            content = handle.read(MAX_INPUT_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as error:
        raise StatementError(StatementErrorReason.INPUT_INVALID) from error
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
        raise StatementError(StatementErrorReason.INPUT_INVALID)
    return content


def read_object(path: Path) -> dict[str, object]:
    try:
        value = strict_json.loads(read_regular_bytes(path).decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise StatementError(StatementErrorReason.INPUT_INVALID) from error
    if not isinstance(value, dict):
        raise StatementError(StatementErrorReason.INPUT_INVALID)
    return value


def validate_framework_selection(value: dict[str, object]) -> dict[str, object]:
    expected_keys = {
        "schema",
        "release_version",
        "release_tag",
        "release_url",
        "repository_commit",
        "manifest_sha256",
        "input_set_sha256",
    }
    version = value.get("release_version")
    tag = value.get("release_tag")
    if (
        set(value) != expected_keys
        or value.get("schema")
        != "reallyme.identity.published_framework_selection.v1"
        or not isinstance(version, str)
        or RELEASE_VERSION.fullmatch(version) is None
        or tag != f"v{version}"
        or value.get("release_url")
        != f"https://github.com/reallyme/identity-conformance/releases/tag/{tag}"
        or not isinstance(value.get("repository_commit"), str)
        or COMMIT.fullmatch(value["repository_commit"]) is None
        or not isinstance(value.get("manifest_sha256"), str)
        or SHA256.fullmatch(value["manifest_sha256"]) is None
        or not isinstance(value.get("input_set_sha256"), str)
        or SHA256.fullmatch(value["input_set_sha256"]) is None
    ):
        raise StatementError(StatementErrorReason.FRAMEWORK_SELECTION_INVALID)
    return value


def oidf_coverage(result: dict[str, object]) -> dict[str, object]:
    protocol = result.get("protocol")
    suite_revision = result.get("suite_revision")
    artifacts = result.get("artifacts")
    if (
        protocol not in {"openid4vci", "openid4vp"}
        or not isinstance(suite_revision, str)
        or COMMIT.fullmatch(suite_revision) is None
        or not isinstance(artifacts, list)
        or not 1 <= len(artifacts) <= 4096
    ):
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    suite_lock = read_object(OIDF_SUITE_LOCK_PATH)
    snapshot = read_object(OIDF_MODULE_SNAPSHOT_PATH)
    plan = read_object(OIDF_CERTIFICATION_PLAN_PATH)
    if (
        suite_lock.get("commit") != suite_revision
        or snapshot.get("suite_commit") != suite_revision
        or not isinstance(snapshot.get("plans"), list)
        or not isinstance(plan.get("plans"), list)
    ):
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    artifact_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        path = artifact["path"]
        if path in artifact_paths:
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        artifact_paths.add(path)

    roles: list[dict[str, object]] = []
    total_profiles = 0
    total_executions = 0
    selected_plans = [
        item
        for item in plan["plans"]
        if isinstance(item, dict) and item.get("protocol") == protocol
    ]
    if len(selected_plans) != 2:
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    for selected in selected_plans:
        plan_id = selected.get("plan_id")
        role = selected.get("role")
        runs = selected.get("certification_runs")
        if (
            not isinstance(plan_id, str)
            or not isinstance(role, str)
            or role not in {"issuer", "wallet", "verifier"}
            or not isinstance(runs, list)
            or not runs
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        profile_ids: list[str] = []
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("profile_id"), str):
                raise StatementError(StatementErrorReason.RESULT_INVALID)
            profile_id = run["profile_id"]
            if profile_id in profile_ids:
                raise StatementError(StatementErrorReason.RESULT_INVALID)
            profile_ids.append(profile_id)
        matches = [
            item
            for item in snapshot["plans"]
            if isinstance(item, dict) and item.get("plan_id") == plan_id
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("configurations"), list):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        configurations = matches[0]["configurations"]
        observed_profiles: set[str] = set()
        execution_count = 0
        for configuration in configurations:
            if (
                not isinstance(configuration, dict)
                or not isinstance(configuration.get("selected_variants"), dict)
                or not isinstance(
                    configuration["selected_variants"].get("profile_id"), str
                )
                or type(configuration.get("module_count")) is not int
                or configuration["module_count"] < 1
                or not isinstance(configuration.get("modules"), list)
                or len(configuration["modules"]) != configuration["module_count"]
            ):
                raise StatementError(StatementErrorReason.RESULT_INVALID)
            profile_id = configuration["selected_variants"]["profile_id"]
            if profile_id in observed_profiles:
                raise StatementError(StatementErrorReason.RESULT_INVALID)
            observed_profiles.add(profile_id)
            execution_count += configuration["module_count"]
        if observed_profiles != set(profile_ids):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        for profile_id in profile_ids:
            prefix = f"{role}/{profile_id}/"
            if (
                f"{prefix}summary.json" not in artifact_paths
                or not any(
                    path.startswith(f"{prefix}suite-export/")
                    for path in artifact_paths
                )
            ):
                raise StatementError(StatementErrorReason.RESULT_INVALID)
        roles.append(
            {
                "role": role,
                "profile_count": len(profile_ids),
                "module_execution_count": execution_count,
            }
        )
        total_profiles += len(profile_ids)
        total_executions += execution_count
    return {
        "authority": "openid_foundation_hosted_suite",
        "protocol": protocol,
        "suite_revision": suite_revision,
        "profile_count": total_profiles,
        "module_execution_count": total_executions,
        "roles": sorted(roles, key=lambda item: str(item["role"])),
        "certification_claim": False,
    }


def oidf_composition(result: dict[str, object]) -> list[dict[str, object]]:
    raw_components = result.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != 6:
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    expected_ids = {"openid4vci", "openid4vp", "wallet", "ssi", "identity", "cose"}
    observed: set[str] = set()
    composition: list[dict[str, object]] = []
    for raw_component in raw_components:
        if not isinstance(raw_component, dict) or set(raw_component) != {
            "component_id",
            "repository",
            "commit",
            "release_ref",
            "release_artifact_sha256",
            "component_attestation_sha256",
            "roles",
        }:
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        component_id = raw_component["component_id"]
        roles = raw_component["roles"]
        if (
            not isinstance(component_id, str)
            or component_id not in expected_ids
            or component_id in observed
            or raw_component["repository"]
            != f"https://github.com/reallyme/{component_id}"
            or not isinstance(raw_component["commit"], str)
            or COMMIT.fullmatch(raw_component["commit"]) is None
            or not isinstance(raw_component["release_ref"], str)
            or RELEASE_REF.fullmatch(raw_component["release_ref"]) is None
            or not raw_component["release_ref"].startswith(
                f"reallyme-{component_id}-v"
            )
            or not isinstance(raw_component["release_artifact_sha256"], str)
            or SHA256.fullmatch(raw_component["release_artifact_sha256"]) is None
            or not isinstance(raw_component["component_attestation_sha256"], str)
            or SHA256.fullmatch(raw_component["component_attestation_sha256"])
            is None
            or not isinstance(roles, list)
            or not roles
            or len(roles) != len(set(roles))
            or not all(
                isinstance(role, str) and IDENTIFIER.fullmatch(role) for role in roles
            )
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        observed.add(component_id)
        composition.append(raw_component)
    if observed != expected_ids:
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    return sorted(composition, key=lambda item: str(item["component_id"]))


def build_statement(
    framework_selection: dict[str, object],
    result_bytes: bytes,
    plan_id: str,
    product_id: str,
    product_release_ref: str,
    product_repository: str,
    product_commit: str,
    workflow_repository: str,
    workflow_revision: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, object]:
    framework = validate_framework_selection(framework_selection)
    release_match = RELEASE_REF.fullmatch(product_release_ref)
    if (
        IDENTIFIER.fullmatch(plan_id) is None
        or IDENTIFIER.fullmatch(product_id) is None
        or release_match is None
        or REPOSITORY.fullmatch(product_repository) is None
        or COMMIT.fullmatch(product_commit) is None
    ):
        raise StatementError(StatementErrorReason.PRODUCT_RELEASE_INVALID)
    if (
        WORKFLOW_REPOSITORY.fullmatch(workflow_repository) is None
        or COMMIT.fullmatch(workflow_revision) is None
        or not 1 <= run_id <= 9_223_372_036_854_775_807
        or not 1 <= run_attempt <= 2_147_483_647
    ):
        raise StatementError(StatementErrorReason.EXECUTION_IDENTITY_INVALID)
    try:
        result = strict_json.loads(result_bytes.decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise StatementError(StatementErrorReason.RESULT_INVALID) from error
    if not isinstance(result, dict):
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    framework_commit = framework["repository_commit"]
    candidate_sha256: object
    coverage: dict[str, object]
    composition: list[dict[str, object]] | None = None
    release_evidence: dict[str, object] | None = None
    component = result.get("component")
    if result.get("result") == "passed":
        try:
            wallet_result_validator.verify_result(result)
        except wallet_result_validator.runner.EudiWalletRunnerError as error:
            raise StatementError(StatementErrorReason.RESULT_INVALID) from error
        if (
            result.get("framework_revision") != framework_commit
            or result.get("plan_id") != plan_id
            or not isinstance(component, dict)
            or component.get("component_id") != product_id
            or component.get("release_ref") != product_release_ref
            or component.get("repository") != product_repository
            or component.get("commit") != product_commit
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        candidate_sha256 = result.get("candidate_sha256")
        raw_coverage = result.get("coverage")
        raw_release_evidence = result.get("release_evidence")
        if not isinstance(raw_coverage, dict) or not isinstance(
            raw_release_evidence, dict
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        coverage = raw_coverage
        release_evidence = raw_release_evidence
    elif (
        result.get("schema_version") == 3
        and result.get("protocol") in {"openid4vci", "openid4vp"}
    ):
        product = result.get("product")
        inputs = result.get("inputs")
        if not isinstance(product, dict) or not isinstance(inputs, dict):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        product_bom = inputs.get("product_component_bom")
        if (
            result.get("framework_revision") != framework_commit
            or product.get("product_id") != product_id
            or product.get("product_version") != release_match.group("version")
            or product.get("release_ref") != product_release_ref
            or product.get("repository") != product_repository
            or product.get("commit") != product_commit
            or not isinstance(product_bom, dict)
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        candidate_sha256 = product_bom.get("canonical_sha256")
        coverage = oidf_coverage(result)
        composition = oidf_composition(result)
        identity_components = [
            component
            for component in composition
            if component.get("component_id") == "identity"
        ]
        if len(identity_components) != 1 or (
            identity_components[0].get("repository") != product_repository
            or identity_components[0].get("commit") != product_commit
            or identity_components[0].get("release_ref") != product_release_ref
        ):
            raise StatementError(StatementErrorReason.RESULT_INVALID)
        reconstructed_bom = {
            "schema_version": 1,
            "purpose": "reallyme-product-conformance-bom",
            "product_id": product["product_id"],
            "product_version": product["product_version"],
            "product_release_ref": product["release_ref"],
            "components": composition,
        }
        try:
            reconstructed_digest = product_bom_validator.canonical_digest(
                reconstructed_bom
            )
        except SystemExit as error:
            raise StatementError(StatementErrorReason.RESULT_INVALID) from error
        if candidate_sha256 != reconstructed_digest:
            raise StatementError(StatementErrorReason.RESULT_INVALID)
    else:
        raise StatementError(StatementErrorReason.RESULT_INVALID)
    if not isinstance(candidate_sha256, str) or SHA256.fullmatch(candidate_sha256) is None:
        raise StatementError(StatementErrorReason.RESULT_INVALID)

    statement = {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.product_conformance_statement.v1",
        "result": "passed",
        "certification_claim": False,
        "plan_id": plan_id,
        "coverage": coverage,
        "product": {
            "product_id": product_id,
            "release_version": release_match.group("version"),
            "release_ref": product_release_ref,
            "repository": product_repository,
            "commit": product_commit,
            "candidate_sha256": candidate_sha256,
        },
        "framework": {
            key: framework[key]
            for key in (
                "release_version",
                "release_tag",
                "release_url",
                "repository_commit",
                "manifest_sha256",
                "input_set_sha256",
            )
        },
        "execution": {
            "workflow_repository": workflow_repository,
            "workflow_revision": workflow_revision,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
    }
    if composition is not None:
        statement["composition"] = composition
    if release_evidence is not None:
        statement["release_evidence"] = release_evidence
    return statement


def write_output(path: Path, value: dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".conformance-statement-", delete=False
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as error:
        raise StatementError(StatementErrorReason.OUTPUT_FAILED) from error


def positive_integer(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,18}", value) is None:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return int(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-selection", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--product-id", required=True)
    parser.add_argument("--product-release-ref", required=True)
    parser.add_argument("--product-repository", required=True)
    parser.add_argument("--product-commit", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--run-id", required=True, type=positive_integer)
    parser.add_argument("--run-attempt", required=True, type=positive_integer)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        statement = build_statement(
            read_object(args.framework_selection),
            read_regular_bytes(args.result),
            args.plan_id,
            args.product_id,
            args.product_release_ref,
            args.product_repository,
            args.product_commit,
            args.workflow_repository,
            args.workflow_revision,
            args.run_id,
            args.run_attempt,
        )
        write_output(args.output, statement)
    except StatementError as error:
        fail(error.reason)
    print("product conformance statement created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
