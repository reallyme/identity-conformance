#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a passed EUDI Identity SDK execution result."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_identity_candidate_bom as candidate_bom  # noqa: E402
import verify_product_component_bom as product_bom  # noqa: E402


MAX_RESULT_BYTES = 256 * 1024
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
EXPECTED_COMPONENT_REPOSITORIES = {
    "ssi": "https://github.com/reallyme/ssi",
    "openid4vci": "https://github.com/reallyme/openid4vci",
    "openid4vp": "https://github.com/reallyme/openid4vp",
}
EXPECTED_LANES = frozenset(
    {
        "normative_trace",
        "rust_product_boundary",
        "eudi_openid_composition",
        "typescript_sdk",
        "python_sdk",
        "go_sdk",
        "kotlin_sdk",
        "swift_sdk",
    }
)
EXPECTED_COVERAGE = {
    "identity_operations": 8,
    "etsi_requirement_rows": 740,
    "eu_requirement_rows": 229,
    "code_and_composed_evidence_rows": 898,
    "external_evidence_rows": 53,
    "not_applicable_rows": 18,
}
EXPECTED_POLICY = {
    "contains_sensitive_data": False,
    "attestations_satisfied_behavior": False,
    "external_evidence_rows_counted_as_code_passes": False,
    "legal_conformity_claim": False,
    "certification_claim": False,
}


class ResultErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    RESULT_INVALID = "result_invalid"
    CANDIDATE_BINDING_INVALID = "candidate_binding_invalid"
    COMPONENT_BINDING_INVALID = "component_binding_invalid"


@dataclass(frozen=True)
class ResultError(Exception):
    reason: ResultErrorReason


def fail(reason: ResultErrorReason) -> NoReturn:
    raise ResultError(reason)


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(ResultErrorReason.RESULT_INVALID)
    return value


def load_result(path: Path) -> dict[str, object]:
    try:
        metadata = path.stat()
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= MAX_RESULT_BYTES
        ):
            fail(ResultErrorReason.INPUT_INVALID)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except ResultError:
        raise
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(ResultErrorReason.INPUT_INVALID)
    if not isinstance(value, dict):
        fail(ResultErrorReason.INPUT_INVALID)
    return value


def validate_result(
    value: dict[str, object], bom_value: dict[str, object]
) -> None:
    if set(value) != {
        "schema",
        "plan_id",
        "result",
        "created_at",
        "framework",
        "execution",
        "candidate",
        "components",
        "product_component_bom_sha256",
        "candidate_cargo_lock_sha256",
        "source_locks",
        "coverage",
        "lanes",
        "evidence_policy",
    }:
        fail(ResultErrorReason.RESULT_INVALID)
    if (
        value.get("schema")
        != "reallyme.identity.eudi_identity_sdk_execution_result.v1"
        or value.get("plan_id") != "eudi-identity-sdk-v1"
        or value.get("result") != "passed"
        or not isinstance(value.get("created_at"), str)
        or TIMESTAMP.fullmatch(value["created_at"]) is None
    ):
        fail(ResultErrorReason.RESULT_INVALID)

    execution = exact_object(
        value.get("execution"),
        {"workflow_repository", "workflow_revision", "run_id", "run_attempt"},
    )
    if (
        execution.get("workflow_repository") != "reallyme/identity"
        or not isinstance(execution.get("workflow_revision"), str)
        or GIT_COMMIT.fullmatch(execution["workflow_revision"]) is None
        or not isinstance(execution.get("run_id"), int)
        or isinstance(execution.get("run_id"), bool)
        or not 1 <= execution["run_id"] <= 9_223_372_036_854_775_807
        or not isinstance(execution.get("run_attempt"), int)
        or isinstance(execution.get("run_attempt"), bool)
        or not 1 <= execution["run_attempt"] <= 2_147_483_647
    ):
        fail(ResultErrorReason.RESULT_INVALID)

    framework = exact_object(
        value.get("framework"),
        {"version", "commit", "manifest_sha256", "input_set_sha256"},
    )
    if (
        not isinstance(framework.get("version"), str)
        or SEMVER.fullmatch(framework["version"]) is None
        or not isinstance(framework.get("commit"), str)
        or GIT_COMMIT.fullmatch(framework["commit"]) is None
        or not isinstance(framework.get("manifest_sha256"), str)
        or SHA256.fullmatch(framework["manifest_sha256"]) is None
        or not isinstance(framework.get("input_set_sha256"), str)
        or SHA256.fullmatch(framework["input_set_sha256"]) is None
    ):
        fail(ResultErrorReason.RESULT_INVALID)

    candidate = value.get("candidate")
    if not isinstance(candidate, dict):
        fail(ResultErrorReason.CANDIDATE_BINDING_INVALID)
    mode = candidate.get("mode")
    expected_keys = {
        "mode",
        "repository",
        "version",
        "commit",
        "source_archive_sha256",
    }
    if mode == "published":
        expected_keys.update({"release_id", "release_ref"})
    if set(candidate) != expected_keys or mode not in {"candidate", "published"}:
        fail(ResultErrorReason.CANDIDATE_BINDING_INVALID)
    version = candidate.get("version")
    commit = candidate.get("commit")
    if (
        candidate.get("repository") != "https://github.com/reallyme/identity"
        or not isinstance(version, str)
        or SEMVER.fullmatch(version) is None
        or not isinstance(commit, str)
        or GIT_COMMIT.fullmatch(commit) is None
        or not isinstance(candidate.get("source_archive_sha256"), str)
        or SHA256.fullmatch(candidate["source_archive_sha256"]) is None
    ):
        fail(ResultErrorReason.CANDIDATE_BINDING_INVALID)
    if mode == "published":
        if (
            candidate.get("release_ref") != f"reallyme-identity-v{version}"
            or not isinstance(candidate.get("release_id"), int)
            or isinstance(candidate.get("release_id"), bool)
            or not 1 <= candidate["release_id"] <= 9_223_372_036_854_775_807
        ):
            fail(ResultErrorReason.CANDIDATE_BINDING_INVALID)

    components = value.get("components")
    if not isinstance(components, list) or len(components) != 3:
        fail(ResultErrorReason.COMPONENT_BINDING_INVALID)
    observed: set[str] = set()
    for raw_component in components:
        component = exact_object(
            raw_component,
            {
                "component_id",
                "repository",
                "release_id",
                "release_ref",
                "commit",
                "source_archive_sha256",
            },
        )
        component_id = component.get("component_id")
        if (
            not isinstance(component_id, str)
            or component_id in observed
            or component_id not in EXPECTED_COMPONENT_REPOSITORIES
            or component.get("repository")
            != EXPECTED_COMPONENT_REPOSITORIES[component_id]
            or not isinstance(component.get("commit"), str)
            or GIT_COMMIT.fullmatch(component["commit"]) is None
            or not isinstance(component.get("release_id"), int)
            or isinstance(component.get("release_id"), bool)
            or not 1 <= component["release_id"] <= 9_223_372_036_854_775_807
            or not isinstance(component.get("source_archive_sha256"), str)
            or SHA256.fullmatch(component["source_archive_sha256"]) is None
            or not isinstance(component.get("release_ref"), str)
            or re.fullmatch(
                rf"reallyme-{re.escape(component_id)}-v"
                r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
                component["release_ref"],
            )
            is None
        ):
            fail(ResultErrorReason.COMPONENT_BINDING_INVALID)
        observed.add(component_id)
    if observed != set(EXPECTED_COMPONENT_REPOSITORIES):
        fail(ResultErrorReason.COMPONENT_BINDING_INVALID)
    try:
        selection = candidate_bom.select_candidate(
            bom_value,
            target_mode=mode,
            target_commit=commit,
            target_version=version,
            target_release_id=(
                candidate["release_id"] if mode == "published" else None
            ),
            target_release_ref=(
                candidate["release_ref"] if mode == "published" else ""
            ),
        )
    except (candidate_bom.CandidateBomError, SystemExit):
        fail(ResultErrorReason.COMPONENT_BINDING_INVALID)
    component_bindings = [
        {
            key: item[key]
            for key in (
                "component_id",
                "repository",
                "release_id",
                "release_ref",
                "commit",
            )
        }
        for item in components
    ]
    if (
        value.get("product_component_bom_sha256")
        != selection["product_component_bom_sha256"]
        or sorted(component_bindings, key=lambda item: str(item["component_id"]))
        != selection["dependencies"]
    ):
        fail(ResultErrorReason.COMPONENT_BINDING_INVALID)
    candidate_lock_digest = value.get("candidate_cargo_lock_sha256")
    if (
        not isinstance(candidate_lock_digest, str)
        or SHA256.fullmatch(candidate_lock_digest) is None
    ):
        fail(ResultErrorReason.CANDIDATE_BINDING_INVALID)
    source_locks = exact_object(
        value.get("source_locks"),
        {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
            "normative_sources_sha256",
        },
    )
    if any(
        not isinstance(digest, str) or SHA256.fullmatch(digest) is None
        for digest in source_locks.values()
    ):
        fail(ResultErrorReason.RESULT_INVALID)

    if value.get("coverage") != EXPECTED_COVERAGE:
        fail(ResultErrorReason.RESULT_INVALID)
    lanes = value.get("lanes")
    if (
        not isinstance(lanes, list)
        or len(lanes) != len(EXPECTED_LANES)
        or len(lanes) != len(set(lanes))
        or frozenset(lanes) != EXPECTED_LANES
    ):
        fail(ResultErrorReason.RESULT_INVALID)
    if value.get("evidence_policy") != EXPECTED_POLICY:
        fail(ResultErrorReason.RESULT_INVALID)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--product-component-bom", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        validate_result(
            load_result(arguments.result),
            product_bom.load_bom(arguments.product_component_bom),
        )
    except (ResultError, SystemExit) as error:
        reason = (
            error.reason.value
            if isinstance(error, ResultError)
            else ResultErrorReason.COMPONENT_BINDING_INVALID.value
        )
        print(
            f"error: EUDI Identity SDK result is invalid ({reason})",
            file=sys.stderr,
        )
        return 65
    print("EUDI Identity SDK execution result valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
