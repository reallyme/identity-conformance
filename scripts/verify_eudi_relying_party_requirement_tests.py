#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate requirement-specific EUDI relying-party test bindings."""

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


MAX_PLAN_BYTES = 256 * 1024
EXIT_INVALID = 78
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
RUST_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
NORMALIZATION = "utf8_line_range_lf_v1"
EXPECTED_ASSERTIONS = {
    "association_is_service_to_service",
    "current_ts5_signed_envelope_is_strict",
}
ALLOWED_FEATURES = {"redb-store", "ssi-rp-registration"}
EVIDENCE_CLASSES = {
    "behavior_test",
    "downgrade_test",
    "invalid_input_test",
    "oversized_input_test",
    "round_trip_test",
}
CASE_KINDS = {
    "positive",
    "downgrade",
    "invalid_input",
    "oversized_input",
    "round_trip",
}


class RequirementTestPlanErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_PLAN = "invalid_plan"
    INVALID_NORMATIVE_STATEMENT = "invalid_normative_statement"
    INVALID_TEST = "invalid_test"
    COVERAGE_MISMATCH = "coverage_mismatch"


@dataclass(frozen=True)
class RequirementTestPlanError(Exception):
    reason: RequirementTestPlanErrorReason


def fail(reason: RequirementTestPlanErrorReason) -> NoReturn:
    print(
        f"EUDI requirement-test plan validation failed: {reason.value}",
        file=sys.stderr,
    )
    raise SystemExit(EXIT_INVALID)


def exact_keys(
    value: object,
    expected: set[str],
    reason: RequirementTestPlanErrorReason,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RequirementTestPlanError(reason)
    return value


def load_plan(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise RequirementTestPlanError(
                RequirementTestPlanErrorReason.INVALID_JSON
            )
        if metadata.st_size < 1 or metadata.st_size > MAX_PLAN_BYTES:
            raise RequirementTestPlanError(
                RequirementTestPlanErrorReason.INVALID_JSON
            )
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise RequirementTestPlanError(
            RequirementTestPlanErrorReason.INVALID_JSON
        ) from error
    if not isinstance(value, dict):
        raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_JSON)
    return value


def safe_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and SAFE_PATH.fullmatch(value) is not None
        and ".." not in value.split("/")
    )


def assertion_index(parent_plan: dict[str, object]) -> dict[str, dict[str, object]]:
    families = parent_plan.get("assertion_families")
    if not isinstance(families, list):
        raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_PLAN)
    assertions: dict[str, dict[str, object]] = {}
    for family in families:
        if not isinstance(family, dict) or not isinstance(
            family.get("assertions"), list
        ):
            raise RequirementTestPlanError(
                RequirementTestPlanErrorReason.INVALID_PLAN
            )
        for assertion in family["assertions"]:
            if not isinstance(assertion, dict) or not isinstance(
                assertion.get("assertion_id"), str
            ):
                raise RequirementTestPlanError(
                    RequirementTestPlanErrorReason.INVALID_PLAN
                )
            assertion_id = assertion["assertion_id"]
            if assertion_id in assertions:
                raise RequirementTestPlanError(
                    RequirementTestPlanErrorReason.INVALID_PLAN
                )
            assertions[assertion_id] = assertion
    return assertions


def validate_statement(
    raw_statement: object,
    source_commit: str,
) -> tuple[str, str]:
    statement = exact_keys(
        raw_statement,
        {
            "statement_id",
            "source_id",
            "source_commit",
            "source_path",
            "source_sha256",
            "clause_locator",
            "start_line",
            "end_line",
            "normalization",
            "statement_sha256",
        },
        RequirementTestPlanErrorReason.INVALID_NORMATIVE_STATEMENT,
    )
    statement_id = statement["statement_id"]
    start_line = statement["start_line"]
    end_line = statement["end_line"]
    if (
        not isinstance(statement_id, str)
        or IDENTIFIER.fullmatch(statement_id) is None
        or statement["source_id"] != "eudi-technical-specifications"
        or statement["source_commit"] != source_commit
        or COMMIT.fullmatch(str(statement["source_commit"])) is None
        or not safe_path(statement["source_path"])
        or SHA256.fullmatch(str(statement["source_sha256"])) is None
        or not isinstance(statement["clause_locator"], str)
        or not statement["clause_locator"]
        or not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or not isinstance(end_line, int)
        or isinstance(end_line, bool)
        or start_line < 1
        or end_line < start_line
        or statement["normalization"] != NORMALIZATION
        or SHA256.fullmatch(str(statement["statement_sha256"])) is None
    ):
        raise RequirementTestPlanError(
            RequirementTestPlanErrorReason.INVALID_NORMATIVE_STATEMENT
        )
    return statement_id, str(statement["source_path"])


def validate_test(
    raw_test: object,
    statement_ids: set[str],
    assertions: dict[str, dict[str, object]],
) -> tuple[str, str, str]:
    test = exact_keys(
        raw_test,
        {
            "command_id",
            "assertion_id",
            "requirement_id",
            "evidence_class",
            "case_kind",
            "normative_statement_ids",
            "package",
            "features",
            "test_target",
            "test_path",
            "symbol",
        },
        RequirementTestPlanErrorReason.INVALID_TEST,
    )
    command_id = test["command_id"]
    assertion_id = test["assertion_id"]
    evidence_class = test["evidence_class"]
    features = test["features"]
    references = test["normative_statement_ids"]
    if (
        not isinstance(command_id, str)
        or IDENTIFIER.fullmatch(command_id) is None
        or not isinstance(assertion_id, str)
        or assertion_id not in EXPECTED_ASSERTIONS
        or assertion_id not in assertions
        or test["requirement_id"]
        != (
            "conformance-scope:eudi_relying_party_control_plane:assertion:"
            f"{assertion_id}"
        )
        or evidence_class not in EVIDENCE_CLASSES
        or test["case_kind"] not in CASE_KINDS
        or not isinstance(references, list)
        or not references
        or len(references) != len(set(references))
        or not set(references).issubset(statement_ids)
        or test["package"] != "reallyme-eudi-qp-app"
        or not isinstance(features, list)
        or len(features) != len(set(features))
        or not set(features).issubset(ALLOWED_FEATURES)
        or not isinstance(test["test_target"], str)
        or RUST_IDENTIFIER.fullmatch(test["test_target"]) is None
        or not safe_path(test["test_path"])
        or not str(test["test_path"]).startswith("apps/eudi-qp/tests/")
        or not str(test["test_path"]).endswith(".rs")
        or Path(str(test["test_path"])).stem != test["test_target"]
        or not isinstance(test["symbol"], str)
        or RUST_IDENTIFIER.fullmatch(test["symbol"]) is None
    ):
        raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_TEST)
    return command_id, assertion_id, str(evidence_class)


def verify_plan(
    plan: dict[str, object],
    parent_plan: dict[str, object],
    source_commit: str,
) -> None:
    exact_keys(
        plan,
        {
            "$comment",
            "schema_version",
            "plan_id",
            "parent_plan_id",
            "subject_repository",
            "complete",
            "normative_statements",
            "tests",
        },
        RequirementTestPlanErrorReason.INVALID_PLAN,
    )
    if (
        plan["schema_version"] != 1
        or plan["plan_id"] != "eudi-relying-party-requirement-tests-v1"
        or plan["parent_plan_id"] != "eudi-relying-party-control-plane-v1"
        or plan["subject_repository"] != "reallyme/eudi"
        or plan["complete"] is not False
        or COMMIT.fullmatch(source_commit) is None
    ):
        raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_PLAN)
    raw_statements = plan["normative_statements"]
    raw_tests = plan["tests"]
    if (
        not isinstance(raw_statements, list)
        or len(raw_statements) != 2
        or not isinstance(raw_tests, list)
        or len(raw_tests) != 7
    ):
        raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_PLAN)
    statement_ids: set[str] = set()
    source_paths: set[str] = set()
    for raw_statement in raw_statements:
        statement_id, source_path = validate_statement(raw_statement, source_commit)
        if statement_id in statement_ids or source_path in source_paths:
            raise RequirementTestPlanError(
                RequirementTestPlanErrorReason.INVALID_NORMATIVE_STATEMENT
            )
        statement_ids.add(statement_id)
        source_paths.add(source_path)
    assertions = assertion_index(parent_plan)
    command_ids: set[str] = set()
    observed_coverage: dict[str, set[str]] = {}
    for raw_test in raw_tests:
        command_id, assertion_id, evidence_class = validate_test(
            raw_test, statement_ids, assertions
        )
        if command_id in command_ids:
            raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_TEST)
        command_ids.add(command_id)
        covered = observed_coverage.setdefault(assertion_id, set())
        if evidence_class in covered:
            raise RequirementTestPlanError(RequirementTestPlanErrorReason.INVALID_TEST)
        covered.add(evidence_class)
    if set(observed_coverage) != EXPECTED_ASSERTIONS:
        raise RequirementTestPlanError(
            RequirementTestPlanErrorReason.COVERAGE_MISMATCH
        )
    for assertion_id, evidence_classes in observed_coverage.items():
        required = assertions[assertion_id].get("required_evidence")
        if not isinstance(required, list) or set(required) != evidence_classes:
            raise RequirementTestPlanError(
                RequirementTestPlanErrorReason.COVERAGE_MISMATCH
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--parent-plan", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        verify_plan(
            load_plan(args.plan),
            load_plan(args.parent_plan),
            args.source_commit,
        )
    except RequirementTestPlanError as error:
        fail(error.reason)
    print("EUDI requirement-test plan valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
