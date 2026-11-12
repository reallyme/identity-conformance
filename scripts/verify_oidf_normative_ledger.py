#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the OIDF normative plan ledger against the pinned real suite source."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = REPOSITORY_ROOT / "plans/oidf/normative-ledger.json"
SUITE_LOCK_PATH = REPOSITORY_ROOT / "upstream/oidf/conformance-suite.lock.json"
SPECIFICATIONS_LOCK_PATH = REPOSITORY_ROOT / "upstream/oidf/specifications.lock.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024


class OidfLedgerErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_LEDGER = "invalid_ledger"
    SUITE_PIN_MISMATCH = "suite_pin_mismatch"
    SPECIFICATION_PIN_MISMATCH = "specification_pin_mismatch"
    PLAN_VALUE_MISMATCH = "plan_value_mismatch"
    SUITE_SOURCE_UNAVAILABLE = "suite_source_unavailable"
    SUITE_SOURCE_MISMATCH = "suite_source_mismatch"


@dataclass(frozen=True)
class OidfLedgerError(Exception):
    reason: OidfLedgerErrorReason


def fail(reason: OidfLedgerErrorReason) -> NoReturn:
    print(f"OIDF normative ledger validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise OidfLedgerError(OidfLedgerErrorReason.INVALID_JSON)
        parsed = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_JSON) from error
    if not isinstance(parsed, dict):
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_JSON)
    return parsed


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    return value


def source_assertion_index(plan: dict[str, object]) -> dict[str, list[str]]:
    assertions = plan.get("suite_source_assertions")
    if not isinstance(assertions, list) or not assertions:
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    indexed: dict[str, list[str]] = {}
    for raw_assertion in assertions:
        assertion = exact_object(raw_assertion, {"path", "required_tokens"})
        path = assertion["path"]
        tokens = assertion["required_tokens"]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or path in indexed
            or not isinstance(tokens, list)
            or not tokens
            or not all(isinstance(token, str) and token for token in tokens)
            or len(tokens) != len(set(tokens))
        ):
            raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
        indexed[path] = tokens
    return indexed


def validate_ledger() -> tuple[dict[str, object], list[dict[str, object]]]:
    ledger = load_object(LEDGER_PATH)
    exact_object(
        ledger,
        {
            "$comment",
            "schema_version",
            "ledger_id",
            "domain",
            "authority",
            "suite",
            "specification_ids",
            "plan_path",
            "coverage",
            "rules",
        },
    )
    suite = exact_object(ledger["suite"], {"lock_path", "repository", "ref", "commit"})
    coverage = exact_object(
        ledger["coverage"], {"scope", "complete_for_declared_plans", "certification_claim"}
    )
    lock = load_object(SUITE_LOCK_PATH)
    if (
        ledger["schema_version"] != 1
        or ledger["domain"] != "oidf"
        or ledger["authority"] != "oidf_conformance_suite"
        or ledger["plan_path"] != "plans/oidf/certification.json"
        or coverage["scope"] != "certification_plan_variant_values"
        or coverage["complete_for_declared_plans"] is not True
        or coverage["certification_claim"] is not False
        or suite["lock_path"] != "upstream/oidf/conformance-suite.lock.json"
        or suite["repository"] != lock.get("repository")
        or suite["ref"] != lock.get("pinned_ref")
        or suite["commit"] != lock.get("commit")
    ):
        raise OidfLedgerError(OidfLedgerErrorReason.SUITE_PIN_MISMATCH)
    specifications = load_object(SPECIFICATIONS_LOCK_PATH).get("publications")
    if not isinstance(specifications, list):
        raise OidfLedgerError(OidfLedgerErrorReason.SPECIFICATION_PIN_MISMATCH)
    if not all(
        isinstance(item, dict) and isinstance(item.get("specification_id"), str)
        for item in specifications
    ):
        raise OidfLedgerError(OidfLedgerErrorReason.SPECIFICATION_PIN_MISMATCH)
    specification_ids = {item["specification_id"] for item in specifications}
    ledger_specification_ids = ledger["specification_ids"]
    if (
        not isinstance(ledger_specification_ids, list)
        or not all(isinstance(item, str) for item in ledger_specification_ids)
        or ledger_specification_ids
        != [
        "openid4vci-1.0-final",
        "openid4vp-1.0-final",
        "openid4vc-haip-1.0-final",
        ]
        or set(ledger_specification_ids) != specification_ids
    ):
        raise OidfLedgerError(OidfLedgerErrorReason.SPECIFICATION_PIN_MISMATCH)
    plan = load_object(REPOSITORY_ROOT / str(ledger["plan_path"]))
    plans = plan.get("plans")
    suite_assertions = source_assertion_index(plan)
    rules = ledger["rules"]
    if not isinstance(plans, list) or not isinstance(rules, list) or len(rules) != len(plans):
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    plans_by_id = {
        item.get("plan_id"): item
        for item in plans
        if isinstance(item, dict) and isinstance(item.get("plan_id"), str)
    }
    if len(plans_by_id) != len(plans):
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    validated_rules: list[dict[str, object]] = []
    observed_plan_ids: set[str] = set()
    observed_rule_ids: set[str] = set()
    for raw_rule in rules:
        rule = exact_object(
            raw_rule,
            {
                "rule_id",
                "plan_id",
                "plan_projection",
                "expected",
                "suite_assertion_paths",
            },
        )
        rule_id = rule["rule_id"]
        plan_id = rule["plan_id"]
        projection = rule["plan_projection"]
        assertion_paths = rule["suite_assertion_paths"]
        expected = rule["expected"]
        if (
            not isinstance(rule_id, str)
            or rule_id in observed_rule_ids
            or not isinstance(plan_id, str)
            or plan_id in observed_plan_ids
            or not isinstance(projection, list)
            or not projection
            or not all(isinstance(key, str) and key for key in projection)
            or len(projection) != len(set(projection))
            or not isinstance(expected, dict)
            or not isinstance(assertion_paths, list)
            or not assertion_paths
            or not all(
                isinstance(path, str) and path in suite_assertions
                for path in assertion_paths
            )
            or len(assertion_paths) != len(set(assertion_paths))
        ):
            raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
        selected_plan = plans_by_id.get(plan_id)
        if selected_plan is None:
            raise OidfLedgerError(OidfLedgerErrorReason.PLAN_VALUE_MISMATCH)
        projected = {key: selected_plan.get(key) for key in projection}
        if set(expected) != set(projection) or projected != expected:
            raise OidfLedgerError(OidfLedgerErrorReason.PLAN_VALUE_MISMATCH)
        observed_rule_ids.add(rule_id)
        observed_plan_ids.add(plan_id)
        validated_rules.append(rule)
    if observed_plan_ids != set(plans_by_id):
        raise OidfLedgerError(OidfLedgerErrorReason.PLAN_VALUE_MISMATCH)
    return ledger, validated_rules


def git_source(repository: Path, commit: str, relative_path: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "show", f"{commit}:{relative_path}"],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OidfLedgerError(OidfLedgerErrorReason.SUITE_SOURCE_UNAVAILABLE) from error
    if completed.returncode != 0 or not 1 <= len(completed.stdout) <= MAX_SOURCE_BYTES:
        raise OidfLedgerError(OidfLedgerErrorReason.SUITE_SOURCE_UNAVAILABLE)
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeError as error:
        raise OidfLedgerError(OidfLedgerErrorReason.SUITE_SOURCE_UNAVAILABLE) from error


def verify_suite_source(
    ledger: dict[str, object], rules: list[dict[str, object]], repository: Path
) -> None:
    suite = ledger["suite"]
    if not isinstance(suite, dict) or not isinstance(suite.get("commit"), str):
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    plan_path = ledger.get("plan_path")
    if not isinstance(plan_path, str):
        raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
    assertions_by_path = source_assertion_index(
        load_object(REPOSITORY_ROOT / plan_path)
    )
    cache: dict[str, str] = {}
    for rule in rules:
        assertion_paths = rule["suite_assertion_paths"]
        if not isinstance(assertion_paths, list):
            raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
        for path in assertion_paths:
            if not isinstance(path, str):
                raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
            tokens = assertions_by_path.get(path)
            if tokens is None:
                raise OidfLedgerError(OidfLedgerErrorReason.INVALID_LEDGER)
            source = cache.get(path)
            if source is None:
                source = git_source(repository, suite["commit"], path)
                cache[path] = source
            if not all(isinstance(token, str) and token in source for token in tokens):
                raise OidfLedgerError(OidfLedgerErrorReason.SUITE_SOURCE_MISMATCH)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite-repository", type=Path)
    args = parser.parse_args()
    try:
        ledger, rules = validate_ledger()
        if args.suite_repository is not None:
            verify_suite_source(ledger, rules, args.suite_repository.resolve())
    except OidfLedgerError as error:
        fail(error.reason)
    print(f"OIDF normative ledger valid ({len(rules)} certification plans)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
