#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate EU normative ledgers against reviewed pins and exact upstream source."""

from __future__ import annotations

import argparse
import re
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
SOURCE_LOCK_PATH = REPOSITORY_ROOT / "upstream/eudi/sources.lock.json"
LEDGER_PATHS = (
    REPOSITORY_ROOT / "plans/eudi/normative/arf-wallet.json",
    REPOSITORY_ROOT / "plans/eudi/normative/technical-specifications-wallet.json",
    REPOSITORY_ROOT / "plans/eudi/normative/fcaf-wallet.json",
)
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
EXPECTED_AUTHORITIES = {"arf", "technical_specification", "fcaf"}
EXPECTED_OPERATORS = {"less_than", "less_than_or_equal", "equal", "one_of"}


class EuLedgerErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_LEDGER = "invalid_ledger"
    INVALID_SOURCE_LOCK = "invalid_source_lock"
    SOURCE_PIN_MISMATCH = "source_pin_mismatch"
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_STATEMENT_MISSING = "source_statement_missing"
    RULE_CONFLICT = "rule_conflict"


@dataclass(frozen=True)
class EuLedgerError(Exception):
    reason: EuLedgerErrorReason


def fail(reason: EuLedgerErrorReason) -> NoReturn:
    print(f"EU normative ledger validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    return value


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise EuLedgerError(EuLedgerErrorReason.INVALID_JSON)
        parsed = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise EuLedgerError(EuLedgerErrorReason.INVALID_JSON) from error
    if not isinstance(parsed, dict):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_JSON)
    return parsed


def source_index() -> dict[str, dict[str, object]]:
    lock = load_object(SOURCE_LOCK_PATH)
    sources = lock.get("sources")
    if not isinstance(sources, list):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_SOURCE_LOCK)
    indexed: dict[str, dict[str, object]] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_SOURCE_LOCK)
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or source_id in indexed:
            raise EuLedgerError(EuLedgerErrorReason.INVALID_SOURCE_LOCK)
        indexed[source_id] = source
    return indexed


def validate_rule(rule: object) -> dict[str, object]:
    value = exact_object(
        rule,
        {
            "rule_id",
            "source_requirement_id",
            "source_path",
            "requirement_level",
            "boundary_id",
            "statement",
            "expected",
        },
    )
    expected = exact_object(value["expected"], {"value_type", "operator", "value"})
    if (
        not isinstance(value["rule_id"], str)
        or IDENTIFIER.fullmatch(value["rule_id"]) is None
        or not isinstance(value["source_requirement_id"], str)
        or not value["source_requirement_id"]
        or not isinstance(value["source_path"], str)
        or value["source_path"].startswith("/")
        or ".." in Path(value["source_path"]).parts
        or value["requirement_level"] != "shall"
        or not isinstance(value["boundary_id"], str)
        or IDENTIFIER.fullmatch(value["boundary_id"]) is None
        or not isinstance(value["statement"], str)
        or len(value["statement"]) < 16
        or not isinstance(expected["value_type"], str)
        or expected["value_type"]
        not in {"duration_seconds", "integer", "string_set"}
        or not isinstance(expected["operator"], str)
        or expected["operator"] not in EXPECTED_OPERATORS
    ):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    if expected["value_type"] in {"duration_seconds", "integer"}:
        if (
            isinstance(expected["value"], bool)
            or not isinstance(expected["value"], int)
            or expected["value"] < 0
            or expected["operator"] not in {"less_than", "less_than_or_equal", "equal"}
        ):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    else:
        choices = expected["value"]
        if (
            expected["operator"] != "one_of"
            or not isinstance(choices, list)
            or not choices
            or not all(isinstance(choice, str) and choice for choice in choices)
            or len(choices) != len(set(choices))
        ):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    return value


def validate_ledger(
    ledger: dict[str, object], sources: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    base_keys = {
        "$comment",
        "schema_version",
        "ledger_id",
        "domain",
        "authority",
        "source",
        "coverage",
        "rules",
    }
    authority = ledger.get("authority")
    expected_keys = base_keys | ({"assessment"} if authority == "fcaf" else set())
    exact_object(ledger, expected_keys)
    source = exact_object(ledger["source"], {"source_id", "ref", "commit", "path"})
    coverage = exact_object(
        ledger["coverage"],
        {"component_id", "scope", "complete_for_declared_boundaries", "certification_claim"},
    )
    if (
        ledger["schema_version"] != 1
        or ledger["domain"] != "eu"
        or not isinstance(authority, str)
        or authority not in EXPECTED_AUTHORITIES
        or not isinstance(ledger["ledger_id"], str)
        or IDENTIFIER.fullmatch(ledger["ledger_id"]) is None
        or coverage["component_id"] != "wallet"
        or coverage["complete_for_declared_boundaries"] is not True
        or coverage["certification_claim"] is not False
        or not isinstance(source["source_id"], str)
        or not isinstance(source["ref"], str)
        or not isinstance(source["commit"], str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(source["path"], str)
        or source["path"].startswith("/")
        or ".." in Path(source["path"]).parts
    ):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    locked = sources.get(source["source_id"])
    if (
        locked is None
        or locked.get("ref") != source["ref"]
        or locked.get("commit") != source["commit"]
    ):
        raise EuLedgerError(EuLedgerErrorReason.SOURCE_PIN_MISMATCH)
    rules = ledger["rules"]
    if not isinstance(rules, list):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    validated = [validate_rule(rule) for rule in rules]
    if len({rule["rule_id"] for rule in validated}) != len(validated):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    if authority == "fcaf":
        assessment = exact_object(
            ledger["assessment"],
            {"execution_state", "executable_test_case_count", "required_classes"},
        )
        classes = assessment["required_classes"]
        if (
            validated
            or assessment["execution_state"] != "methodology_only"
            or assessment["executable_test_case_count"] != 0
            or not isinstance(classes, list)
            or len(classes) != 5
            or not all(isinstance(item, str) and item for item in classes)
            or len(set(classes)) != 5
        ):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    elif not validated:
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    return validated


def git_source(repository: Path, commit: str, source_path: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "show", f"{commit}:{source_path}"],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EuLedgerError(EuLedgerErrorReason.SOURCE_UNAVAILABLE) from error
    if completed.returncode != 0 or not 1 <= len(completed.stdout) <= MAX_SOURCE_BYTES:
        raise EuLedgerError(EuLedgerErrorReason.SOURCE_UNAVAILABLE)
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeError as error:
        raise EuLedgerError(EuLedgerErrorReason.SOURCE_UNAVAILABLE) from error


def verify_source(ledger: dict[str, object], repository: Path) -> None:
    source = ledger["source"]
    if not isinstance(source, dict):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    rules = ledger["rules"]
    if not isinstance(rules, list):
        raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
    cache: dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
        statement = rule.get("statement")
        requirement_id = rule.get("source_requirement_id")
        source_path = rule.get("source_path")
        if not isinstance(source_path, str):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
        text = cache.get(source_path)
        if text is None:
            text = git_source(repository, str(source["commit"]), source_path)
            cache[source_path] = text
        if (
            not isinstance(statement, str)
            or statement not in text
            or not isinstance(requirement_id, str)
            or requirement_id not in text
        ):
            raise EuLedgerError(EuLedgerErrorReason.SOURCE_STATEMENT_MISSING)
    if ledger["authority"] == "fcaf":
        text = git_source(repository, str(source["commit"]), str(source["path"]))
        assessment = ledger["assessment"]
        if not isinstance(assessment, dict) or not isinstance(
            assessment.get("required_classes"), list
        ):
            raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
        if not all(item in text for item in assessment["required_classes"]):
            raise EuLedgerError(EuLedgerErrorReason.SOURCE_STATEMENT_MISSING)


def load_ledgers() -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    sources = source_index()
    ledgers = [load_object(path) for path in LEDGER_PATHS]
    rules: dict[str, dict[str, object]] = {}
    boundary_values: dict[str, tuple[object, object, object]] = {}
    for ledger in ledgers:
        for rule in validate_ledger(ledger, sources):
            rule_id = str(rule["rule_id"])
            if rule_id in rules:
                raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
            rules[rule_id] = rule
            expected = rule["expected"]
            if not isinstance(expected, dict):
                raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
            signature = (
                expected.get("value_type"),
                expected.get("operator"),
                expected.get("value"),
            )
            boundary_id = str(rule["boundary_id"])
            previous = boundary_values.get(boundary_id)
            if previous is not None and previous != signature:
                raise EuLedgerError(EuLedgerErrorReason.RULE_CONFLICT)
            boundary_values[boundary_id] = signature
    return ledgers, rules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--authority",
        choices=("all", "arf", "technical_specification", "fcaf"),
        default="all",
    )
    parser.add_argument("--source-repository", type=Path)
    args = parser.parse_args()
    try:
        ledgers, rules = load_ledgers()
        selected = [
            ledger
            for ledger in ledgers
            if args.authority == "all" or ledger["authority"] == args.authority
        ]
        if args.source_repository is not None:
            if not selected or (args.authority == "all" and len(selected) != 3):
                raise EuLedgerError(EuLedgerErrorReason.INVALID_LEDGER)
            for ledger in selected:
                verify_source(ledger, args.source_repository.resolve())
        elif args.authority != "all":
            raise EuLedgerError(EuLedgerErrorReason.SOURCE_UNAVAILABLE)
    except EuLedgerError as error:
        fail(error.reason)
    selected_rule_count = sum(
        len(ledger["rules"])
        for ledger in selected
        if isinstance(ledger.get("rules"), list)
    )
    if args.authority == "fcaf":
        print("EU FCAF assessment ledger valid (methodology only; 0 executable cases)")
    elif args.authority == "all":
        print(f"EU normative ledgers valid ({len(rules)} executable rules)")
    else:
        authority_label = {
            "arf": "ARF",
            "technical_specification": "technical specification",
        }[args.authority]
        rule_label = "rule" if selected_rule_count == 1 else "rules"
        print(
            f"EU {authority_label} normative ledger valid "
            f"({selected_rule_count} executable {rule_label})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
