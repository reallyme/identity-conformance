#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Independently compare Wallet boundary behavior with the EU normative ledgers."""

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
import verify_eu_normative_ledgers as eu_ledgers  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = REPOSITORY_ROOT / "adapters/eudi-wallet/normative-boundaries.json"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
RUST_INTEGER = re.compile(r"^[0-9][0-9_]*$")


class BoundaryErrorReason(Enum):
    INVALID_ADAPTER = "invalid_adapter"
    INVALID_SOURCE = "invalid_source"
    MISSING_BOUNDARY = "missing_boundary"
    UNCLASSIFIED_RULE = "unclassified_rule"
    OBSERVATION_UNAVAILABLE = "observation_unavailable"


@dataclass(frozen=True)
class BoundaryError(Exception):
    reason: BoundaryErrorReason


@dataclass(frozen=True)
class BoundaryResult:
    boundary_id: str
    normative_checks: tuple[str, ...]
    expected_operator: str
    expected_value: object
    observed_operator: str
    observed_value: object

    @property
    def passed(self) -> bool:
        return (
            self.expected_operator == self.observed_operator
            and self.expected_value == self.observed_value
        )


def fail(reason: BoundaryErrorReason) -> NoReturn:
    print(f"EU Wallet normative boundary validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(1 if reason is BoundaryErrorReason.OBSERVATION_UNAVAILABLE else 78)


def load_adapter() -> dict[str, object]:
    try:
        adapter = eu_ledgers.load_object(ADAPTER_PATH)
    except eu_ledgers.EuLedgerError as error:
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER) from error
    if set(adapter) != {
        "$comment",
        "schema_version",
        "adapter_id",
        "component_id",
        "repository",
        "required_ledgers",
        "implemented_boundaries",
        "product_policy_boundaries",
    }:
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    if (
        adapter["schema_version"] != 1
        or adapter["adapter_id"] != "eudi_wallet_normative_boundaries_v1"
        or adapter["component_id"] != "wallet"
        or adapter["repository"] != "https://github.com/reallyme/wallet"
        or adapter["required_ledgers"]
        != [str(path.relative_to(REPOSITORY_ROOT)) for path in eu_ledgers.LEDGER_PATHS]
    ):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    policies = adapter["product_policy_boundaries"]
    if not isinstance(policies, list):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    observed_policy_ids: set[str] = set()
    for raw_policy in policies:
        if not isinstance(raw_policy, dict) or set(raw_policy) != {
            "boundary_id",
            "reason",
        }:
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        boundary_id = raw_policy["boundary_id"]
        reason = raw_policy["reason"]
        if (
            not isinstance(boundary_id, str)
            or eu_ledgers.IDENTIFIER.fullmatch(boundary_id) is None
            or boundary_id in observed_policy_ids
            or not isinstance(reason, str)
            or len(reason) < 16
        ):
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        observed_policy_ids.add(boundary_id)
    return adapter


def regular_source(root: Path, relative: str) -> str:
    path = root / relative
    try:
        metadata = path.lstat()
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= MAX_SOURCE_BYTES
        ):
            raise BoundaryError(BoundaryErrorReason.INVALID_SOURCE)
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as error:
        raise BoundaryError(BoundaryErrorReason.INVALID_SOURCE) from error


def accepted_operator(rejection_operator: str) -> str:
    operators = {
        ">=": "less_than",
        ">": "less_than_or_equal",
        "<=": "greater_than",
        "<": "greater_than_or_equal",
        "==": "not_equal",
    }
    observed = operators.get(rejection_operator)
    if observed is None:
        raise BoundaryError(BoundaryErrorReason.OBSERVATION_UNAVAILABLE)
    return observed


def observe_rust_integer_guard(
    source_root: Path, observation: dict[str, object]
) -> tuple[str, int]:
    if set(observation) != {
        "kind",
        "path",
        "function",
        "constant",
        "measured_expression",
    } or observation.get("kind") != "rust_integer_guard":
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    path = observation.get("path")
    function = observation.get("function")
    constant = observation.get("constant")
    expression = observation.get("measured_expression")
    if not all(
        isinstance(value, str) and value
        for value in (path, function, constant, expression)
    ):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    text = regular_source(source_root, path)
    constant_match = re.search(
        rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+"
        rf"{re.escape(constant)}\s*:\s*(?:i64|u64|usize|u32)\s*=\s*"
        rf"([0-9][0-9_]*)\s*;",
        text,
    )
    function_match = re.search(rf"(?m)^\s*fn\s+{re.escape(function)}\s*\(", text)
    if constant_match is None or function_match is None:
        raise BoundaryError(BoundaryErrorReason.OBSERVATION_UNAVAILABLE)
    literal = constant_match.group(1)
    if RUST_INTEGER.fullmatch(literal) is None:
        raise BoundaryError(BoundaryErrorReason.OBSERVATION_UNAVAILABLE)
    guard_match = re.search(
        rf"\bif\s+{re.escape(expression)}\s*(>=|>|<=|<|==)\s*{re.escape(constant)}\b",
        text[function_match.start() :],
    )
    if guard_match is None:
        raise BoundaryError(BoundaryErrorReason.OBSERVATION_UNAVAILABLE)
    return accepted_operator(guard_match.group(1)), int(literal.replace("_", ""))


def observe_rust_enum_variants(
    source_root: Path, observation: dict[str, object]
) -> tuple[str, tuple[str, ...]]:
    if set(observation) != {
        "kind",
        "path",
        "enum",
        "expected_to_variant",
    } or observation.get("kind") != "rust_enum_variants":
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    path = observation.get("path")
    enum_name = observation.get("enum")
    expected_to_variant = observation.get("expected_to_variant")
    if (
        not isinstance(path, str)
        or not path
        or not isinstance(enum_name, str)
        or not enum_name
        or not isinstance(expected_to_variant, dict)
        or not expected_to_variant
        or not all(
            isinstance(expected, str)
            and expected
            and isinstance(variant, str)
            and re.fullmatch(r"[A-Z][A-Za-z0-9]*", variant) is not None
            for expected, variant in expected_to_variant.items()
        )
    ):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    text = regular_source(source_root, path)
    enum_match = re.search(
        rf"(?s)\bpub\s+enum\s+{re.escape(enum_name)}\s*\{{(.*?)\n\}}",
        text,
    )
    if enum_match is None:
        raise BoundaryError(BoundaryErrorReason.OBSERVATION_UNAVAILABLE)
    variants = set(
        re.findall(r"(?m)^\s{4}([A-Z][A-Za-z0-9]*)\s*,\s*$", enum_match.group(1))
    )
    reverse = {variant: expected for expected, variant in expected_to_variant.items()}
    if len(reverse) != len(expected_to_variant):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    observed = tuple(sorted(reverse.get(variant, f"unmapped:{variant}") for variant in variants))
    return "one_of", observed


def canonical_value(value: object) -> object:
    if isinstance(value, list):
        return tuple(sorted(canonical_value(item) for item in value))
    if isinstance(value, dict):
        return tuple(sorted((key, canonical_value(item)) for key, item in value.items()))
    return value


def evaluate(source_root: Path) -> list[BoundaryResult]:
    adapter = load_adapter()
    try:
        _ledgers, rules = eu_ledgers.load_ledgers()
    except eu_ledgers.EuLedgerError as error:
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER) from error
    boundaries = adapter["implemented_boundaries"]
    if not isinstance(boundaries, list) or not boundaries:
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    observed_rule_ids: set[str] = set()
    observed_boundaries: set[str] = set()
    results: list[BoundaryResult] = []
    for raw_boundary in boundaries:
        if not isinstance(raw_boundary, dict) or set(raw_boundary) != {
            "boundary_id",
            "normative_rule_ids",
            "normative_checks",
            "observation",
        }:
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        boundary_id = raw_boundary["boundary_id"]
        rule_ids = raw_boundary["normative_rule_ids"]
        normative_checks = raw_boundary["normative_checks"]
        observation = raw_boundary["observation"]
        if (
            not isinstance(boundary_id, str)
            or eu_ledgers.IDENTIFIER.fullmatch(boundary_id) is None
            or boundary_id in observed_boundaries
            or not isinstance(rule_ids, list)
            or not rule_ids
            or not all(isinstance(rule_id, str) for rule_id in rule_ids)
            or len(rule_ids) != len(set(rule_ids))
            or not isinstance(normative_checks, dict)
            or set(normative_checks) != set(rule_ids)
            or not all(
                isinstance(check_id, str)
                and eu_ledgers.IDENTIFIER.fullmatch(check_id) is not None
                and check_id.startswith("normative.eu.")
                for check_id in normative_checks.values()
            )
            or len(set(normative_checks.values())) != len(normative_checks)
            or not isinstance(observation, dict)
        ):
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        observed_boundaries.add(boundary_id)
        selected = []
        for rule_id in rule_ids:
            if not isinstance(rule_id, str) or rule_id in observed_rule_ids:
                raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
            rule = rules.get(rule_id)
            if rule is None or rule.get("boundary_id") != boundary_id:
                raise BoundaryError(BoundaryErrorReason.MISSING_BOUNDARY)
            observed_rule_ids.add(rule_id)
            selected.append(rule)
        expected_values: list[tuple[object, object]] = []
        for rule in selected:
            expected = rule.get("expected")
            if not isinstance(expected, dict):
                raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
            expected_values.append(
                (expected.get("operator"), canonical_value(expected.get("value")))
            )
        if len(set(expected_values)) != 1:
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        expected_operator, expected_value = expected_values[0]
        if not isinstance(expected_operator, str):
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        observation_kind = observation.get("kind")
        if observation_kind == "rust_integer_guard":
            observed_operator, observed_value = observe_rust_integer_guard(
                source_root, observation
            )
        elif observation_kind == "rust_enum_variants":
            observed_operator, observed_value = observe_rust_enum_variants(
                source_root, observation
            )
        else:
            raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
        results.append(
            BoundaryResult(
                boundary_id,
                tuple(normative_checks[rule_id] for rule_id in rule_ids),
                expected_operator,
                expected_value,
                observed_operator,
                observed_value,
            )
        )
    if observed_rule_ids != set(rules):
        raise BoundaryError(BoundaryErrorReason.UNCLASSIFIED_RULE)
    policies = adapter["product_policy_boundaries"]
    if not isinstance(policies, list):
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    policy_ids = {
        policy["boundary_id"]
        for policy in policies
        if isinstance(policy, dict) and isinstance(policy.get("boundary_id"), str)
    }
    if len(policy_ids) != len(policies) or policy_ids & observed_boundaries:
        raise BoundaryError(BoundaryErrorReason.INVALID_ADAPTER)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    try:
        results = evaluate(args.source.resolve())
    except BoundaryError as error:
        fail(error.reason)
    failed = [result for result in results if not result.passed]
    if failed:
        for result in failed:
            print(
                f"EU boundary mismatch: {result.boundary_id}: "
                f"expected {result.expected_operator} {result.expected_value}, "
                f"observed {result.observed_operator} {result.observed_value}",
                file=sys.stderr,
            )
        return 1
    print(f"EU Wallet normative boundaries valid ({len(results)} boundaries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
