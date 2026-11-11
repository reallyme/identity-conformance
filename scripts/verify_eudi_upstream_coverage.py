#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate EUDI source pins and the boundary between pins and execution."""

from __future__ import annotations

import datetime
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import NoReturn
from urllib.parse import urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK_PATH = REPOSITORY_ROOT / "upstream/eudi/sources.lock.json"
COVERAGE_PATH = REPOSITORY_ROOT / "plans/eudi/upstream-coverage.json"
MAX_JSON_BYTES = 1_000_000
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$")
SOURCE_ID = re.compile(r"^eudi-[a-z0-9]+(?:-[a-z0-9]+)*$")
ROLE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
ALLOWED_COVERAGE_CLASSES = {
    "normative_baseline",
    "assessment_methodology",
    "engineering_reference",
    "official_test_asset",
    "interoperability_target",
    "legacy_compatibility",
    "monitor_only",
}
ALLOWED_UPDATE_STRATEGIES = {"latest_release", "latest_tag", "default_branch"}
ALLOWED_SOURCE_BINDINGS = {"verified_checkout", "lock_digest", "freshness_monitor"}
ALLOWED_EXECUTION_STATES = {
    "reallyme_control_execution",
    "component_attestation_only",
    "external_runner_required",
    "interoperability_target_only",
    "compatibility_only",
    "monitor_only",
}
EXPECTED_FOCUS_SOURCE_IDS = {
    "eudi-age-verification-specification",
    "eudi-issuer-wallet-tester",
    "eudi-rqes-wallet-driven-tester",
    "eudi-android-wallet-ui",
    "eudi-android-wallet-core",
    "eudi-ios-wallet-ui",
    "eudi-ios-wallet-kit",
    "eudi-multiplatform-verifier-ui",
    "eudi-web-verifier",
    "eudi-trust-validator",
    "eudi-status-validator",
    "eudi-status-list-service",
    "eudi-trusted-list-manager",
    "eudi-etsi-1196x2-library",
    "eudi-android-rqes-core",
    "eudi-ios-rqes-kit",
    "eudi-jvm-rqes-csc-library",
    "eudi-ios-rqes-csc-library",
    "eudi-rqes-qtsp-service",
    "eudi-rqes-external-sca-service",
    "eudi-rqes-wallet-driven-relying-party",
    "eudi-documentation-site",
}


class CoverageErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_SOURCE_LOCK = "invalid_source_lock"
    INVALID_SOURCE = "invalid_source"
    DUPLICATE_SOURCE = "duplicate_source"
    REQUIRED_SOURCE_MISSING = "required_source_missing"
    INVALID_COVERAGE = "invalid_coverage"
    COVERAGE_MISMATCH = "coverage_mismatch"
    INVALID_EXECUTION_CLAIM = "invalid_execution_claim"


@dataclass(frozen=True)
class CoverageError(Exception):
    reason: CoverageErrorReason


def fail(reason: CoverageErrorReason) -> NoReturn:
    print(f"EUDI upstream coverage validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise CoverageError(CoverageErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise CoverageError(CoverageErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise CoverageError(CoverageErrorReason.INVALID_JSON)
    return value


def exact_object(value: object, keys: set[str], reason: CoverageErrorReason) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CoverageError(reason)
    return value


def required_text(value: object, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE)
    return value


def validate_source_lock(lock: dict[str, object]) -> dict[str, dict[str, object]]:
    exact_object(
        lock,
        {"schema_version", "copyright", "license", "observed_at", "purpose", "sources"},
        CoverageErrorReason.INVALID_SOURCE_LOCK,
    )
    if (
        lock["schema_version"] != 2
        or lock["copyright"]
        != "Copyright © 2026 ReallyMe Technologies Limited. All rights reserved"
        or lock["license"] != "MIT OR Apache-2.0"
        or lock["purpose"] != "eudi-wallet-conformance-and-interoperability-source-pins"
    ):
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE_LOCK)
    try:
        observed_at = datetime.date.fromisoformat(required_text(lock["observed_at"]))
    except ValueError as error:
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE_LOCK) from error
    if observed_at > datetime.date.today():
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE_LOCK)

    sources = lock["sources"]
    if not isinstance(sources, list) or not sources:
        raise CoverageError(CoverageErrorReason.INVALID_SOURCE_LOCK)
    indexed: dict[str, dict[str, object]] = {}
    repositories: set[str] = set()
    checkouts: set[str] = set()
    common_keys = {
        "source_id",
        "role",
        "coverage_class",
        "repository",
        "ref",
        "update_strategy",
        "commit",
        "license",
        "certification_claim",
        "local_checkout",
    }
    for raw_source in sources:
        if not isinstance(raw_source, dict) or set(raw_source) not in (
            common_keys,
            common_keys | {"certification_ready"},
        ):
            raise CoverageError(CoverageErrorReason.INVALID_SOURCE)
        source_id = required_text(raw_source["source_id"], SOURCE_ID)
        role = required_text(raw_source["role"], ROLE)
        coverage_class = required_text(raw_source["coverage_class"])
        repository = required_text(raw_source["repository"])
        source_ref = required_text(raw_source["ref"])
        strategy = required_text(raw_source["update_strategy"])
        commit = required_text(raw_source["commit"], COMMIT)
        required_text(raw_source["license"])
        checkout = required_text(raw_source["local_checkout"])
        parsed_repository = urlsplit(repository)
        repository_parts = PurePosixPath(parsed_repository.path).parts
        checkout_path = PurePosixPath(checkout)
        if (
            parsed_repository.scheme != "https"
            or parsed_repository.netloc != "github.com"
            or len(repository_parts) != 3
            or repository_parts[1] != "eu-digital-identity-wallet"
            or parsed_repository.query
            or parsed_repository.fragment
            or coverage_class not in ALLOWED_COVERAGE_CLASSES
            or strategy not in ALLOWED_UPDATE_STRATEGIES
            or raw_source["certification_claim"] is not False
            or checkout_path.parts
            != ("upstream", "eudi", "checkouts", repository_parts[2])
            or len(source_ref) > 128
            or len(commit) != 40
            or ("certification_ready" in raw_source and raw_source["certification_ready"] is not False)
            or ("certification_ready" in raw_source and source_id != "eudi-fcaf")
        ):
            raise CoverageError(CoverageErrorReason.INVALID_SOURCE)
        if source_id in indexed or repository in repositories or checkout in checkouts:
            raise CoverageError(CoverageErrorReason.DUPLICATE_SOURCE)
        indexed[source_id] = raw_source
        repositories.add(repository)
        checkouts.add(checkout)
        if not role:
            raise CoverageError(CoverageErrorReason.INVALID_SOURCE)
    if not EXPECTED_FOCUS_SOURCE_IDS.issubset(indexed):
        raise CoverageError(CoverageErrorReason.REQUIRED_SOURCE_MISSING)
    return indexed


def validate_coverage(
    coverage: dict[str, object], sources: dict[str, dict[str, object]]
) -> None:
    exact_object(
        coverage,
        {"$comment", "schema", "source_lock_path", "scope", "current_claims", "executed_controls", "source_groups"},
        CoverageErrorReason.INVALID_COVERAGE,
    )
    if (
        not isinstance(coverage["$comment"], str)
        or coverage["schema"] != "reallyme.identity.eudi_upstream_coverage.v1"
        or coverage["source_lock_path"] != "upstream/eudi/sources.lock.json"
        or coverage["scope"] != ["wallet", "eidas_2", "oidf"]
    ):
        raise CoverageError(CoverageErrorReason.INVALID_COVERAGE)
    claims = exact_object(
        coverage["current_claims"],
        {"official_ui_suite_executed", "itb_suite_executed", "fcaf_conformity_established", "rqes_tester_executed", "eu_certification_claim"},
        CoverageErrorReason.INVALID_EXECUTION_CLAIM,
    )
    if any(value is not False for value in claims.values()):
        raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)

    controls = coverage["executed_controls"]
    if not isinstance(controls, list) or len(controls) != 2:
        raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)
    observed_control_lanes: set[str] = set()
    for raw_control in controls:
        control = exact_object(
            raw_control,
            {"lane", "execution_owner", "scope", "external_suite"},
            CoverageErrorReason.INVALID_EXECUTION_CLAIM,
        )
        lane = control["lane"]
        if (
            lane not in {"relying_party", "wallet"}
            or lane in observed_control_lanes
            or control["execution_owner"] != "reallyme"
            or not isinstance(control["scope"], str)
            or not control["scope"]
            or control["external_suite"] is not False
        ):
            raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)
        observed_control_lanes.add(lane)
    if observed_control_lanes != {"relying_party", "wallet"}:
        raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)

    groups = coverage["source_groups"]
    if not isinstance(groups, list) or not groups:
        raise CoverageError(CoverageErrorReason.INVALID_COVERAGE)
    observed_coverage_ids: set[str] = set()
    observed_source_ids: set[str] = set()
    for raw_group in groups:
        group = exact_object(
            raw_group,
            {"coverage_id", "source_ids", "coverage_class", "source_binding", "execution_state", "prerequisites", "certification_claim"},
            CoverageErrorReason.INVALID_COVERAGE,
        )
        coverage_id = group["coverage_id"]
        coverage_class = group["coverage_class"]
        source_binding = group["source_binding"]
        execution_state = group["execution_state"]
        source_ids = group["source_ids"]
        prerequisites = group["prerequisites"]
        if (
            not isinstance(coverage_id, str)
            or IDENTIFIER.fullmatch(coverage_id) is None
            or coverage_id in observed_coverage_ids
            or coverage_class not in ALLOWED_COVERAGE_CLASSES
            or source_binding not in ALLOWED_SOURCE_BINDINGS
            or execution_state not in ALLOWED_EXECUTION_STATES
            or group["certification_claim"] is not False
            or not isinstance(source_ids, list)
            or not source_ids
            or not isinstance(prerequisites, list)
            or len(prerequisites) != len(set(prerequisites))
            or any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in prerequisites)
        ):
            raise CoverageError(CoverageErrorReason.INVALID_COVERAGE)
        observed_coverage_ids.add(coverage_id)
        if coverage_class == "legacy_compatibility" and (
            source_binding != "freshness_monitor" or execution_state != "compatibility_only"
        ):
            raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)
        if coverage_class == "monitor_only" and (
            source_binding != "freshness_monitor" or execution_state != "monitor_only"
        ):
            raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)
        if coverage_class == "official_test_asset" and execution_state != "external_runner_required":
            raise CoverageError(CoverageErrorReason.INVALID_EXECUTION_CLAIM)
        for source_id in source_ids:
            if (
                not isinstance(source_id, str)
                or source_id not in sources
                or source_id in observed_source_ids
                or sources[source_id]["coverage_class"] != coverage_class
            ):
                raise CoverageError(CoverageErrorReason.COVERAGE_MISMATCH)
            observed_source_ids.add(source_id)
    if observed_source_ids != set(sources):
        raise CoverageError(CoverageErrorReason.COVERAGE_MISMATCH)


def verify(source_lock: dict[str, object], coverage: dict[str, object]) -> None:
    validate_coverage(coverage, validate_source_lock(source_lock))


def main() -> int:
    try:
        verify(load_object(SOURCE_LOCK_PATH), load_object(COVERAGE_PATH))
    except CoverageError as error:
        fail(error.reason)
    print("EUDI upstream source pins and execution coverage are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
