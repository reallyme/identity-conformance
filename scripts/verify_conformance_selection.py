#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a caller's profile and badge selection against the release catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


CATALOG_PATH = REPOSITORY_ROOT / "plans/conformance-catalog.json"
MAX_JSON_BYTES = 512 * 1024
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CAPABILITY = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$")
PRODUCT_KINDS = frozenset({"eudi-relying-party", "identity", "wallet", "zk"})
EXECUTABLE_STATE = "executable"
AVAILABLE_STATE = "available"
NORMATIVE_TRACE_CLASSES = frozenset(
    {
        "partial_exact_clause_trace",
        "exact_requirement_registry_trace",
        "suite_inventory_trace",
        "source_document_provenance",
        "framework_assertion_contract",
        "mixed",
    }
)
ASSERTION_EVIDENCE_CLASSES = frozenset(
    {
        "mixed_exact_and_candidate_test_inventory",
        "framework_executed_component_and_sdk_tests",
        "external_suite_observation",
        "caller_runner_required",
        "attestation_only",
        "source_bound_test_candidates_and_attestation",
        "candidate_test_inventory_or_linked_observation",
        "mixed_with_known_gaps",
    }
)


class SelectionErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    CATALOG_INVALID = "catalog_invalid"
    BADGE_UNKNOWN = "badge_unknown"
    BADGE_UNAVAILABLE = "badge_unavailable"
    PRODUCT_INELIGIBLE = "product_ineligible"
    PROFILE_UNKNOWN = "profile_unknown"
    PROFILE_UNAVAILABLE = "profile_unavailable"
    CAPABILITY_MISSING = "capability_missing"
    MANDATORY_PROFILE_MISSING = "mandatory_profile_missing"


@dataclass(frozen=True)
class SelectionError(Exception):
    reason: SelectionErrorReason


def fail(reason: SelectionErrorReason) -> NoReturn:
    raise SelectionError(reason)


def load_object(path: Path, reason: SelectionErrorReason) -> dict[str, object]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAX_JSON_BYTES
        ):
            fail(reason)
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


def string_array(
    value: object,
    pattern: re.Pattern[str],
    reason: SelectionErrorReason,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > 32
        or any(not isinstance(item, str) or pattern.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        fail(reason)
    return tuple(value)


def profile_index(catalog: dict[str, object]) -> dict[str, dict[str, object]]:
    raw_profiles = catalog.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        fail(SelectionErrorReason.CATALOG_INVALID)
    profiles: dict[str, dict[str, object]] = {}
    required_fields = {
        "profile_id",
        "label",
        "authority",
        "execution_state",
        "badge_eligible",
        "product_kinds",
        "required_capabilities",
        "required_profiles",
        "workflow",
        "evidence_class",
        "normative_trace",
        "assertion_evidence",
        "summary",
    }
    for raw_profile in raw_profiles:
        if not isinstance(raw_profile, dict) or set(raw_profile) != required_fields:
            fail(SelectionErrorReason.CATALOG_INVALID)
        profile_id = raw_profile.get("profile_id")
        product_kinds = string_array(
            raw_profile.get("product_kinds"),
            IDENTIFIER,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=False,
        )
        string_array(
            raw_profile.get("required_capabilities"),
            CAPABILITY,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=True,
        )
        string_array(
            raw_profile.get("required_profiles"),
            IDENTIFIER,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=True,
        )
        workflow = raw_profile.get("workflow")
        if (
            not isinstance(profile_id, str)
            or IDENTIFIER.fullmatch(profile_id) is None
            or profile_id in profiles
            or not set(product_kinds).issubset(PRODUCT_KINDS)
            or not isinstance(raw_profile.get("label"), str)
            or not isinstance(raw_profile.get("authority"), str)
            or not isinstance(raw_profile.get("execution_state"), str)
            or not isinstance(raw_profile.get("badge_eligible"), bool)
            or not isinstance(raw_profile.get("evidence_class"), str)
            or raw_profile.get("normative_trace") not in NORMATIVE_TRACE_CLASSES
            or raw_profile.get("assertion_evidence")
            not in ASSERTION_EVIDENCE_CLASSES
            or not isinstance(raw_profile.get("summary"), str)
            or (
                workflow is not None
                and (
                    not isinstance(workflow, str)
                    or not workflow.startswith(".github/workflows/")
                    or not workflow.endswith(".yml")
                    or ".." in Path(workflow).parts
                )
            )
            or (
                raw_profile.get("badge_eligible") is True
                and raw_profile.get("execution_state") != EXECUTABLE_STATE
            )
        ):
            fail(SelectionErrorReason.CATALOG_INVALID)
        profiles[profile_id] = raw_profile
    for profile_id, profile in profiles.items():
        dependencies = string_array(
            profile["required_profiles"],
            IDENTIFIER,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=True,
        )
        if profile_id in dependencies or not set(dependencies).issubset(profiles):
            fail(SelectionErrorReason.CATALOG_INVALID)
    return profiles


def badge_index(
    catalog: dict[str, object], profiles: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    raw_badges = catalog.get("badges")
    if not isinstance(raw_badges, list) or not raw_badges:
        fail(SelectionErrorReason.CATALOG_INVALID)
    badges: dict[str, dict[str, object]] = {}
    required_fields = {
        "badge_id",
        "label",
        "product_kinds",
        "execution_state",
        "required_profiles",
    }
    for raw_badge in raw_badges:
        if not isinstance(raw_badge, dict) or set(raw_badge) != required_fields:
            fail(SelectionErrorReason.CATALOG_INVALID)
        badge_id = raw_badge.get("badge_id")
        product_kinds = string_array(
            raw_badge.get("product_kinds"),
            IDENTIFIER,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=False,
        )
        required_profiles = string_array(
            raw_badge.get("required_profiles"),
            IDENTIFIER,
            SelectionErrorReason.CATALOG_INVALID,
            allow_empty=False,
        )
        if (
            not isinstance(badge_id, str)
            or IDENTIFIER.fullmatch(badge_id) is None
            or badge_id in badges
            or not set(product_kinds).issubset(PRODUCT_KINDS)
            or not isinstance(raw_badge.get("label"), str)
            or raw_badge.get("execution_state") not in {AVAILABLE_STATE, "incomplete"}
            or not set(required_profiles).issubset(profiles)
            or (
                raw_badge.get("execution_state") == AVAILABLE_STATE
                and any(
                    profiles[profile_id].get("execution_state") != EXECUTABLE_STATE
                    or profiles[profile_id].get("badge_eligible") is not True
                    for profile_id in required_profiles
                )
            )
        ):
            fail(SelectionErrorReason.CATALOG_INVALID)
        badges[badge_id] = raw_badge
    return badges


def validate_catalog(
    catalog: dict[str, object],
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    if (
        set(catalog) != {"schema_version", "catalog_id", "profiles", "badges"}
        or catalog.get("schema_version") != 1
        or catalog.get("catalog_id") != "reallyme-identity-conformance"
    ):
        fail(SelectionErrorReason.CATALOG_INVALID)
    profiles = profile_index(catalog)
    badges = badge_index(catalog, profiles)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(profile_id: str) -> None:
        if profile_id in visiting:
            fail(SelectionErrorReason.CATALOG_INVALID)
        if profile_id in visited:
            return
        visiting.add(profile_id)
        for dependency in profiles[profile_id]["required_profiles"]:
            visit(dependency)
        visiting.remove(profile_id)
        visited.add(profile_id)

    for profile_id in profiles:
        visit(profile_id)
    return profiles, badges


def required_profile_closure(
    profile_ids: tuple[str, ...], profiles: dict[str, dict[str, object]]
) -> frozenset[str]:
    required: set[str] = set()
    pending = list(profile_ids)
    while pending:
        profile_id = pending.pop()
        if profile_id in required:
            continue
        profile = profiles.get(profile_id)
        if profile is None:
            fail(SelectionErrorReason.CATALOG_INVALID)
        required.add(profile_id)
        pending.extend(
            string_array(
                profile["required_profiles"],
                IDENTIFIER,
                SelectionErrorReason.CATALOG_INVALID,
                allow_empty=True,
            )
        )
        if len(required) > len(profiles):
            fail(SelectionErrorReason.CATALOG_INVALID)
    return frozenset(required)


def validate_selection(
    selection: dict[str, object], catalog: dict[str, object]
) -> dict[str, object]:
    required_fields = {
        "schema_version",
        "product_kind",
        "product_version",
        "capabilities",
        "requested_badge_id",
        "selected_profiles",
    }
    product_kind = selection.get("product_kind")
    product_version = selection.get("product_version")
    requested_badge_id = selection.get("requested_badge_id")
    if (
        set(selection) != required_fields
        or selection.get("schema_version") != 1
        or not isinstance(product_kind, str)
        or product_kind not in PRODUCT_KINDS
        or not isinstance(product_version, str)
        or VERSION.fullmatch(product_version) is None
        or not isinstance(requested_badge_id, str)
        or IDENTIFIER.fullmatch(requested_badge_id) is None
    ):
        fail(SelectionErrorReason.INPUT_INVALID)
    capabilities = frozenset(
        string_array(
            selection.get("capabilities"),
            CAPABILITY,
            SelectionErrorReason.INPUT_INVALID,
            allow_empty=False,
        )
    )
    selected_profiles = frozenset(
        string_array(
            selection.get("selected_profiles"),
            IDENTIFIER,
            SelectionErrorReason.INPUT_INVALID,
            allow_empty=False,
        )
    )
    profiles, badges = validate_catalog(catalog)
    badge = badges.get(requested_badge_id)
    if badge is None:
        fail(SelectionErrorReason.BADGE_UNKNOWN)
    if badge.get("execution_state") != AVAILABLE_STATE:
        fail(SelectionErrorReason.BADGE_UNAVAILABLE)
    if product_kind not in badge["product_kinds"]:
        fail(SelectionErrorReason.PRODUCT_INELIGIBLE)
    unknown_profiles = selected_profiles.difference(profiles)
    if unknown_profiles:
        fail(SelectionErrorReason.PROFILE_UNKNOWN)
    for profile_id in selected_profiles:
        profile = profiles[profile_id]
        if (
            profile.get("execution_state") != EXECUTABLE_STATE
            or profile.get("badge_eligible") is not True
        ):
            fail(SelectionErrorReason.PROFILE_UNAVAILABLE)
        if product_kind not in profile["product_kinds"]:
            fail(SelectionErrorReason.PRODUCT_INELIGIBLE)
        required_capabilities = frozenset(profile["required_capabilities"])
        if not required_capabilities.issubset(capabilities):
            fail(SelectionErrorReason.CAPABILITY_MISSING)
    mandatory = required_profile_closure(
        tuple(badge["required_profiles"]), profiles
    )
    if not mandatory.issubset(selected_profiles):
        fail(SelectionErrorReason.MANDATORY_PROFILE_MISSING)
    normalized = {
        "schema_version": 1,
        "catalog_id": catalog["catalog_id"],
        "product_kind": product_kind,
        "product_version": product_version,
        "capabilities": sorted(capabilities),
        "requested_badge_id": requested_badge_id,
        "selected_profiles": sorted(selected_profiles),
        "mandatory_profiles": sorted(mandatory),
    }
    encoded = json.dumps(
        normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    normalized["canonical_sha256"] = hashlib.sha256(encoded).hexdigest()
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    arguments = parser.parse_args()
    try:
        validated = validate_selection(
            load_object(arguments.selection, SelectionErrorReason.INPUT_INVALID),
            load_object(arguments.catalog, SelectionErrorReason.CATALOG_INVALID),
        )
    except SelectionError as error:
        print(
            f"conformance selection invalid: {error.reason.value}", file=sys.stderr
        )
        return 65
    print(json.dumps(validated, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
