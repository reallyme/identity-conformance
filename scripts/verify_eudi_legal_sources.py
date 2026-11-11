#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate immutable EU legal identities and their amendment graph."""

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


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK_PATH = REPOSITORY_ROOT / "upstream" / "eudi" / "legal-sources.lock.json"
MAX_LOCK_BYTES = 256 * 1024
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
CELEX = re.compile(r"^320[0-9]{2}R[0-9]{4}$")
ELI = re.compile(
    r"^https://data\.europa\.eu/eli/(?:reg|reg_impl)/[0-9]{4}/[0-9]+/oj$"
)
CONSOLIDATED_ELI = re.compile(
    r"^https://data\.europa\.eu/eli/reg_impl/[0-9]{4}/[0-9]+/"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}$"
)
EXPECTED_SOURCE_IDS = {
    "eu-regulation-910-2014",
    "eu-regulation-2024-1183",
    "cir-2024-2977",
    "cir-2024-2979",
    "cir-2024-2980",
    "cir-2024-2981",
    "cir-2024-2982",
    "cir-2025-846",
    "cir-2025-847",
    "cir-2025-848",
    "cir-2025-849",
    "cir-2025-1569",
    "cir-2026-1730",
    "cir-2026-1731",
}
EXPECTED_AMENDMENTS = {
    "eu-regulation-2024-1183": {"eu-regulation-910-2014"},
    "cir-2026-1730": {"cir-2025-848"},
    "cir-2026-1731": {
        "cir-2024-2977",
        "cir-2024-2979",
        "cir-2024-2980",
        "cir-2024-2982",
    },
}
EXPECTED_CONSOLIDATIONS = {
    "cir-2024-2977",
    "cir-2024-2979",
    "cir-2024-2980",
    "cir-2024-2982",
    "cir-2025-848",
}
SOURCE_KINDS = {
    "governing_regulation",
    "governing_amendment",
    "implementing_regulation",
    "implementing_amendment",
}


class EudiLegalSourcesErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_LOCK = "invalid_lock"
    INVALID_SOURCE = "invalid_source"
    INVALID_AMENDMENT_GRAPH = "invalid_amendment_graph"
    INVALID_CONSOLIDATION = "invalid_consolidation"


@dataclass(frozen=True)
class EudiLegalSourcesError(Exception):
    reason: EudiLegalSourcesErrorReason


def fail(reason: EudiLegalSourcesErrorReason) -> NoReturn:
    print(f"EUDI legal-source lock invalid: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def load_lock(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= MAX_LOCK_BYTES
        ):
            raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_JSON)
    return value


def string_set(value: object, reason: EudiLegalSourcesErrorReason) -> set[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise EudiLegalSourcesError(reason)
    return set(value)


def verify_lock(value: dict[str, object]) -> None:
    if set(value) != {
        "$comment",
        "schema",
        "observed_at",
        "pin_policy",
        "sources",
        "current_consolidations",
    }:
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_LOCK)
    if (
        value["schema"] != "reallyme.identity.eudi_legal_sources.v1"
        or value["pin_policy"] != "immutable_eli_and_celex_identifiers"
        or not isinstance(value["observed_at"], str)
        or DATE.fullmatch(value["observed_at"]) is None
    ):
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_LOCK)
    sources = value["sources"]
    if not isinstance(sources, list) or len(sources) != len(EXPECTED_SOURCE_IDS):
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_SOURCE)
    by_id: dict[str, dict[str, object]] = {}
    celex_ids: set[str] = set()
    eli_ids: set[str] = set()
    for raw_source in sources:
        if not isinstance(raw_source, dict):
            raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_SOURCE)
        allowed_keys = {
            "source_id",
            "kind",
            "celex",
            "eli",
            "adopted_on",
            "title",
            "amends",
            "amended_by",
        }
        required_keys = {
            "source_id",
            "kind",
            "celex",
            "eli",
            "adopted_on",
            "title",
        }
        if not required_keys.issubset(raw_source) or not set(raw_source).issubset(
            allowed_keys
        ):
            raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_SOURCE)
        source_id = raw_source["source_id"]
        celex = raw_source["celex"]
        eli = raw_source["eli"]
        if (
            not isinstance(source_id, str)
            or source_id in by_id
            or source_id not in EXPECTED_SOURCE_IDS
            or raw_source["kind"] not in SOURCE_KINDS
            or not isinstance(celex, str)
            or CELEX.fullmatch(celex) is None
            or celex in celex_ids
            or not isinstance(eli, str)
            or ELI.fullmatch(eli) is None
            or eli in eli_ids
            or not isinstance(raw_source["adopted_on"], str)
            or DATE.fullmatch(raw_source["adopted_on"]) is None
            or not isinstance(raw_source["title"], str)
            or not 10 <= len(raw_source["title"]) <= 256
        ):
            raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_SOURCE)
        by_id[source_id] = raw_source
        celex_ids.add(celex)
        eli_ids.add(eli)
    if set(by_id) != EXPECTED_SOURCE_IDS:
        raise EudiLegalSourcesError(EudiLegalSourcesErrorReason.INVALID_SOURCE)
    observed_amendments: dict[str, set[str]] = {}
    for source_id, source in by_id.items():
        if "amends" in source:
            observed_amendments[source_id] = string_set(
                source["amends"], EudiLegalSourcesErrorReason.INVALID_AMENDMENT_GRAPH
            )
    if observed_amendments != EXPECTED_AMENDMENTS:
        raise EudiLegalSourcesError(
            EudiLegalSourcesErrorReason.INVALID_AMENDMENT_GRAPH
        )
    for amendment_id, amended_ids in EXPECTED_AMENDMENTS.items():
        for amended_id in amended_ids:
            amended_by = string_set(
                by_id[amended_id].get("amended_by"),
                EudiLegalSourcesErrorReason.INVALID_AMENDMENT_GRAPH,
            )
            expected_reverse = {
                candidate
                for candidate, targets in EXPECTED_AMENDMENTS.items()
                if amended_id in targets
            }
            if amendment_id not in amended_by or amended_by != expected_reverse:
                raise EudiLegalSourcesError(
                    EudiLegalSourcesErrorReason.INVALID_AMENDMENT_GRAPH
                )
    consolidations = value["current_consolidations"]
    if not isinstance(consolidations, list) or len(consolidations) != len(
        EXPECTED_CONSOLIDATIONS
    ):
        raise EudiLegalSourcesError(
            EudiLegalSourcesErrorReason.INVALID_CONSOLIDATION
        )
    observed_consolidations: set[str] = set()
    for raw_consolidation in consolidations:
        if not isinstance(raw_consolidation, dict) or set(raw_consolidation) != {
            "source_id",
            "as_of",
            "eli",
        }:
            raise EudiLegalSourcesError(
                EudiLegalSourcesErrorReason.INVALID_CONSOLIDATION
            )
        source_id = raw_consolidation["source_id"]
        if (
            not isinstance(source_id, str)
            or source_id in observed_consolidations
            or source_id not in EXPECTED_CONSOLIDATIONS
            or raw_consolidation["as_of"] != "2026-08-11"
            or not isinstance(raw_consolidation["eli"], str)
            or CONSOLIDATED_ELI.fullmatch(raw_consolidation["eli"]) is None
        ):
            raise EudiLegalSourcesError(
                EudiLegalSourcesErrorReason.INVALID_CONSOLIDATION
            )
        observed_consolidations.add(source_id)
    if observed_consolidations != EXPECTED_CONSOLIDATIONS:
        raise EudiLegalSourcesError(
            EudiLegalSourcesErrorReason.INVALID_CONSOLIDATION
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK_PATH)
    args = parser.parse_args()
    try:
        verify_lock(load_lock(args.lock))
    except EudiLegalSourcesError as error:
        fail(error.reason)
    print("EUDI legal-source lock valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
