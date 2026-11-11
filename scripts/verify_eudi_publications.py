#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate independently pinned publications used by the EUDI wallet scope."""

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
PUBLICATIONS_PATH = REPOSITORY_ROOT / "references/eudi-publications.lock.json"
MAX_JSON_BYTES = 1_000_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
EXPECTED_PUBLICATION_IDS = {
    "iso-iec-18013-5-2021",
    "iso-iec-ts-18013-6-2025",
    "iso-iec-ts-18013-7-2025",
    "iso-iec-ts-23220-2-2024",
    "rfc-5280",
    "rfc-8949",
    "rfc-9052",
    "rfc-9053",
    "rfc-9901",
    "w3c-vc-data-model-2.0",
    "w3c-digital-credentials-2026-11-05",
    "etsi-ts-119-411-8-v1.1.1",
    "etsi-ts-119-432-v1.3.1",
    "etsi-ts-119-475-v1.2.1",
}
EXPECTED_DELEGATED_IDS = {
    "openid4vci-1.0-final",
    "openid4vp-1.0-final",
    "openid4vc-haip-1.0-final",
    "etsi-ts-119-612-v2.4.1",
    "etsi-ts-119-472-1-v1.2.1",
    "etsi-ts-119-472-2-v1.3.1",
    "etsi-ts-119-472-3-v1.1.1",
}
EXPECTED_HOSTS = {
    "ISO/IEC": "www.iso.org",
    "IETF": "www.rfc-editor.org",
    "W3C": "www.w3.org",
    "ETSI": "www.etsi.org",
}
DELEGATED_LOCKS = {
    "upstream/oidf/specifications.lock.json": "specification_id",
    "references/normative-sources.lock.json": "id",
}


class PublicationErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_LEDGER = "invalid_ledger"
    INVALID_PUBLICATION = "invalid_publication"
    DUPLICATE_PUBLICATION = "duplicate_publication"
    REQUIRED_PUBLICATION_MISSING = "required_publication_missing"
    INVALID_BINDING = "invalid_binding"
    INVALID_DELEGATED_BINDING = "invalid_delegated_binding"


@dataclass(frozen=True)
class PublicationError(Exception):
    reason: PublicationErrorReason


def fail(reason: PublicationErrorReason) -> NoReturn:
    print(f"EUDI publication validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise PublicationError(PublicationErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise PublicationError(PublicationErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise PublicationError(PublicationErrorReason.INVALID_JSON)
    return value


def exact_object(value: object, keys: set[str], reason: PublicationErrorReason) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PublicationError(reason)
    return value


def required_text(value: object, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
        raise PublicationError(PublicationErrorReason.INVALID_PUBLICATION)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise PublicationError(PublicationErrorReason.INVALID_PUBLICATION)
    return value


def validate_publication(raw_publication: object) -> str:
    publication = exact_object(
        raw_publication,
        {"id", "title", "publisher", "edition", "publication_date", "maturity", "canonical_url", "certification_claim", "binding"},
        PublicationErrorReason.INVALID_PUBLICATION,
    )
    publication_id = required_text(publication["id"], IDENTIFIER)
    required_text(publication["title"])
    publisher = required_text(publication["publisher"])
    required_text(publication["edition"])
    publication_date = required_text(publication["publication_date"])
    maturity = required_text(publication["maturity"])
    url = required_text(publication["canonical_url"])
    try:
        datetime.datetime.strptime(publication_date, "%Y-%m")
    except ValueError as error:
        raise PublicationError(PublicationErrorReason.INVALID_PUBLICATION) from error
    parsed_url = urlsplit(url)
    if (
        publisher not in EXPECTED_HOSTS
        or parsed_url.scheme != "https"
        or parsed_url.netloc != EXPECTED_HOSTS[publisher]
        or parsed_url.query
        or parsed_url.fragment
        or maturity not in {"published_standard", "working_draft"}
        or (maturity == "working_draft" and publisher != "W3C")
        or publication["certification_claim"] is not False
    ):
        raise PublicationError(PublicationErrorReason.INVALID_PUBLICATION)

    binding = publication["binding"]
    if not isinstance(binding, dict):
        raise PublicationError(PublicationErrorReason.INVALID_BINDING)
    kind = binding.get("kind")
    if kind == "content_sha256":
        exact_object(
            binding,
            {"kind", "sha256", "content_length"},
            PublicationErrorReason.INVALID_BINDING,
        )
        digest = binding["sha256"]
        content_length = binding["content_length"]
        if (
            publisher == "ISO/IEC"
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or not isinstance(content_length, int)
            or isinstance(content_length, bool)
            or not 1 <= content_length <= 4 * 1024 * 1024
        ):
            raise PublicationError(PublicationErrorReason.INVALID_BINDING)
    elif kind == "official_edition":
        exact_object(
            binding,
            {"kind", "standard_number", "copyright_restricted", "local_copy_allowed"},
            PublicationErrorReason.INVALID_BINDING,
        )
        standard_number = binding["standard_number"]
        if (
            publisher != "ISO/IEC"
            or not isinstance(standard_number, str)
            or not standard_number.startswith("ISO/IEC")
            or binding["copyright_restricted"] is not True
            or binding["local_copy_allowed"] is not False
        ):
            raise PublicationError(PublicationErrorReason.INVALID_BINDING)
    else:
        raise PublicationError(PublicationErrorReason.INVALID_BINDING)
    return publication_id


def delegated_target_ids(relative_path: str, identifier_field: str) -> set[str]:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)
    document = load_object(REPOSITORY_ROOT / path)
    entries = document.get("publications") if identifier_field == "specification_id" else document.get("sources")
    if not isinstance(entries, list):
        raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)
    identifiers: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get(identifier_field), str):
            raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)
        identifiers.add(entry[identifier_field])
    return identifiers


def verify_ledger(ledger: dict[str, object]) -> None:
    exact_object(
        ledger,
        {"$comment", "schema", "observed_on", "scope", "publications", "delegated_bindings"},
        PublicationErrorReason.INVALID_LEDGER,
    )
    if (
        not isinstance(ledger["$comment"], str)
        or ledger["schema"] != "reallyme.identity.eudi_publications.v1"
        or ledger["scope"] != ["wallet", "eidas_2", "oidf"]
    ):
        raise PublicationError(PublicationErrorReason.INVALID_LEDGER)
    try:
        observed_on = datetime.date.fromisoformat(required_text(ledger["observed_on"]))
    except ValueError as error:
        raise PublicationError(PublicationErrorReason.INVALID_LEDGER) from error
    if observed_on > datetime.date.today():
        raise PublicationError(PublicationErrorReason.INVALID_LEDGER)

    publications = ledger["publications"]
    if not isinstance(publications, list) or not publications:
        raise PublicationError(PublicationErrorReason.INVALID_LEDGER)
    publication_ids: set[str] = set()
    for publication in publications:
        publication_id = validate_publication(publication)
        if publication_id in publication_ids:
            raise PublicationError(PublicationErrorReason.DUPLICATE_PUBLICATION)
        publication_ids.add(publication_id)
    if publication_ids != EXPECTED_PUBLICATION_IDS:
        raise PublicationError(PublicationErrorReason.REQUIRED_PUBLICATION_MISSING)

    delegated = ledger["delegated_bindings"]
    if not isinstance(delegated, list) or not delegated:
        raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)
    delegated_ids: set[str] = set()
    targets_by_lock = {
        path: delegated_target_ids(path, field)
        for path, field in DELEGATED_LOCKS.items()
    }
    for raw_binding in delegated:
        binding = exact_object(
            raw_binding,
            {"publication_id", "lock_path", "target_id"},
            PublicationErrorReason.INVALID_DELEGATED_BINDING,
        )
        publication_id = binding["publication_id"]
        lock_path = binding["lock_path"]
        target_id = binding["target_id"]
        if (
            not isinstance(publication_id, str)
            or IDENTIFIER.fullmatch(publication_id) is None
            or publication_id in delegated_ids
            or lock_path not in targets_by_lock
            or not isinstance(target_id, str)
            or target_id != publication_id
            or target_id not in targets_by_lock[lock_path]
        ):
            raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)
        delegated_ids.add(publication_id)
    if delegated_ids != EXPECTED_DELEGATED_IDS or publication_ids.intersection(delegated_ids):
        raise PublicationError(PublicationErrorReason.INVALID_DELEGATED_BINDING)


def main() -> int:
    try:
        verify_ledger(load_object(PUBLICATIONS_PATH))
    except PublicationError as error:
        fail(error.reason)
    print("EUDI external publication pins are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
