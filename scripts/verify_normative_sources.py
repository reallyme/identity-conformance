#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate hash-pinned, reference-only normative source metadata."""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path, PurePosixPath
from typing import NoReturn
from urllib.parse import urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK_PATH = REPOSITORY_ROOT / "references" / "normative-sources.lock.json"
MAX_JSON_BYTES = 1_000_000
EXIT_INVALID_INPUT = 65
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_ID = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
REPOSITORY = re.compile(r"^reallyme/[A-Za-z0-9_.-]+$")


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID_INPUT)


def load_object(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            fail("normative source ledger exceeds the accepted size")
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("normative source ledger is unavailable or invalid JSON")
    if not isinstance(value, dict):
        fail("normative source ledger must contain an object")
    return value


def require_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty string")
    return value


def validate_relative_path(value: object, context: str) -> str:
    path = require_string(value, context)
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts:
        fail(f"{context} must be a normalized repository-relative path")
    return path


def validate_date(value: object, context: str) -> None:
    text = require_string(value, context)
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        fail(f"{context} must be an ISO 8601 calendar date")


def verify_source(raw_source: object, observed_ids: set[str]) -> None:
    if not isinstance(raw_source, dict):
        fail("every normative source must be an object")
    source = raw_source
    expected_keys = {
        "id",
        "title",
        "publisher",
        "version",
        "publication_date",
        "canonical_url",
        "sha256",
        "content_length",
        "verified_on",
        "vendoring_policy",
        "reviewed_clauses",
        "implementation_evidence",
        "clause_review",
    }
    if set(source) != expected_keys:
        fail("normative source fields do not match the v1 contract")

    source_id = require_string(source.get("id"), "source.id")
    if SOURCE_ID.fullmatch(source_id) is None or source_id in observed_ids:
        fail("source.id is invalid or duplicated")
    observed_ids.add(source_id)
    for field in ("title", "publisher", "version", "publication_date"):
        require_string(source.get(field), f"{source_id}.{field}")

    url = require_string(source.get("canonical_url"), f"{source_id}.canonical_url")
    parsed_url = urlsplit(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.fragment:
        fail(f"{source_id}.canonical_url must be an absolute HTTPS URL without a fragment")
    digest = require_string(source.get("sha256"), f"{source_id}.sha256")
    if SHA256.fullmatch(digest) is None:
        fail(f"{source_id}.sha256 must be a lowercase SHA-256 digest")
    content_length = source.get("content_length")
    if not isinstance(content_length, int) or isinstance(content_length, bool) or content_length <= 0:
        fail(f"{source_id}.content_length must be a positive integer")
    validate_date(source.get("verified_on"), f"{source_id}.verified_on")
    if source.get("vendoring_policy") != "reference_only_copyrighted_source":
        fail(f"{source_id}.vendoring_policy must keep the source reference-only")

    clauses = source.get("reviewed_clauses")
    if not isinstance(clauses, list) or not clauses:
        fail(f"{source_id}.reviewed_clauses must be a non-empty unique array")
    if any(not isinstance(clause, str) or not clause for clause in clauses):
        fail(f"{source_id}.reviewed_clauses contains an invalid clause")
    if len(clauses) != len(set(clauses)):
        fail(f"{source_id}.reviewed_clauses must be a non-empty unique array")

    evidence = source.get("implementation_evidence")
    if not isinstance(evidence, list) or not evidence:
        fail(f"{source_id}.implementation_evidence must be non-empty")
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"repository", "path"}:
            fail(f"{source_id}.implementation_evidence contains an invalid item")
        repository = require_string(item.get("repository"), "evidence.repository")
        if REPOSITORY.fullmatch(repository) is None:
            fail("evidence.repository must identify a ReallyMe repository")
        validate_relative_path(item.get("path"), "evidence.path")

    clause_review = validate_relative_path(
        source.get("clause_review"), f"{source_id}.clause_review"
    )
    if not (REPOSITORY_ROOT / clause_review).is_file():
        fail(f"{source_id}.clause_review does not resolve to a checked file")


def verify_ledger(ledger: dict[str, object]) -> None:
    if set(ledger) != {"$comment", "schema", "sources"}:
        fail("normative source ledger fields do not match the v1 contract")
    require_string(ledger.get("$comment"), "ledger.$comment")
    if ledger.get("schema") != "reallyme.identity.normative_sources.v1":
        fail("normative source ledger has an unsupported schema")
    sources = ledger.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("normative source ledger must contain at least one source")
    observed_ids: set[str] = set()
    for source in sources:
        verify_source(source, observed_ids)


def main() -> int:
    verify_ledger(load_object(SOURCE_LOCK_PATH))
    print("Normative source references are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
