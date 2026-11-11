#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the EUDI Wallet plan, adapter, and immutable source baseline."""

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
import verify_eudi_legal_sources as legal_sources  # noqa: E402
import verify_eudi_upstream_coverage as upstream_coverage  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = REPOSITORY_ROOT / "plans" / "eudi" / "wallet.json"
ADAPTER_PATH = REPOSITORY_ROOT / "adapters" / "eudi-wallet" / "adapter.json"
UPSTREAM_LOCK_PATH = REPOSITORY_ROOT / "upstream" / "eudi" / "sources.lock.json"
LEGAL_SOURCES_LOCK_PATH = (
    REPOSITORY_ROOT / "upstream" / "eudi" / "legal-sources.lock.json"
)
PUBLICATIONS_LOCK_PATH = REPOSITORY_ROOT / "references/eudi-publications.lock.json"
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_ARTIFACT_BYTES = 16 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
EXPECTED_COMPONENT_REQUIREMENT = {
    "component_id": "wallet",
    "repository": "https://github.com/reallyme/wallet",
}
EXPECTED_UPSTREAM_SOURCE_IDS = {
    "eudi-arf",
    "eudi-fcaf",
    "eudi-technical-specifications",
    "eudi-attestation-rulebooks",
    "eudi-functional-tests",
    "eudi-itb",
}
EXPECTED_ASSERTIONS = {
    "candidate_source_integrity",
    "upstream_reference_binding",
    "eudi_minimum_requirements",
    "issuance_flow",
    "presentation_flow",
    "malicious_input_rejection",
    "wallet_release_quality",
}
EXPECTED_SOURCE_ARTIFACTS = {
    "cargo-lock": "Cargo.lock",
    "wallet-sources-lock": "conformance/sources.lock",
    "reference-implementation-lock": "conformance/eudi/reference-implementation.lock",
    "upstream-tests": "conformance/eudi/upstream-tests.json",
    "eudi-wallet-minimums": "conformance/requirements/eudi-wallet-minimums.json",
}
EXPECTED_PACKAGES = ["reallyme-wallet-conformance"]
EXPECTED_ATTESTATION_CATEGORIES = {
    "format",
    "lint",
    "unit",
    "integration",
    "vector",
    "security",
    "build",
}
EXPECTED_POLICY = {
    "contains_sensitive_data": False,
    "raw_process_output_retained": False,
    "credential_payloads_retained": False,
    "private_key_material_retained": False,
}


class EudiWalletAdapterErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_PLAN = "invalid_plan"
    INVALID_ADAPTER = "invalid_adapter"
    INVALID_UPSTREAM_LOCK = "invalid_upstream_lock"
    INVALID_CHECKOUT = "invalid_checkout"
    DIRTY_CHECKOUT = "dirty_checkout"
    REVISION_MISMATCH = "revision_mismatch"
    SOURCE_ARTIFACT_MISMATCH = "source_artifact_mismatch"


@dataclass(frozen=True)
class EudiWalletAdapterError(Exception):
    reason: EudiWalletAdapterErrorReason


def fail(reason: EudiWalletAdapterErrorReason) -> NoReturn:
    print(f"EUDI Wallet adapter validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: EudiWalletAdapterErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EudiWalletAdapterError(reason)
    return value


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_JSON) from error
    if not isinstance(value, dict):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_JSON)
    return value


def validate_plan(plan: dict[str, object]) -> None:
    exact_object(
        plan,
        {
            "$comment",
            "schema_version",
            "plan_id",
            "execution_status",
            "certification_claim",
            "required_components",
            "upstream_source_ids",
            "legal_source_ids",
            "assertions",
            "evidence_policy",
        },
        EudiWalletAdapterErrorReason.INVALID_PLAN,
    )
    if (
        plan["schema_version"] != 1
        or plan["plan_id"] != "eudi-wallet-engineering-v1"
        or plan["execution_status"] != "executable"
        or plan["certification_claim"] is not False
        or plan["required_components"] != [EXPECTED_COMPONENT_REQUIREMENT]
        or plan["evidence_policy"] != EXPECTED_POLICY
        or not isinstance(plan["upstream_source_ids"], list)
        or set(plan["upstream_source_ids"]) != EXPECTED_UPSTREAM_SOURCE_IDS
        or len(plan["upstream_source_ids"]) != len(EXPECTED_UPSTREAM_SOURCE_IDS)
        or not isinstance(plan["legal_source_ids"], list)
        or set(plan["legal_source_ids"]) != legal_sources.EXPECTED_SOURCE_IDS
        or len(plan["legal_source_ids"]) != len(legal_sources.EXPECTED_SOURCE_IDS)
    ):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_PLAN)
    assertions = plan["assertions"]
    if not isinstance(assertions, list) or len(assertions) != len(EXPECTED_ASSERTIONS):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_PLAN)
    observed: set[str] = set()
    for raw_assertion in assertions:
        assertion = exact_object(
            raw_assertion,
            {"assertion_id", "required_checks"},
            EudiWalletAdapterErrorReason.INVALID_PLAN,
        )
        assertion_id = assertion["assertion_id"]
        checks = assertion["required_checks"]
        if (
            not isinstance(assertion_id, str)
            or assertion_id in observed
            or assertion_id not in EXPECTED_ASSERTIONS
            or not isinstance(checks, list)
            or not checks
            or len(checks) != len(set(checks))
            or not all(
                isinstance(check, str) and IDENTIFIER.fullmatch(check) is not None
                for check in checks
            )
        ):
            raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_PLAN)
        observed.add(assertion_id)


def validate_upstream_sources(plan: dict[str, object]) -> None:
    lock = load_object(UPSTREAM_LOCK_PATH)
    try:
        observed = set(upstream_coverage.validate_source_lock(lock))
    except upstream_coverage.CoverageError as error:
        raise EudiWalletAdapterError(
            EudiWalletAdapterErrorReason.INVALID_UPSTREAM_LOCK
        ) from error
    required = plan["upstream_source_ids"]
    if not isinstance(required, list) or not set(required).issubset(observed):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_UPSTREAM_LOCK)
    try:
        legal_lock = legal_sources.load_lock(LEGAL_SOURCES_LOCK_PATH)
        legal_sources.verify_lock(legal_lock)
    except legal_sources.EudiLegalSourcesError as error:
        raise EudiWalletAdapterError(
            EudiWalletAdapterErrorReason.INVALID_UPSTREAM_LOCK
        ) from error


def validate_adapter(adapter: dict[str, object], plan: dict[str, object]) -> None:
    exact_object(
        adapter,
        {
            "$comment",
            "schema_version",
            "adapter_id",
            "plan_path",
            "component_requirement",
            "source_artifacts",
            "cargo_packages",
            "required_attestation_categories",
            "evidence_policy",
        },
        EudiWalletAdapterErrorReason.INVALID_ADAPTER,
    )
    if (
        adapter["schema_version"] != 1
        or adapter["adapter_id"] != "eudi_wallet_engineering"
        or adapter["plan_path"] != "plans/eudi/wallet.json"
        or adapter["component_requirement"] != EXPECTED_COMPONENT_REQUIREMENT
        or adapter["cargo_packages"] != EXPECTED_PACKAGES
        or not isinstance(adapter["required_attestation_categories"], list)
        or set(adapter["required_attestation_categories"]) != EXPECTED_ATTESTATION_CATEGORIES
        or len(adapter["required_attestation_categories"]) != len(EXPECTED_ATTESTATION_CATEGORIES)
        or adapter["evidence_policy"] != EXPECTED_POLICY
    ):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_ADAPTER)
    artifacts = adapter["source_artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(EXPECTED_SOURCE_ARTIFACTS):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_ADAPTER)
    observed: set[str] = set()
    for raw_artifact in artifacts:
        artifact = exact_object(
            raw_artifact,
            {"artifact_id", "path"},
            EudiWalletAdapterErrorReason.INVALID_ADAPTER,
        )
        artifact_id = artifact["artifact_id"]
        if (
            not isinstance(artifact_id, str)
            or artifact_id in observed
            or artifact["path"] != EXPECTED_SOURCE_ARTIFACTS.get(artifact_id)
        ):
            raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_ADAPTER)
        observed.add(artifact_id)


def git_output(checkout: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_CHECKOUT) from error
    if completed.returncode != 0:
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_CHECKOUT)
    return completed.stdout.strip()


def verify_source_file(source: Path, relative_path: str) -> None:
    candidate = source / relative_path
    try:
        metadata = candidate.lstat()
        candidate.resolve(strict=True).relative_to(source.resolve(strict=True))
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or not 1 <= metadata.st_size <= MAX_SOURCE_ARTIFACT_BYTES
        ):
            raise EudiWalletAdapterError(
                EudiWalletAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH
            )
    except (OSError, ValueError) as error:
        raise EudiWalletAdapterError(
            EudiWalletAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH
        ) from error
    if not git_output(source, "ls-files", "--error-unmatch", "--", relative_path):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
    return None


def verify_checkout(
    source: Path, adapter: dict[str, object], expected_commit: str
) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.REVISION_MISMATCH)
    if git_output(source, "rev-parse", "HEAD") != expected_commit:
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.REVISION_MISMATCH)
    if git_output(source, "status", "--porcelain"):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.DIRTY_CHECKOUT)
    artifacts = adapter["source_artifacts"]
    if not isinstance(artifacts, list):
        raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_ADAPTER)
    for raw_artifact in artifacts:
        if not isinstance(raw_artifact, dict):
            raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.INVALID_ADAPTER)
        path = raw_artifact.get("path")
        if (
            not isinstance(path, str)
        ):
            raise EudiWalletAdapterError(EudiWalletAdapterErrorReason.SOURCE_ARTIFACT_MISMATCH)
        verify_source_file(source, path)


def load_contract() -> tuple[dict[str, object], dict[str, object]]:
    plan = load_object(PLAN_PATH)
    adapter = load_object(ADAPTER_PATH)
    validate_plan(plan)
    validate_upstream_sources(plan)
    validate_adapter(adapter, plan)
    return plan, adapter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    try:
        _plan, adapter = load_contract()
        if args.source is not None:
            if args.expected_commit is None:
                raise EudiWalletAdapterError(
                    EudiWalletAdapterErrorReason.REVISION_MISMATCH
                )
            verify_checkout(args.source, adapter, args.expected_commit)
    except EudiWalletAdapterError as error:
        fail(error.reason)
    print("EUDI Wallet engineering adapter valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
