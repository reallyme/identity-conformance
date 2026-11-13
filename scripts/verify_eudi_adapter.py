#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the executable EUDI adapter, source bindings, and checkouts."""

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
import verify_eudi_relying_party_plan as plan_verifier  # noqa: E402
import verify_eudi_relying_party_requirement_tests as requirement_tests  # noqa: E402
import verify_eudi_upstream_coverage as upstream_coverage  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = (
    REPOSITORY_ROOT / "adapters" / "eudi-relying-party" / "adapter.json"
)
PLAN_PATH = REPOSITORY_ROOT / "plans" / "eudi" / "relying-party-control-plane.json"
REQUIREMENT_TEST_PLAN_PATH = (
    REPOSITORY_ROOT / "plans" / "eudi" / "relying-party-requirement-tests.json"
)
UPSTREAM_LOCK_PATH = REPOSITORY_ROOT / "upstream" / "eudi" / "sources.lock.json"
LEGAL_SOURCES_LOCK_PATH = (
    REPOSITORY_ROOT / "upstream" / "eudi" / "legal-sources.lock.json"
)
PUBLICATIONS_LOCK_PATH = REPOSITORY_ROOT / "references/eudi-publications.lock.json"
MAX_JSON_BYTES = 256 * 1024
EXIT_INVALID = 78
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_PART = re.compile(r"^[A-Za-z0-9._-]+$")
EXPECTED_EXECUTION_SOURCES = {
    "eudi-arf",
    "eudi-fcaf",
    "eudi-technical-specifications",
    "eudi-relying-party-registration-service",
}
EXPECTED_NORMATIVE_PROFILES = [
    {
        "profile_id": "ts5",
        "source_id": "eudi-technical-specifications",
        "version_field": "ts5_version",
        "expected_version": "1.6.1",
        "commit_field": "ts5_baseline_commit",
        "candidate_root": "apps/eudi-qp/resources/upstream/ts5",
        "upstream_root": (
            "eudi-doc-standards-and-technical-specifications/"
            "docs/technical-specifications"
        ),
        "files": [
            {
                "artifact_id": "json_common_rp_data_model",
                "candidate_path": "ts5-json-common-rp-data-model.json",
                "upstream_path": "api/ts5-json-common-rp-data-model.json",
            },
            {
                "artifact_id": "registrar_api",
                "candidate_path": "ts5-openapi31-registrar-api.yml",
                "upstream_path": "api/ts5-openapi31-registrar-api.yml",
            },
            {
                "artifact_id": "write_api",
                "candidate_path": "ts5-openapi31-write-api.yml",
                "upstream_path": "api/ts5-openapi31-write-api.yml",
            },
        ],
    },
    {
        "profile_id": "ts6",
        "source_id": "eudi-technical-specifications",
        "version_field": "ts6_version",
        "expected_version": "1.2.2",
        "commit_field": "ts6_baseline_commit",
        "candidate_root": "apps/eudi-qp/resources/upstream/ts6",
        "upstream_root": (
            "eudi-doc-standards-and-technical-specifications/"
            "docs/technical-specifications"
        ),
        "files": [
            {
                "artifact_id": "common_set_of_rp_information",
                "candidate_path": (
                    "ts6-common-set-of-rp-information-to-be-registered.md"
                ),
                "upstream_path": (
                    "ts6-common-set-of-rp-information-to-be-registered.md"
                ),
            },
        ],
    },
]


class AdapterErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_ADAPTER = "invalid_adapter"
    INVALID_PLAN = "invalid_plan"
    INVALID_UPSTREAM_LOCK = "invalid_upstream_lock"
    INVALID_SOURCE_BINDING = "invalid_source_binding"
    INVALID_CHECKOUT = "invalid_checkout"
    DIRTY_CHECKOUT = "dirty_checkout"
    REVISION_MISMATCH = "revision_mismatch"
    SOURCE_BINDING_MISMATCH = "source_binding_mismatch"


@dataclass(frozen=True)
class AdapterError(Exception):
    reason: AdapterErrorReason


@dataclass(frozen=True)
class ContractBundle:
    adapter: dict[str, object]
    plan: dict[str, object]
    requirement_test_plan: dict[str, object]
    upstream_lock: dict[str, object]
    upstream_sources: dict[str, dict[str, object]]


def fail(reason: AdapterErrorReason) -> NoReturn:
    print(f"EUDI adapter validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise AdapterError(AdapterErrorReason.INVALID_JSON)
        if metadata.st_size < 1 or metadata.st_size > MAX_JSON_BYTES:
            raise AdapterError(AdapterErrorReason.INVALID_JSON)
        parsed = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise AdapterError(AdapterErrorReason.INVALID_JSON) from error
    if not isinstance(parsed, dict):
        raise AdapterError(AdapterErrorReason.INVALID_JSON)
    return parsed


def exact_keys(value: object, expected: set[str], reason: AdapterErrorReason) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AdapterError(reason)
    return value


def validate_adapter(adapter: dict[str, object]) -> None:
    exact_keys(
        adapter,
        {
            "$comment",
            "schema_version",
            "adapter_id",
            "plan_path",
            "requirement_test_plan_path",
            "upstream_lock_path",
            "legal_sources_lock_path",
            "component",
            "dependent_artifacts",
            "execution_sources",
            "normative_profiles",
            "source_bindings",
            "probes",
            "evidence_policy",
        },
        AdapterErrorReason.INVALID_ADAPTER,
    )
    if (
        adapter["schema_version"] != 1
        or adapter["adapter_id"] != "eudi_relying_party_control_plane"
        or adapter["plan_path"] != "plans/eudi/relying-party-control-plane.json"
        or adapter["requirement_test_plan_path"]
        != "plans/eudi/relying-party-requirement-tests.json"
        or adapter["upstream_lock_path"] != "upstream/eudi/sources.lock.json"
        or adapter["legal_sources_lock_path"]
        != "upstream/eudi/legal-sources.lock.json"
    ):
        raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
    component = exact_keys(
        adapter["component"],
        {"component_id", "repository_policy", "features"},
        AdapterErrorReason.INVALID_ADAPTER,
    )
    if component != {
        "component_id": "candidate",
        "repository_policy": "reallyme_owned",
        "features": ["live_probe"],
    }:
        raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
    dependent_components = adapter["dependent_artifacts"]
    if not isinstance(dependent_components, list) or len(dependent_components) != 2:
        raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
    expected_dependents = {
        "trust_service": {
            "component_id": "trust_service",
            "artifact_id": "trust_service",
        },
        "credential_authority": {
            "component_id": "credential_authority",
            "artifact_id": "credential_authority",
        },
    }
    observed_dependents: set[str] = set()
    for raw_dependent in dependent_components:
        dependent = exact_keys(
            raw_dependent,
            {"component_id", "artifact_id"},
            AdapterErrorReason.INVALID_ADAPTER,
        )
        component_id = dependent["component_id"]
        if (
            not isinstance(component_id, str)
            or component_id in observed_dependents
            or dependent != expected_dependents.get(component_id)
        ):
            raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
        observed_dependents.add(component_id)
    if observed_dependents != set(expected_dependents):
        raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
    execution_sources = adapter["execution_sources"]
    if not isinstance(execution_sources, list) or set(execution_sources) != EXPECTED_EXECUTION_SOURCES:
        raise AdapterError(AdapterErrorReason.INVALID_ADAPTER)
    if adapter["normative_profiles"] != EXPECTED_NORMATIVE_PROFILES:
        raise AdapterError(AdapterErrorReason.INVALID_SOURCE_BINDING)
    bindings = adapter["source_bindings"]
    if not isinstance(bindings, list) or not bindings:
        raise AdapterError(AdapterErrorReason.INVALID_SOURCE_BINDING)
    observed: set[str] = set()
    for raw_binding in bindings:
        binding = exact_keys(
            raw_binding,
            {"source_id", "field", "attestation_check_id"},
            AdapterErrorReason.INVALID_SOURCE_BINDING,
        )
        source_id = binding["source_id"]
        if (
            not isinstance(source_id, str)
            or source_id not in EXPECTED_EXECUTION_SOURCES
            or source_id in observed
            or binding["field"] not in {"commit", "ref", "ref_without_v"}
            or binding["attestation_check_id"]
            != f"upstream_binding.{source_id.replace('-', '_')}"
        ):
            raise AdapterError(AdapterErrorReason.INVALID_SOURCE_BINDING)
        observed.add(source_id)
    if observed != {
        "eudi-arf",
        "eudi-technical-specifications",
        "eudi-relying-party-registration-service",
    }:
        raise AdapterError(AdapterErrorReason.INVALID_SOURCE_BINDING)


def validate_plan(plan: dict[str, object], adapter: dict[str, object]) -> None:
    try:
        plan_verifier.verify_plan(plan)
    except plan_verifier.PlanError as error:
        raise AdapterError(AdapterErrorReason.INVALID_PLAN) from error
    system = plan.get("system_under_test")
    sources = plan.get("sources")
    if not isinstance(system, dict) or not isinstance(sources, dict):
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)
    if system != {
        "component_id": "eudi-relying-party-control-plane",
        "adapter_contract": "adapters/eudi-relying-party/README.md",
    }:
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)
    execution_sources = sources.get("execution_sources")
    if not isinstance(execution_sources, list):
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)
    plan_source_ids = {
        item.get("source_id") for item in execution_sources if isinstance(item, dict)
    }
    if plan_source_ids != set(adapter["execution_sources"]):
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)


def index_upstream_sources(lock: dict[str, object]) -> dict[str, dict[str, object]]:
    try:
        indexed = upstream_coverage.validate_source_lock(lock)
    except upstream_coverage.CoverageError as error:
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK) from error
    if not EXPECTED_EXECUTION_SOURCES.issubset(indexed):
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK)
    return indexed


def load_contract_bundle() -> ContractBundle:
    adapter = load_object(ADAPTER_PATH)
    plan = load_object(PLAN_PATH)
    requirement_test_plan = requirement_tests.load_plan(REQUIREMENT_TEST_PLAN_PATH)
    upstream_lock = load_object(UPSTREAM_LOCK_PATH)
    validate_adapter(adapter)
    validate_plan(plan, adapter)
    indexed = index_upstream_sources(upstream_lock)
    technical_specification_commit = indexed["eudi-technical-specifications"].get(
        "commit"
    )
    if not isinstance(technical_specification_commit, str):
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK)
    try:
        requirement_tests.verify_plan(
            requirement_test_plan,
            plan,
            technical_specification_commit,
        )
    except requirement_tests.RequirementTestPlanError as error:
        raise AdapterError(AdapterErrorReason.INVALID_PLAN) from error
    try:
        legal_lock = legal_sources.load_lock(LEGAL_SOURCES_LOCK_PATH)
        legal_sources.verify_lock(legal_lock)
    except legal_sources.EudiLegalSourcesError as error:
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK) from error
    sources = plan["sources"]
    if not isinstance(sources, dict) or not isinstance(sources.get("legacy_reference"), dict):
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)
    legacy = sources["legacy_reference"]
    reference = indexed["eudi-relying-party-registration-service"]
    if legacy.get("commit") != reference.get("commit"):
        raise AdapterError(AdapterErrorReason.INVALID_PLAN)
    return ContractBundle(
        adapter,
        plan,
        requirement_test_plan,
        upstream_lock,
        indexed,
    )


def git_output(checkout: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdapterError(AdapterErrorReason.INVALID_CHECKOUT) from error
    if completed.returncode != 0:
        raise AdapterError(AdapterErrorReason.INVALID_CHECKOUT)
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise AdapterError(AdapterErrorReason.INVALID_CHECKOUT) from error


def verify_checkout(checkout: Path, expected_commit: str) -> None:
    try:
        resolved = checkout.resolve(strict=True)
        checkout.lstat()
    except OSError as error:
        raise AdapterError(AdapterErrorReason.INVALID_CHECKOUT) from error
    if checkout.is_symlink() or not resolved.is_dir():
        raise AdapterError(AdapterErrorReason.INVALID_CHECKOUT)
    if git_output(resolved, "rev-parse", "HEAD") != expected_commit:
        raise AdapterError(AdapterErrorReason.REVISION_MISMATCH)
    if git_output(resolved, "status", "--porcelain=v1", "--untracked-files=all"):
        raise AdapterError(AdapterErrorReason.DIRTY_CHECKOUT)


def checkout_directory(source: dict[str, object], upstream_root: Path) -> Path:
    local_checkout = source.get("local_checkout")
    if not isinstance(local_checkout, str):
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK)
    name = Path(local_checkout).name
    if SAFE_PART.fullmatch(name) is None:
        raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK)
    return upstream_root / name


def verify_upstream_checkouts(bundle: ContractBundle, upstream_root: Path) -> None:
    for source_id in sorted(EXPECTED_EXECUTION_SOURCES):
        source = bundle.upstream_sources[source_id]
        commit = source.get("commit")
        if not isinstance(commit, str):
            raise AdapterError(AdapterErrorReason.INVALID_UPSTREAM_LOCK)
        verify_checkout(checkout_directory(source, upstream_root), commit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", type=Path)
    args = parser.parse_args()
    try:
        bundle = load_contract_bundle()
        if args.upstream_root is not None:
            verify_upstream_checkouts(bundle, args.upstream_root)
    except AdapterError as error:
        fail(error.reason)
    print("EUDI relying-party adapter contract valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
