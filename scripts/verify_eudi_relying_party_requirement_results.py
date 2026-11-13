#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify EUDI relying-party requirement results against their exact test plan."""

from __future__ import annotations

import argparse
import hashlib
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
import verify_eudi_adapter as adapter_verifier  # noqa: E402


MAX_DOCUMENT_BYTES = 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXIT_INVALID = 78


class RequirementResultErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    INDEX_INVALID = "index_invalid"
    RESULT_INVALID = "result_invalid"
    OBSERVATION_INVALID = "observation_invalid"
    RECEIPT_INVALID = "receipt_invalid"
    SOURCE_BINDING_INVALID = "source_binding_invalid"


@dataclass(frozen=True)
class RequirementResultError(Exception):
    reason: RequirementResultErrorReason


def fail(reason: RequirementResultErrorReason) -> NoReturn:
    raise RequirementResultError(reason)


def load_document(path: Path) -> tuple[dict[str, object], str]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or metadata.st_size < 1
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            fail(RequirementResultErrorReason.INPUT_INVALID)
        payload = path.read_bytes()
        value = strict_json.loads(payload.decode("utf-8"))
    except RequirementResultError:
        raise
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(RequirementResultErrorReason.INPUT_INVALID)
    if not isinstance(value, dict):
        fail(RequirementResultErrorReason.INPUT_INVALID)
    return value, hashlib.sha256(payload).hexdigest()


def regular_source_sha256(root: Path, relative_path: str) -> str:
    try:
        resolved_root = root.resolve(strict=True)
        path = root / relative_path
        resolved_path = path.resolve(strict=True)
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not resolved_path.is_relative_to(resolved_root)
            or not path.is_file()
            or metadata.st_size < 1
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            fail(RequirementResultErrorReason.SOURCE_BINDING_INVALID)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except RequirementResultError:
        raise
    except OSError:
        fail(RequirementResultErrorReason.SOURCE_BINDING_INVALID)


def directory_entry_names(path: Path) -> set[str]:
    try:
        path.lstat()
        if path.is_symlink() or not path.is_dir():
            fail(RequirementResultErrorReason.INPUT_INVALID)
        entries = list(path.iterdir())
        if any(entry.is_symlink() for entry in entries):
            fail(RequirementResultErrorReason.INPUT_INVALID)
        return {entry.name for entry in entries}
    except RequirementResultError:
        raise
    except OSError:
        fail(RequirementResultErrorReason.INPUT_INVALID)


def validate_neutral_result(
    value: dict[str, object],
    test: dict[str, object],
    record: dict[str, object],
) -> None:
    if set(value) != {
        "$comment",
        "schema",
        "command_id",
        "assertion_id",
        "evidence_class",
        "status",
        "exit_code",
        "stdout_sha256",
        "stderr_sha256",
        "metadata_only",
    }:
        fail(RequirementResultErrorReason.RESULT_INVALID)
    if (
        value.get("schema") != "reallyme.identity.eudi_requirement_test_result.v1"
        or value.get("command_id") != test["command_id"]
        or value.get("assertion_id") != test["assertion_id"]
        or value.get("evidence_class") != test["evidence_class"]
        or value.get("status") != record["status"]
        or value.get("metadata_only") is not True
    ):
        fail(RequirementResultErrorReason.RESULT_INVALID)
    validate_process_result(value)


def validate_taxonomy_result(
    value: dict[str, object],
    test: dict[str, object],
    record: dict[str, object],
) -> None:
    if set(value) != {
        "$comment",
        "schema",
        "observation_id",
        "requirement_id",
        "requirement_sha256",
        "status",
        "exit_code",
        "assertion_results",
        "stdout_sha256",
        "stderr_sha256",
    }:
        fail(RequirementResultErrorReason.RESULT_INVALID)
    assertion_results = value.get("assertion_results")
    if (
        value.get("schema")
        != "reallyme.identity.conformance_execution_result.v1"
        or value.get("observation_id") != test["command_id"]
        or value.get("requirement_id") != test["requirement_id"]
        or not isinstance(value.get("requirement_sha256"), str)
        or SHA256.fullmatch(value["requirement_sha256"]) is None
        or value.get("status") != record["status"]
        or assertion_results
        != [{"assertion_id": test["assertion_id"], "status": record["status"]}]
    ):
        fail(RequirementResultErrorReason.RESULT_INVALID)
    validate_process_result(value)


def validate_process_result(value: dict[str, object]) -> None:
    exit_code = value.get("exit_code")
    if (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not 0 <= exit_code <= 255
        or not isinstance(value.get("stdout_sha256"), str)
        or SHA256.fullmatch(value["stdout_sha256"]) is None
        or not isinstance(value.get("stderr_sha256"), str)
        or SHA256.fullmatch(value["stderr_sha256"]) is None
        or (value.get("status") == "passed" and exit_code != 0)
    ):
        fail(RequirementResultErrorReason.RESULT_INVALID)


def validate_observation(
    value: dict[str, object],
    test: dict[str, object],
    candidate_commit: str,
    framework_commit: str,
    result_sha256: str,
) -> None:
    producer = value.get("producer")
    subject = value.get("subject")
    runner = value.get("runner")
    test_binding = value.get("test")
    outcome = value.get("outcome")
    if (
        value.get("schema")
        != "reallyme.identity.conformance_execution_observation.v1"
        or value.get("observation_id") != test["command_id"]
        or value.get("requirement_id") != test["requirement_id"]
        or value.get("evidence_class") != test["evidence_class"]
        or value.get("case_kind") != test["case_kind"]
        or producer
        != {
            "repository": "reallyme/identity-conformance",
            "source_revision": framework_commit,
        }
        or subject
        != {"repository": "reallyme/eudi", "source_revision": candidate_commit}
        or not isinstance(runner, dict)
        or runner.get("repository") != "reallyme/identity-conformance"
        or runner.get("source_revision") != framework_commit
        or not isinstance(test_binding, dict)
        or test_binding.get("repository") != "reallyme/eudi"
        or test_binding.get("path") != test["test_path"]
        or test_binding.get("symbol") != test["symbol"]
        or not isinstance(outcome, dict)
        or outcome.get("result_sha256") != result_sha256
        or value.get("clean_source_tree") is not True
        or value.get("metadata_only") is not True
    ):
        fail(RequirementResultErrorReason.OBSERVATION_INVALID)


def validate_receipt(
    value: dict[str, object],
    observation: dict[str, object],
    observation_sha256: str,
    test: dict[str, object],
    result_sha256: str,
    taxonomy_source: Path,
    taxonomy_commit: str,
) -> None:
    expected_fields = {
        "$comment",
        "schema",
        "audit_status",
        "observation_id",
        "observation_path",
        "observation_sha256",
        "inventory_sha256",
        "taxonomy_source_sha256",
        "requirement_id",
        "requirement_sha256",
        "evidence_class",
        "execution_status",
        "auditor",
        "producer",
        "subject",
        "runner",
        "test",
        "result_sha256",
        "completed_at",
        "metadata_only",
    }
    auditor = value.get("auditor")
    observation_runner = observation.get("runner")
    observation_outcome = observation.get("outcome")
    expected_observation_path = (
        f"conformance/observations/executions/{test['command_id']}.json"
    )
    expected_auditor = {
        "repository": "reallyme/identity-taxonomy",
        "source_revision": taxonomy_commit,
        "entrypoint_path": "scripts/audit_conformance_execution_observation.rb",
        "entrypoint_sha256": regular_source_sha256(
            taxonomy_source,
            "scripts/audit_conformance_execution_observation.rb",
        ),
        "implementation_path": "scripts/conformance_execution_observation.rb",
        "implementation_sha256": regular_source_sha256(
            taxonomy_source,
            "scripts/conformance_execution_observation.rb",
        ),
    }
    expected_runner = (
        {
            "repository": observation_runner.get("repository"),
            "source_revision": observation_runner.get("source_revision"),
            "release_version": observation_runner.get("release_version"),
        }
        if isinstance(observation_runner, dict)
        else None
    )
    inventory_sha256 = regular_source_sha256(
        taxonomy_source, "conformance/inventory/requirements.json"
    )
    if (
        set(value) != expected_fields
        or not isinstance(value.get("$comment"), str)
        or not value["$comment"]
        or value.get("schema")
        != "reallyme.identity.conformance_execution_audit_receipt.v1"
        or value.get("audit_status") != "passed"
        or value.get("observation_id") != test["command_id"]
        or value.get("observation_path") != expected_observation_path
        or value.get("observation_sha256") != observation_sha256
        or value.get("inventory_sha256") != inventory_sha256
        or value.get("taxonomy_source_sha256")
        != observation.get("taxonomy_source_sha256")
        or value.get("requirement_id") != observation.get("requirement_id")
        or value.get("requirement_sha256") != observation.get("requirement_sha256")
        or value.get("evidence_class") != test["evidence_class"]
        or not isinstance(observation_outcome, dict)
        or value.get("execution_status") != observation_outcome.get("status")
        or auditor != expected_auditor
        or value.get("producer") != observation.get("producer")
        or value.get("subject") != observation.get("subject")
        or value.get("runner") != expected_runner
        or value.get("test") != observation.get("test")
        or not isinstance(value.get("test"), dict)
        or value["test"].get("selector") != test["symbol"]
        or value.get("result_sha256") != result_sha256
        or value.get("completed_at") != observation_outcome.get("completed_at")
        or value.get("metadata_only") is not True
    ):
        fail(RequirementResultErrorReason.RECEIPT_INVALID)


def verify_results(
    result_dir: Path,
    candidate_source: Path,
    candidate_commit: str,
    framework_commit: str,
    taxonomy_observations: str,
    taxonomy_receipts: str,
    taxonomy_source: Path | None = None,
    taxonomy_commit: str | None = None,
) -> None:
    if (
        COMMIT.fullmatch(candidate_commit) is None
        or COMMIT.fullmatch(framework_commit) is None
        or taxonomy_observations not in {"required", "forbidden"}
        or taxonomy_receipts not in {"required", "forbidden"}
        or (taxonomy_receipts == "required" and taxonomy_observations != "required")
        or ((taxonomy_source is None) != (taxonomy_commit is None))
        or (
            taxonomy_receipts == "required"
            and (
                taxonomy_source is None
                or taxonomy_commit is None
                or COMMIT.fullmatch(taxonomy_commit) is None
            )
        )
        or (taxonomy_receipts == "forbidden" and taxonomy_source is not None)
    ):
        fail(RequirementResultErrorReason.INPUT_INVALID)
    bundle = adapter_verifier.load_contract_bundle()
    plan = bundle.requirement_test_plan
    index, _ = load_document(result_dir / "index.json")
    if set(index) != {
        "$comment",
        "schema",
        "plan_id",
        "framework_commit",
        "candidate_repository",
        "candidate_commit",
        "command_manifest_sha256",
        "status",
        "records",
        "taxonomy_observations_emitted",
    }:
        fail(RequirementResultErrorReason.INDEX_INVALID)
    manifest_path = (
        SCRIPT_DIRECTORY.parent / "plans/eudi/relying-party-requirement-tests.json"
    )
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    observations_required = taxonomy_observations == "required"
    records = index.get("records")
    if (
        index.get("schema")
        != "reallyme.identity.eudi_requirement_test_execution.v1"
        or index.get("plan_id") != plan["plan_id"]
        or index.get("framework_commit") != framework_commit
        or index.get("candidate_repository") != "reallyme/eudi"
        or index.get("candidate_commit") != candidate_commit
        or index.get("command_manifest_sha256") != manifest_sha256
        or index.get("status") != "passed"
        or index.get("taxonomy_observations_emitted") is not observations_required
        or not isinstance(records, list)
        or len(records) != len(plan["tests"])
    ):
        fail(RequirementResultErrorReason.INDEX_INVALID)
    expected_tests = {
        str(test["command_id"]): test
        for test in plan["tests"]
        if isinstance(test, dict)
    }
    expected_names = {f"{command_id}.json" for command_id in expected_tests}
    expected_root_entries = {"index.json", "results"}
    if observations_required:
        expected_root_entries.add("observations")
    if taxonomy_receipts == "required":
        expected_root_entries.add("receipts")
    if (
        directory_entry_names(result_dir) != expected_root_entries
        or directory_entry_names(result_dir / "results") != expected_names
        or (
            observations_required
            and directory_entry_names(result_dir / "observations") != expected_names
        )
        or (
            taxonomy_receipts == "required"
            and directory_entry_names(result_dir / "receipts") != expected_names
        )
    ):
        fail(RequirementResultErrorReason.INPUT_INVALID)
    observed: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "command_id",
            "assertion_id",
            "evidence_class",
            "status",
            "test_source_sha256",
            "result_sha256",
            "observation_emitted",
        }:
            fail(RequirementResultErrorReason.INDEX_INVALID)
        command_id = record.get("command_id")
        if (
            not isinstance(command_id, str)
            or command_id in observed
            or command_id not in expected_tests
        ):
            fail(RequirementResultErrorReason.INDEX_INVALID)
        test = expected_tests[command_id]
        expected_source_sha256 = regular_source_sha256(
            candidate_source, str(test["test_path"])
        )
        if (
            record.get("assertion_id") != test["assertion_id"]
            or record.get("evidence_class") != test["evidence_class"]
            or record.get("status") != "passed"
            or record.get("test_source_sha256") != expected_source_sha256
            or record.get("observation_emitted") is not observations_required
            or not isinstance(record.get("result_sha256"), str)
            or SHA256.fullmatch(record["result_sha256"]) is None
        ):
            fail(RequirementResultErrorReason.INDEX_INVALID)
        result, result_sha256 = load_document(
            result_dir / "results" / f"{command_id}.json"
        )
        if result_sha256 != record["result_sha256"]:
            fail(RequirementResultErrorReason.RESULT_INVALID)
        if observations_required:
            validate_taxonomy_result(result, test, record)
            observation, observation_sha256 = load_document(
                result_dir / "observations" / f"{command_id}.json"
            )
            validate_observation(
                observation,
                test,
                candidate_commit,
                framework_commit,
                result_sha256,
            )
            if taxonomy_receipts == "required":
                receipt, _ = load_document(
                    result_dir / "receipts" / f"{command_id}.json"
                )
                if taxonomy_source is None or taxonomy_commit is None:
                    fail(RequirementResultErrorReason.INPUT_INVALID)
                validate_receipt(
                    receipt,
                    observation,
                    observation_sha256,
                    test,
                    result_sha256,
                    taxonomy_source,
                    taxonomy_commit,
                )
        else:
            validate_neutral_result(result, test, record)
        observed.add(command_id)
    if observed != set(expected_tests):
        fail(RequirementResultErrorReason.INDEX_INVALID)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", required=True, type=Path)
    parser.add_argument("--candidate-source", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--framework-commit", required=True)
    parser.add_argument(
        "--taxonomy-observations",
        required=True,
        choices=("required", "forbidden"),
    )
    parser.add_argument("--taxonomy-source", type=Path)
    parser.add_argument("--taxonomy-commit")
    parser.add_argument(
        "--taxonomy-receipts",
        required=True,
        choices=("required", "forbidden"),
    )
    arguments = parser.parse_args()
    try:
        verify_results(
            arguments.result_dir,
            arguments.candidate_source,
            arguments.candidate_commit,
            arguments.framework_commit,
            arguments.taxonomy_observations,
            arguments.taxonomy_receipts,
            arguments.taxonomy_source,
            arguments.taxonomy_commit,
        )
    except (adapter_verifier.AdapterError, OSError, KeyError, ValueError):
        print(
            "EUDI requirement result verification failed: input_invalid",
            file=sys.stderr,
        )
        return EXIT_INVALID
    except RequirementResultError as error:
        print(
            f"EUDI requirement result verification failed: {error.reason.value}",
            file=sys.stderr,
        )
        return EXIT_INVALID
    print("EUDI relying-party requirement results valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
