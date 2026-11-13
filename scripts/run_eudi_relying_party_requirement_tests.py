#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Run exact EUDI relying-party requirement tests and emit bounded evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO, NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_eudi_adapter as adapter_verifier  # noqa: E402
import verify_eudi_execution_result as execution_result_verifier  # noqa: E402
import verify_eudi_relying_party_requirement_tests as plan_verifier  # noqa: E402


MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
TEST_TIMEOUT_SECONDS = 1_800
EXIT_INVALID = 78
EXIT_FAILED = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
TOOLCHAIN_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")
NOTICE = (
    "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
    "SPDX-License-Identifier: MIT OR Apache-2.0"
)
PASSED_TEST_SUMMARY = re.compile(
    rb"(?:^|\n)test result: ok\. 1 passed; 0 failed; [^\n]*\n"
)


class RequirementRunnerErrorReason(Enum):
    INVALID_ARGUMENT = "invalid_argument"
    INVALID_CHECKOUT = "invalid_checkout"
    DIRTY_CHECKOUT = "dirty_checkout"
    INVALID_EXECUTION_RESULT = "invalid_execution_result"
    INVALID_NORMATIVE_SOURCE = "invalid_normative_source"
    INVALID_TEST_SOURCE = "invalid_test_source"
    INVALID_INVENTORY = "invalid_inventory"
    RESULT_PATH_EXISTS = "result_path_exists"
    RESULT_WRITE_FAILED = "result_write_failed"


@dataclass(frozen=True)
class RequirementRunnerError(Exception):
    reason: RequirementRunnerErrorReason


@dataclass(frozen=True)
class TestOutcome:
    status: str
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    started_at: str
    completed_at: str


def fail(reason: RequirementRunnerErrorReason) -> NoReturn:
    print(f"EUDI requirement-test runner failed: {reason.value}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def hash_regular_file(path: Path, maximum_bytes: int) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_TEST_SOURCE
            )
        if metadata.st_size < 1 or metadata.st_size > maximum_bytes:
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_TEST_SOURCE
            )
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_TEST_SOURCE
        ) from error


def resolve_regular_file(root: Path, relative_path: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = root / relative_path
        resolved_candidate = candidate.resolve(strict=True)
        metadata = candidate.lstat()
    except OSError as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_TEST_SOURCE
        ) from error
    if (
        not resolved_candidate.is_relative_to(resolved_root)
        or candidate.is_symlink()
        or not resolved_candidate.is_file()
        or metadata.st_size < 1
        or metadata.st_size > MAX_SOURCE_BYTES
    ):
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_TEST_SOURCE
        )
    return candidate


def git_output(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_CHECKOUT
        ) from error
    if completed.returncode != 0:
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_CHECKOUT)
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_CHECKOUT
        ) from error


def verify_clean_checkout(root: Path, expected_commit: str) -> None:
    if COMMIT.fullmatch(expected_commit) is None:
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
    if git_output(root, "rev-parse", "HEAD") != expected_commit:
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_CHECKOUT)
    if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RequirementRunnerError(RequirementRunnerErrorReason.DIRTY_CHECKOUT)


def normalized_statement_sha256(
    source: bytes,
    start_line: int,
    end_line: int,
) -> str:
    if len(source) > MAX_SOURCE_BYTES or b"\0" in source:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
        )
    try:
        text = source.decode("utf-8")
    except UnicodeError as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
        ) from error
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
        )
    statement = "\n".join(lines[start_line - 1 : end_line]) + "\n"
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def verify_normative_statements(
    plan: dict[str, object],
    technical_specification_root: Path,
) -> None:
    statements = plan.get("normative_statements")
    if not isinstance(statements, list):
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
        )
    for statement in statements:
        if not isinstance(statement, dict):
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
            )
        source_path = statement.get("source_path")
        start_line = statement.get("start_line")
        end_line = statement.get("end_line")
        if (
            not isinstance(source_path, str)
            or not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or not isinstance(end_line, int)
            or isinstance(end_line, bool)
        ):
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
            )
        path = resolve_regular_file(technical_specification_root, source_path)
        try:
            source = path.read_bytes()
        except OSError as error:
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
            ) from error
        if (
            hashlib.sha256(source).hexdigest() != statement.get("source_sha256")
            or normalized_statement_sha256(source, start_line, end_line)
            != statement.get("statement_sha256")
        ):
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_NORMATIVE_SOURCE
            )


def read_bounded_output(stream: BinaryIO) -> bytes:
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() > MAX_OUTPUT_BYTES:
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.RESULT_WRITE_FAILED
            )
        stream.seek(0)
        return stream.read()
    except (OSError, ValueError) as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.RESULT_WRITE_FAILED
        ) from error


def execute_test(candidate_root: Path, test: dict[str, object]) -> TestOutcome:
    arguments = [
        "cargo",
        "test",
        "--quiet",
        "--locked",
        "-p",
        str(test["package"]),
    ]
    features = test["features"]
    if not isinstance(features, list):
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
    if features:
        arguments.extend(["--features", ",".join(str(value) for value in features)])
    arguments.extend(
        [
            "--test",
            str(test["test_target"]),
            str(test["symbol"]),
            "--",
            "--exact",
        ]
    )
    environment = os.environ.copy()
    environment.update({"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"})
    started_at = utc_now()
    return_code = 124
    status = "error"
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                arguments,
                cwd=candidate_root,
                env=environment,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=TEST_TIMEOUT_SECONDS,
            )
            return_code = completed.returncode
            status = "passed" if completed.returncode == 0 else "failed"
        except (OSError, subprocess.TimeoutExpired):
            return_code = 124
            status = "error"
        stdout.flush()
        stderr.flush()
        stdout_bytes = read_bounded_output(stdout)
        stderr_bytes = read_bounded_output(stderr)
        stdout_sha256 = hashlib.sha256(stdout_bytes).hexdigest()
        stderr_sha256 = hashlib.sha256(stderr_bytes).hexdigest()
        if status == "passed" and PASSED_TEST_SUMMARY.search(stdout_bytes) is None:
            status = "failed"
            return_code = 125
    return TestOutcome(
        status,
        return_code if 0 <= return_code <= 255 else 125,
        stdout_sha256,
        stderr_sha256,
        started_at,
        utc_now(),
    )


def write_json(path: Path, value: dict[str, object]) -> str:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary_path: Path | None = None
    try:
        if path.exists() or path.is_symlink():
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.RESULT_PATH_EXISTS
            )
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
        temporary_path = None
    except RequirementRunnerError:
        raise
    except OSError as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.RESULT_WRITE_FAILED
        ) from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
    return hashlib.sha256(payload).hexdigest()


def load_inventory(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or metadata.st_size < 1
            or metadata.st_size > MAX_INVENTORY_BYTES
        ):
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_INVENTORY
            )
        inventory = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise RequirementRunnerError(
            RequirementRunnerErrorReason.INVALID_INVENTORY
        ) from error
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema")
        != "reallyme.identity.conformance_requirement_inventory.v1"
        or SHA256.fullmatch(str(inventory.get("taxonomy_source_sha256"))) is None
        or not isinstance(inventory.get("requirements"), list)
    ):
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_INVENTORY)
    return inventory


def requirement_from_inventory(
    inventory: dict[str, object],
    requirement_id: str,
    evidence_class: str,
) -> dict[str, object]:
    requirements = inventory["requirements"]
    if not isinstance(requirements, list):
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_INVENTORY)
    matches = [
        requirement
        for requirement in requirements
        if isinstance(requirement, dict)
        and requirement.get("requirement_id") == requirement_id
    ]
    if len(matches) != 1:
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_INVENTORY)
    requirement = matches[0]
    if (
        SHA256.fullmatch(str(requirement.get("requirement_sha256"))) is None
        or requirement.get("subject_repository") != "reallyme/eudi"
        or not isinstance(requirement.get("required_evidence"), list)
        or evidence_class not in requirement["required_evidence"]
    ):
        raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_INVENTORY)
    return requirement


def result_document(
    test: dict[str, object],
    observation_id: str,
    requirement_sha256: str,
    outcome: TestOutcome,
) -> dict[str, object]:
    return {
        "$comment": NOTICE,
        "schema": "reallyme.identity.conformance_execution_result.v1",
        "observation_id": observation_id,
        "requirement_id": test["requirement_id"],
        "requirement_sha256": requirement_sha256,
        "status": outcome.status,
        "exit_code": outcome.exit_code,
        "assertion_results": [
            {"assertion_id": test["assertion_id"], "status": outcome.status}
        ],
        "stdout_sha256": outcome.stdout_sha256,
        "stderr_sha256": outcome.stderr_sha256,
    }


def neutral_result_document(
    test: dict[str, object],
    outcome: TestOutcome,
) -> dict[str, object]:
    return {
        "$comment": NOTICE,
        "schema": "reallyme.identity.eudi_requirement_test_result.v1",
        "command_id": test["command_id"],
        "assertion_id": test["assertion_id"],
        "evidence_class": test["evidence_class"],
        "status": outcome.status,
        "exit_code": outcome.exit_code,
        "stdout_sha256": outcome.stdout_sha256,
        "stderr_sha256": outcome.stderr_sha256,
        "metadata_only": True,
    }


def observation_document(
    test: dict[str, object],
    observation_id: str,
    requirement_sha256: str,
    taxonomy_source_sha256: str,
    candidate_commit: str,
    framework_commit: str,
    framework_version: str,
    command_manifest_sha256: str,
    test_source_sha256: str,
    rust_version: str,
    result_path: str,
    result_sha256: str,
    outcome: TestOutcome,
) -> dict[str, object]:
    return {
        "$comment": NOTICE,
        "schema": "reallyme.identity.conformance_execution_observation.v1",
        "observation_id": observation_id,
        "taxonomy_source_sha256": taxonomy_source_sha256,
        "requirement_id": test["requirement_id"],
        "requirement_sha256": requirement_sha256,
        "evidence_class": test["evidence_class"],
        "case_kind": test["case_kind"],
        "producer": {
            "repository": "reallyme/identity-conformance",
            "source_revision": framework_commit,
        },
        "subject": {
            "repository": "reallyme/eudi",
            "source_revision": candidate_commit,
        },
        "runner": {
            "repository": "reallyme/identity-conformance",
            "source_revision": framework_commit,
            "release_version": framework_version,
            "command_id": test["command_id"],
            "command_manifest_path": (
                "plans/eudi/relying-party-requirement-tests.json"
            ),
            "command_manifest_sha256": command_manifest_sha256,
        },
        "test": {
            "repository": "reallyme/eudi",
            "path": test["test_path"],
            "symbol": test["symbol"],
            "selector": test["symbol"],
            "source_sha256": test_source_sha256,
            "assertion_ids": [test["assertion_id"]],
        },
        "fixtures": [],
        "environment": {
            "platform": "linux",
            "architecture": "x86_64",
            "toolchains": [{"name": "rust", "version": rust_version}],
        },
        "outcome": {
            "status": outcome.status,
            "exit_code": outcome.exit_code,
            "result_path": result_path,
            "result_sha256": result_sha256,
            "started_at": outcome.started_at,
            "completed_at": outcome.completed_at,
        },
        "clean_source_tree": True,
        "metadata_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-source", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-repository", required=True)
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--framework-commit", required=True)
    parser.add_argument("--technical-specification-source", required=True, type=Path)
    parser.add_argument("--validated-execution-result", required=True, type=Path)
    parser.add_argument("--result-dir", required=True, type=Path)
    parser.add_argument("--rust-version", required=True)
    parser.add_argument("--taxonomy-inventory", type=Path)
    parser.add_argument("--taxonomy-source", type=Path)
    parser.add_argument("--taxonomy-commit")
    args = parser.parse_args()
    try:
        framework_root = args.framework_root.resolve(strict=True)
        script_framework_root = SCRIPT_DIRECTORY.parent.resolve(strict=True)
        if (
            args.candidate_repository != "reallyme/eudi"
            or TOOLCHAIN_VERSION.fullmatch(args.rust_version) is None
            or args.result_dir.exists()
            or args.result_dir.is_symlink()
            or framework_root != script_framework_root
            or ((args.taxonomy_inventory is None) != (args.taxonomy_source is None))
            or ((args.taxonomy_inventory is None) != (args.taxonomy_commit is None))
        ):
            raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
        result_directory = args.result_dir.resolve(strict=False)
        if args.taxonomy_inventory is not None and not result_directory.is_relative_to(
            framework_root
        ):
            raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
        verify_clean_checkout(args.candidate_source, args.candidate_commit)
        verify_clean_checkout(args.framework_root, args.framework_commit)
        if args.taxonomy_source is not None and args.taxonomy_commit is not None:
            verify_clean_checkout(args.taxonomy_source, args.taxonomy_commit)
        bundle = adapter_verifier.load_contract_bundle()
        plan = bundle.requirement_test_plan
        source_commit = bundle.upstream_sources[
            "eudi-technical-specifications"
        ]["commit"]
        if not isinstance(source_commit, str):
            raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
        plan_verifier.verify_plan(plan, bundle.plan, source_commit)
        execution_result = adapter_verifier.load_object(
            args.validated_execution_result
        )
        execution_result_verifier.verify_result(execution_result)
        candidate_components = [
            component
            for component in execution_result["components"]
            if isinstance(component, dict)
            and component.get("component_id") == "candidate"
        ]
        if (
            len(candidate_components) != 1
            or candidate_components[0].get("commit") != args.candidate_commit
            or candidate_components[0].get("repository")
            != "https://github.com/reallyme/eudi"
        ):
            raise RequirementRunnerError(
                RequirementRunnerErrorReason.INVALID_EXECUTION_RESULT
            )
        verify_normative_statements(plan, args.technical_specification_source)
        version_path = resolve_regular_file(args.framework_root, "VERSION")
        framework_version = version_path.read_text(encoding="utf-8").strip()
        if VERSION.fullmatch(framework_version) is None:
            raise RequirementRunnerError(RequirementRunnerErrorReason.INVALID_ARGUMENT)
        command_manifest_sha256 = hash_regular_file(
            args.framework_root
            / "plans/eudi/relying-party-requirement-tests.json",
            MAX_SOURCE_BYTES,
        )
        inventory = (
            load_inventory(args.taxonomy_inventory)
            if args.taxonomy_inventory is not None
            else None
        )
        args.result_dir.mkdir(mode=0o700, parents=True)
        results_directory = args.result_dir / "results"
        observations_directory = args.result_dir / "observations"
        records: list[dict[str, object]] = []
        for raw_test in plan["tests"]:
            if not isinstance(raw_test, dict):
                raise RequirementRunnerError(
                    RequirementRunnerErrorReason.INVALID_ARGUMENT
                )
            test_source = resolve_regular_file(
                args.candidate_source, str(raw_test["test_path"])
            )
            try:
                source_bytes = test_source.read_bytes()
            except OSError as error:
                raise RequirementRunnerError(
                    RequirementRunnerErrorReason.INVALID_TEST_SOURCE
                ) from error
            symbol = str(raw_test["symbol"])
            if f"fn {symbol}".encode("utf-8") not in source_bytes:
                raise RequirementRunnerError(
                    RequirementRunnerErrorReason.INVALID_TEST_SOURCE
                )
            test_source_sha256 = hashlib.sha256(source_bytes).hexdigest()
            outcome = execute_test(args.candidate_source, raw_test)
            observation_id = str(raw_test["command_id"])
            requirement_sha256 = None
            taxonomy_source_sha256 = None
            if inventory is not None:
                requirement = requirement_from_inventory(
                    inventory,
                    str(raw_test["requirement_id"]),
                    str(raw_test["evidence_class"]),
                )
                requirement_sha256 = str(requirement["requirement_sha256"])
                taxonomy_source_sha256 = str(inventory["taxonomy_source_sha256"])
            result_path = results_directory / f"{observation_id}.json"
            result_sha256 = write_json(
                result_path,
                result_document(
                    raw_test,
                    observation_id,
                    requirement_sha256,
                    outcome,
                )
                if requirement_sha256 is not None
                else neutral_result_document(raw_test, outcome),
            )
            observation_path = None
            if taxonomy_source_sha256 is not None and requirement_sha256 is not None:
                relative_result_path = result_path.resolve().relative_to(
                    args.framework_root.resolve()
                )
                observation_path = observations_directory / f"{observation_id}.json"
                write_json(
                    observation_path,
                    observation_document(
                        raw_test,
                        observation_id,
                        requirement_sha256,
                        taxonomy_source_sha256,
                        args.candidate_commit,
                        args.framework_commit,
                        framework_version,
                        command_manifest_sha256,
                        test_source_sha256,
                        args.rust_version,
                        relative_result_path.as_posix(),
                        result_sha256,
                        outcome,
                    ),
                )
            records.append(
                {
                    "command_id": raw_test["command_id"],
                    "assertion_id": raw_test["assertion_id"],
                    "evidence_class": raw_test["evidence_class"],
                    "status": outcome.status,
                    "test_source_sha256": test_source_sha256,
                    "result_sha256": result_sha256,
                    "observation_emitted": observation_path is not None,
                }
            )
        verify_clean_checkout(args.candidate_source, args.candidate_commit)
        verify_clean_checkout(args.framework_root, args.framework_commit)
        if args.taxonomy_source is not None and args.taxonomy_commit is not None:
            verify_clean_checkout(args.taxonomy_source, args.taxonomy_commit)
        overall_status = (
            "passed"
            if all(record["status"] == "passed" for record in records)
            else "failed"
        )
        write_json(
            args.result_dir / "index.json",
            {
                "$comment": NOTICE,
                "schema": (
                    "reallyme.identity.eudi_requirement_test_execution.v1"
                ),
                "plan_id": plan["plan_id"],
                "framework_commit": args.framework_commit,
                "candidate_repository": args.candidate_repository,
                "candidate_commit": args.candidate_commit,
                "command_manifest_sha256": command_manifest_sha256,
                "status": overall_status,
                "records": records,
                "taxonomy_observations_emitted": inventory is not None,
            },
        )
        print(f"EUDI requirement tests {overall_status}")
        return 0 if overall_status == "passed" else EXIT_FAILED
    except (
        adapter_verifier.AdapterError,
        plan_verifier.RequirementTestPlanError,
        KeyError,
        OSError,
        UnicodeError,
        ValueError,
    ) as error:
        fail(RequirementRunnerErrorReason.INVALID_ARGUMENT)
    except RequirementRunnerError as error:
        fail(error.reason)


if __name__ == "__main__":
    raise SystemExit(main())
