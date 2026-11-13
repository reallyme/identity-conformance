#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the digest-bound EUDI Wallet engineering conformance lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_component_attestation as component_attestation  # noqa: E402
import verify_eu_wallet_boundaries as normative_boundaries  # noqa: E402
import verify_eudi_wallet_adapter as wallet_adapter  # noqa: E402
import verify_wallet_package_bundle as wallet_package_bundle  # noqa: E402


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_DISCOVERED_TESTS = 100_000
COMMAND_TIMEOUT_SECONDS = 3_600
TEST_COMMAND_ID = "cargo-test-workspace-all-features-v1"
TEST_CASES_RELATIVE_PATH = "conformance/eudi/test-cases.json"
MINIMUMS_RELATIVE_PATH = "conformance/requirements/eudi-wallet-minimums.json"
TEST_BUILD_COMMAND = (
    "cargo",
    "test",
    "--locked",
    "--workspace",
    "--all-features",
    "--no-run",
    "--message-format=json",
)
TEST_LIST_COMMAND = (
    "cargo",
    "test",
    "--locked",
    "--workspace",
    "--all-features",
    "--",
    "--list",
)
TEST_RUN_COMMAND = (
    "cargo",
    "test",
    "--locked",
    "--workspace",
    "--all-features",
    "--",
    "--include-ignored",
)
METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--no-deps",
    "--format-version",
    "1",
)
FRAMEWORK_PROBE_COMMANDS = {
    "cargo-test-framework-key-storage-probe-v1": (
        "cargo",
        "test",
        "--locked",
        "--package",
        "reallyme-wallet-provider",
        "--test",
        "identity_conformance_key_storage_boundaries",
        "--all-features",
        "--",
        "--include-ignored",
    ),
    "cargo-test-framework-key-custody-codec-v1": (
        "cargo",
        "test",
        "--locked",
        "--package",
        "reallyme-wallet-proto-codec",
        "--test",
        "identity_conformance_key_custody_codec",
        "--all-features",
        "--",
        "--include-ignored",
    ),
    "cargo-test-framework-consent-policy-context-v1": (
        "cargo",
        "test",
        "--locked",
        "--package",
        "reallyme-wallet-conformance",
        "--test",
        "identity_conformance_consent_policy_context",
        "--all-features",
        "--",
        "--include-ignored",
    ),
    "cargo-test-framework-flow-resume-probe-v1": (
        "cargo",
        "test",
        "--locked",
        "--package",
        "reallyme-wallet-conformance",
        "--test",
        "identity_conformance_flow_resume_boundaries",
        "--all-features",
        "--",
        "--include-ignored",
    ),
    "cargo-test-framework-lifecycle-probe-v1": (
        "cargo",
        "test",
        "--locked",
        "--package",
        "reallyme-wallet-conformance",
        "--test",
        "identity_conformance_lifecycle_boundaries",
        "--all-features",
        "--",
        "--include-ignored",
    ),
}
NORMATIVE_LEDGER_PATHS = {
    "eu_arf_sha256": wallet_adapter.REPOSITORY_ROOT
    / "plans/eudi/normative/arf-wallet.json",
    "eu_fcaf_sha256": wallet_adapter.REPOSITORY_ROOT
    / "plans/eudi/normative/fcaf-wallet.json",
    "eu_technical_specifications_sha256": wallet_adapter.REPOSITORY_ROOT
    / "plans/eudi/normative/technical-specifications-wallet.json",
    "eu_wallet_boundary_adapter_sha256": wallet_adapter.REPOSITORY_ROOT
    / "adapters/eudi-wallet/normative-boundaries.json",
}
FRAMEWORK_VERSION_PATH = wallet_adapter.REPOSITORY_ROOT / "VERSION"
SEMANTIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
PACKAGE_ID = re.compile(
    r"#(?P<name>[a-z0-9][a-z0-9_-]*)@"
    r"(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$"
)
RUNNING_TEST_TARGET = re.compile(r"^\s*Running .+ \((?P<executable>[^)]+)\)$")
RUNNING_DOC_TEST = re.compile(r"^\s*Doc-tests (?P<target>[A-Za-z0-9_-]+)$")
TEST_SUMMARY = re.compile(
    r"^test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>[0-9]+) passed; (?P<failed>[0-9]+) failed; "
    r"(?P<ignored>[0-9]+) ignored; (?P<measured>[0-9]+) measured; "
    r"(?P<filtered>[0-9]+) filtered out;"
)


class EudiWalletRunnerErrorReason(Enum):
    INVALID_DEPLOYMENT = "invalid_deployment"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_ATTESTATION = "invalid_attestation"
    RESULT_PATH_EXISTS = "result_path_exists"
    RESULT_WRITE_FAILED = "result_write_failed"


@dataclass(frozen=True)
class EudiWalletRunnerError(Exception):
    reason: EudiWalletRunnerErrorReason


@dataclass(frozen=True)
class Check:
    check_id: str
    kind: str
    result: str


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    content: bytes


@dataclass(frozen=True)
class TestExecution:
    command_id: str
    discovered_test_count: int
    test_inventory_sha256: str
    executed_test_count: int
    passed_test_count: int
    failed_test_count: int
    ignored_test_count: int
    measured_test_count: int
    filtered_test_count: int
    declared_executable_case_count: int
    declared_test_functions_sha256: str
    result: str


@dataclass(frozen=True)
class FrameworkProbeExecution:
    probe_id: str
    command_id: str
    source_sha256: str
    executed_test_count: int
    passed_test_count: int
    failed_test_count: int
    ignored_test_count: int
    measured_test_count: int
    filtered_test_count: int
    result: str


def fail(reason: EudiWalletRunnerErrorReason) -> NoReturn:
    print(f"EUDI Wallet conformance runner failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def exact_object(
    value: object, keys: set[str], reason: EudiWalletRunnerErrorReason
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EudiWalletRunnerError(reason)
    return value


def validate_deployment(
    value: dict[str, object], adapter: dict[str, object]
) -> dict[str, object]:
    exact_object(
        value,
        {
            "schema",
            "plan_id",
            "component",
            "target",
            "package_bundle",
            "component_attestation_sha256",
            "source_locks",
            "evidence_policy",
        },
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        value["schema"] != "reallyme.identity.eudi_wallet_deployment_manifest.v2"
        or value["plan_id"] != "eudi-wallet-engineering-v1"
        or value["evidence_policy"] != wallet_adapter.EXPECTED_POLICY
        or not isinstance(value["component_attestation_sha256"], str)
        or wallet_adapter.SHA256.fullmatch(value["component_attestation_sha256"])
        is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    component = exact_object(
        value["component"],
        {"component_id", "repository", "commit"},
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    requirement = adapter.get("component_requirement")
    if (
        not isinstance(requirement, dict)
        or component.get("component_id") != requirement.get("component_id")
        or component.get("repository") != requirement.get("repository")
        or not isinstance(component.get("commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", component["commit"]) is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    target = value["target"]
    if not isinstance(target, dict):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    mode = target.get("mode")
    target_keys = {"mode", "version", "commit", "preflight_run_id"}
    if mode == "published":
        target_keys.update({"release_id", "release_ref"})
    target = exact_object(
        target,
        target_keys,
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        mode not in {"candidate", "published"}
        or not isinstance(target["version"], str)
        or SEMANTIC_VERSION.fullmatch(target["version"]) is None
        or target["commit"] != component["commit"]
        or type(target["preflight_run_id"]) is not int
        or target["preflight_run_id"] < 1
        or (
            mode == "published"
            and (
                type(target["release_id"]) is not int
                or target["release_id"] < 1
                or target["release_ref"]
                != f"reallyme-wallet-v{target['version']}"
            )
        )
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    artifact = exact_object(
        value["package_bundle"],
        {"artifact_id", "kind", "sha256"},
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if (
        artifact["artifact_id"] != "wallet-package-bundle"
        or artifact["kind"] != "archive"
        or not isinstance(artifact["sha256"], str)
        or wallet_adapter.SHA256.fullmatch(artifact["sha256"]) is None
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    source_locks = exact_object(
        value["source_locks"],
        {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
        },
        EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT,
    )
    if not all(
        isinstance(digest, str)
        and wallet_adapter.SHA256.fullmatch(digest) is not None
        for digest in source_locks.values()
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return artifact


def normative_ledger_digests() -> dict[str, str]:
    return {
        identifier: hash_regular_file(path)
        for identifier, path in sorted(NORMATIVE_LEDGER_PATHS.items())
    }


def framework_version() -> str:
    try:
        metadata = FRAMEWORK_VERSION_PATH.lstat()
        if (
            FRAMEWORK_VERSION_PATH.is_symlink()
            or not FRAMEWORK_VERSION_PATH.is_file()
            or not 1 <= metadata.st_size <= 64
        ):
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        version = FRAMEWORK_VERSION_PATH.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        ) from error
    if SEMANTIC_VERSION.fullmatch(version) is None:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return version


def candidate_digest(deployment: dict[str, object]) -> str:
    candidate = {
        "plan_id": deployment["plan_id"],
        "framework_version": deployment.get("framework_version", framework_version()),
        "component": deployment["component"],
        "target": deployment["target"],
        "package_bundle": deployment["package_bundle"],
        "component_attestation_sha256": deployment["component_attestation_sha256"],
        "source_locks": deployment["source_locks"],
        "normative_ledgers": normative_ledger_digests(),
    }
    encoded = json.dumps(
        candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hash_regular_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
        if not 1 <= metadata.st_size <= MAX_ARTIFACT_BYTES:
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT) from error


def verify_package_bundle(path: Path, expected_digest: str) -> str:
    observed_digest = hash_regular_file(path)
    if observed_digest != expected_digest:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ARTIFACT)
    return observed_digest


def verify_attestation(
    path: Path,
    expected_digest: str,
    expected_artifact_digest: str,
    expected_commit: str,
    expected_target: dict[str, object],
) -> tuple[set[str], dict[str, object]]:
    if hash_regular_file(path) != expected_digest:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    try:
        attestation = component_attestation.load_attestation(path)
        component_attestation.verify_attestation(attestation)
    except component_attestation.AttestationError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_ATTESTATION
        ) from error
    component = attestation["component"]
    target = attestation.get("target")
    artifacts = attestation["artifacts"]
    checks = attestation["checks"]
    if (
        component
        != {
            "component_id": "wallet",
            "repository": "https://github.com/reallyme/wallet",
            "source_commit": expected_commit,
        }
        or target != expected_target
        or not isinstance(artifacts, list)
        or not any(
            isinstance(artifact, dict)
            and artifact.get("artifact_id") == "wallet-package-bundle"
            and artifact.get("sha256") == expected_artifact_digest
            for artifact in artifacts
        )
        or not isinstance(checks, list)
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    categories = {
        check["category"]
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("category"), str)
    }
    if not wallet_adapter.EXPECTED_ATTESTATION_CATEGORIES.issubset(categories):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_ATTESTATION)
    return categories, attestation


def publishable_workspace_packages(source: Path) -> dict[str, str]:
    output = capture_command_output(source, METADATA_COMMAND)
    if output is None or output.returncode != 0:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    try:
        metadata = json.loads(decode_command_output(output.content))
    except json.JSONDecodeError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        ) from error
    if not isinstance(metadata, dict) or not {
        "packages",
        "workspace_members",
    }.issubset(metadata):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    raw_packages = metadata["packages"]
    raw_members = metadata["workspace_members"]
    if (
        not isinstance(raw_packages, list)
        or not isinstance(raw_members, list)
        or not 1 <= len(raw_packages) <= 256
        or not 1 <= len(raw_members) <= 256
        or not all(isinstance(member, str) for member in raw_members)
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    members = set(raw_members)
    if len(members) != len(raw_members):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    packages: dict[str, str] = {}
    observed_members: set[str] = set()
    for raw_package in raw_packages:
        if not isinstance(raw_package, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        package_id = raw_package.get("id")
        if package_id not in members:
            continue
        if not isinstance(package_id, str) or package_id in observed_members:
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        observed_members.add(package_id)
        publish = raw_package.get("publish")
        is_publishable = publish is None or (
            isinstance(publish, list)
            and "crates-io" in publish
            and all(isinstance(registry, str) for registry in publish)
        )
        if not is_publishable:
            continue
        name = raw_package.get("name")
        version = raw_package.get("version")
        if (
            not isinstance(name, str)
            or wallet_package_bundle.CRATE_NAME.fullmatch(name) is None
            or name in packages
            or not isinstance(version, str)
            or wallet_package_bundle.SEMVER.fullmatch(version) is None
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        packages[name] = version
    if observed_members != members or not packages:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return packages


def digest_text_entries(entries: list[str]) -> str:
    payload = "".join(f"{entry}\n" for entry in sorted(entries)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def capture_command_output(
    source: Path, command: tuple[str, ...], *, combine_stderr: bool = False
) -> CommandOutput | None:
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            environment = os.environ.copy()
            environment["CARGO_TERM_COLOR"] = "never"
            process = subprocess.Popen(
                command,
                cwd=source,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT if combine_stderr else subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
            )
            deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
            while process.poll() is None:
                if (
                    os.fstat(output.fileno()).st_size > MAX_COMMAND_OUTPUT_BYTES
                    or time.monotonic() >= deadline
                ):
                    terminate_process_group(process)
                    return None
                time.sleep(0.05)
            size = os.fstat(output.fileno()).st_size
            if not 0 <= size <= MAX_COMMAND_OUTPUT_BYTES:
                return None
            output.seek(0)
            content = output.read(MAX_COMMAND_OUTPUT_BYTES + 1)
            if len(content) != size:
                return None
            return CommandOutput(process.returncode, content)
    except OSError:
        return None


def decode_command_output(output: bytes) -> str:
    try:
        return output.decode("utf-8")
    except UnicodeError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        ) from error


def test_target_identities(source: Path) -> tuple[dict[Path, str], dict[str, str]]:
    build = capture_command_output(source, TEST_BUILD_COMMAND)
    if build is None or build.returncode != 0:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    executable_identities: dict[Path, str] = {}
    doctest_identities: dict[str, str] = {}
    source_root = source.resolve(strict=True)
    for line in decode_command_output(build.content).splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            ) from error
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        profile = message.get("profile")
        target = message.get("target")
        executable = message.get("executable")
        manifest_path = message.get("manifest_path")
        package_id = message.get("package_id")
        if (
            not isinstance(profile, dict)
            or profile.get("test") is not True
            or not isinstance(target, dict)
            or not isinstance(executable, str)
            or not isinstance(manifest_path, str)
            or not isinstance(package_id, str)
        ):
            continue
        try:
            Path(manifest_path).resolve(strict=True).relative_to(source_root)
            executable_path = Path(executable).resolve(strict=True)
        except (OSError, ValueError) as error:
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            ) from error
        package_match = PACKAGE_ID.search(package_id)
        target_name = target.get("name")
        target_kinds = target.get("kind")
        if (
            package_match is None
            or not isinstance(target_name, str)
            or not isinstance(target_kinds, list)
            or not target_kinds
            or not all(isinstance(kind, str) and kind for kind in target_kinds)
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        identity = (
            f"{package_match.group('name')}@{package_match.group('version')}|"
            f"{','.join(sorted(target_kinds))}|{target_name}"
        )
        if executable_path in executable_identities or identity in executable_identities.values():
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        executable_identities[executable_path] = identity
        if target.get("doctest") is True:
            if target_name in doctest_identities:
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            doctest_identities[target_name] = f"{identity}|doc"
    if not executable_identities:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return executable_identities, doctest_identities


def discovered_tests(
    source: Path,
    output: bytes,
    executable_identities: dict[Path, str],
    doctest_identities: dict[str, str],
) -> list[str]:
    text = decode_command_output(output)
    tests: list[str] = []
    current_target: str | None = None
    for line in text.splitlines():
        running_target = RUNNING_TEST_TARGET.fullmatch(line)
        if running_target is not None:
            raw_path = Path(running_target.group("executable"))
            try:
                executable_path = (
                    raw_path if raw_path.is_absolute() else source / raw_path
                ).resolve(strict=True)
            except OSError as error:
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                ) from error
            current_target = executable_identities.get(executable_path)
            if current_target is None:
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            continue
        running_doc = RUNNING_DOC_TEST.fullmatch(line)
        if running_doc is not None:
            current_target = doctest_identities.get(running_doc.group("target"))
            if current_target is None:
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            continue
        if not line.endswith(": test"):
            continue
        name = line[: -len(": test")].strip()
        if (
            current_target is None
            or not name
            or len(name) > 1_024
            or any(character.isspace() for character in name)
        ):
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        tests.append(f"{current_target}|{name}")
    if not 1 <= len(tests) <= MAX_DISCOVERED_TESTS:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return tests


def test_execution_counts(output: bytes) -> tuple[int, int, int, int, int]:
    passed = 0
    failed = 0
    ignored = 0
    measured = 0
    filtered = 0
    summaries = 0
    for line in decode_command_output(output).splitlines():
        summary = TEST_SUMMARY.match(line)
        if summary is None:
            continue
        summaries += 1
        passed += int(summary.group("passed"))
        failed += int(summary.group("failed"))
        ignored += int(summary.group("ignored"))
        measured += int(summary.group("measured"))
        filtered += int(summary.group("filtered"))
    if summaries == 0:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return passed, failed, ignored, measured, filtered


def declared_test_functions(source: Path) -> list[str]:
    manifest = wallet_adapter.load_object(source / TEST_CASES_RELATIVE_PATH)
    if set(manifest) != {"schema_version", "source_lock", "test_cases"} or (
        manifest["schema_version"] != 1
        or manifest["source_lock"] != "conformance/sources.lock"
        or not isinstance(manifest["test_cases"], list)
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    functions: list[str] = []
    case_ids: set[str] = set()
    allowed_statuses = {
        "unit_covered",
        "implemented",
        "fixture_available",
        "fixture_seeded",
    }
    for raw_case in manifest["test_cases"]:
        if not isinstance(raw_case, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        case_id = raw_case.get("id")
        status = raw_case.get("status")
        if (
            not isinstance(case_id, str)
            or wallet_adapter.IDENTIFIER.fullmatch(case_id) is None
            or case_id in case_ids
            or status not in allowed_statuses
            or not isinstance(raw_case.get("source"), str)
            or not isinstance(raw_case.get("fixtures"), list)
            or not all(isinstance(item, str) and item for item in raw_case["fixtures"])
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        case_ids.add(case_id)
        test_function = raw_case.get("test_function")
        if status in {"unit_covered", "implemented"}:
            if (
                not isinstance(test_function, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", test_function) is None
                or test_function in functions
            ):
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            functions.append(test_function)
        elif test_function is not None:
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    if not functions:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return functions


def coverage_summary(
    source: Path,
    executable_case_count: int,
    evaluated_boundary_count: int,
    normative_check_count: int,
) -> dict[str, object]:
    minimums = wallet_adapter.load_object(source / MINIMUMS_RELATIVE_PATH)
    if set(minimums) != {
        "schema_version",
        "source_lock",
        "reference_implementation_lock",
        "minimums",
    } or (
        minimums["schema_version"] != 1
        or minimums["source_lock"] != "conformance/sources.lock"
        or minimums["reference_implementation_lock"]
        != "conformance/eudi/reference-implementation.lock"
        or not isinstance(minimums["minimums"], list)
        or not 1 <= len(minimums["minimums"]) <= 256
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    minimum_status_counts = {
        "implemented": 0,
        "partial": 0,
        "operational_required": 0,
        "delegated": 0,
        "fixture_seeded": 0,
    }
    minimum_ids: set[str] = set()
    incomplete_minimums: list[dict[str, object]] = []
    expected_minimum_keys = {
        "id",
        "status",
        "summary",
        "source_ids",
        "evidence",
        "test_evidence",
        "conformance_case_ids",
        "limitations",
    }
    for raw_minimum in minimums["minimums"]:
        if not isinstance(raw_minimum, dict) or set(raw_minimum) != expected_minimum_keys:
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        minimum_id = raw_minimum["id"]
        status = raw_minimum["status"]
        string_lists = (
            raw_minimum["source_ids"],
            raw_minimum["evidence"],
            raw_minimum["test_evidence"],
            raw_minimum["conformance_case_ids"],
            raw_minimum["limitations"],
        )
        if (
            not isinstance(minimum_id, str)
            or wallet_adapter.IDENTIFIER.fullmatch(minimum_id) is None
            or minimum_id in minimum_ids
            or status not in minimum_status_counts
            or not isinstance(raw_minimum["summary"], str)
            or not raw_minimum["summary"]
            or any(
                not isinstance(items, list)
                or not all(isinstance(item, str) and item for item in items)
                for items in string_lists
            )
        ):
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        minimum_ids.add(minimum_id)
        minimum_status_counts[status] += 1
        if status != "implemented":
            incomplete_minimums.append(
                {
                    "minimum_id": minimum_id,
                    "status": status,
                    "limitations": raw_minimum["limitations"],
                }
            )

    cases = wallet_adapter.load_object(source / TEST_CASES_RELATIVE_PATH)
    raw_cases = cases.get("test_cases")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 10_000:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    case_status_counts = {
        "unit_covered": 0,
        "implemented": 0,
        "fixture_available": 0,
        "fixture_seeded": 0,
    }
    non_executable_cases: list[dict[str, str]] = []
    case_ids: set[str] = set()
    for raw_case in raw_cases:
        case_id = raw_case.get("id") if isinstance(raw_case, dict) else None
        status = raw_case.get("status") if isinstance(raw_case, dict) else None
        if (
            not isinstance(case_id, str)
            or wallet_adapter.IDENTIFIER.fullmatch(case_id) is None
            or case_id in case_ids
            or status not in case_status_counts
        ):
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        case_ids.add(case_id)
        case_status_counts[status] += 1
        if status in {"fixture_available", "fixture_seeded"}:
            non_executable_cases.append({"case_id": case_id, "status": status})
    observed_executable = (
        case_status_counts["unit_covered"] + case_status_counts["implemented"]
    )
    if observed_executable != executable_case_count:
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    return {
        "authority": "internal_engineering",
        "certification_claim": False,
        "minimum_requirements": {
            "total": len(minimum_ids),
            "status_counts": minimum_status_counts,
            "incomplete": sorted(
                incomplete_minimums, key=lambda item: str(item["minimum_id"])
            ),
        },
        "declared_cases": {
            "total": len(raw_cases),
            "executable": observed_executable,
            "non_executable": len(raw_cases) - observed_executable,
            "status_counts": case_status_counts,
            "non_executable_cases": sorted(
                non_executable_cases, key=lambda item: item["case_id"]
            ),
        },
        "normative_boundaries": {
            "implemented": evaluated_boundary_count,
            "checks": normative_check_count,
        },
    }


def execute_wallet_tests(source: Path) -> TestExecution:
    declared = declared_test_functions(source)
    executable_identities, doctest_identities = test_target_identities(source)
    raw_inventory = capture_command_output(
        source, TEST_LIST_COMMAND, combine_stderr=True
    )
    inventory = (
        discovered_tests(
            source,
            raw_inventory.content,
            executable_identities,
            doctest_identities,
        )
        if raw_inventory is not None and raw_inventory.returncode == 0
        else []
    )
    suffix_counts: dict[str, int] = {}
    for test in inventory:
        test_name = test.rsplit("|", maxsplit=1)[-1]
        suffix = test_name.rsplit("::", maxsplit=1)[-1]
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
    declared_cases_present = all(suffix_counts.get(function) == 1 for function in declared)
    passed_count = 0
    failed_count = 0
    ignored_count = 0
    measured_count = 0
    filtered_count = 0
    execution_returncode: int | None = None
    if inventory and declared_cases_present:
        execution = capture_command_output(source, TEST_RUN_COMMAND)
        if execution is not None:
            execution_returncode = execution.returncode
            (
                passed_count,
                failed_count,
                ignored_count,
                measured_count,
                filtered_count,
            ) = test_execution_counts(execution.content)
    executed_count = passed_count + failed_count + ignored_count + measured_count
    tests_passed = (
        execution_returncode == 0
        and passed_count == len(inventory)
        and executed_count == len(inventory)
        and failed_count == 0
        and ignored_count == 0
        and measured_count == 0
        and filtered_count == 0
    )
    return TestExecution(
        command_id=TEST_COMMAND_ID,
        discovered_test_count=len(inventory),
        test_inventory_sha256=digest_text_entries(inventory),
        executed_test_count=executed_count,
        passed_test_count=passed_count,
        failed_test_count=failed_count,
        ignored_test_count=ignored_count,
        measured_test_count=measured_count,
        filtered_test_count=filtered_count,
        declared_executable_case_count=len(declared),
        declared_test_functions_sha256=digest_text_entries(declared),
        result="passed" if tests_passed and declared_cases_present else "failed",
    )


def read_framework_probe(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= 1024 * 1024
        ):
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        return path.read_bytes()
    except OSError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        ) from error


def execute_framework_probe(
    source: Path, contract: dict[str, object]
) -> FrameworkProbeExecution:
    probe_id = contract.get("probe_id")
    command_id = contract.get("command_id")
    source_path = contract.get("source_path")
    target_path = contract.get("target_path")
    expected_test_count = contract.get("expected_test_count")
    if (
        not isinstance(probe_id, str)
        or not isinstance(command_id, str)
        or command_id not in FRAMEWORK_PROBE_COMMANDS
        or not isinstance(source_path, str)
        or not isinstance(target_path, str)
        or type(expected_test_count) is not int
        or not 1 <= expected_test_count <= 1_000
    ):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    framework_source = wallet_adapter.REPOSITORY_ROOT / source_path
    probe = read_framework_probe(framework_source)
    target = source / target_path
    created = False
    try:
        source_root = source.resolve(strict=True)
        target.parent.resolve(strict=True).relative_to(source_root)
        if target.exists() or target.is_symlink() or target.parent.is_symlink():
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(probe)
            handle.flush()
            os.fsync(handle.fileno())
        execution = capture_command_output(
            source, FRAMEWORK_PROBE_COMMANDS[command_id]
        )
        if execution is None:
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
            )
        passed, failed, ignored, measured, filtered = test_execution_counts(
            execution.content
        )
        executed = passed + failed + ignored + measured
        probe_passed = (
            execution.returncode == 0
            and executed == expected_test_count
            and passed == expected_test_count
            and failed == 0
            and ignored == 0
            and measured == 0
            and filtered == 0
        )
        return FrameworkProbeExecution(
            probe_id=probe_id,
            command_id=command_id,
            source_sha256=hashlib.sha256(probe).hexdigest(),
            executed_test_count=executed,
            passed_test_count=passed,
            failed_test_count=failed,
            ignored_test_count=ignored,
            measured_test_count=measured,
            filtered_test_count=filtered,
            result="passed" if probe_passed else "failed",
        )
    except (OSError, ValueError) as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
        ) from error
    finally:
        if created:
            try:
                target.unlink()
            except OSError as error:
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                ) from error
        if wallet_adapter.git_output(source, "status", "--porcelain"):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)


def write_result(output: Path, result: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".eudi-wallet-result-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise EudiWalletRunnerError(
            EudiWalletRunnerErrorReason.RESULT_WRITE_FAILED
        ) from error


def build_assertions(
    plan: dict[str, object], checks: list[Check]
) -> list[dict[str, object]]:
    check_results = {check.check_id: check.result for check in checks}
    raw_assertions = plan["assertions"]
    if not isinstance(raw_assertions, list):
        raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
    assertions: list[dict[str, object]] = []
    for raw_assertion in raw_assertions:
        if not isinstance(raw_assertion, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        assertion_id = raw_assertion.get("assertion_id")
        required_checks = raw_assertion.get("required_checks")
        if not isinstance(assertion_id, str) or not isinstance(required_checks, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        assertions.append(
            {
                "assertion_id": assertion_id,
                "check_ids": required_checks,
                "result": "passed"
                if all(check_results.get(check) == "passed" for check in required_checks)
                else "failed",
            }
        )
    return assertions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--package-bundle", required=True, type=Path)
    parser.add_argument("--component-attestation", required=True, type=Path)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan, adapter = wallet_adapter.load_contract()
        deployment = wallet_adapter.load_object(args.deployment_manifest)
        artifact = validate_deployment(deployment, adapter)
        source_locks = deployment["source_locks"]
        if not isinstance(source_locks, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        if (
            hash_regular_file(wallet_adapter.UPSTREAM_LOCK_PATH)
            != source_locks["eudi_sources_sha256"]
            or hash_regular_file(wallet_adapter.LEGAL_SOURCES_LOCK_PATH)
            != source_locks["eudi_legal_sources_sha256"]
            or hash_regular_file(wallet_adapter.PUBLICATIONS_LOCK_PATH)
            != source_locks["eudi_publications_sha256"]
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        if (
            re.fullmatch(r"[0-9a-f]{40}", args.framework_revision) is None
            or re.fullmatch(r"[0-9a-f]{40}", args.workflow_revision) is None
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        artifact_digest = verify_package_bundle(
            args.package_bundle, artifact["sha256"]
        )
        component = deployment["component"]
        target = deployment["target"]
        if (
            not isinstance(component, dict)
            or not isinstance(component.get("commit"), str)
            or not isinstance(target, dict)
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        wallet_adapter.verify_checkout(args.source, adapter, component["commit"])
        categories, attestation = verify_attestation(
            args.component_attestation,
            deployment["component_attestation_sha256"],
            artifact_digest,
            component["commit"],
            target,
        )
        try:
            package_evidence = wallet_package_bundle.verify_bundle(
                args.package_bundle,
                attestation,
                target["mode"],
                component["commit"],
                target["version"],
                target["preflight_run_id"],
                publishable_workspace_packages(args.source),
                args.source / "Cargo.lock",
            )
        except wallet_package_bundle.WalletPackageBundleError as error:
            raise EudiWalletRunnerError(
                EudiWalletRunnerErrorReason.INVALID_ARTIFACT
            ) from error
        source_artifacts = adapter["source_artifacts"]
        if not isinstance(source_artifacts, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        checks = [
            Check(f"source.{artifact['artifact_id']}", "source", "passed")
            for artifact in source_artifacts
            if isinstance(artifact, dict) and isinstance(artifact.get("artifact_id"), str)
        ]
        if len(checks) != len(source_artifacts):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        checks.append(Check("artifact.wallet-package-bundle", "artifact", "passed"))
        checks.append(Check("framework.eudi-source-lock", "source", "passed"))
        checks.append(Check("framework.eudi-legal-source-lock", "source", "passed"))
        checks.append(Check("framework.eudi-publications-lock", "source", "passed"))
        for category in sorted(wallet_adapter.EXPECTED_ATTESTATION_CATEGORIES):
            checks.append(
                Check(
                    f"attestation.{category}",
                    "attestation",
                    "passed" if category in categories else "failed",
                )
            )
        try:
            evaluated_boundaries = normative_boundaries.evaluate(args.source)
        except normative_boundaries.BoundaryError as error:
            if (
                error.reason
                is not normative_boundaries.BoundaryErrorReason.OBSERVATION_UNAVAILABLE
            ):
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                ) from error
            evaluated_boundaries = []
        boundary_adapter = normative_boundaries.load_adapter()
        raw_boundaries = boundary_adapter.get("implemented_boundaries")
        if not isinstance(raw_boundaries, list):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        expected_normative_checks: set[str] = set()
        for raw_boundary in raw_boundaries:
            if not isinstance(raw_boundary, dict):
                raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
            normative_checks = raw_boundary.get("normative_checks")
            if not isinstance(normative_checks, dict):
                raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
            for check_id in normative_checks.values():
                if not isinstance(check_id, str):
                    raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
                expected_normative_checks.add(check_id)
        observed_normative_checks = {
            check_id: boundary.passed
            for boundary in evaluated_boundaries
            for check_id in boundary.normative_checks
        }
        for check_id in sorted(expected_normative_checks):
            checks.append(
                Check(
                    check_id,
                    "normative",
                    "passed" if observed_normative_checks.get(check_id) is True else "failed",
                )
            )
        test_contract = adapter["test_execution"]
        if not isinstance(test_contract, dict):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        test_execution = execute_wallet_tests(args.source)
        coverage = coverage_summary(
            args.source,
            test_execution.declared_executable_case_count,
            len(evaluated_boundaries),
            len(observed_normative_checks),
        )
        check_id = test_contract.get("check_id")
        if (
            not isinstance(check_id, str)
            or test_contract.get("command_id") != test_execution.command_id
            or test_contract.get("declared_cases_path") != TEST_CASES_RELATIVE_PATH
        ):
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        checks.append(Check(check_id, "cargo", test_execution.result))
        raw_probes = adapter["framework_probes"]
        if not isinstance(raw_probes, list) or not raw_probes:
            raise EudiWalletRunnerError(EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT)
        probe_executions: list[FrameworkProbeExecution] = []
        for raw_probe in raw_probes:
            if not isinstance(raw_probe, dict):
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            probe_execution = execute_framework_probe(args.source, raw_probe)
            if (
                raw_probe.get("probe_id") != probe_execution.probe_id
                or raw_probe.get("command_id") != probe_execution.command_id
                or not isinstance(raw_probe.get("check_id"), str)
            ):
                raise EudiWalletRunnerError(
                    EudiWalletRunnerErrorReason.INVALID_DEPLOYMENT
                )
            probe_executions.append(probe_execution)
            checks.append(
                Check(raw_probe["check_id"], "probe", probe_execution.result)
            )
        assertions = build_assertions(plan, checks)
        passed = all(check.result == "passed" for check in checks) and all(
            assertion["result"] == "passed" for assertion in assertions
        )
        result = {
            "schema": "reallyme.identity.eudi_wallet_execution_result.v3",
            "plan_id": "eudi-wallet-engineering-v1",
            "result": "passed" if passed else "failed",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "framework_version": framework_version(),
            "framework_revision": args.framework_revision,
            "workflow_revision": args.workflow_revision,
            "candidate_sha256": candidate_digest(deployment),
            "component": component,
            "target": target,
            "package_bundle_sha256": artifact_digest,
            "component_attestation_sha256": deployment["component_attestation_sha256"],
            "package_evidence": {
                "preflight_run_id": package_evidence.preflight_run_id,
                "preflight_job_id": package_evidence.preflight_job_id,
                "fuzz_run_id": package_evidence.fuzz_run_id,
                "protobuf_ci_run_id": package_evidence.protobuf_ci_run_id,
                "rust_ci_run_id": package_evidence.rust_ci_run_id,
                "crate_count": package_evidence.crate_count,
                "crates": [crate.__dict__ for crate in package_evidence.crates],
                "crate_inventory_sha256": package_evidence.crate_inventory_sha256,
                "evidence_count": package_evidence.evidence_count,
                "evidence_inventory_sha256": package_evidence.evidence_inventory_sha256,
                "cargo_lock_sha256": package_evidence.cargo_lock_sha256,
            },
            "source_locks": source_locks,
            "normative_ledgers": normative_ledger_digests(),
            "coverage": coverage,
            "test_execution": {
                "command_id": test_execution.command_id,
                "discovered_test_count": test_execution.discovered_test_count,
                "test_inventory_sha256": test_execution.test_inventory_sha256,
                "executed_test_count": test_execution.executed_test_count,
                "passed_test_count": test_execution.passed_test_count,
                "failed_test_count": test_execution.failed_test_count,
                "ignored_test_count": test_execution.ignored_test_count,
                "measured_test_count": test_execution.measured_test_count,
                "filtered_test_count": test_execution.filtered_test_count,
                "declared_executable_case_count": test_execution.declared_executable_case_count,
                "declared_test_functions_sha256": test_execution.declared_test_functions_sha256,
                "result": test_execution.result,
            },
            "framework_probes": [
                {
                    "probe_id": probe_execution.probe_id,
                    "command_id": probe_execution.command_id,
                    "source_sha256": probe_execution.source_sha256,
                    "executed_test_count": probe_execution.executed_test_count,
                    "passed_test_count": probe_execution.passed_test_count,
                    "failed_test_count": probe_execution.failed_test_count,
                    "ignored_test_count": probe_execution.ignored_test_count,
                    "measured_test_count": probe_execution.measured_test_count,
                    "filtered_test_count": probe_execution.filtered_test_count,
                    "result": probe_execution.result,
                }
                for probe_execution in probe_executions
            ],
            "checks": [check.__dict__ for check in sorted(checks, key=lambda item: item.check_id)],
            "assertions": sorted(assertions, key=lambda item: str(item["assertion_id"])),
            "evidence_policy": wallet_adapter.EXPECTED_POLICY,
        }
        write_result(args.output, result)
        return 0 if passed else 1
    except wallet_adapter.EudiWalletAdapterError as error:
        wallet_adapter.fail(error.reason)
    except EudiWalletRunnerError as error:
        fail(error.reason)


if __name__ == "__main__":
    raise SystemExit(main())
