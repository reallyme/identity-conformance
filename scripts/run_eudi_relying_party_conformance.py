#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Execute the EUDI relying-party control-plane conformance lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_eudi_adapter as adapter_verifier  # noqa: E402
import verify_component_attestation as component_attestation  # noqa: E402
import strict_json  # noqa: E402


MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_PROBE_OUTPUT_BYTES = 16 * 1024
MAX_SERVICE_PROBE_BYTES = 4 * 1024
MAX_NORMATIVE_SOURCE_BYTES = 32 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 1_800
SERVICE_PROBE_TIMEOUT_SECONDS = 15
EXIT_CONFIGURATION = 78
EXIT_FAILED = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID = re.compile(r"^[0-9a-f]{32}$")
BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{32,512}$")
EXPECTED_COMPONENT_REPOSITORIES = {
    "platform": "https://github.com/reallyme/platform",
    "ssi": "https://github.com/reallyme/ssi",
}
CANDIDATE_REPOSITORY = re.compile(
    r"^https://github\.com/reallyme/[A-Za-z0-9_.-]+$"
)
EXECUTION_MODES = {"engineering", "deployed", "live_ts5"}


class RunnerErrorReason(Enum):
    INVALID_DEPLOYMENT_MANIFEST = "invalid_deployment_manifest"
    INVALID_COMPONENT_LAYOUT = "invalid_component_layout"
    INVALID_ARTIFACT = "invalid_artifact"
    INVALID_ATTESTATION = "invalid_attestation"
    INVALID_EVIDENCE_PATH = "invalid_evidence_path"
    INVALID_LIVE_INPUT = "invalid_live_input"
    RESULT_PATH_EXISTS = "result_path_exists"
    RESULT_WRITE_FAILED = "result_write_failed"


@dataclass(frozen=True)
class RunnerError(Exception):
    reason: RunnerErrorReason


@dataclass(frozen=True)
class Check:
    check_id: str
    kind: str
    result: str


def fail(reason: RunnerErrorReason) -> NoReturn:
    print(f"EUDI conformance runner failed: {reason.value}", file=sys.stderr)
    raise SystemExit(EXIT_CONFIGURATION)


def exact_keys(value: object, expected: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    return value


def validate_deployment_manifest(
    value: dict[str, object], expected_candidate_repository: str | None = None
) -> dict[str, dict[str, str]]:
    exact_keys(
        value,
        {
            "schema_version",
            "purpose",
            "plan_id",
            "mode",
            "components",
            "artifact",
            "trust_artifact",
            "credential_authority_artifact",
            "component_attestation_sha256",
            "upstream_lock_sha256",
            "legal_sources_lock_sha256",
            "publications_lock_sha256",
            "evidence_policy",
        },
    )
    if (
        value["schema_version"] != 1
        or value["purpose"] != "eudi-relying-party-conformance-deployment"
        or value["plan_id"] != "eudi-relying-party-control-plane-v1"
        or value["mode"] not in EXECUTION_MODES
        or not isinstance(value["upstream_lock_sha256"], str)
        or SHA256.fullmatch(value["upstream_lock_sha256"]) is None
        or not isinstance(value["legal_sources_lock_sha256"], str)
        or SHA256.fullmatch(value["legal_sources_lock_sha256"]) is None
        or not isinstance(value["publications_lock_sha256"], str)
        or SHA256.fullmatch(value["publications_lock_sha256"]) is None
        or not isinstance(value["component_attestation_sha256"], str)
        or SHA256.fullmatch(value["component_attestation_sha256"]) is None
    ):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    components = value["components"]
    if not isinstance(components, list) or len(components) != 3:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    indexed: dict[str, dict[str, str]] = {}
    for raw_component in components:
        component = exact_keys(raw_component, {"component_id", "repository", "commit"})
        component_id = component["component_id"]
        repository = component["repository"]
        commit = component["commit"]
        if (
            not isinstance(component_id, str)
            or component_id in indexed
            or not isinstance(repository, str)
            or not isinstance(commit, str)
            or adapter_verifier.GIT_COMMIT.fullmatch(commit) is None
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        if component_id == "candidate":
            if (
                CANDIDATE_REPOSITORY.fullmatch(repository) is None
                or expected_candidate_repository is not None
                and repository != expected_candidate_repository
            ):
                raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        elif EXPECTED_COMPONENT_REPOSITORIES.get(component_id) != repository:
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        indexed[component_id] = {
            "component_id": component_id,
            "repository": repository,
            "commit": commit,
        }
    if set(indexed) != {"candidate", *EXPECTED_COMPONENT_REPOSITORIES}:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    artifact = exact_keys(value["artifact"], {"kind", "sha256"})
    if (
        artifact["kind"] != "binary"
        or not isinstance(artifact["sha256"], str)
        or SHA256.fullmatch(artifact["sha256"]) is None
    ):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    trust_artifact = exact_keys(value["trust_artifact"], {"kind", "sha256"})
    if (
        trust_artifact["kind"] != "binary"
        or not isinstance(trust_artifact["sha256"], str)
        or SHA256.fullmatch(trust_artifact["sha256"]) is None
    ):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    credential_authority_artifact = exact_keys(
        value["credential_authority_artifact"], {"kind", "sha256"}
    )
    if (
        credential_authority_artifact["kind"] not in {"binary", "deployment_bundle"}
        or not isinstance(credential_authority_artifact["sha256"], str)
        or SHA256.fullmatch(credential_authority_artifact["sha256"]) is None
    ):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    policy = exact_keys(
        value["evidence_policy"],
        {
            "raw_process_output_retained",
            "transaction_content_retained",
            "private_key_material_retained",
            "credentials_retained",
        },
    )
    if any(policy_item is not False for policy_item in policy.values()):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    return indexed


def hash_regular_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        if metadata.st_size < 1 or metadata.st_size > MAX_ARTIFACT_BYTES:
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT) from error


def require_regular_file(path: Path, reason: RunnerErrorReason) -> None:
    try:
        path.lstat()
    except OSError as error:
        raise RunnerError(reason) from error
    if path.is_symlink() or not path.is_file():
        raise RunnerError(reason)


def verify_component_layout(
    components: dict[str, dict[str, str]],
    candidate_source: Path,
    platform_source: Path,
    ssi_source: Path,
) -> None:
    roots = {
        "candidate": candidate_source.resolve(),
        "platform": platform_source.resolve(),
        "ssi": ssi_source.resolve(),
    }
    if len({root.parent for root in roots.values()}) != 1:
        raise RunnerError(RunnerErrorReason.INVALID_COMPONENT_LAYOUT)
    for component_id, root in roots.items():
        adapter_verifier.verify_checkout(root, components[component_id]["commit"])
        observed_repository = adapter_verifier.git_output(
            root, "config", "--get", "remote.origin.url"
        ).removesuffix(".git")
        if observed_repository != components[component_id]["repository"]:
            raise RunnerError(RunnerErrorReason.INVALID_COMPONENT_LAYOUT)


def required_attestation_checks(
    plan: dict[str, object], adapter: dict[str, object]
) -> tuple[set[str], list[dict[str, object]]]:
    families = plan.get("assertion_families")
    if not isinstance(families, list):
        raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
    required: set[str] = set()
    assertions: list[dict[str, object]] = []
    for raw_family in families:
        if not isinstance(raw_family, dict) or not isinstance(raw_family.get("assertions"), list):
            raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
        family_id = raw_family.get("family_id")
        if not isinstance(family_id, str):
            raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
        for raw_assertion in raw_family["assertions"]:
            if not isinstance(raw_assertion, dict) or not isinstance(
                raw_assertion.get("evidence_contracts"), list
            ):
                raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
            assertion_id = raw_assertion.get("assertion_id")
            if not isinstance(assertion_id, str):
                raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
            check_ids = set(raw_assertion["evidence_contracts"])
            if check_ids != {f"attestation.{assertion_id}"}:
                raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
            required.update(check_ids)
            assertions.append(
                {
                    "family_id": family_id,
                    "assertion_id": assertion_id,
                    "check_ids": sorted(check_ids),
                    "evidence_strength": "attestation_only",
                }
            )
    bindings = adapter.get("source_bindings")
    if not isinstance(bindings, list):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    for binding in bindings:
        if not isinstance(binding, dict) or not isinstance(
            binding.get("attestation_check_id"), str
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        required.add(binding["attestation_check_id"])
    return required, assertions


def verify_attestation(
    path: Path,
    expected_digest: str,
    component: dict[str, str],
    artifact_digests: dict[str, str],
    required_check_ids: set[str],
) -> set[str]:
    if hash_regular_file(path) != expected_digest:
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION)
    try:
        attestation = component_attestation.load_attestation(path)
        component_attestation.verify_attestation(attestation)
    except component_attestation.AttestationError as error:
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION) from error
    if attestation.get("component") != {
        "component_id": "candidate",
        "repository": component["repository"],
        "source_commit": component["commit"],
    }:
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION)
    artifacts = attestation.get("artifacts")
    checks = attestation.get("checks")
    if not isinstance(artifacts, list) or not isinstance(checks, list):
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION)
    observed_artifacts = {
        artifact.get("artifact_id"): artifact.get("sha256")
        for artifact in artifacts
        if isinstance(artifact, dict)
    }
    if any(
        observed_artifacts.get(artifact_id) != digest
        for artifact_id, digest in artifact_digests.items()
    ):
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION)
    observed_checks = {
        check.get("check_id")
        for check in checks
        if isinstance(check, dict) and check.get("result") == "passed"
    }
    if not required_check_ids.issubset(observed_checks):
        raise RunnerError(RunnerErrorReason.INVALID_ATTESTATION)
    return required_check_ids


def execute_quiet(arguments: list[str], cwd: Path, timeout: int = COMMAND_TIMEOUT_SECONDS) -> bool:
    environment = os.environ.copy()
    environment.update({"CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"})
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def execute_bounded_probe(
    arguments: list[str],
    cwd: Path,
    *,
    expected_success: bool,
    required_tokens: list[str] | None = None,
    exact_output: str | None = None,
) -> bool:
    output = bytearray()
    try:
        with tempfile.TemporaryFile() as stdout:
            completed = subprocess.run(
                arguments,
                cwd=cwd,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if (completed.returncode == 0) is not expected_success:
                return False
            if required_tokens is None and exact_output is None:
                return True
            size = stdout.tell()
            if size > MAX_PROBE_OUTPUT_BYTES:
                return False
            stdout.seek(0)
            output.extend(stdout.read(MAX_PROBE_OUTPUT_BYTES + 1))
        if exact_output is not None and output != exact_output.encode("utf-8"):
            return False
        return required_tokens is None or all(
            token.encode("utf-8") in output for token in required_tokens
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        output[:] = b"\0" * len(output)


def execute_profile_probe(
    arguments: list[str],
    cwd: Path,
    required_tokens: list[str],
    required_fields: set[str],
) -> dict[str, str] | None:
    """Run the offline profile command and parse only reviewed scalar fields."""

    output = bytearray()
    try:
        with tempfile.TemporaryFile() as stdout:
            completed = subprocess.run(
                arguments,
                cwd=cwd,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                timeout=120,
            )
            if completed.returncode != 0 or stdout.tell() > MAX_PROBE_OUTPUT_BYTES:
                return None
            stdout.seek(0)
            output.extend(stdout.read(MAX_PROBE_OUTPUT_BYTES + 1))
        if any(token.encode("utf-8") not in output for token in required_tokens):
            return None
        decoded = output.decode("utf-8")
        fields: dict[str, str] = {}
        for line in decoded.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in required_fields:
                if (
                    key in fields
                    or not value
                    or any(character.isspace() for character in value)
                ):
                    return None
                fields[key] = value
        if set(fields) != required_fields:
            return None
        return fields
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    finally:
        output[:] = b"\0" * len(output)


def hash_normative_source(path: Path, root: Path) -> str | None:
    """Hash one regular source file only when it remains inside its checkout."""

    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        if not resolved_path.is_relative_to(resolved_root):
            return None
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            return None
        if metadata.st_size < 1 or metadata.st_size > MAX_NORMATIVE_SOURCE_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(128 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def evaluate_normative_profiles(
    profile_fields: dict[str, str],
    candidate_source: Path,
    upstream_root: Path,
    adapter: dict[str, object],
) -> list[Check]:
    """Bind candidate-vendored normative inputs to the framework-owned checkout."""

    raw_profiles = adapter.get("normative_profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    checks: list[Check] = []
    for raw_profile in raw_profiles:
        if not isinstance(raw_profile, dict):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        profile_id = raw_profile.get("profile_id")
        version_field = raw_profile.get("version_field")
        expected_version = raw_profile.get("expected_version")
        commit_field = raw_profile.get("commit_field")
        candidate_root = raw_profile.get("candidate_root")
        pinned_root = raw_profile.get("upstream_root")
        files = raw_profile.get("files")
        if (
            not isinstance(profile_id, str)
            or not isinstance(version_field, str)
            or not isinstance(expected_version, str)
            or not isinstance(commit_field, str)
            or not isinstance(candidate_root, str)
            or not isinstance(pinned_root, str)
            or not isinstance(files, list)
            or not files
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        declared_commit = profile_fields.get(commit_field)
        declared_version = profile_fields.get(version_field)
        profile_matches = (
            declared_version == expected_version
            and isinstance(declared_commit, str)
            and adapter_verifier.GIT_COMMIT.fullmatch(declared_commit) is not None
        )
        for raw_file in files:
            if not isinstance(raw_file, dict):
                raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
            artifact_id = raw_file.get("artifact_id")
            candidate_path = raw_file.get("candidate_path")
            upstream_path = raw_file.get("upstream_path")
            if (
                not isinstance(artifact_id, str)
                or not isinstance(candidate_path, str)
                or not isinstance(upstream_path, str)
            ):
                raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
            matches = False
            if profile_matches and declared_commit is not None:
                candidate_file = (
                    candidate_source / candidate_root / declared_commit / candidate_path
                )
                pinned_file = upstream_root / pinned_root / upstream_path
                candidate_digest = hash_normative_source(
                    candidate_file, candidate_source
                )
                pinned_digest = hash_normative_source(pinned_file, upstream_root)
                matches = (
                    candidate_digest is not None
                    and pinned_digest is not None
                    and candidate_digest == pinned_digest
                )
            checks.append(
                Check(
                    f"normative_source.{profile_id}.{artifact_id}",
                    "normative_source_binding",
                    "passed" if matches else "failed",
                )
            )
    return checks


def required_normative_check_ids(adapter: dict[str, object]) -> set[str]:
    raw_profiles = adapter.get("normative_profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    check_ids: set[str] = set()
    for profile in raw_profiles:
        if not isinstance(profile, dict) or not isinstance(
            profile.get("profile_id"), str
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        files = profile.get("files")
        if not isinstance(files, list) or not files:
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        for source_file in files:
            if not isinstance(source_file, dict) or not isinstance(
                source_file.get("artifact_id"), str
            ):
                raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
            check_id = (
                f"normative_source.{profile['profile_id']}."
                f"{source_file['artifact_id']}"
            )
            if check_id in check_ids:
                raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
            check_ids.add(check_id)
    return check_ids


def probe_contract(adapter: dict[str, object]) -> dict[str, dict[str, object]]:
    probes = adapter.get("probes")
    if not isinstance(probes, dict):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    indexed: dict[str, dict[str, object]] = {}
    for name in ("profile", "invalid_command", "journal", "live_ts5"):
        value = probes.get(name)
        if not isinstance(value, dict):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        indexed[name] = value
    return indexed


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a reviewed probe cannot switch network authority."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def validate_service_endpoint(endpoint: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT) from error
    if (
        len(endpoint) > 2_048
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or port is None
        or not 1 <= port <= 65_535
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)


def service_probe_contract(adapter: dict[str, object]) -> dict[str, dict[str, object]]:
    probes = adapter.get("probes")
    if not isinstance(probes, dict):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    raw_services = probes.get("deployed_services")
    if not isinstance(raw_services, list) or len(raw_services) != 2:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    services: dict[str, dict[str, object]] = {}
    for raw_service in raw_services:
        service = exact_keys(
            raw_service,
            {
                "service_id",
                "required_status",
                "required_media_type",
                "required_body",
            },
        )
        service_id = service["service_id"]
        if (
            not isinstance(service_id, str)
            or service_id in services
            or service_id not in {"trust_service", "credential_authority"}
            or service["required_status"] != 200
            or service["required_media_type"] != "application/json"
            or service["required_body"]
            != {"service": service_id, "status": "ready"}
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        services[service_id] = service
    if set(services) != {"trust_service", "credential_authority"}:
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    return services


def run_service_probe(
    endpoint: str,
    token: str,
    ca_certificate: Path,
    service: dict[str, object],
) -> Check:
    validate_service_endpoint(endpoint)
    require_regular_file(ca_certificate, RunnerErrorReason.INVALID_LIVE_INPUT)
    if BEARER_TOKEN.fullmatch(token) is None:
        raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
    service_id = service["service_id"]
    if not isinstance(service_id, str):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    passed = False
    try:
        context = ssl.create_default_context(cafile=str(ca_certificate))
        opener = urllib.request.build_opener(
            NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
        )
        request = urllib.request.Request(
            endpoint,
            method="GET",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        with opener.open(request, timeout=SERVICE_PROBE_TIMEOUT_SECONDS) as response:
            media_type = response.headers.get_content_type()
            body = response.read(MAX_SERVICE_PROBE_BYTES + 1)
            if len(body) <= MAX_SERVICE_PROBE_BYTES:
                decoded = strict_json.loads(body.decode("utf-8"))
                passed = (
                    response.status == service["required_status"]
                    and media_type == service["required_media_type"]
                    and decoded == service["required_body"]
                )
    except (
        OSError,
        UnicodeError,
        ValueError,
        strict_json.StrictJsonError,
        urllib.error.URLError,
    ):
        passed = False
    return Check(
        f"service_probe.{service_id}",
        "service_probe",
        "passed" if passed else "failed",
    )


def run_binary_probes(
    binary: Path,
    source_root: Path,
    upstream_root: Path,
    adapter: dict[str, object],
) -> list[Check]:
    probes = probe_contract(adapter)
    profile_arguments = probes["profile"].get("arguments")
    profile_tokens = probes["profile"].get("required_output_tokens")
    invalid_arguments = probes["invalid_command"].get("arguments")
    if (
        not isinstance(profile_arguments, list)
        or not all(isinstance(item, str) for item in profile_arguments)
        or not isinstance(profile_tokens, list)
        or not all(isinstance(item, str) for item in profile_tokens)
        or not isinstance(invalid_arguments, list)
        or not all(isinstance(item, str) for item in invalid_arguments)
    ):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    raw_profiles = adapter.get("normative_profiles")
    if not isinstance(raw_profiles, list):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    required_profile_fields = {
        field
        for profile in raw_profiles
        if isinstance(profile, dict)
        for field in (profile.get("version_field"), profile.get("commit_field"))
        if isinstance(field, str)
    }
    profile_fields = execute_profile_probe(
        [str(binary), *profile_arguments],
        source_root,
        profile_tokens,
        required_profile_fields,
    )
    checks = [
        Check(
            "binary_probe.profile",
            "binary_probe",
            "passed" if profile_fields is not None else "failed",
        ),
        Check(
            "binary_probe.invalid_command",
            "binary_probe",
            "passed"
            if execute_bounded_probe(
                [str(binary), *invalid_arguments],
                source_root,
                expected_success=False,
            )
            else "failed",
        ),
    ]
    checks.extend(
        evaluate_normative_profiles(
            profile_fields if profile_fields is not None else {},
            source_root,
            upstream_root,
            adapter,
        )
    )
    journal = probes["journal"]
    initialize = journal.get("initialize_argument")
    health = journal.get("health_argument")
    expected = journal.get("required_output")
    if not isinstance(initialize, str) or not isinstance(health, str) or not isinstance(expected, str):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="eudi-conformance-journal-") as directory:
        journal_path = Path(directory) / "journal.redb"
        initialized = execute_bounded_probe(
            [str(binary), initialize, str(journal_path)],
            source_root,
            expected_success=True,
            exact_output=expected,
        )
        healthy = initialized and execute_bounded_probe(
            [str(binary), health, str(journal_path)],
            source_root,
            expected_success=True,
            exact_output=expected,
        )
    checks.append(
        Check(
            "binary_probe.journal_round_trip",
            "binary_probe",
            "passed" if healthy else "failed",
        )
    )
    return checks


def run_live_probe(
    binary: Path,
    source_root: Path,
    adapter: dict[str, object],
    config: Path,
    journal: Path,
    relying_party_id: str,
) -> Check:
    require_regular_file(config, RunnerErrorReason.INVALID_LIVE_INPUT)
    require_regular_file(journal, RunnerErrorReason.INVALID_LIVE_INPUT)
    if OPAQUE_ID.fullmatch(relying_party_id) is None:
        raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
    live = probe_contract(adapter)["live_ts5"]
    argument = live.get("argument")
    tokens = live.get("required_output_tokens")
    if not isinstance(argument, str) or not isinstance(tokens, list) or not all(isinstance(item, str) for item in tokens):
        raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    passed = execute_bounded_probe(
        [str(binary), argument, str(config), str(journal), relying_party_id],
        source_root,
        expected_success=True,
        required_tokens=tokens,
    )
    return Check("live_probe.ts5_public_reads", "live_probe", "passed" if passed else "failed")


def write_result(result_directory: Path, result: dict[str, object]) -> None:
    if result_directory.exists() or result_directory.is_symlink():
        raise RunnerError(RunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        result_directory.mkdir(mode=0o700, parents=True)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=result_directory,
            prefix=".eudi-result-",
            delete=False,
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, result_directory / "result.json")
    except OSError as error:
        raise RunnerError(RunnerErrorReason.RESULT_WRITE_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--candidate-source", required=True, type=Path)
    parser.add_argument("--platform-source", required=True, type=Path)
    parser.add_argument("--ssi-source", required=True, type=Path)
    parser.add_argument("--upstream-root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--trust-artifact", required=True, type=Path)
    parser.add_argument("--credential-authority-artifact", required=True, type=Path)
    parser.add_argument("--component-attestation", required=True, type=Path)
    parser.add_argument("--result-dir", required=True, type=Path)
    parser.add_argument("--trust-service-health-endpoint")
    parser.add_argument("--trust-service-token")
    parser.add_argument("--credential-authority-health-endpoint")
    parser.add_argument("--credential-authority-token")
    parser.add_argument("--service-ca-certificate", type=Path)
    parser.add_argument("--live-config", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--relying-party-id")
    args = parser.parse_args()
    try:
        deployment = adapter_verifier.load_object(args.deployment_manifest)
        components = validate_deployment_manifest(deployment)
        bundle = adapter_verifier.load_contract_bundle()
        expected_lock_digest = deployment["upstream_lock_sha256"]
        if hash_regular_file(adapter_verifier.UPSTREAM_LOCK_PATH) != expected_lock_digest:
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        expected_legal_lock_digest = deployment["legal_sources_lock_sha256"]
        if (
            hash_regular_file(adapter_verifier.LEGAL_SOURCES_LOCK_PATH)
            != expected_legal_lock_digest
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        expected_publications_lock_digest = deployment["publications_lock_sha256"]
        if (
            hash_regular_file(adapter_verifier.PUBLICATIONS_LOCK_PATH)
            != expected_publications_lock_digest
        ):
            raise RunnerError(RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        verify_component_layout(
            components, args.candidate_source, args.platform_source, args.ssi_source
        )
        adapter_verifier.verify_upstream_checkouts(bundle, args.upstream_root)
        require_regular_file(args.binary, RunnerErrorReason.INVALID_ARTIFACT)
        require_regular_file(args.trust_artifact, RunnerErrorReason.INVALID_ARTIFACT)
        require_regular_file(
            args.credential_authority_artifact,
            RunnerErrorReason.INVALID_ARTIFACT,
        )
        if not os.access(args.binary, os.X_OK):
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        binary = args.binary.resolve(strict=True)
        trust_artifact_path = args.trust_artifact.resolve(strict=True)
        credential_authority_artifact_path = (
            args.credential_authority_artifact.resolve(strict=True)
        )
        artifact = deployment["artifact"]
        if not isinstance(artifact, dict) or hash_regular_file(binary) != artifact.get("sha256"):
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        trust_artifact = deployment["trust_artifact"]
        if (
            not isinstance(trust_artifact, dict)
            or hash_regular_file(trust_artifact_path) != trust_artifact.get("sha256")
        ):
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        credential_authority_artifact = deployment["credential_authority_artifact"]
        if (
            not isinstance(credential_authority_artifact, dict)
            or hash_regular_file(credential_authority_artifact_path)
            != credential_authority_artifact.get("sha256")
        ):
            raise RunnerError(RunnerErrorReason.INVALID_ARTIFACT)
        required_checks, assertion_templates = required_attestation_checks(
            bundle.plan, bundle.adapter
        )
        attested_checks = verify_attestation(
            args.component_attestation,
            deployment["component_attestation_sha256"],
            components["candidate"],
            {
                "candidate_binary": artifact["sha256"],
                "trust_service": trust_artifact["sha256"],
                "credential_authority": credential_authority_artifact["sha256"],
                "eudi_sources_lock": expected_lock_digest,
                "eudi_legal_sources_lock": expected_legal_lock_digest,
            },
            required_checks,
        )
        checks = [Check(check_id, "attestation", "passed") for check_id in attested_checks]
        checks.extend(
            run_binary_probes(
                binary,
                args.candidate_source,
                args.upstream_root,
                bundle.adapter,
            )
        )
        mode = deployment["mode"]
        live_inputs = (args.live_config, args.journal, args.relying_party_id)
        service_inputs = (
            args.trust_service_health_endpoint,
            args.trust_service_token,
            args.credential_authority_health_endpoint,
            args.credential_authority_token,
            args.service_ca_certificate,
        )
        if mode in {"deployed", "live_ts5"}:
            if any(value is None for value in service_inputs):
                raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
            services = service_probe_contract(bundle.adapter)
            checks.extend(
                [
                    run_service_probe(
                        args.trust_service_health_endpoint,
                        args.trust_service_token,
                        args.service_ca_certificate,
                        services["trust_service"],
                    ),
                    run_service_probe(
                        args.credential_authority_health_endpoint,
                        args.credential_authority_token,
                        args.service_ca_certificate,
                        services["credential_authority"],
                    ),
                ]
            )
        elif any(value is not None for value in service_inputs):
            raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
        if mode == "live_ts5":
            if any(value is None for value in live_inputs):
                raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
            checks.append(
                run_live_probe(
                    binary,
                        args.candidate_source,
                    bundle.adapter,
                    args.live_config,
                    args.journal,
                    args.relying_party_id,
                )
            )
        elif any(value is not None for value in live_inputs):
            raise RunnerError(RunnerErrorReason.INVALID_LIVE_INPUT)
        check_results = {check.check_id: check.result for check in checks}
        assertions: list[dict[str, object]] = []
        for template in assertion_templates:
            check_ids = template["check_ids"]
            if not isinstance(check_ids, list):
                raise RunnerError(RunnerErrorReason.INVALID_EVIDENCE_PATH)
            assertions.append(
                {
                    **template,
                    "result": "passed"
                    if all(check_results.get(check_id) == "passed" for check_id in check_ids)
                    else "failed",
                }
            )
        passed = all(check.result == "passed" for check in checks) and all(
            assertion["result"] == "passed" for assertion in assertions
        )
        upstream_sources = [
            {
                "source_id": source_id,
                "repository": bundle.upstream_sources[source_id]["repository"],
                "ref": bundle.upstream_sources[source_id]["ref"],
                "commit": bundle.upstream_sources[source_id]["commit"],
            }
            for source_id in sorted(adapter_verifier.EXPECTED_EXECUTION_SOURCES)
        ]
        result = {
            "schema": "reallyme.identity.eudi_execution_result.v1",
            "plan_id": "eudi-relying-party-control-plane-v1",
            "mode": mode,
            "result": "passed" if passed else "failed",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "components": [components[key] for key in sorted(components)],
            "artifact_sha256": artifact["sha256"],
            "trust_artifact_sha256": trust_artifact["sha256"],
            "credential_authority_artifact_sha256": credential_authority_artifact[
                "sha256"
            ],
            "component_attestation_sha256": deployment[
                "component_attestation_sha256"
            ],
            "source_locks": {
                "eudi_sources_sha256": expected_lock_digest,
                "eudi_legal_sources_sha256": expected_legal_lock_digest,
                "eudi_publications_sha256": expected_publications_lock_digest,
            },
            "upstream_sources": upstream_sources,
            "checks": [check.__dict__ for check in sorted(checks, key=lambda item: item.check_id)],
            "assertions": sorted(assertions, key=lambda item: str(item["assertion_id"])),
            "evidence_policy": {
                "contains_sensitive_data": False,
                "raw_process_output_retained": False,
                "transaction_content_retained": False,
                "private_key_material_retained": False,
                "credentials_retained": False,
            },
        }
        write_result(args.result_dir, result)
    except adapter_verifier.AdapterError as error:
        adapter_verifier.fail(error.reason)
    except RunnerError as error:
        fail(error.reason)
    return 0 if passed else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
