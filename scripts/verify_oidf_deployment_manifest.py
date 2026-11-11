#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the immutable deployment BOM used for OIDF certification runs."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_component_lock as component_lock_validator  # noqa: E402
import strict_json  # noqa: E402
import verify_zk_adapter as zk_adapter_validator  # noqa: E402


MAX_MANIFEST_BYTES = 256 * 1024
EXIT_INVALID_INPUT = 65
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
SOURCE_REPOSITORY = re.compile(
    r"^https://github\.com/reallyme/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)
ROLE_ENDPOINTS = {
    "openid4vci_issuer": {"issuer_base_url"},
    "openid4vci_wallet": {
        "wallet_harness_endpoint",
        "wallet_harness_health_endpoint",
    },
    "openid4vp_verifier": {
        "verifier_base_url",
        "verifier_evidence_endpoint",
        "verifier_launch_endpoint",
        "verifier_health_endpoint",
    },
    "openid4vp_wallet": {
        "wallet_harness_endpoint",
        "wallet_harness_health_endpoint",
    },
}
ARTIFACT_KINDS = {"binary", "mobile_application", "oci_image", "web_bundle"}
ENVIRONMENTS = {"preproduction", "production"}


def fail(reason: str) -> NoReturn:
    print(f"error: {reason}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID_INPUT)


def load_manifest(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            fail("deployment manifest must be a regular file")
        if before.st_size < 1 or before.st_size > MAX_MANIFEST_BYTES:
            fail("deployment manifest has an invalid size")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            handle = os.fdopen(descriptor, "rb")
        except OSError:
            os.close(descriptor)
            raise
        with handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or not stat.S_ISREG(opened.st_mode)
            ):
                fail("deployment manifest changed while being read")
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(raw) != before.st_size or any(
            getattr(before, field) != getattr(after_open, field)
            or getattr(before, field) != getattr(after_path, field)
            for field in stable_fields
        ):
            fail("deployment manifest changed while being read")
        value = strict_json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("deployment manifest is unavailable or invalid JSON")
    if not isinstance(value, dict):
        fail("deployment manifest must contain an object")
    return value


def require_exact_keys(
    value: dict[str, object], expected: set[str], context: str
) -> None:
    if set(value) != expected:
        fail(f"{context} has an invalid field set")


def require_string(value: object, context: str, maximum_length: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_length
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        fail(f"{context} must be a bounded non-control string")
    return value


def require_object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    return value


def validate_public_https_endpoint(value: object, context: str) -> str:
    endpoint = require_string(value, context, 2048)
    if (
        not endpoint.isascii()
        or not endpoint.startswith("https://")
        or any(character.isspace() for character in endpoint)
        or "\\" in endpoint
    ):
        fail(f"{context} must be a valid public HTTPS endpoint")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        fail(f"{context} must be a valid public HTTPS endpoint")
    if (
        parsed.scheme != "https"
        or hostname is None
        or "@" in parsed.netloc
        or "%" in parsed.netloc
        or hostname.endswith(".")
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{context} must be a valid public HTTPS endpoint")
    normalized_host = hostname.lower()
    is_local_name = normalized_host in {"localhost", "host.docker.internal"}
    if is_local_name or normalized_host.endswith(".localhost"):
        fail(f"{context} must be a public HTTPS endpoint")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        fail(f"{context} must be a public HTTPS endpoint")
    if address is None:
        reserved_suffixes = (".example", ".invalid", ".local", ".test")
        if DNS_NAME.fullmatch(normalized_host) is None or normalized_host.endswith(
            reserved_suffixes
        ):
            fail(f"{context} must be a public HTTPS endpoint")
    return endpoint


def validate_source_repository(value: object, context: str) -> str:
    repository = validate_public_https_endpoint(value, context)
    if SOURCE_REPOSITORY.fullmatch(repository) is None:
        fail(f"{context} must identify a ReallyMe GitHub repository")
    return repository


def validate_manifest(value: dict[str, object]) -> dict[str, dict[str, str]]:
    require_exact_keys(
        value,
        {
            "schema_version",
            "purpose",
            "legal_entity",
            "product_name",
            "product_version",
            "environment",
            "roles",
            "capabilities",
        },
        "deployment manifest",
    )
    if value.get("schema_version") != 4:
        fail("deployment manifest has an unsupported schema version")
    if value.get("purpose") != "oidf-certification-deployment-bom":
        fail("deployment manifest has an invalid purpose")
    require_string(value.get("legal_entity"), "legal_entity")
    require_string(value.get("product_name"), "product_name")
    require_string(value.get("product_version"), "product_version")
    if value.get("environment") not in ENVIRONMENTS:
        fail("environment must be preproduction or production")

    capabilities = require_object(value.get("capabilities"), "capabilities")
    require_exact_keys(capabilities, {"zk_presentations"}, "capabilities")
    zk_presentations = require_object(
        capabilities.get("zk_presentations"), "capabilities.zk_presentations"
    )
    enabled = zk_presentations.get("enabled")
    if enabled is False:
        require_exact_keys(
            zk_presentations, {"enabled"}, "capabilities.zk_presentations"
        )
    elif enabled is True:
        require_exact_keys(
            zk_presentations,
            {
                "enabled",
                "plan_id",
                "source_repository",
                "source_commit",
                "release_artifact",
                "component_attestation_sha256",
            },
            "capabilities.zk_presentations",
        )
        _zk_plan, zk_adapter = zk_adapter_validator.load_contract()
        component = zk_adapter["component"]
        if (
            zk_presentations.get("plan_id") != "zk-presentation-proofs-v1"
            or not isinstance(component, dict)
            or zk_presentations.get("source_repository") != component.get("repository")
            or zk_presentations.get("source_commit") != component.get("commit")
        ):
            fail("enabled ZK capability does not match the selected ZK framework lane")
        release_artifact = require_object(
            zk_presentations.get("release_artifact"),
            "capabilities.zk_presentations.release_artifact",
        )
        require_exact_keys(
            release_artifact,
            {"artifact_id", "kind", "sha256"},
            "capabilities.zk_presentations.release_artifact",
        )
        if (
            release_artifact.get("artifact_id") != "zk-release-bundle"
            or release_artifact.get("kind") != "archive"
            or not isinstance(release_artifact.get("sha256"), str)
            or SHA256.fullmatch(release_artifact["sha256"]) is None
            or not isinstance(zk_presentations.get("component_attestation_sha256"), str)
            or SHA256.fullmatch(zk_presentations["component_attestation_sha256"])
            is None
        ):
            fail("enabled ZK capability has invalid artifact evidence")
    else:
        fail("capabilities.zk_presentations.enabled must be Boolean")

    roles = require_object(value.get("roles"), "roles")
    if set(roles) != set(ROLE_ENDPOINTS):
        fail("roles must contain the complete four-role certification scope")
    resolved_endpoints: dict[str, dict[str, str]] = {}
    for role, required_endpoints in ROLE_ENDPOINTS.items():
        deployment = require_object(roles.get(role), role)
        require_exact_keys(
            deployment,
            {"source_repository", "source_commit", "artifact", "endpoints"},
            role,
        )
        validate_source_repository(
            deployment.get("source_repository"), f"{role}.source_repository"
        )
        source_commit = require_string(
            deployment.get("source_commit"), f"{role}.source_commit"
        )
        if GIT_COMMIT.fullmatch(source_commit) is None:
            fail(f"{role}.source_commit must be a full lowercase Git commit")

        artifact = require_object(deployment.get("artifact"), f"{role}.artifact")
        require_exact_keys(
            artifact, {"kind", "identifier", "sha256"}, f"{role}.artifact"
        )
        if artifact.get("kind") not in ARTIFACT_KINDS:
            fail(f"{role}.artifact.kind is unsupported")
        require_string(artifact.get("identifier"), f"{role}.artifact.identifier", 512)
        artifact_digest = require_string(
            artifact.get("sha256"), f"{role}.artifact.sha256", 64
        )
        if SHA256.fullmatch(artifact_digest) is None:
            fail(f"{role}.artifact.sha256 must be a lowercase SHA-256 digest")

        endpoints = require_object(deployment.get("endpoints"), f"{role}.endpoints")
        if set(endpoints) != required_endpoints:
            fail(f"{role}.endpoints has an invalid field set")
        resolved_endpoints[role] = {
            endpoint_name: validate_public_https_endpoint(
                endpoints.get(endpoint_name), f"{role}.endpoints.{endpoint_name}"
            )
            for endpoint_name in sorted(required_endpoints)
        }
    return resolved_endpoints


def verify_component_bindings(
    manifest: dict[str, object], component_lock: dict[str, object]
) -> None:
    """Require every deployed role to name its exact locked source revision."""
    component_lock_validator.verify_lock(component_lock)
    repositories = component_lock.get("repositories")
    if not isinstance(repositories, list):
        fail("component lock repository inventory is invalid")

    approved: dict[str, tuple[str, frozenset[str]]] = {}
    for item in repositories:
        if not isinstance(item, dict):
            fail("component lock repository inventory is invalid")
        repository = item.get("repository")
        commit = item.get("commit")
        roles = item.get("roles")
        if (
            not isinstance(repository, str)
            or not isinstance(commit, str)
            or not isinstance(roles, list)
            or any(not isinstance(role, str) for role in roles)
        ):
            fail("component lock repository inventory is invalid")
        approved[repository] = (commit, frozenset(roles))

    roles = require_object(manifest.get("roles"), "roles")
    for role, raw_deployment in roles.items():
        deployment = require_object(raw_deployment, role)
        repository = deployment.get("source_repository")
        commit = deployment.get("source_commit")
        if not isinstance(repository, str) or not isinstance(commit, str):
            fail(f"{role} source binding is invalid")
        locked = approved.get(repository)
        if locked is None or locked[0] != commit or role not in locked[1]:
            fail(f"{role} source binding does not match the component lock")


def verify_bindings(
    endpoints: dict[str, dict[str, str]], bindings: list[tuple[str, str]]
) -> None:
    observed: set[str] = set()
    for name, endpoint in bindings:
        if name in observed:
            fail("deployment endpoint binding is repeated")
        observed.add(name)
        try:
            role, endpoint_name = name.split(".", 1)
            expected = endpoints[role][endpoint_name]
        except (KeyError, ValueError):
            fail("deployment endpoint binding is unknown")
        if validate_public_https_endpoint(endpoint, name) != expected:
            fail(f"{name} does not match the deployment manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--component-lock", required=True, type=Path)
    parser.add_argument(
        "--binding",
        action="append",
        nargs=2,
        default=[],
        metavar=("ROLE.ENDPOINT", "URL"),
        help="require an environment endpoint to equal the manifest value",
    )
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    endpoints = validate_manifest(manifest)
    component_lock = component_lock_validator.load_lock(args.component_lock)
    verify_component_bindings(manifest, component_lock)
    verify_bindings(endpoints, args.binding)
    print("deployment manifest covers four immutable OIDF role deployments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
