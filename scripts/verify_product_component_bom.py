#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a caller-owned ReallyMe product component bill of materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple, NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


MAX_BOM_BYTES = 64 * 1024
EXIT_INVALID_INPUT = 65
EXIT_CONFIGURATION = 78
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
PRODUCT_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$")
RELEASE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ComponentPolicy(NamedTuple):
    repository: str
    checkout: str
    release_prefix: str
    roles: frozenset[str]


class Component(NamedTuple):
    component_id: str
    repository: str
    checkout: str
    commit: str
    release_ref: str | None
    release_artifact_sha256: str
    component_attestation_sha256: str
    roles: frozenset[str]


COMPONENTS = {
    "openid4vci": ComponentPolicy(
        "https://github.com/reallyme/openid4vci",
        "../openid4vci",
        "reallyme-openid4vci-v",
        frozenset({"openid4vci_issuer", "openid4vci_wallet"}),
    ),
    "openid4vp": ComponentPolicy(
        "https://github.com/reallyme/openid4vp",
        "../openid4vp",
        "reallyme-openid4vp-v",
        frozenset({"openid4vp_verifier", "openid4vp_wallet"}),
    ),
    "wallet": ComponentPolicy(
        "https://github.com/reallyme/wallet",
        "../wallet",
        "reallyme-wallet-v",
        frozenset({"openid4vci_wallet", "openid4vp_wallet"}),
    ),
    "ssi": ComponentPolicy(
        "https://github.com/reallyme/ssi",
        "../ssi",
        "reallyme-ssi-v",
        frozenset(
            {
                "openid4vci_issuer",
                "openid4vci_wallet",
                "openid4vp_verifier",
                "openid4vp_wallet",
            }
        ),
    ),
    "identity": ComponentPolicy(
        "https://github.com/reallyme/identity",
        "../identity",
        "reallyme-identity-v",
        frozenset(
            {"openid4vci_wallet", "openid4vp_verifier", "openid4vp_wallet"}
        ),
    ),
    "cose": ComponentPolicy(
        "https://github.com/reallyme/cose",
        "../cose",
        "reallyme-cose-v",
        frozenset(
            {
                "openid4vci_issuer",
                "openid4vci_wallet",
                "openid4vp_verifier",
                "openid4vp_wallet",
            }
        ),
    ),
}


def fail(message: str, exit_code: int = EXIT_INVALID_INPUT) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def load_bom(path: Path) -> dict[str, object]:
    """Read a stable regular file without following symbolic links."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
            fail("product component BOM must be a non-empty regular file")
        if before.st_size > MAX_BOM_BYTES:
            fail("product component BOM exceeds the accepted size")
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
                fail("product component BOM changed while being opened")
            raw = handle.read(MAX_BOM_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(
            getattr(before, field) != getattr(after_open, field)
            or getattr(before, field) != getattr(after_path, field)
            for field in stable_fields
        ):
            fail("product component BOM changed while being read")
        value = strict_json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("product component BOM is unavailable or invalid JSON")
    if not isinstance(value, dict):
        fail("product component BOM must contain an object")
    return value


def required_string(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        fail(f"{context} must be a bounded non-control string")
    return value


def validate_bom(
    value: dict[str, object], *, require_release_refs: bool = False
) -> dict[str, Component]:
    allowed_top_level_fields = {
        "schema_version",
        "purpose",
        "product_id",
        "product_version",
        "product_release_ref",
        "components",
    }
    required_top_level_fields = allowed_top_level_fields.difference(
        {"product_release_ref"}
    )
    if (
        not required_top_level_fields.issubset(value)
        or not set(value).issubset(allowed_top_level_fields)
    ):
        fail("product component BOM has an invalid field set")
    if value.get("schema_version") != 1:
        fail("product component BOM has an unsupported schema version")
    if value.get("purpose") != "reallyme-product-conformance-bom":
        fail("product component BOM has an invalid purpose")
    if value.get("product_id") != "identity":
        fail("product component BOM must identify the Identity product")
    product_version = required_string(value.get("product_version"), "product_version")
    if PRODUCT_VERSION.fullmatch(product_version) is None:
        fail("product_version is invalid")
    raw_product_release_ref = value.get("product_release_ref")
    product_release_ref: str | None = None
    if raw_product_release_ref is not None:
        product_release_ref = required_string(
            raw_product_release_ref, "product_release_ref"
        )
        if product_release_ref != f"reallyme-identity-v{product_version}":
            fail("product_release_ref does not match product_version")
    elif require_release_refs:
        fail("product_release_ref is required for a release BOM")
    raw_components = value.get("components")
    if not isinstance(raw_components, list) or len(raw_components) != len(COMPONENTS):
        fail("product component BOM must contain the complete component set")

    observed: dict[str, Component] = {}
    for raw_component in raw_components:
        if not isinstance(raw_component, dict):
            fail("product component BOM entry must be an object")
        allowed_fields = {
            "component_id",
            "repository",
            "commit",
            "release_ref",
            "release_artifact_sha256",
            "component_attestation_sha256",
            "roles",
        }
        required_fields = allowed_fields.difference({"release_ref"})
        if not required_fields.issubset(raw_component) or not set(raw_component).issubset(
            allowed_fields
        ):
            fail("product component BOM entry has an invalid field set")
        component_id = required_string(raw_component.get("component_id"), "component_id")
        if component_id in observed:
            fail("product component BOM repeats a component")
        policy = COMPONENTS.get(component_id)
        if policy is None:
            fail("product component BOM contains an unknown component")
        repository = required_string(
            raw_component.get("repository"), f"{component_id}.repository"
        )
        commit = required_string(raw_component.get("commit"), f"{component_id}.commit")
        if repository != policy.repository:
            fail(f"{component_id} repository identity is invalid")
        if GIT_COMMIT.fullmatch(commit) is None:
            fail(f"{component_id} commit must be a full lowercase Git commit")
        release_artifact_sha256 = required_string(
            raw_component.get("release_artifact_sha256"),
            f"{component_id}.release_artifact_sha256",
        )
        component_attestation_sha256 = required_string(
            raw_component.get("component_attestation_sha256"),
            f"{component_id}.component_attestation_sha256",
        )
        if (
            re.fullmatch(r"[0-9a-f]{64}", release_artifact_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", component_attestation_sha256) is None
        ):
            fail(f"{component_id} evidence digest is invalid")
        raw_release_ref = raw_component.get("release_ref")
        release_ref: str | None = None
        if raw_release_ref is not None:
            release_ref = required_string(raw_release_ref, f"{component_id}.release_ref")
            if (
                RELEASE_REF.fullmatch(release_ref) is None
                or not release_ref.startswith(policy.release_prefix)
            ):
                fail(f"{component_id} release reference is invalid")
        elif require_release_refs:
            fail(f"{component_id} requires an immutable release reference")
        raw_roles = raw_component.get("roles")
        if (
            not isinstance(raw_roles, list)
            or any(not isinstance(role, str) for role in raw_roles)
            or len(raw_roles) != len(set(raw_roles))
            or frozenset(raw_roles) != policy.roles
        ):
            fail(f"{component_id} role coverage is invalid")
        observed[component_id] = Component(
            component_id,
            repository,
            policy.checkout,
            commit,
            release_ref,
            release_artifact_sha256,
            component_attestation_sha256,
            policy.roles,
        )
    if set(observed) != set(COMPONENTS):
        fail("product component BOM does not cover the approved component set")
    identity = observed.get("identity")
    if (
        require_release_refs
        and (
            identity is None
            or identity.release_ref is None
            or identity.release_ref != product_release_ref
        )
    ):
        fail("Identity component release does not match the product release")
    return observed


def canonical_digest(value: dict[str, object]) -> str:
    """Return the digest of the validated, order-independent BOM encoding."""
    components = validate_bom(value)
    normalized: dict[str, object] = {
        "schema_version": value["schema_version"],
        "purpose": value["purpose"],
        "product_id": value["product_id"],
        "product_version": value["product_version"],
        "components": [
            {
                "component_id": component.component_id,
                "repository": component.repository,
                "commit": component.commit,
                **(
                    {"release_ref": component.release_ref}
                    if component.release_ref is not None
                    else {}
                ),
                "release_artifact_sha256": component.release_artifact_sha256,
                "component_attestation_sha256": (
                    component.component_attestation_sha256
                ),
                "roles": sorted(component.roles),
            }
            for component in sorted(components.values(), key=lambda item: item.component_id)
        ],
    }
    if "product_release_ref" in value:
        normalized["product_release_ref"] = value["product_release_ref"]
    encoded = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def git_output(checkout: Path, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        fail("unable to inspect a product component checkout", EXIT_CONFIGURATION)
    if result.returncode != 0:
        fail("unable to inspect a product component checkout", EXIT_CONFIGURATION)
    return result.stdout.strip()


def verify_checkouts(repository_root: Path, components: dict[str, Component]) -> None:
    for component in components.values():
        checkout = (repository_root / component.checkout).resolve()
        if not (checkout / ".git").exists():
            fail(
                f"{component.component_id} checkout is unavailable",
                EXIT_CONFIGURATION,
            )
        if git_output(checkout, ["rev-parse", "HEAD"]) != component.commit:
            fail(
                f"{component.component_id} checkout is not at the candidate commit",
                EXIT_CONFIGURATION,
            )
        if (
            component.release_ref is not None
            and git_output(checkout, ["rev-list", "-n", "1", component.release_ref])
            != component.commit
        ):
            fail(
                f"{component.component_id} release reference does not select "
                "the candidate commit",
                EXIT_CONFIGURATION,
            )


def verify_plan_requirements(path: Path, components: dict[str, Component]) -> None:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_BOM_BYTES:
            fail("conformance plan must be a bounded regular file")
        plan = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("conformance plan is unavailable or invalid JSON")
    if not isinstance(plan, dict) or not isinstance(plan.get("required_components"), list):
        fail("conformance plan does not declare required components")
    required: dict[str, str] = {}
    for raw_requirement in plan["required_components"]:
        if (
            not isinstance(raw_requirement, dict)
            or set(raw_requirement) != {"component_id", "repository"}
        ):
            fail("conformance plan has an invalid component requirement")
        component_id = required_string(
            raw_requirement.get("component_id"), "required component identifier"
        )
        repository = required_string(
            raw_requirement.get("repository"), "required component repository"
        )
        if component_id in required:
            fail("conformance plan repeats a required component")
        required[component_id] = repository
    if set(required) != set(components) or any(
        components[component_id].repository != repository
        for component_id, repository in required.items()
    ):
        fail("product component BOM does not satisfy the conformance plan")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bom", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument(
        "--require-release-refs",
        action="store_true",
        help="require an immutable release reference for every component",
    )
    parser.add_argument(
        "--verify-checkouts",
        action="store_true",
        help="require every sibling checkout to be at the candidate commit",
    )
    args = parser.parse_args()
    components = validate_bom(
        load_bom(args.bom), require_release_refs=args.require_release_refs
    )
    if args.verify_checkouts:
        verify_checkouts(SCRIPT_DIRECTORY.parent, components)
    if args.plan is not None:
        verify_plan_requirements(args.plan, components)
    print("caller product BOM covers six repositories and four OIDF roles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
