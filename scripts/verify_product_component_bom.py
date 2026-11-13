#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a caller-owned product bill of materials without pinning its inventory."""

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


MAX_BOM_BYTES = 256 * 1024
MAX_COMPONENTS = 64
EXIT_INVALID_INPUT = 65
EXIT_CONFIGURATION = 78
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PRODUCT_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$")
RELEASE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPOSITORY = re.compile(
    r"^https://github\.com/reallyme/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,99}))$"
)
PRODUCT_REPOSITORY = "https://github.com/reallyme/identity"
PRODUCT_RELEASE_PREFIX = "reallyme-identity-v"
OIDF_ROLES = frozenset(
    {
        "openid4vci_issuer",
        "openid4vci_wallet",
        "openid4vp_verifier",
        "openid4vp_wallet",
    }
)
ADAPTER_CONTRACTS = frozenset({"openid4vci", "openid4vp", "zk"})


class Component(NamedTuple):
    component_id: str
    repository: str
    repository_slug: str
    commit: str
    release_id: int | None
    release_ref: str | None
    roles: frozenset[str]
    adapter_contracts: frozenset[str]


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


def required_string(value: object, context: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) <= 31 or ord(character) == 127 for character in value)
    ):
        fail(f"{context} must be a bounded non-control string")
    return value


def string_set(
    value: object, allowed: frozenset[str], context: str, maximum: int
) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
        or not set(value).issubset(allowed)
    ):
        fail(f"{context} is invalid")
    return frozenset(value)


def validate_bom(
    value: dict[str, object], *, require_release_refs: bool = False
) -> dict[str, Component]:
    allowed_top_level = {
        "schema_version",
        "purpose",
        "product_id",
        "product_version",
        "product_component_id",
        "product_release_id",
        "product_release_ref",
        "components",
    }
    required_top_level = allowed_top_level.difference(
        {"product_release_id", "product_release_ref"}
    )
    if not required_top_level.issubset(value) or not set(value).issubset(
        allowed_top_level
    ):
        fail("product component BOM has an invalid field set")
    if value.get("schema_version") != 3:
        fail("product component BOM has an unsupported schema version")
    if value.get("purpose") != "reallyme-product-conformance-bom":
        fail("product component BOM has an invalid purpose")
    if value.get("product_id") != "identity":
        fail("product component BOM must identify the Identity product")
    product_version = required_string(value.get("product_version"), "product_version")
    if PRODUCT_VERSION.fullmatch(product_version) is None:
        fail("product_version is invalid")
    product_component_id = required_string(
        value.get("product_component_id"), "product_component_id", 64
    )
    if COMPONENT_ID.fullmatch(product_component_id) is None:
        fail("product_component_id is invalid")
    raw_product_release_ref = value.get("product_release_ref")
    raw_product_release_id = value.get("product_release_id")
    product_release_id: int | None = None
    product_release_ref: str | None = None
    if raw_product_release_id is not None:
        if (
            not isinstance(raw_product_release_id, int)
            or isinstance(raw_product_release_id, bool)
            or not 1 <= raw_product_release_id <= 9_223_372_036_854_775_807
        ):
            fail("product_release_id is invalid")
        product_release_id = raw_product_release_id
    if raw_product_release_ref is not None:
        product_release_ref = required_string(
            raw_product_release_ref, "product_release_ref", 128
        )
        if product_release_ref != f"{PRODUCT_RELEASE_PREFIX}{product_version}":
            fail("product_release_ref does not match product_version")
    elif require_release_refs:
        fail("product_release_ref is required for a release BOM")
    if (product_release_id is None) != (product_release_ref is None):
        fail("product release ID and reference must be supplied together")
    if require_release_refs and product_release_id is None:
        fail("product_release_id is required for a release BOM")

    raw_components = value.get("components")
    if (
        not isinstance(raw_components, list)
        or not raw_components
        or len(raw_components) > MAX_COMPONENTS
    ):
        fail("product component BOM has an invalid component count")

    observed: dict[str, Component] = {}
    observed_repositories: set[str] = set()
    for raw_component in raw_components:
        if not isinstance(raw_component, dict):
            fail("product component BOM entry must be an object")
        allowed_fields = {
            "component_id",
            "repository",
            "commit",
            "release_id",
            "release_ref",
            "roles",
            "adapter_contracts",
        }
        required_fields = allowed_fields.difference({"release_id", "release_ref"})
        if not required_fields.issubset(raw_component) or not set(
            raw_component
        ).issubset(allowed_fields):
            fail("product component BOM entry has an invalid field set")
        component_id = required_string(
            raw_component.get("component_id"), "component_id", 64
        )
        if COMPONENT_ID.fullmatch(component_id) is None:
            fail("component_id is invalid")
        if component_id in observed:
            fail("product component BOM repeats a component identifier")
        repository = required_string(
            raw_component.get("repository"), f"{component_id}.repository"
        )
        repository_match = REPOSITORY.fullmatch(repository)
        if repository_match is None:
            fail(f"{component_id} repository identity is invalid")
        if repository in observed_repositories:
            fail("product component BOM repeats a repository identity")
        commit = required_string(raw_component.get("commit"), f"{component_id}.commit")
        if GIT_COMMIT.fullmatch(commit) is None:
            fail(f"{component_id} commit must be a full lowercase Git commit")
        raw_release_id = raw_component.get("release_id")
        release_id: int | None = None
        if raw_release_id is not None:
            if (
                not isinstance(raw_release_id, int)
                or isinstance(raw_release_id, bool)
                or not 1 <= raw_release_id <= 9_223_372_036_854_775_807
            ):
                fail(f"{component_id} release ID is invalid")
            release_id = raw_release_id
        raw_release_ref = raw_component.get("release_ref")
        release_ref: str | None = None
        if raw_release_ref is not None:
            release_ref = required_string(
                raw_release_ref, f"{component_id}.release_ref", 128
            )
            if RELEASE_REF.fullmatch(release_ref) is None:
                fail(f"{component_id} release reference is invalid")
        elif require_release_refs:
            fail(f"{component_id} requires an immutable release reference")
        if (release_id is None) != (release_ref is None):
            fail(f"{component_id} release ID and reference must be supplied together")
        if require_release_refs and release_id is None:
            fail(f"{component_id} requires an immutable release ID")
        roles = string_set(
            raw_component.get("roles"), OIDF_ROLES, f"{component_id}.roles", 4
        )
        adapter_contracts = string_set(
            raw_component.get("adapter_contracts"),
            ADAPTER_CONTRACTS,
            f"{component_id}.adapter_contracts",
            3,
        )
        observed[component_id] = Component(
            component_id=component_id,
            repository=repository,
            repository_slug=repository_match.group(1),
            commit=commit,
            release_id=release_id,
            release_ref=release_ref,
            roles=roles,
            adapter_contracts=adapter_contracts,
        )
        observed_repositories.add(repository)

    product_component = observed.get(product_component_id)
    if product_component is None or product_component.repository != PRODUCT_REPOSITORY:
        fail("product_component_id must select the Identity product repository")
    if (
        require_release_refs
        and (
            product_component.release_id != product_release_id
            or product_component.release_ref != product_release_ref
        )
    ):
        fail("Identity product release does not match product_release_ref")
    return observed


def canonical_digest(value: dict[str, object]) -> str:
    """Return the digest of the validated, order-independent BOM encoding."""
    components = validate_bom(value)
    normalized: dict[str, object] = {
        "schema_version": value["schema_version"],
        "purpose": value["purpose"],
        "product_id": value["product_id"],
        "product_version": value["product_version"],
        "product_component_id": value["product_component_id"],
        "components": [
            {
                "component_id": component.component_id,
                "repository": component.repository,
                "commit": component.commit,
                **(
                    {"release_id": component.release_id}
                    if component.release_id is not None
                    else {}
                ),
                **(
                    {"release_ref": component.release_ref}
                    if component.release_ref is not None
                    else {}
                ),
                "roles": sorted(component.roles),
                "adapter_contracts": sorted(component.adapter_contracts),
            }
            for component in sorted(
                components.values(), key=lambda item: item.component_id
            )
        ],
    }
    if "product_release_id" in value:
        normalized["product_release_id"] = value["product_release_id"]
    if "product_release_ref" in value:
        normalized["product_release_ref"] = value["product_release_ref"]
    encoded = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def git_output(checkout: Path, arguments: list[str]) -> str:
    environment = os.environ.copy()
    for variable in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"):
        environment.pop(variable, None)
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        fail("unable to inspect a product component checkout", EXIT_CONFIGURATION)
    if result.returncode != 0:
        fail("unable to inspect a product component checkout", EXIT_CONFIGURATION)
    return result.stdout.strip()


def verify_checkouts(
    components: dict[str, Component], checkouts: dict[str, Path]
) -> None:
    if not checkouts or not set(checkouts).issubset(components):
        fail("checkout selection is invalid", EXIT_CONFIGURATION)
    for component_id, checkout in checkouts.items():
        component = components[component_id]
        if not (checkout / ".git").exists() or checkout.is_symlink():
            fail(f"{component_id} checkout is unavailable", EXIT_CONFIGURATION)
        if git_output(checkout, ["rev-parse", "HEAD"]) != component.commit:
            fail(
                f"{component_id} checkout is not at the candidate commit",
                EXIT_CONFIGURATION,
            )
        if git_output(checkout, ["status", "--porcelain", "--untracked-files=normal"]):
            fail(f"{component_id} checkout is not clean", EXIT_CONFIGURATION)
        if (
            component.release_ref is not None
            and git_output(checkout, ["rev-list", "-n", "1", component.release_ref])
            != component.commit
        ):
            fail(
                f"{component_id} release reference does not select the candidate commit",
                EXIT_CONFIGURATION,
            )


def require_plan_string_set(
    plan: dict[str, object], field: str, allowed: frozenset[str]
) -> frozenset[str]:
    value = plan.get(field)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
        or not set(value).issubset(allowed)
    ):
        fail(f"conformance plan has an invalid {field} contract")
    return frozenset(value)


def verify_plan_requirements(path: Path, components: dict[str, Component]) -> None:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_BOM_BYTES:
            fail("conformance plan must be a bounded regular file")
        plan = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail("conformance plan is unavailable or invalid JSON")
    if not isinstance(plan, dict):
        fail("conformance plan must contain an object")
    required_roles = require_plan_string_set(plan, "required_roles", OIDF_ROLES)
    required_adapters = require_plan_string_set(
        plan, "required_adapter_contracts", ADAPTER_CONTRACTS
    )
    supplied_roles = frozenset().union(
        *(component.roles for component in components.values())
    )
    if not required_roles.issubset(supplied_roles):
        fail("product component BOM does not cover every required product role")
    for adapter in required_adapters:
        providers = [
            component
            for component in components.values()
            if adapter in component.adapter_contracts
        ]
        if len(providers) != 1:
            fail("product component BOM must select one provider per adapter contract")


def parse_checkouts(values: list[str]) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for value in values:
        component_id, separator, raw_path = value.partition("=")
        if (
            not separator
            or COMPONENT_ID.fullmatch(component_id) is None
            or not raw_path
            or component_id in parsed
        ):
            fail("checkout selection is invalid", EXIT_CONFIGURATION)
        parsed[component_id] = Path(raw_path).resolve()
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bom", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument(
        "--require-release-refs",
        action="store_true",
        help=(
            "require an immutable release database ID and reference for every "
            "supplied component"
        ),
    )
    parser.add_argument(
        "--checkout",
        action="append",
        default=[],
        metavar="COMPONENT_ID=PATH",
        help="verify one caller-selected checkout; may be repeated",
    )
    args = parser.parse_args()
    components = validate_bom(
        load_bom(args.bom), require_release_refs=args.require_release_refs
    )
    if args.checkout:
        verify_checkouts(components, parse_checkouts(args.checkout))
    if args.plan is not None:
        verify_plan_requirements(args.plan, components)
    print(
        f"caller product BOM covers {len(components)} components under stable role and adapter contracts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
