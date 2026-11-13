#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the caller-selected Identity candidate BOM for the EU SDK lane."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_product_component_bom as product_bom  # noqa: E402


IDENTITY_REPOSITORY = "https://github.com/reallyme/identity"
DEPENDENCY_REPOSITORIES = {
    "ssi": "https://github.com/reallyme/ssi",
    "openid4vci": "https://github.com/reallyme/openid4vci",
    "openid4vp": "https://github.com/reallyme/openid4vp",
}
STABLE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
DEPENDENCY_RELEASE_REF = re.compile(
    r"^reallyme-(ssi|openid4vci|openid4vp)-v"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


class CandidateBomErrorReason(Enum):
    TARGET_INVALID = "target_invalid"
    PRODUCT_BINDING_INVALID = "product_binding_invalid"
    DEPENDENCY_BINDING_INVALID = "dependency_binding_invalid"
    OUTPUT_INVALID = "output_invalid"


@dataclass(frozen=True)
class CandidateBomError(Exception):
    reason: CandidateBomErrorReason


def fail(reason: CandidateBomErrorReason) -> NoReturn:
    raise CandidateBomError(reason)


def component_record(component: product_bom.Component) -> dict[str, object]:
    value: dict[str, object] = {
        "component_id": component.component_id,
        "repository": component.repository,
        "commit": component.commit,
    }
    if component.release_id is not None:
        value["release_id"] = component.release_id
    if component.release_ref is not None:
        value["release_ref"] = component.release_ref
    return value


def select_candidate(
    value: dict[str, object],
    *,
    target_mode: str,
    target_commit: str,
    target_version: str,
    target_release_id: int | None,
    target_release_ref: str,
) -> dict[str, object]:
    if (
        target_mode not in {"candidate", "published"}
        or product_bom.GIT_COMMIT.fullmatch(target_commit) is None
        or STABLE_VERSION.fullmatch(target_version) is None
    ):
        fail(CandidateBomErrorReason.TARGET_INVALID)
    if target_mode == "candidate" and (
        target_release_id is not None or target_release_ref
    ):
        fail(CandidateBomErrorReason.TARGET_INVALID)
    expected_product_release_ref = f"reallyme-identity-v{target_version}"
    if (
        target_mode == "published"
        and (
            target_release_id is None
            or not 1 <= target_release_id <= 9_223_372_036_854_775_807
            or target_release_ref != expected_product_release_ref
        )
    ):
        fail(CandidateBomErrorReason.TARGET_INVALID)

    try:
        components = product_bom.validate_bom(value)
    except SystemExit:
        fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)
    expected_component_ids = {"identity", *DEPENDENCY_REPOSITORIES}
    if set(components) != expected_component_ids:
        fail(CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID)
    if value.get("product_version") != target_version:
        fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)
    product_component_id = value.get("product_component_id")
    if not isinstance(product_component_id, str):
        fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)
    identity = components.get(product_component_id)
    if (
        identity is None
        or identity.component_id != "identity"
        or identity.repository != IDENTITY_REPOSITORY
        or identity.commit != target_commit
    ):
        fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)
    if target_mode == "candidate":
        if (
            "product_release_id" in value
            or "product_release_ref" in value
            or identity.release_id is not None
            or identity.release_ref is not None
        ):
            fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)
    elif (
        value.get("product_release_id") != target_release_id
        or value.get("product_release_ref") != target_release_ref
        or identity.release_id != target_release_id
        or identity.release_ref != target_release_ref
    ):
        fail(CandidateBomErrorReason.PRODUCT_BINDING_INVALID)

    dependencies: list[dict[str, object]] = []
    for component_id, repository in DEPENDENCY_REPOSITORIES.items():
        component = components.get(component_id)
        if component is None or component.repository != repository:
            fail(CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID)
        release_ref = component.release_ref
        if component.release_id is None or not isinstance(release_ref, str):
            fail(CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID)
        match = DEPENDENCY_RELEASE_REF.fullmatch(release_ref)
        if match is None or match.group(1) != component_id:
            fail(CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID)
        dependencies.append(component_record(component))

    return {
        "schema": "reallyme.identity.eudi_identity_candidate_selection.v1",
        "product_component_bom_sha256": product_bom.canonical_digest(value),
        "component_count": len(expected_component_ids),
        "product": component_record(identity),
        "dependencies": sorted(
            dependencies, key=lambda component: str(component["component_id"])
        ),
    }


def write_output(path: Path, value: dict[str, object]) -> None:
    try:
        if path.exists() or path.is_symlink():
            fail(CandidateBomErrorReason.OUTPUT_INVALID)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_path, path, follow_symlinks=False)
        finally:
            temporary_path.unlink(missing_ok=True)
    except CandidateBomError:
        raise
    except OSError:
        fail(CandidateBomErrorReason.OUTPUT_INVALID)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bom", required=True, type=Path)
    parser.add_argument("--target-mode", required=True)
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--target-release-id", type=int)
    parser.add_argument("--target-release-ref", default="")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        selection = select_candidate(
            product_bom.load_bom(arguments.bom),
            target_mode=arguments.target_mode,
            target_commit=arguments.target_commit,
            target_version=arguments.target_version,
            target_release_id=arguments.target_release_id,
            target_release_ref=arguments.target_release_ref,
        )
        write_output(arguments.output, selection)
    except (CandidateBomError, SystemExit) as error:
        reason = (
            error.reason.value
            if isinstance(error, CandidateBomError)
            else CandidateBomErrorReason.PRODUCT_BINDING_INVALID.value
        )
        print(f"error: Identity candidate BOM is invalid ({reason})", file=sys.stderr)
        return 65
    print("Identity candidate BOM is bound to the caller-selected product")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
