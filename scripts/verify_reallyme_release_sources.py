#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate ReallyMe repositories that callers may select at run time."""

from __future__ import annotations

import re
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INVENTORY = REPOSITORY_ROOT / "references/reallyme/release-sources.json"
MAX_BYTES = 64 * 1024
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
RELEASE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EXPECTED_COMPONENTS = {
    "ssi",
    "identity",
    "zk",
    "wallet",
    "openid4vci",
    "openid4vp",
}


class ReleaseSourceError(Exception):
    """Raised when the release-source inventory is not closed and canonical."""


def load_inventory(path: Path = INVENTORY) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_BYTES:
            raise ReleaseSourceError("release source inventory is unavailable")
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise ReleaseSourceError("release source inventory is invalid") from error
    if not isinstance(value, dict):
        raise ReleaseSourceError("release source inventory is invalid")
    return value


def verify_inventory(value: dict[str, object]) -> None:
    if (
        set(value) != {"$comment", "schema", "purpose", "sources"}
        or value.get("schema") != "reallyme.identity.runtime_target_inventory.v1"
        or value.get("purpose") != "runtime-target-discovery-only"
        or not isinstance(value.get("$comment"), str)
        or not isinstance(value.get("sources"), list)
    ):
        raise ReleaseSourceError("release source inventory has an invalid shape")
    observed: set[str] = set()
    for source in value["sources"]:
        if not isinstance(source, dict) or set(source) != {
            "component_id",
            "repository",
            "release_prefix",
            "update_strategy",
        }:
            raise ReleaseSourceError("release source entry has an invalid shape")
        component_id = source["component_id"]
        if (
            not isinstance(component_id, str)
            or IDENTIFIER.fullmatch(component_id) is None
            or component_id in observed
            or source["repository"] != f"https://github.com/reallyme/{component_id}"
            or not isinstance(source["release_prefix"], str)
            or RELEASE_PREFIX.fullmatch(source["release_prefix"]) is None
            or not source["release_prefix"].startswith(f"reallyme-{component_id}-v")
            or source["update_strategy"] != "observe_latest_release"
        ):
            raise ReleaseSourceError("release source entry is invalid")
        observed.add(component_id)
    if observed != EXPECTED_COMPONENTS:
        raise ReleaseSourceError("release source inventory is incomplete")


def main() -> int:
    try:
        verify_inventory(load_inventory())
    except ReleaseSourceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 65
    print("ReallyMe runtime target discovery inventory valid (6 repositories)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
