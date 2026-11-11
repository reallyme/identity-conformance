#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify a pinned OIDF plan parameter contract against suite source.

This check reads source only. It deliberately does not build or execute the
third-party conformance suite. Full certification still requires running every
claimed profile through an OIDF-hosted or locally deployed suite instance.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


MAX_MANIFEST_BYTES = 1_000_000
MAX_SOURCE_BYTES = 2_000_000
EXIT_INVALID_INPUT = 65
EXIT_NOT_FOUND = 66
EXIT_CONFIGURATION = 78
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SUITE_LOCK_PATH = REPOSITORY_ROOT / "upstream" / "oidf" / "conformance-suite.lock.json"
DEFAULT_SUITE_PATH = REPOSITORY_ROOT / "upstream" / "oidf" / "openid-conformance-suite"
DEFAULT_MANIFEST_PATH = REPOSITORY_ROOT / "plans" / "oidf" / "certification.json"
SUITE_LOCK_RELATIVE_PATH = "upstream/oidf/conformance-suite.lock.json"


def fail(message: str, exit_code: int) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def read_bounded_text(path: Path, limit: int) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        fail(f"required file is unavailable: {path}", EXIT_NOT_FOUND)
    if size > limit:
        fail(f"required file exceeds the accepted size: {path}", EXIT_INVALID_INPUT)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        fail(f"required file is not readable UTF-8: {path}", EXIT_INVALID_INPUT)


def load_manifest(path: Path) -> dict[str, object]:
    text = read_bounded_text(path, MAX_MANIFEST_BYTES)
    try:
        parsed = strict_json.loads(text)
    except strict_json.StrictJsonError:
        fail("OIDF parameter manifest is invalid JSON", EXIT_INVALID_INPUT)
    if not isinstance(parsed, dict):
        fail("OIDF parameter manifest must be an object", EXIT_INVALID_INPUT)
    return parsed


def required_string(mapping: object, key: str) -> str:
    if not isinstance(mapping, dict):
        fail("OIDF parameter manifest has an invalid object", EXIT_INVALID_INPUT)
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        fail(f"OIDF parameter manifest requires {key}", EXIT_INVALID_INPUT)
    return value


def suite_commit(suite_dir: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(suite_dir), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        fail("unable to resolve the conformance-suite revision", EXIT_CONFIGURATION)
    commit = result.stdout.strip()
    if result.returncode != 0 or len(commit) != 40:
        fail("conformance-suite checkout has no resolvable commit", EXIT_CONFIGURATION)
    return commit


def suite_is_clean(suite_dir: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(suite_dir), "status", "--porcelain"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        fail("unable to inspect the conformance-suite worktree", EXIT_CONFIGURATION)
    if result.returncode != 0:
        fail("unable to inspect the conformance-suite worktree", EXIT_CONFIGURATION)
    return not result.stdout.strip()


def resolve_source(suite_dir: Path, relative: str) -> Path:
    candidate = (suite_dir / relative).resolve()
    try:
        candidate.relative_to(suite_dir)
    except ValueError:
        fail("suite source assertion escapes the checkout", EXIT_INVALID_INPUT)
    return candidate


def verify_assertions(suite_dir: Path, assertions: object) -> None:
    if not isinstance(assertions, list) or not assertions:
        fail("OIDF parameter manifest has no source assertions", EXIT_INVALID_INPUT)
    for assertion in assertions:
        if not isinstance(assertion, dict):
            fail("suite source assertion must be an object", EXIT_INVALID_INPUT)
        relative = required_string(assertion, "path")
        tokens = assertion.get("required_tokens")
        if not isinstance(tokens, list) or not tokens:
            fail(f"suite source assertion has no tokens: {relative}", EXIT_INVALID_INPUT)
        source = read_bounded_text(resolve_source(suite_dir, relative), MAX_SOURCE_BYTES)
        for token in tokens:
            if not isinstance(token, str) or not token:
                fail(f"suite source assertion has an invalid token: {relative}", EXIT_INVALID_INPUT)
            if token not in source:
                fail(f"suite certification contract drifted: {relative}", EXIT_CONFIGURATION)


def verify_target_matches_lock(
    manifest: dict[str, object], suite_lock: dict[str, object],
    expected_lock: str = SUITE_LOCK_RELATIVE_PATH,
) -> str:
    target = manifest.get("suite_target")
    if not isinstance(target, dict):
        fail("OIDF parameter manifest requires suite_target", EXIT_INVALID_INPUT)
    if target.get("lock_file") != expected_lock:
        fail("OIDF parameter manifest does not reference the suite lock", EXIT_INVALID_INPUT)
    for key in ("repository", "local_checkout", "pinned_ref", "commit"):
        if target.get(key) != suite_lock.get(key):
            fail("OIDF parameter manifest disagrees with the suite lock", EXIT_CONFIGURATION)
    return required_string(suite_lock, "commit")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify pinned OIDF plan parameters against suite source."
    )
    parser.add_argument(
        "suite_dir",
        nargs="?",
        default=str(DEFAULT_SUITE_PATH),
        help="Pinned OpenID conformance-suite checkout",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST_PATH),
        help="OIDF parameter manifest path",
    )
    args = parser.parse_args()

    suite_dir = Path(args.suite_dir).resolve()
    if not suite_dir.is_dir():
        fail("conformance-suite directory does not exist", EXIT_NOT_FOUND)
    manifest = load_manifest(Path(args.manifest).resolve())
    expected_lock = SUITE_LOCK_RELATIVE_PATH
    target = manifest.get("suite_target")
    if (
        manifest.get("scope") == "non_certification_final_engineering"
        and isinstance(target, dict)
        and target.get("lock_file") == "upstream/oidf/engineering-master.lock.json"
    ):
        expected_lock = "upstream/oidf/engineering-master.lock.json"
    suite_lock = load_manifest(REPOSITORY_ROOT / expected_lock)
    expected_commit = verify_target_matches_lock(manifest, suite_lock, expected_lock)
    if suite_commit(suite_dir) != expected_commit:
        fail("conformance-suite revision does not match the certification target", EXIT_CONFIGURATION)
    if not suite_is_clean(suite_dir):
        fail("conformance-suite checkout contains local source changes", EXIT_CONFIGURATION)
    verify_assertions(suite_dir, manifest.get("suite_source_assertions"))
    print("OIDF parameters match the pinned suite source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
