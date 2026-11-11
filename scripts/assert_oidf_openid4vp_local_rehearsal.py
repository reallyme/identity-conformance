#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate all six composed OpenID4VP profiles from a local rehearsal."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import assert_oidf_openid4vp_pre_submission as profile_validation  # noqa: E402


EXPECTED_SCOPE = {
    "schema_version": 1,
    "protocol": "openid4vp",
    "execution_scope": "local_rehearsal",
    "certification_evidence": False,
    "submission_authorized": False,
}


def validate(args: argparse.Namespace) -> None:
    result_root = args.result_root.resolve(strict=True)
    if not result_root.is_dir() or result_root.is_symlink():
        profile_validation.fail("result_root_invalid")

    scope = profile_validation.load_object(
        result_root / "evidence-scope.json", "evidence_scope_invalid"
    )
    if scope != EXPECTED_SCOPE:
        profile_validation.fail("evidence_scope_invalid")

    plan = profile_validation.load_object(
        args.certification_plan, "certification_plan_invalid"
    )
    matrix = profile_validation.load_object(
        args.profile_matrix, "profile_matrix_invalid"
    )
    lock = profile_validation.load_object(
        args.component_lock, "component_lock_invalid"
    )
    selected = profile_validation.selected_profiles(plan)
    supported = profile_validation.supported_profiles(matrix)

    suite = profile_validation.require_object(
        matrix.get("suite"), "profile_matrix_invalid"
    )
    suite_commit = profile_validation.require_string(
        suite.get("commit"), "profile_matrix_invalid"
    )
    if profile_validation.GIT_COMMIT.fullmatch(suite_commit) is None:
        profile_validation.fail("profile_matrix_invalid")

    suite_revision_path = result_root / "oidf-suite-revision.txt"
    try:
        metadata = suite_revision_path.lstat()
        if not suite_revision_path.is_file() or metadata.st_size != 41:
            profile_validation.fail("suite_revision_evidence_invalid")
        suite_revision = suite_revision_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        profile_validation.fail("suite_revision_evidence_invalid")
    if suite_revision != suite_commit:
        profile_validation.fail("suite_revision_evidence_invalid")

    repository, commit = profile_validation.locked_component(lock)
    if matrix.get("source_repository") != repository:
        profile_validation.fail("profile_matrix_source_mismatch")
    profile_validation.assert_checkout(args.openid4vp_source_dir, commit)
    if not args.result_assertion.is_file() or args.result_assertion.is_symlink():
        profile_validation.fail("result_assertion_unavailable")

    for profile_id, selection in selected.items():
        profile = supported.get(profile_id)
        if profile is None:
            profile_validation.fail("selected_profile_not_supported")
        profile_validation.assert_profile(
            result_root,
            profile_id,
            selection,
            profile,
            args.result_assertion,
            args.profile_matrix,
        )

    expected_by_role = {
        role: {
            profile_id
            for profile_id, (item_role, _, _) in selected.items()
            if item_role == role
        }
        for role in ("verifier", "wallet")
    }
    for role, expected in expected_by_role.items():
        export_root = result_root / "exports" / role
        try:
            observed = {
                item.name
                for item in export_root.iterdir()
                if item.is_dir() and not item.is_symlink()
            }
        except OSError:
            profile_validation.fail("profile_export_inventory_invalid")
        if observed != expected:
            profile_validation.fail("profile_export_inventory_invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", required=True, type=Path)
    parser.add_argument("--certification-plan", required=True, type=Path)
    parser.add_argument("--profile-matrix", required=True, type=Path)
    parser.add_argument("--component-lock", required=True, type=Path)
    parser.add_argument("--openid4vp-source-dir", required=True, type=Path)
    parser.add_argument("--result-assertion", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate(args)
    except (profile_validation.EvidenceError, OSError) as error:
        reason = (
            str(error)
            if isinstance(error, profile_validation.EvidenceError)
            else "evidence_io_failure"
        )
        print(f"OpenID4VP local rehearsal invalid: {reason}", file=sys.stderr)
        return 70
    print("OpenID4VP local rehearsal covers all six composed profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
