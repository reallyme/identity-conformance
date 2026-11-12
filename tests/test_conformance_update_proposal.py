# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "build_conformance_update_proposal",
        REPOSITORY_ROOT / "scripts/build_conformance_update_proposal.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("conformance update proposal script could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


BUILDER = load_script()


class ConformanceUpdateProposalTests(unittest.TestCase):
    def test_checked_in_update_policy_is_valid(self) -> None:
        policy = BUILDER.update_policy()
        self.assertEqual(policy["schedule"]["cadence"], "weekly")
        self.assertFalse(policy["schedule"]["automatic_publication"])

    def test_stale_pin_proposes_next_patch_without_automatic_publication(self) -> None:
        checks = [
            BUILDER.freshness.CheckResult(
                check_id="oidf.release.tag",
                status="stale",
                expected="release-v5.3.4",
                observed="release-v5.4.0",
            )
        ]
        with (
            patch.object(BUILDER.freshness, "run_checks", return_value=(checks, [])),
            patch.object(
                BUILDER.oidf,
                "build_proposal",
                return_value={"review_status": "proposal_not_approved"},
            ),
        ):
            proposal = BUILDER.build_proposal()
        current_version = BUILDER.catalog.read_version()
        self.assertTrue(proposal["update_available"])
        self.assertEqual(proposal["current_framework_version"], current_version)
        self.assertEqual(
            proposal["proposed_framework_version"],
            BUILDER.next_patch_version(current_version),
        )
        self.assertTrue(proposal["version_candidate_available"])
        self.assertFalse(proposal["release_policy"]["automatic_publication"])
        self.assertEqual(proposal["changes"], [BUILDER.asdict(checks[0])])

    def test_current_baseline_does_not_invent_a_release(self) -> None:
        with (
            patch.object(BUILDER.freshness, "run_checks", return_value=([], [])),
            patch.object(BUILDER.oidf, "build_proposal", return_value={}),
        ):
            proposal = BUILDER.build_proposal()
        self.assertFalse(proposal["update_available"])
        self.assertFalse(proposal["version_candidate_available"])
        self.assertIsNone(proposal["proposed_framework_version"])

    def test_default_branch_movement_requires_snapshot_review(self) -> None:
        checks = [
            BUILDER.freshness.CheckResult(
                check_id="eudi.source.eudi-technical-specifications.commit",
                status="stale",
                expected="a" * 40,
                observed="b" * 40,
            )
        ]
        with (
            patch.object(BUILDER.freshness, "run_checks", return_value=(checks, [])),
            patch.object(BUILDER.oidf, "build_proposal", return_value={}),
        ):
            proposal = BUILDER.build_proposal()
        self.assertTrue(proposal["update_available"])
        self.assertFalse(proposal["version_candidate_available"])
        self.assertIsNone(proposal["proposed_framework_version"])
        self.assertEqual(
            proposal["change_groups"]["branch_snapshot_reviews"],
            [BUILDER.asdict(checks[0])],
        )

    def test_patch_version_bump_is_deterministic(self) -> None:
        self.assertEqual(BUILDER.next_patch_version("1.2.3"), "1.2.4")
        with self.assertRaises(BUILDER.ProposalError):
            BUILDER.next_patch_version("1.2.3-rc.1")

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "proposal.json"
            output.write_text("existing", encoding="utf-8")
            with self.assertRaises(BUILDER.ProposalError):
                BUILDER.write_proposal(output, {})
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")


if __name__ == "__main__":
    unittest.main()
