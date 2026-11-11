# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts/verify_eudi_upstream_coverage.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_upstream_coverage", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("EUDI upstream coverage verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class EudiUpstreamCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_lock = VERIFIER.load_object(VERIFIER.SOURCE_LOCK_PATH)
        self.coverage = VERIFIER.load_object(VERIFIER.COVERAGE_PATH)

    def test_repository_inventory_and_coverage_are_valid(self) -> None:
        VERIFIER.verify(self.source_lock, self.coverage)

    def test_missing_focus_source_is_rejected(self) -> None:
        changed_lock = copy.deepcopy(self.source_lock)
        changed_lock["sources"] = [
            source
            for source in changed_lock["sources"]
            if source["source_id"] != "eudi-age-verification-specification"
        ]
        with self.assertRaises(VERIFIER.CoverageError) as raised:
            VERIFIER.verify(changed_lock, self.coverage)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.CoverageErrorReason.REQUIRED_SOURCE_MISSING,
        )

    def test_duplicate_source_coverage_is_rejected(self) -> None:
        changed = copy.deepcopy(self.coverage)
        changed["source_groups"][1]["source_ids"].append("eudi-arf")
        with self.assertRaises(VERIFIER.CoverageError) as raised:
            VERIFIER.verify(self.source_lock, changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.CoverageErrorReason.COVERAGE_MISMATCH,
        )

    def test_external_execution_claim_is_rejected(self) -> None:
        changed = copy.deepcopy(self.coverage)
        changed["current_claims"]["official_ui_suite_executed"] = True
        with self.assertRaises(VERIFIER.CoverageError) as raised:
            VERIFIER.verify(self.source_lock, changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.CoverageErrorReason.INVALID_EXECUTION_CLAIM,
        )

    def test_legacy_tester_cannot_be_promoted_to_conformance_execution(self) -> None:
        changed = copy.deepcopy(self.coverage)
        legacy_group = next(
            group
            for group in changed["source_groups"]
            if group["coverage_id"] == "legacy_issuer_wallet_tester"
        )
        legacy_group["execution_state"] = "reallyme_control_execution"
        with self.assertRaises(VERIFIER.CoverageError) as raised:
            VERIFIER.verify(self.source_lock, changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.CoverageErrorReason.INVALID_EXECUTION_CLAIM,
        )

    def test_future_dated_inventory_is_rejected(self) -> None:
        changed = copy.deepcopy(self.source_lock)
        changed["observed_at"] = "2999-01-01"
        with self.assertRaises(VERIFIER.CoverageError) as raised:
            VERIFIER.verify(changed, self.coverage)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.CoverageErrorReason.INVALID_SOURCE_LOCK,
        )


if __name__ == "__main__":
    unittest.main()
