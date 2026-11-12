# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str, relative_path: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        name, REPOSITORY_ROOT / relative_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("test script module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


LEDGERS = load_script(
    "verify_eu_normative_ledgers", "scripts/verify_eu_normative_ledgers.py"
)
BOUNDARIES = load_script(
    "verify_eu_wallet_boundaries", "scripts/verify_eu_wallet_boundaries.py"
)


def wallet_source(rejection_operator: str, value: str = "86_400") -> str:
    return f"""
const WALLET_UNIT_ATTESTATION_LIFETIME_LIMIT_SECONDS: i64 = {value};

fn validate_fields() {{
    let lifetime = 1_i64;
    if lifetime {rejection_operator} WALLET_UNIT_ATTESTATION_LIFETIME_LIMIT_SECONDS {{
        return;
    }}
}}
"""


class EuNormativeLedgerTests(unittest.TestCase):
    def write_wallet_source(self, root: Path, content: str) -> None:
        source = root / "crates/attestation/src/validate.rs"
        source.parent.mkdir(parents=True)
        source.write_text(content, encoding="utf-8")
        policy = root / "crates/consent/src/apply_unregistered_attribute_policy.rs"
        policy.parent.mkdir(parents=True)
        policy.write_text(
            "pub enum UnregisteredAttributePolicy {\n"
            "    WarnAndAllowAll,\n"
            "    RegisteredOnly,\n"
            "    RejectRequest,\n"
            "}\n",
            encoding="utf-8",
        )

    def test_reviewed_ledgers_are_closed_and_consistent(self) -> None:
        ledgers, rules = LEDGERS.load_ledgers()
        self.assertEqual({ledger["authority"] for ledger in ledgers}, {
            "arf",
            "technical_specification",
            "fcaf",
        })
        self.assertEqual(set(rules), {
            "eu.arf.WUA_33.wia_technical_validity",
            "eu.arf.EW-DM-44-027.unregistered_attribute_policy",
            "eu.ts3.section-2.2.1.1.wia_time_to_live",
        })

    def test_fcaf_lane_cannot_claim_executable_wallet_cases(self) -> None:
        ledgers, _rules = LEDGERS.load_ledgers()
        fcaf = next(ledger for ledger in ledgers if ledger["authority"] == "fcaf")
        self.assertEqual(fcaf["rules"], [])
        self.assertEqual(fcaf["assessment"]["execution_state"], "methodology_only")
        self.assertEqual(fcaf["assessment"]["executable_test_case_count"], 0)

    def test_nested_string_set_value_is_rejected_without_crashing(self) -> None:
        _ledgers, rules = LEDGERS.load_ledgers()
        changed = copy.deepcopy(
            rules["eu.arf.EW-DM-44-027.unregistered_attribute_policy"]
        )
        changed["expected"]["value"] = [["nested"]]
        with self.assertRaises(LEDGERS.EuLedgerError) as raised:
            LEDGERS.validate_rule(changed)
        self.assertIs(
            raised.exception.reason,
            LEDGERS.EuLedgerErrorReason.INVALID_LEDGER,
        )

    def test_exactly_twenty_four_hours_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_wallet_source(root, wallet_source(">="))
            results = BOUNDARIES.evaluate(root)
        self.assertEqual(len(results), 2)
        lifetime = next(
            result
            for result in results
            if result.boundary_id == "wallet.wia.technical_validity_seconds"
        )
        self.assertTrue(lifetime.passed)
        self.assertEqual(lifetime.expected_operator, "less_than")
        self.assertEqual(lifetime.observed_value, 86_400)

    def test_inclusive_twenty_four_hour_boundary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_wallet_source(root, wallet_source(">"))
            results = BOUNDARIES.evaluate(root)
        lifetime = next(
            result
            for result in results
            if result.boundary_id == "wallet.wia.technical_validity_seconds"
        )
        self.assertFalse(lifetime.passed)
        self.assertEqual(lifetime.observed_operator, "less_than_or_equal")

    def test_substituted_numeric_limit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_wallet_source(root, wallet_source(">=", "86_399"))
            results = BOUNDARIES.evaluate(root)
        lifetime = next(
            result
            for result in results
            if result.boundary_id == "wallet.wia.technical_validity_seconds"
        )
        self.assertFalse(lifetime.passed)
        self.assertEqual(lifetime.observed_value, 86_399)

    def test_missing_policy_outcome_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_wallet_source(root, wallet_source(">="))
            policy = root / "crates/consent/src/apply_unregistered_attribute_policy.rs"
            policy.write_text(
                "pub enum UnregisteredAttributePolicy {\n"
                "    WarnAndAllowAll,\n"
                "    RejectRequest,\n"
                "}\n",
                encoding="utf-8",
            )
            results = BOUNDARIES.evaluate(root)
        policy_result = next(
            result
            for result in results
            if result.boundary_id
            == "wallet.presentation.unregistered_attribute_policy"
        )
        self.assertFalse(policy_result.passed)

    def test_missing_guard_is_not_treated_as_conforming(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_wallet_source(
                root,
                "const WALLET_UNIT_ATTESTATION_LIFETIME_LIMIT_SECONDS: i64 = 86_400;\n"
                "fn validate_fields() {}\n",
            )
            with self.assertRaises(BOUNDARIES.BoundaryError) as raised:
                BOUNDARIES.evaluate(root)
        self.assertIs(
            raised.exception.reason,
            BOUNDARIES.BoundaryErrorReason.OBSERVATION_UNAVAILABLE,
        )


if __name__ == "__main__":
    unittest.main()
