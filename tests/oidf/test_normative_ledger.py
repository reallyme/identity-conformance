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


LEDGER = load_script(
    "verify_oidf_normative_ledger", "scripts/verify_oidf_normative_ledger.py"
)


class OidfNormativeLedgerTests(unittest.TestCase):
    def test_ledger_covers_every_certification_plan(self) -> None:
        ledger, rules = LEDGER.validate_ledger()
        self.assertEqual(ledger["domain"], "oidf")
        self.assertEqual(len(rules), 4)
        self.assertEqual(
            {rule["plan_id"] for rule in rules},
            {
                "oid4vci-1_0-issuer-haip-test-plan",
                "oid4vci-1_0-wallet-haip-test-plan",
                "oid4vp-1final-verifier-haip-test-plan",
                "oid4vp-1final-wallet-haip-test-plan",
            },
        )

    def test_ledger_binds_all_final_specifications(self) -> None:
        ledger, _rules = LEDGER.validate_ledger()
        self.assertEqual(
            ledger["specification_ids"],
            [
                "openid4vci-1.0-final",
                "openid4vp-1.0-final",
                "openid4vc-haip-1.0-final",
            ],
        )

    def test_wallet_haip_matrix_binds_dc_api_exclusion_to_suite_source(self) -> None:
        _ledger, rules = LEDGER.validate_ledger()
        wallet_rule = next(
            rule
            for rule in rules
            if rule["plan_id"] == "oid4vci-1_0-wallet-haip-test-plan"
        )
        self.assertEqual(
            wallet_rule["expected"]["selectable_parameters"]
            ["vci_authorization_code_flow_variant"],
            ["wallet_initiated", "issuer_initiated"],
        )
        self.assertIn(
            "src/main/java/net/openid/conformance/vci10wallet/AbstractVCIWalletTest.java",
            wallet_rule["suite_assertion_paths"],
        )

    def test_every_rule_reuses_certification_plan_source_assertions(self) -> None:
        ledger, rules = LEDGER.validate_ledger()
        plan = LEDGER.load_object(REPOSITORY_ROOT / ledger["plan_path"])
        assertion_paths = set(LEDGER.source_assertion_index(plan))
        referenced_paths = {
            path for rule in rules for path in rule["suite_assertion_paths"]
        }
        self.assertTrue(referenced_paths)
        self.assertTrue(referenced_paths.issubset(assertion_paths))

    def test_nested_source_token_is_rejected_without_crashing(self) -> None:
        ledger, _rules = LEDGER.validate_ledger()
        plan = LEDGER.load_object(REPOSITORY_ROOT / ledger["plan_path"])
        changed = copy.deepcopy(plan)
        changed["suite_source_assertions"][0]["required_tokens"] = [["nested"]]
        with self.assertRaises(LEDGER.OidfLedgerError) as raised:
            LEDGER.source_assertion_index(changed)
        self.assertIs(
            raised.exception.reason,
            LEDGER.OidfLedgerErrorReason.INVALID_LEDGER,
        )


if __name__ == "__main__":
    unittest.main()
