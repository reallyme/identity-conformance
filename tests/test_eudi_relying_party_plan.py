# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts" / "verify_eudi_relying_party_plan.py"
    specification = importlib.util.spec_from_file_location("verify_eudi_relying_party_plan", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("test script module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class EudiRelyingPartyPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = VERIFIER.load_plan()

    def test_checked_plan_is_valid(self) -> None:
        VERIFIER.verify_plan(self.plan)

    def test_certification_claim_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["certification_claim"] = True
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_non_executable_status_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["execution_status"] = "planned_pending_deployable_adapter"
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_missing_execution_source_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["sources"]["execution_sources"].pop()
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_missing_family_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["assertion_families"].pop()
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_duplicate_assertion_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        duplicate = copy.deepcopy(changed["assertion_families"][0]["assertions"][0])
        changed["assertion_families"][1]["assertions"].append(duplicate)
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_missing_assertion_from_nonempty_family_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["assertion_families"][2]["assertions"].pop()
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_substituted_evidence_contract_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["assertion_families"][0]["assertions"][0]["evidence_contracts"] = [
            "attestation.unrelated"
        ]
        with self.assertRaises(VERIFIER.PlanError):
            VERIFIER.verify_plan(changed)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(VERIFIER.PlanError):
                VERIFIER.load_plan(path)

    def test_plan_round_trips_as_utf8_json(self) -> None:
        encoded = json.dumps(self.plan, ensure_ascii=False, sort_keys=True)
        self.assertEqual(self.plan, json.loads(encoded))


if __name__ == "__main__":
    unittest.main()
