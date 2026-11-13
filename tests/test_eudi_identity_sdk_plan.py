# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts/verify_eudi_identity_sdk_plan.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_identity_sdk_plan", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("EUDI Identity SDK plan verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("test JSON root must be an object")
    return value


class EudiIdentitySdkPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = load_json(VERIFIER.PLAN_PATH)
        self.legal_sources = VERIFIER.source_ids(
            load_json(VERIFIER.LEGAL_SOURCES_PATH)
        )
        self.standards = VERIFIER.normative_source_ids(
            load_json(VERIFIER.NORMATIVE_SOURCES_PATH)
        )
        self.eudi_sources = VERIFIER.source_ids(
            load_json(VERIFIER.EUDI_SOURCES_PATH)
        )

    def validate(self, value: dict[str, object]) -> None:
        VERIFIER.validate_plan(
            value,
            self.legal_sources,
            self.standards,
            self.eudi_sources,
        )

    def test_checked_in_plan_is_valid(self) -> None:
        self.validate(self.plan)

    def test_plan_keeps_identity_and_semantic_component_ownership_separate(self) -> None:
        self.assertEqual(
            self.plan["system_under_test"]["component_id"], "identity"
        )
        self.assertEqual(
            set(self.plan["ownership"]["semantic_component_roles"]),
            {"openid4vci", "openid4vp", "ssi"},
        )
        self.assertEqual(
            {
                operation["semantic_owner_role"]
                for operation in self.plan["operations"]
            },
            {"ssi"},
        )

    def test_all_eight_identity_operations_are_required(self) -> None:
        self.assertEqual(
            {operation["operation_id"] for operation in self.plan["operations"]},
            VERIFIER.EXPECTED_OPERATIONS,
        )
        changed = copy.deepcopy(self.plan)
        changed["operations"].pop()
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(raised.exception.reason, VERIFIER.PlanErrorReason.PLAN_INVALID)

    def test_candidate_inventory_is_selected_only_by_the_caller(self) -> None:
        contract = self.plan["candidate_contract"]
        self.assertEqual(contract["selection"], "caller_product_component_bom")
        self.assertIs(contract["reference_baseline_fallback"], False)
        self.assertIs(contract["dependency_release_refs_required"], True)
        self.assertEqual(
            {
                component["component_id"]: component["repository"]
                for component in contract["required_components"]
            },
            VERIFIER.EXPECTED_CANDIDATE_COMPONENTS,
        )

    def test_reference_baseline_cannot_become_an_execution_default(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["candidate_contract"]["reference_baseline_fallback"] = True
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(raised.exception.reason, VERIFIER.PlanErrorReason.PLAN_INVALID)

    def test_external_evidence_cannot_be_reclassified_as_code(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["evidence_policy"]["external_evidence_rows_are_code_passes"] = True
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(raised.exception.reason, VERIFIER.PlanErrorReason.PLAN_INVALID)

    def test_normative_reference_and_external_evidence_are_separate(self) -> None:
        classes = self.plan["evidence_classes"]
        self.assertEqual(classes["normative_specifications"]["status"], "executed")
        self.assertEqual(
            classes["reference_implementation_parity"]["status"],
            "separate_deployed_interoperability_profile",
        )
        targets = {
            target["scope_id"]: target
            for target in classes["reference_implementation_parity"]["targets"]
        }
        self.assertEqual(
            targets["identity_eudi_operations"]["status"], "not_applicable"
        )
        self.assertEqual(
            targets["openid4vci_composition"]["status"],
            "external_runner_required",
        )
        self.assertEqual(
            targets["openid4vp_verifier_composition"]["status"],
            "external_runner_required",
        )
        self.assertEqual(
            targets["openid4vp_wallet_composition"]["status"], "not_applicable"
        )
        self.assertEqual(
            classes["external_legal_and_certification"]["status"],
            "external_evidence_required",
        )
        changed = copy.deepcopy(self.plan)
        changed["evidence_classes"]["external_legal_and_certification"][
            "legal_conformity_claim"
        ] = True
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(raised.exception.reason, VERIFIER.PlanErrorReason.PLAN_INVALID)

    def test_attestations_cannot_satisfy_behavior(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["evidence_policy"]["attestations_satisfy_behavior"] = True
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(raised.exception.reason, VERIFIER.PlanErrorReason.PLAN_INVALID)

    def test_unpinned_source_identifier_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["sources"]["legal"][0] = "future-unreviewed-law"
        with self.assertRaises(VERIFIER.PlanError) as raised:
            self.validate(changed)
        self.assertIs(
            raised.exception.reason, VERIFIER.PlanErrorReason.SOURCE_BINDING_INVALID
        )

    def test_every_platform_lane_is_directly_executable(self) -> None:
        pending = {
            lane["lane_id"]
            for lane in self.plan["execution_lanes"]
            if lane["state"] == "workflow_pending"
        }
        self.assertEqual(pending, set())
        self.assertIs(self.plan["evidence_coverage"]["badge_eligible"], True)

    def test_plan_schema_is_current_json_schema(self) -> None:
        schema = load_json(
            REPOSITORY_ROOT / "schemas/eudi-identity-sdk-plan.schema.json"
        )
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(schema["properties"]["plan_id"]["const"], self.plan["plan_id"])


if __name__ == "__main__":
    unittest.main()
