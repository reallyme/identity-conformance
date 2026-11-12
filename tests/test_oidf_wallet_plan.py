# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_oidf_wallet_plan",
        REPOSITORY_ROOT / "scripts/verify_oidf_wallet_plan.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("OIDF Wallet plan verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class OidfWalletPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        paths = (
            "plans/oidf/wallet.json",
            "plans/oidf/certification.json",
            "upstream/oidf/conformance-suite.lock.json",
            "upstream/oidf/snapshots/certification-modules.json",
        )
        for relative_path in paths:
            source = REPOSITORY_ROOT / relative_path
            destination = self.root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def paths(self) -> tuple[Path, Path, Path, Path]:
        return (
            self.root / "plans/oidf/wallet.json",
            self.root / "plans/oidf/certification.json",
            self.root / "upstream/oidf/conformance-suite.lock.json",
            self.root / "upstream/oidf/snapshots/certification-modules.json",
        )

    def read_json(self, relative_path: str) -> dict[str, object]:
        value = json.loads((self.root / relative_path).read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def write_json(self, relative_path: str, value: dict[str, object]) -> None:
        (self.root / relative_path).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def assert_reason(self, expected_reason: object) -> None:
        with self.assertRaises(VERIFIER.OidfWalletPlanError) as context:
            VERIFIER.validate_paths(*self.paths())
        self.assertEqual(context.exception.reason, expected_reason)

    def test_complete_official_wallet_scope_is_accepted(self) -> None:
        summary = VERIFIER.validate_paths(*self.paths())
        self.assertEqual(summary.profile_count, 10)
        self.assertEqual(summary.module_execution_count, 278)
        self.assertEqual(summary.suite_ref, "release-v5.3.4")
        self.assertEqual(
            summary.suite_commit,
            "23353b36957d6466010de767c812d2c91ed37638",
        )

    def test_suite_commit_substitution_is_rejected(self) -> None:
        plan = self.read_json("plans/oidf/wallet.json")
        source_bindings = copy.deepcopy(plan["source_bindings"])
        self.assertIsInstance(source_bindings, dict)
        source_bindings["suite_commit"] = "0" * 40
        plan["source_bindings"] = source_bindings
        self.write_json("plans/oidf/wallet.json", plan)
        self.assert_reason(VERIFIER.OidfWalletPlanErrorReason.SOURCE_BINDING_MISMATCH)

    def test_missing_wallet_profile_is_rejected(self) -> None:
        certification = self.read_json("plans/oidf/certification.json")
        plans = certification["plans"]
        self.assertIsInstance(plans, list)
        for plan in plans:
            if isinstance(plan, dict) and plan.get("plan_id") == (
                "oid4vci-1_0-wallet-haip-test-plan"
            ):
                runs = plan["certification_runs"]
                self.assertIsInstance(runs, list)
                plan["certification_runs"] = runs[:-1]
        self.write_json("plans/oidf/certification.json", certification)
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
        )

    def test_module_selector_is_rejected(self) -> None:
        certification = self.read_json("plans/oidf/certification.json")
        plans = certification["plans"]
        self.assertIsInstance(plans, list)
        wallet_plan = next(
            plan
            for plan in plans
            if isinstance(plan, dict)
            and plan.get("plan_id") == "oid4vp-1final-wallet-haip-test-plan"
        )
        runs = wallet_plan["certification_runs"]
        self.assertIsInstance(runs, list)
        first_run = runs[0]
        self.assertIsInstance(first_run, dict)
        first_run["expression"] = f"{first_run['expression']}:selected-module"
        self.write_json("plans/oidf/certification.json", certification)
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
        )

    def test_incomplete_module_inventory_is_rejected(self) -> None:
        snapshot = self.read_json(
            "upstream/oidf/snapshots/certification-modules.json"
        )
        plans = snapshot["plans"]
        self.assertIsInstance(plans, list)
        wallet_plan = next(
            plan
            for plan in plans
            if isinstance(plan, dict)
            and plan.get("plan_id") == "oid4vp-1final-wallet-haip-test-plan"
        )
        configurations = wallet_plan["configurations"]
        self.assertIsInstance(configurations, list)
        configuration = configurations[0]
        self.assertIsInstance(configuration, dict)
        modules = configuration["modules"]
        self.assertIsInstance(modules, list)
        configuration["modules"] = modules[:-1]
        self.write_json(
            "upstream/oidf/snapshots/certification-modules.json", snapshot
        )
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
        )

    def test_duplicate_module_is_rejected(self) -> None:
        snapshot = self.read_json(
            "upstream/oidf/snapshots/certification-modules.json"
        )
        plans = snapshot["plans"]
        self.assertIsInstance(plans, list)
        wallet_plan = next(
            plan
            for plan in plans
            if isinstance(plan, dict)
            and plan.get("plan_id") == "oid4vci-1_0-wallet-haip-test-plan"
        )
        configurations = wallet_plan["configurations"]
        self.assertIsInstance(configurations, list)
        configuration = configurations[0]
        self.assertIsInstance(configuration, dict)
        modules = configuration["modules"]
        self.assertIsInstance(modules, list)
        modules[1] = copy.deepcopy(modules[0])
        self.write_json(
            "upstream/oidf/snapshots/certification-modules.json", snapshot
        )
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
        )

    def test_component_test_substitution_is_rejected(self) -> None:
        plan = self.read_json("plans/oidf/wallet.json")
        execution_policy = copy.deepcopy(plan["execution_policy"])
        self.assertIsInstance(execution_policy, dict)
        execution_policy["component_test_substitution_allowed"] = True
        plan["execution_policy"] = execution_policy
        self.write_json("plans/oidf/wallet.json", plan)
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )

    def test_mobile_application_requirement_is_rejected_for_core_library(self) -> None:
        plan = self.read_json("plans/oidf/wallet.json")
        execution_policy = copy.deepcopy(plan["execution_policy"])
        self.assertIsInstance(execution_policy, dict)
        execution_policy["mobile_app_required"] = True
        plan["execution_policy"] = execution_policy
        self.write_json("plans/oidf/wallet.json", plan)
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )

    def test_partial_rerun_is_rejected(self) -> None:
        plan = self.read_json("plans/oidf/wallet.json")
        execution_policy = copy.deepcopy(plan["execution_policy"])
        self.assertIsInstance(execution_policy, dict)
        execution_policy["partial_reruns_allowed"] = True
        plan["execution_policy"] = execution_policy
        self.write_json("plans/oidf/wallet.json", plan)
        self.assert_reason(
            VERIFIER.OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )

    def test_unknown_plan_field_is_rejected(self) -> None:
        plan = self.read_json("plans/oidf/wallet.json")
        plan["unreviewed_override"] = True
        self.write_json("plans/oidf/wallet.json", plan)
        self.assert_reason(VERIFIER.OidfWalletPlanErrorReason.INVALID_PLAN)

    def test_duplicate_json_member_is_rejected(self) -> None:
        plan_path = self.root / "plans/oidf/wallet.json"
        content = plan_path.read_text(encoding="utf-8")
        plan_path.write_text(
            content.replace(
                '"schema_version": 1,',
                '"schema_version": 1,\n  "schema_version": 1,',
                1,
            ),
            encoding="utf-8",
        )
        self.assert_reason(VERIFIER.OidfWalletPlanErrorReason.INVALID_JSON)

    def test_wrong_suite_checkout_revision_is_rejected(self) -> None:
        checkout = self.root / "suite-checkout"
        checkout.mkdir()
        commands = (
            ("git", "init"),
            ("git", "config", "user.name", "ReallyMe Test"),
            ("git", "config", "user.email", "test@really.me"),
        )
        for command in commands:
            completed = subprocess.run(
                command,
                cwd=checkout,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        marker = checkout / "README"
        marker.write_text("test suite\n", encoding="utf-8")
        for command in (("git", "add", "README"), ("git", "commit", "-m", "Test suite")):
            completed = subprocess.run(
                command,
                cwd=checkout,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        with self.assertRaises(VERIFIER.OidfWalletPlanError) as context:
            VERIFIER.validate_paths(*self.paths(), suite_checkout=checkout)
        self.assertEqual(
            context.exception.reason,
            VERIFIER.OidfWalletPlanErrorReason.SUITE_CHECKOUT_MISMATCH,
        )


if __name__ == "__main__":
    unittest.main()
