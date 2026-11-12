# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts/verify_eudi_upstream_assets.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_upstream_assets", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("EUDI upstream asset verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class EudiUpstreamAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.plan = VERIFIER.load_object(VERIFIER.PLAN_PATH)
        self.source_lock = VERIFIER.load_object(VERIFIER.SOURCE_LOCK_PATH)
        self.assets = {
            asset["asset_id"]: asset["expected"] for asset in self.plan["assets"]
        }
        self.checkouts = {
            "eudi-fcaf": self.root / "fcaf",
            "eudi-functional-tests": self.root / "ui",
            "eudi-itb": self.root / "itb",
            "eudi-age-verification-specification": self.root / "age",
            "eudi-rqes-wallet-driven-tester": self.root / "rqes",
        }
        self.build_fcaf()
        self.build_ui()
        self.build_itb()
        self.build_age_verification()
        self.build_rqes()

    @staticmethod
    def write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def build_fcaf(self) -> None:
        root = self.checkouts["eudi-fcaf"]
        expected = self.assets["fcaf-wallet-methodology"]
        for index, relative in enumerate(expected["wallet_sut_documents"]):
            self.write(root / relative, f"# Wallet document {index}\n")
        additional_count = expected["markdown_document_count"] - len(
            expected["wallet_sut_documents"]
        )
        for index in range(additional_count):
            self.write(root / f"docs/fcaf/additional-{index}.md", "# Additional\n")

    def build_ui(self) -> None:
        root = self.checkouts["eudi-functional-tests"]
        expected = self.assets["wallet-ui-tests"]
        for relative in expected["required_files"]:
            self.write(root / relative, "fixture\n")
        for platform in expected["platforms"]:
            file_count = platform["feature_file_count"]
            remaining_scenarios = platform["scenario_count"]
            for index in range(file_count):
                scenarios = remaining_scenarios - (file_count - index - 1)
                if index > 0:
                    scenarios = 1
                remaining_scenarios -= scenarios
                content = [f"Feature: {platform['name']} {index}"]
                content.extend(
                    f"Scenario: case {scenario}" for scenario in range(scenarios)
                )
                self.write(
                    root / platform["root"] / f"feature-{index}.feature",
                    "\n".join(content) + "\n",
                )

    def build_itb(self) -> None:
        root = self.checkouts["eudi-itb"]
        expected = self.assets["interoperability-testbed"]
        for relative in expected["required_files"]:
            self.write(root / relative, "fixture\n")
        namespace = "http://www.gitb.com/tdl/v1/"
        ElementTree.register_namespace("", namespace)
        for suite in expected["suites"]:
            suite_root = ElementTree.Element(
                f"{{{namespace}}}testsuite", {"id": suite["suite_id"]}
            )
            for test_case_id in suite["test_case_ids"]:
                ElementTree.SubElement(
                    suite_root, f"{{{namespace}}}testcase", {"id": test_case_id}
                )
            suite_path = root / suite["path"]
            self.write(
                suite_path,
                ElementTree.tostring(suite_root, encoding="unicode") + "\n",
            )
            case_directory = suite_path.parent / "tests"
            for index, test_case_id in enumerate(suite["test_case_ids"]):
                case_root = ElementTree.Element(
                    f"{{{namespace}}}testcase", {"id": test_case_id}
                )
                self.write(
                    case_directory / f"case-{index}.xml",
                    ElementTree.tostring(case_root, encoding="unicode") + "\n",
                )

    def build_age_verification(self) -> None:
        root = self.checkouts["eudi-age-verification-specification"]
        expected = self.assets["age-verification-profile"]
        remaining_headings = expected["heading_count"]
        document_count = len(expected["documents"])
        for index, relative in enumerate(expected["documents"]):
            headings = remaining_headings - (document_count - index - 1)
            if index > 0:
                headings = 1
            remaining_headings -= headings
            self.write(
                root / relative,
                "\n".join(f"# Heading {number}" for number in range(headings))
                + "\n",
            )

    def build_rqes(self) -> None:
        root = self.checkouts["eudi-rqes-wallet-driven-tester"]
        expected = self.assets["rqes-wallet-driven-tester"]
        environment = "\n".join(
            f"{key}=" for key in expected["required_environment_keys"]
        )
        self.write(root / ".env.sample", environment + "\n")
        self.write(
            root / "requirements.txt",
            "\n".join(expected["requirements_entries"]) + "\n",
        )
        routes = []
        for index in range(expected["route_count"]):
            routes.extend(
                [
                    f"@app.route('/route-{index}')",
                    f"def route_{index}():",
                    "    return None",
                    "",
                ]
            )
        self.write(root / "app/app.py", "\n".join(routes) + "\n")
        for index in range(expected["python_file_count"] - 1):
            self.write(root / f"app/module_{index}.py", "VALUE = None\n")

    def verify(self, plan: dict[str, object] | None = None) -> None:
        VERIFIER.verify_assets(
            self.plan if plan is None else plan,
            self.source_lock,
            self.checkouts,
            verify_commits=False,
        )

    def test_exact_upstream_asset_inventory_is_accepted(self) -> None:
        self.verify()

    def test_missing_gherkin_scenario_is_rejected(self) -> None:
        path = (
            self.checkouts["eudi-functional-tests"]
            / "src/test/resources/features/android/feature-0.feature"
        )
        self.write(path, "Feature: altered\n")
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify()
        self.assertEqual(
            raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_GHERKIN
        )

    def test_xml_entity_declaration_is_rejected(self) -> None:
        suite_path = self.assets["interoperability-testbed"]["suites"][0]["path"]
        self.write(
            self.checkouts["eudi-itb"] / suite_path,
            "<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
            '<testsuite xmlns="http://www.gitb.com/tdl/v1/" id="testSuite1"/>\n',
        )
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify()
        self.assertEqual(raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_XML)

    def test_invalid_python_source_is_rejected(self) -> None:
        self.write(
            self.checkouts["eudi-rqes-wallet-driven-tester"] / "app/module_0.py",
            "def invalid(:\n",
        )
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify()
        self.assertEqual(
            raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_PYTHON
        )

    def test_product_execution_claim_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["product_execution_claim"] = True
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify(changed)
        self.assertEqual(raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_PLAN)

    def test_path_traversal_in_plan_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        ui = next(
            asset for asset in changed["assets"] if asset["asset_id"] == "wallet-ui-tests"
        )
        ui["expected"]["required_files"][0] = "../outside"
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify(changed)
        self.assertEqual(raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_PLAN)

    def test_unreviewed_requirement_change_is_rejected(self) -> None:
        self.write(
            self.checkouts["eudi-rqes-wallet-driven-tester"] / "requirements.txt",
            "flask==99.0.0\n",
        )
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify()
        self.assertEqual(
            raised.exception.reason, VERIFIER.AssetErrorReason.INVALID_REQUIREMENTS
        )

    def test_symlinked_test_definition_is_rejected(self) -> None:
        feature_root = (
            self.checkouts["eudi-functional-tests"]
            / "src/test/resources/features/android"
        )
        target = feature_root / "feature-1.feature"
        link = feature_root / "feature-0.feature"
        link.unlink()
        try:
            link.symlink_to(target.name)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaises(VERIFIER.AssetError) as raised:
            self.verify()
        self.assertEqual(raised.exception.reason, VERIFIER.AssetErrorReason.UNSAFE_PATH)


if __name__ == "__main__":
    unittest.main()
