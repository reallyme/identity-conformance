# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "render_conformance_catalog",
        REPOSITORY_ROOT / "scripts/render_conformance_catalog.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("conformance catalog script could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


CATALOG = load_script()


class ConformanceCatalogTests(unittest.TestCase):
    def test_checked_in_catalog_matches_release_inputs(self) -> None:
        current_readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        expected_readme_with_badges = CATALOG.replace_generated_section(
            current_readme,
            CATALOG.BADGES_START_MARKER,
            CATALOG.BADGES_END_MARKER,
            CATALOG.render_badges(),
        )
        expected_readme = CATALOG.replace_generated_section(
            expected_readme_with_badges,
            CATALOG.SUMMARY_START_MARKER,
            CATALOG.SUMMARY_END_MARKER,
            CATALOG.render_summary(),
        )
        self.assertEqual(current_readme, expected_readme)

        current_baseline = (REPOSITORY_ROOT / "docs/STANDARDS_BASELINE.md").read_text(
            encoding="utf-8"
        )
        expected_baseline = CATALOG.replace_generated_section(
            current_baseline,
            CATALOG.CATALOG_START_MARKER,
            CATALOG.CATALOG_END_MARKER,
            CATALOG.render_catalog(),
        )
        self.assertEqual(current_baseline, expected_baseline)

    def test_catalog_contains_exact_release_and_source_bindings(self) -> None:
        catalog = CATALOG.render_catalog()
        version = CATALOG.read_version()
        self.assertIn(f"Framework version: **v{version}**", catalog)
        self.assertIn(
            "label=EU%20ARF&message=v3.0.0%20included", catalog
        )
        self.assertIn("Inclusion does not imply product conformance.", catalog)
        self.assertIn(
            "blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/", catalog
        )
        self.assertIn(
            "-/tree/23353b36957d6466010de767c812d2c91ed37638", catalog
        )
        self.assertIn("wallet.wia.technical_validity_seconds < 86,400", catalog)
        self.assertIn("Verifies `126` feature files and `798` scenarios", catalog)
        self.assertIn("Verifies `5` suites and `39` test cases", catalog)
        self.assertIn("Upstream dependencies are excluded from CI", catalog)

    def test_readme_summary_contains_current_release_inventory(self) -> None:
        summary = CATALOG.render_summary()
        self.assertIn("EU Architecture and Reference Framework", summary)
        self.assertIn("OpenID Conformance Suite", summary)
        self.assertIn("`126` feature files and `798` scenarios", summary)
        self.assertIn("`5` suites and `39` test cases", summary)
        self.assertIn("`main @ cfc383e4`", summary)
        self.assertIn("`main @ b0e22243`", summary)
        self.assertIn("docs/STANDARDS_BASELINE.md", summary)

    def test_readme_badges_distinguish_health_from_included_baselines(self) -> None:
        badges = CATALOG.render_badges()
        version = CATALOG.read_version()
        self.assertIn("release-readiness.yml/badge.svg", badges)
        self.assertIn("secret-scan.yml/badge.svg", badges)
        self.assertIn(f"label=Framework&message=v{version}", badges)
        self.assertIn("label=EU%20ARF&message=v3.0.0%20included", badges)
        self.assertIn(
            "label=OIDF%20suite&message=release-v5.3.4%20included",
            badges,
        )
        self.assertNotIn("message=passing", badges)

    def test_inconsistent_ledger_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            shutil.copytree(REPOSITORY_ROOT / "upstream", root / "upstream")
            shutil.copytree(REPOSITORY_ROOT / "plans", root / "plans")
            (root / "VERSION").write_text("0.2.0\n", encoding="ascii")
            ledger_path = root / "plans/eudi/normative/arf-wallet.json"
            content = ledger_path.read_text(encoding="utf-8")
            ledger_path.write_text(content.replace("c64f2cbb", "a64f2cbb"), encoding="utf-8")
            with self.assertRaises(CATALOG.CatalogError) as context:
                CATALOG.build_rows(root)
            self.assertEqual(
                context.exception.reason,
                CATALOG.CatalogErrorReason.INCONSISTENT_BASELINE,
            )

    def test_prerelease_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "VERSION").write_text("0.3.0-rc.1\n", encoding="ascii")
            with self.assertRaises(CATALOG.CatalogError) as context:
                CATALOG.read_version(root)
            self.assertEqual(
                context.exception.reason, CATALOG.CatalogErrorReason.INVALID_VERSION
            )


if __name__ == "__main__":
    unittest.main()
