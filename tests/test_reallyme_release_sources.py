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
    specification = importlib.util.spec_from_file_location(
        "verify_reallyme_release_sources",
        REPOSITORY_ROOT / "scripts/verify_reallyme_release_sources.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("ReallyMe release source validator could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class ReallyMeReleaseSourceTests(unittest.TestCase):
    def test_checked_in_inventory_is_closed_and_valid(self) -> None:
        value = VERIFIER.load_inventory()
        VERIFIER.verify_inventory(value)
        self.assertEqual(
            {source["component_id"] for source in value["sources"]},
            VERIFIER.EXPECTED_COMPONENTS,
        )

    def test_missing_repository_is_rejected(self) -> None:
        value = VERIFIER.load_inventory()
        changed = copy.deepcopy(value)
        changed["sources"] = changed["sources"][:-1]
        with self.assertRaises(VERIFIER.ReleaseSourceError):
            VERIFIER.verify_inventory(changed)

    def test_non_release_strategy_is_rejected(self) -> None:
        value = VERIFIER.load_inventory()
        changed = copy.deepcopy(value)
        changed["sources"][0]["update_strategy"] = "default_branch"
        with self.assertRaises(VERIFIER.ReleaseSourceError):
            VERIFIER.verify_inventory(changed)


if __name__ == "__main__":
    unittest.main()
