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
    path = REPOSITORY_ROOT / "scripts" / "verify_eudi_legal_sources.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_legal_sources", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("EUDI legal-source verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class EudiLegalSourcesTests(unittest.TestCase):
    def test_checked_lock_is_valid(self) -> None:
        VERIFIER.verify_lock(VERIFIER.load_lock(VERIFIER.DEFAULT_LOCK_PATH))

    def test_missing_governing_source_is_rejected(self) -> None:
        changed = copy.deepcopy(VERIFIER.load_lock(VERIFIER.DEFAULT_LOCK_PATH))
        changed["sources"].pop()
        with self.assertRaises(VERIFIER.EudiLegalSourcesError):
            VERIFIER.verify_lock(changed)

    def test_duplicate_celex_is_rejected(self) -> None:
        changed = copy.deepcopy(VERIFIER.load_lock(VERIFIER.DEFAULT_LOCK_PATH))
        changed["sources"][1]["celex"] = changed["sources"][0]["celex"]
        with self.assertRaises(VERIFIER.EudiLegalSourcesError):
            VERIFIER.verify_lock(changed)

    def test_incomplete_amendment_graph_is_rejected(self) -> None:
        changed = copy.deepcopy(VERIFIER.load_lock(VERIFIER.DEFAULT_LOCK_PATH))
        amendment = next(
            source
            for source in changed["sources"]
            if source["source_id"] == "cir-2026-1731"
        )
        amendment["amends"].pop()
        with self.assertRaises(VERIFIER.EudiLegalSourcesError):
            VERIFIER.verify_lock(changed)

    def test_unknown_consolidation_is_rejected(self) -> None:
        changed = copy.deepcopy(VERIFIER.load_lock(VERIFIER.DEFAULT_LOCK_PATH))
        changed["current_consolidations"][0]["source_id"] = "cir-2024-2981"
        with self.assertRaises(VERIFIER.EudiLegalSourcesError):
            VERIFIER.verify_lock(changed)


if __name__ == "__main__":
    unittest.main()
