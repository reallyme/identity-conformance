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
    path = REPOSITORY_ROOT / "scripts/verify_eudi_publications.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_publications", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("EUDI publication verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


class EudiPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = VERIFIER.load_object(VERIFIER.PUBLICATIONS_PATH)

    def test_repository_publication_ledger_is_valid(self) -> None:
        VERIFIER.verify_ledger(self.ledger)

    def test_content_digest_substitution_is_rejected(self) -> None:
        changed = copy.deepcopy(self.ledger)
        publication = next(
            item for item in changed["publications"] if item["id"] == "rfc-9901"
        )
        publication["binding"]["sha256"] = "invalid"
        with self.assertRaises(VERIFIER.PublicationError) as raised:
            VERIFIER.verify_ledger(changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.PublicationErrorReason.INVALID_BINDING,
        )

    def test_iso_catalog_entry_cannot_claim_a_content_hash(self) -> None:
        changed = copy.deepcopy(self.ledger)
        publication = next(
            item
            for item in changed["publications"]
            if item["id"] == "iso-iec-18013-5-2021"
        )
        publication["binding"] = {
            "kind": "content_sha256",
            "sha256": "a" * 64,
            "content_length": 1,
        }
        with self.assertRaises(VERIFIER.PublicationError) as raised:
            VERIFIER.verify_ledger(changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.PublicationErrorReason.INVALID_BINDING,
        )

    def test_missing_delegated_oidf_final_is_rejected(self) -> None:
        changed = copy.deepcopy(self.ledger)
        changed["delegated_bindings"] = [
            item
            for item in changed["delegated_bindings"]
            if item["publication_id"] != "openid4vp-1.0-final"
        ]
        with self.assertRaises(VERIFIER.PublicationError) as raised:
            VERIFIER.verify_ledger(changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.PublicationErrorReason.INVALID_DELEGATED_BINDING,
        )

    def test_working_draft_cannot_make_a_certification_claim(self) -> None:
        changed = copy.deepcopy(self.ledger)
        publication = next(
            item
            for item in changed["publications"]
            if item["maturity"] == "working_draft"
        )
        publication["certification_claim"] = True
        with self.assertRaises(VERIFIER.PublicationError) as raised:
            VERIFIER.verify_ledger(changed)
        self.assertEqual(
            raised.exception.reason,
            VERIFIER.PublicationErrorReason.INVALID_PUBLICATION,
        )


if __name__ == "__main__":
    unittest.main()
