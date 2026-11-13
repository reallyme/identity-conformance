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
        "verify_conformance_selection",
        REPOSITORY_ROOT / "scripts/verify_conformance_selection.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("conformance selection script could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


SELECTION = load_script()


def identity_selection(version: str = "1.0.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "product_kind": "identity",
        "product_version": version,
        "capabilities": [
            "openid4vci_issuer",
            "openid4vci_wallet",
            "openid4vp_verifier",
            "openid4vp_wallet",
        ],
        "requested_badge_id": "oidf-full-self-assessment",
        "selected_profiles": [
            "oidf-openid4vci-self-assessment",
            "oidf-openid4vp-self-assessment",
        ],
    }


def identity_eu_sdk_selection(version: str = "1.0.0") -> dict[str, object]:
    return {
        "schema_version": 1,
        "product_kind": "identity",
        "product_version": version,
        "capabilities": ["eudi_identity_sdk"],
        "requested_badge_id": "eu-identity-sdk-engineering",
        "selected_profiles": ["eu-identity-sdk-engineering"],
    }


class ConformanceSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SELECTION.load_object(
            SELECTION.CATALOG_PATH, SELECTION.SelectionErrorReason.CATALOG_INVALID
        )

    def assert_reason(
        self, value: dict[str, object], reason: object
    ) -> None:
        with self.assertRaises(SELECTION.SelectionError) as raised:
            SELECTION.validate_selection(value, self.catalog)
        self.assertIs(raised.exception.reason, reason)

    def test_valid_oidf_full_selection_is_digest_bound(self) -> None:
        validated = SELECTION.validate_selection(
            identity_selection(), self.catalog
        )
        self.assertEqual(
            validated["mandatory_profiles"],
            [
                "oidf-openid4vci-self-assessment",
                "oidf-openid4vp-self-assessment",
            ],
        )
        self.assertEqual(len(validated["canonical_sha256"]), 64)

    def test_future_caller_version_needs_no_framework_change(self) -> None:
        validated = SELECTION.validate_selection(
            identity_selection("17.4.2"), self.catalog
        )
        self.assertEqual(validated["product_version"], "17.4.2")

    def test_eu_identity_sdk_selection_is_available(self) -> None:
        validated = SELECTION.validate_selection(
            identity_eu_sdk_selection(), self.catalog
        )
        self.assertEqual(
            validated["mandatory_profiles"], ["eu-identity-sdk-engineering"]
        )
        self.assertEqual(len(validated["canonical_sha256"]), 64)

    def test_ineligible_product_is_rejected(self) -> None:
        changed = identity_selection()
        changed["product_kind"] = "wallet"
        self.assert_reason(
            changed, SELECTION.SelectionErrorReason.PRODUCT_INELIGIBLE
        )

    def test_omitted_mandatory_profile_is_rejected(self) -> None:
        changed = identity_selection()
        changed["selected_profiles"].pop()
        self.assert_reason(
            changed, SELECTION.SelectionErrorReason.MANDATORY_PROFILE_MISSING
        )

    def test_unknown_profile_is_rejected(self) -> None:
        changed = identity_selection()
        changed["selected_profiles"].append("future-unreviewed-profile")
        self.assert_reason(changed, SELECTION.SelectionErrorReason.PROFILE_UNKNOWN)

    def test_unknown_badge_is_rejected(self) -> None:
        changed = identity_selection()
        changed["requested_badge_id"] = "future-unreviewed-badge"
        self.assert_reason(changed, SELECTION.SelectionErrorReason.BADGE_UNKNOWN)

    def test_incomplete_expanded_badge_is_rejected(self) -> None:
        changed = identity_selection()
        changed["requested_badge_id"] = "identity-expanded-conformity"
        self.assert_reason(
            changed, SELECTION.SelectionErrorReason.BADGE_UNAVAILABLE
        )

    def test_external_runner_profile_cannot_be_selected_as_a_pass(self) -> None:
        changed = identity_selection()
        changed["selected_profiles"].append("oidf-wallet-role-self-assessment")
        self.assert_reason(
            changed, SELECTION.SelectionErrorReason.PROFILE_UNAVAILABLE
        )

    def test_missing_capability_is_rejected(self) -> None:
        changed = identity_selection()
        changed["capabilities"].remove("openid4vp_wallet")
        self.assert_reason(
            changed, SELECTION.SelectionErrorReason.CAPABILITY_MISSING
        )

    def test_catalog_rejects_available_badge_for_unavailable_profile(self) -> None:
        changed = copy.deepcopy(self.catalog)
        changed["badges"][1]["required_profiles"] = [
            "eu-relying-party-engineering"
        ]
        with self.assertRaises(SELECTION.SelectionError) as raised:
            SELECTION.validate_catalog(changed)
        self.assertIs(
            raised.exception.reason,
            SELECTION.SelectionErrorReason.CATALOG_INVALID,
        )

    def test_relying_party_profile_is_not_an_identity_sdk_profile(self) -> None:
        profiles, _badges = SELECTION.validate_catalog(self.catalog)
        relying_party = profiles["eu-relying-party-engineering"]
        expanded = profiles["identity-expanded-conformity"]
        self.assertEqual(relying_party["product_kinds"], ["eudi-relying-party"])
        self.assertNotIn("eudi_relying_party", expanded["required_capabilities"])
        self.assertNotIn(
            "eu-relying-party-engineering", expanded["required_profiles"]
        )


if __name__ == "__main__":
    unittest.main()
