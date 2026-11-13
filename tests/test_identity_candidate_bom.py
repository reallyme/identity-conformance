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


VERIFIER = load_script(
    "verify_identity_candidate_bom", "scripts/verify_identity_candidate_bom.py"
)


def component(
    component_id: str,
    repository: str,
    commit_digit: str,
    *,
    release_id: int | None,
    release_ref: str | None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "component_id": component_id,
        "repository": f"https://github.com/reallyme/{repository}",
        "commit": commit_digit * 40,
        "roles": [],
        "adapter_contracts": [],
    }
    if release_id is not None:
        value["release_id"] = release_id
    if release_ref is not None:
        value["release_ref"] = release_ref
    return value


def candidate_bom(
    *, revision: int = 1, identity_commit_digit: str = "1"
) -> dict[str, object]:
    version = f"1.0.{revision}"
    return {
        "schema_version": 3,
        "purpose": "reallyme-product-conformance-bom",
        "product_id": "identity",
        "product_version": version,
        "product_component_id": "identity",
        "components": [
            component(
                "identity",
                "identity",
                identity_commit_digit,
                release_id=None,
                release_ref=None,
            ),
            component(
                "ssi",
                "ssi",
                "2",
                release_id=100 + revision,
                release_ref=f"reallyme-ssi-v0.6.{revision}",
            ),
            component(
                "openid4vci",
                "openid4vci",
                "3",
                release_id=200 + revision,
                release_ref=f"reallyme-openid4vci-v0.3.{revision}",
            ),
            component(
                "openid4vp",
                "openid4vp",
                "4",
                release_id=300 + revision,
                release_ref=f"reallyme-openid4vp-v0.3.{revision}",
            ),
        ],
    }


class IdentityCandidateBomTests(unittest.TestCase):
    def select(self, value: dict[str, object]) -> dict[str, object]:
        identity = next(
            component
            for component in value["components"]
            if component["component_id"] == "identity"
        )
        return VERIFIER.select_candidate(
            value,
            target_mode="candidate",
            target_commit=identity["commit"],
            target_version=str(value["product_version"]),
            target_release_id=None,
            target_release_ref="",
        )

    def test_two_caller_selected_component_sets_use_the_same_contract(self) -> None:
        first = self.select(candidate_bom(revision=1))
        second = self.select(candidate_bom(revision=2, identity_commit_digit="9"))
        self.assertNotEqual(
            first["product_component_bom_sha256"],
            second["product_component_bom_sha256"],
        )
        self.assertEqual(first["component_count"], second["component_count"])

    def test_product_commit_must_match_the_caller_target(self) -> None:
        changed = candidate_bom()
        changed["components"][0]["commit"] = "9" * 40
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            VERIFIER.select_candidate(
                changed,
                target_mode="candidate",
                target_commit="1" * 40,
                target_version="1.0.1",
                target_release_id=None,
                target_release_ref="",
            )
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.PRODUCT_BINDING_INVALID,
        )

    def test_dependency_release_ref_is_required(self) -> None:
        changed = candidate_bom()
        del changed["components"][1]["release_ref"]
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            self.select(changed)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.PRODUCT_BINDING_INVALID,
        )

    def test_dependency_release_id_is_required(self) -> None:
        changed = candidate_bom()
        del changed["components"][1]["release_id"]
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            self.select(changed)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.PRODUCT_BINDING_INVALID,
        )

    def test_unverifiable_artifact_claim_is_rejected(self) -> None:
        changed = candidate_bom()
        changed["components"][0]["release_artifact_sha256"] = "a" * 64
        with self.assertRaises(VERIFIER.CandidateBomError):
            self.select(changed)

    def test_substituted_dependency_repository_is_rejected(self) -> None:
        changed = candidate_bom()
        changed["components"][2]["repository"] = (
            "https://github.com/reallyme/openid4vci-fork"
        )
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            self.select(changed)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID,
        )

    def test_candidate_cannot_claim_a_product_release(self) -> None:
        changed = candidate_bom()
        changed["product_release_ref"] = "reallyme-identity-v1.0.1"
        changed["product_release_id"] = 9001
        changed["components"][0]["release_id"] = 9001
        changed["components"][0]["release_ref"] = "reallyme-identity-v1.0.1"
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            self.select(changed)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.PRODUCT_BINDING_INVALID,
        )

    def test_published_product_requires_matching_release_ref(self) -> None:
        value = candidate_bom()
        value["product_release_ref"] = "reallyme-identity-v1.0.1"
        value["product_release_id"] = 9001
        value["components"][0]["release_id"] = 9001
        value["components"][0]["release_ref"] = "reallyme-identity-v1.0.1"
        selection = VERIFIER.select_candidate(
            value,
            target_mode="published",
            target_commit="1" * 40,
            target_version="1.0.1",
            target_release_id=9001,
            target_release_ref="reallyme-identity-v1.0.1",
        )
        self.assertEqual(
            selection["product"]["release_ref"], "reallyme-identity-v1.0.1"
        )

    def test_incomplete_bom_is_rejected(self) -> None:
        changed = candidate_bom()
        changed["components"] = [
            item
            for item in changed["components"]
            if item["component_id"] != "openid4vp"
        ]
        with self.assertRaises(VERIFIER.CandidateBomError):
            self.select(changed)

    def test_unexpected_component_is_rejected(self) -> None:
        changed = candidate_bom()
        changed["components"].append(
            component(
                "wallet",
                "wallet",
                "5",
                release_id=401,
                release_ref="reallyme-wallet-v0.1.2",
            )
        )
        with self.assertRaises(VERIFIER.CandidateBomError) as raised:
            self.select(changed)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.CandidateBomErrorReason.DEPENDENCY_BINDING_INVALID,
        )

    def test_component_order_does_not_change_the_candidate_digest(self) -> None:
        value = candidate_bom()
        reordered = copy.deepcopy(value)
        reordered["components"].reverse()
        self.assertEqual(
            self.select(value)["product_component_bom_sha256"],
            self.select(reordered)["product_component_bom_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
