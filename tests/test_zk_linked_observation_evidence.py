# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
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
        raise RuntimeError("linked observation verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


ADAPTER = load_script("verify_zk_adapter", "scripts/verify_zk_adapter.py")
VERIFIER = load_script(
    "verify_zk_linked_observation_evidence",
    "scripts/verify_zk_linked_observation_evidence.py",
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def valid_bom() -> dict[str, object]:
    return {
        "schema_version": 3,
        "purpose": "reallyme-product-conformance-bom",
        "product_id": "identity",
        "product_version": "9.1.0",
        "product_component_id": "identity-candidate",
        "product_release_id": 901,
        "product_release_ref": "reallyme-identity-v9.1.0",
        "components": [
            {
                "component_id": "identity-candidate",
                "repository": "https://github.com/reallyme/identity",
                "commit": "1" * 40,
                "release_id": 901,
                "release_ref": "reallyme-identity-v9.1.0",
                "roles": [
                    "openid4vci_issuer",
                    "openid4vci_wallet",
                    "openid4vp_verifier",
                    "openid4vp_wallet",
                ],
                "adapter_contracts": [],
            },
            {
                "component_id": "proof-provider",
                "repository": "https://github.com/reallyme/zk",
                "commit": "2" * 40,
                "release_id": 902,
                "release_ref": "reallyme-zk-v9.1.0",
                "roles": [],
                "adapter_contracts": ["zk"],
            },
        ],
    }


def valid_evidence(*, immutable: bool = False) -> dict[str, object]:
    plan, _adapter = ADAPTER.load_contract()
    contract = plan["linked_observation_contract"]
    components = [
        {
            "component_role": "zk_provider",
            "component_id": "proof-provider" if immutable else "zk-working-tree",
            "repository": "https://github.com/reallyme/zk",
            "source_commit": "2" * 40,
            "source_tree": "3" * 40,
            "source_state": "clean",
            "working_tree_diff_sha256": None,
            "release_id": 902 if immutable else None,
            "release_ref": "reallyme-zk-v9.1.0" if immutable else None,
            "release_artifact_sha256": digest("zk-artifact") if immutable else None,
            "component_attestation_sha256": (
                digest("zk-attestation") if immutable else None
            ),
        },
        {
            "component_role": "identity_product",
            "component_id": (
                "identity-candidate" if immutable else "identity-working-tree"
            ),
            "repository": "https://github.com/reallyme/identity",
            "source_commit": "1" * 40,
            "source_tree": "4" * 40,
            "source_state": "clean" if immutable else "dirty",
            "working_tree_diff_sha256": None if immutable else digest("identity-diff"),
            "release_id": 901 if immutable else None,
            "release_ref": "reallyme-identity-v9.1.0" if immutable else None,
            "release_artifact_sha256": (
                digest("identity-artifact") if immutable else None
            ),
            "component_attestation_sha256": (
                digest("identity-attestation") if immutable else None
            ),
        },
    ]
    toolchains = [
        {
            "binding_id": binding_id,
            "version": "1.0.0",
            "sha256": None if binding_id == "rustc" else digest(binding_id),
        }
        for binding_id in contract["required_toolchain_bindings"]
    ]
    component_by_role = {
        component["component_role"]: component for component in components
    }
    probes = [
        {
            "probe_id": probe["probe_id"],
            "component_role": probe["component_role"],
            "test_selector": probe["test_selector"],
            "source_commit": component_by_role[probe["component_role"]][
                "source_commit"
            ],
            "source_tree": component_by_role[probe["component_role"]]["source_tree"],
            "toolchain_binding_ids": probe["required_toolchain_binding_ids"],
            "input_digests": [
                {
                    "binding_id": binding_id,
                    "sha256": digest(f"{probe['probe_id']}:{binding_id}"),
                }
                for binding_id in probe["required_input_binding_ids"]
            ],
            "result": "passed",
        }
        for probe in contract["probes"]
    ]
    proof_rows = [
        {
            "lane": lane,
            "mode": mode,
            "stage": stage,
            "circuit_ref": f"persona/{lane}/{mode}/{stage}",
            "artifact_sha256": digest(f"artifact:{lane}:{mode}:{stage}"),
            "verification_key_sha256": digest(f"vk:{lane}:{mode}:{stage}"),
            "proof_sha256": digest(f"proof:{lane}:{mode}:{stage}"),
            "public_inputs_sha256": digest(f"inputs:{lane}:{mode}:{stage}"),
            "frozen_request_sha256": digest(f"request:{lane}:{mode}:{stage}"),
            "result": "passed",
            "tampered_proof_rejected": True,
            "tampered_public_inputs_rejected": True,
        }
        for lane in contract["proof_matrix"]["lanes"]
        for mode in contract["proof_matrix"]["modes"]
        for stage in contract["proof_matrix"]["stages"]
    ]
    bom = valid_bom() if immutable else None
    return {
        "schema": "reallyme.identity.zk_linked_observation_evidence.v1",
        "plan_id": "zk-presentation-proofs-v1",
        "profile_id": "identity-zk-linked-presentation-proofs-v1",
        "candidate_binding": (
            "immutable_release" if immutable else "working_tree_observation"
        ),
        "framework_revision": "5" * 40,
        "workflow_revision": "6" * 40,
        "product_component_bom_sha256": (
            VERIFIER.bom_verifier.canonical_digest(bom)
            if bom is not None
            else None
        ),
        "components": components,
        "toolchain_bindings": toolchains,
        "probes": probes,
        "proof_rows": proof_rows,
        "evidence_policy": VERIFIER.EXPECTED_POLICY,
    }


class ZkLinkedObservationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan, _adapter = ADAPTER.load_contract()

    def assert_reason(
        self,
        evidence: dict[str, object],
        reason: object,
        *,
        bom: dict[str, object] | None = None,
    ) -> None:
        with self.assertRaises(VERIFIER.LinkedObservationError) as raised:
            VERIFIER.validate_evidence(evidence, self.plan, bom=bom)
        self.assertIs(raised.exception.reason, reason)

    def test_complete_working_tree_observation_is_accepted_without_badge_binding(
        self,
    ) -> None:
        summary = VERIFIER.validate_evidence(valid_evidence(), self.plan)
        self.assertEqual(summary.candidate_binding, "working_tree_observation")
        self.assertIsNone(summary.product_component_bom_sha256)
        self.assertEqual(len(summary.probe_ids), 11)
        self.assertEqual(summary.proof_row_count, 20)

    def test_complete_immutable_observation_is_bom_bound(self) -> None:
        bom = valid_bom()
        summary = VERIFIER.validate_evidence(
            valid_evidence(immutable=True), self.plan, bom=bom
        )
        self.assertEqual(summary.candidate_binding, "immutable_release")
        self.assertEqual(
            summary.product_component_bom_sha256,
            VERIFIER.bom_verifier.canonical_digest(bom),
        )

    def test_probe_selector_substitution_is_rejected(self) -> None:
        changed = valid_evidence()
        changed["probes"][0]["test_selector"] = "substituted"
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROBE_INVENTORY
        )

    def test_missing_probe_is_rejected(self) -> None:
        changed = valid_evidence()
        changed["probes"].pop()
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROBE_INVENTORY
        )

    def test_probe_cannot_drop_a_required_input_binding(self) -> None:
        changed = valid_evidence()
        changed["probes"][0]["input_digests"].pop()
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROBE_INVENTORY
        )

    def test_probe_cannot_substitute_its_toolchain_set(self) -> None:
        changed = valid_evidence()
        changed["probes"][0]["toolchain_binding_ids"].remove("bb")
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROBE_INVENTORY
        )

    def test_incomplete_proof_matrix_is_rejected(self) -> None:
        changed = valid_evidence()
        changed["proof_rows"].pop()
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROOF_MATRIX
        )

    def test_tamper_negative_cannot_be_omitted(self) -> None:
        changed = valid_evidence()
        changed["proof_rows"][0]["tampered_proof_rejected"] = False
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROOF_MATRIX
        )

    def test_duplicate_proof_row_is_rejected(self) -> None:
        changed = valid_evidence()
        changed["proof_rows"][1] = copy.deepcopy(changed["proof_rows"][0])
        self.assert_reason(
            changed, VERIFIER.LinkedObservationErrorReason.INVALID_PROOF_MATRIX
        )

    def test_dirty_observation_cannot_claim_immutable_release(self) -> None:
        changed = valid_evidence()
        changed["candidate_binding"] = "immutable_release"
        self.assert_reason(
            changed,
            VERIFIER.LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING,
        )

    def test_immutable_observation_rejects_substituted_bom_component(self) -> None:
        evidence = valid_evidence(immutable=True)
        bom = valid_bom()
        bom["components"][1]["commit"] = "9" * 40
        evidence["product_component_bom_sha256"] = (
            VERIFIER.bom_verifier.canonical_digest(bom)
        )
        self.assert_reason(
            evidence,
            VERIFIER.LinkedObservationErrorReason.INVALID_CANDIDATE_BINDING,
            bom=bom,
        )

    def test_revision_substitution_is_rejected(self) -> None:
        with self.assertRaises(VERIFIER.LinkedObservationError) as raised:
            VERIFIER.validate_evidence(
                valid_evidence(),
                self.plan,
                expected_framework_revision="7" * 40,
            )
        self.assertIs(
            raised.exception.reason,
            VERIFIER.LinkedObservationErrorReason.REVISION_MISMATCH,
        )


if __name__ == "__main__":
    unittest.main()
