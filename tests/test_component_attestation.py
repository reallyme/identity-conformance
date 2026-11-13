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
    path = REPOSITORY_ROOT / "scripts" / "verify_component_attestation.py"
    specification = importlib.util.spec_from_file_location(
        "verify_component_attestation", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("component attestation verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


def valid_attestation() -> dict[str, object]:
    return {
        "schema": "reallyme.identity.component_attestation.v1",
        "classification": "internal",
        "component": {
            "component_id": "ssi",
            "repository": "https://github.com/reallyme/ssi",
            "source_commit": "a" * 40,
        },
        "release": {"version": "0.6.1", "source_ref": "reallyme-ssi-v0.6.1"},
        "artifacts": [
            {"artifact_id": "reallyme-ssi-core", "kind": "package", "sha256": "b" * 64}
        ],
        "dependency_lock": {"kind": "cargo", "sha256": "c" * 64},
        "toolchain": {"identifier": "rust", "version": "1.100.0"},
        "checks": [
            {
                "check_id": "cargo-clippy",
                "category": "lint",
                "result": "passed",
                "evidence_sha256": "d" * 64,
            }
        ],
        "created_at": "2026-11-11T12:00:00Z",
        "evidence_policy": {
            "contains_sensitive_data": False,
            "raw_process_output_retained": False,
            "credentials_retained": False,
            "private_key_material_retained": False,
        },
    }


def valid_wallet_attestation(mode: str = "candidate") -> dict[str, object]:
    value = valid_attestation()
    value["schema"] = "reallyme.identity.wallet_component_attestation.v2"
    value["component"] = {
        "component_id": "wallet",
        "repository": "https://github.com/reallyme/wallet",
        "source_commit": "e" * 40,
    }
    del value["release"]
    value["target"] = {
        "mode": mode,
        "version": "0.1.2",
        "commit": "e" * 40,
        "preflight_run_id": 123,
    }
    if mode == "published":
        value["target"].update(
            {"release_id": 456, "release_ref": "reallyme-wallet-v0.1.2"}
        )
    value["artifacts"] = [
        {
            "artifact_id": "wallet-package-bundle",
            "kind": "archive",
            "sha256": "b" * 64,
        }
    ]
    return value


class ComponentAttestationTests(unittest.TestCase):
    def test_valid_attestation_is_accepted(self) -> None:
        VERIFIER.verify_attestation(valid_attestation())

    def test_wallet_candidate_attestation_is_accepted_without_release_claim(self) -> None:
        VERIFIER.verify_attestation(valid_wallet_attestation())

    def test_wallet_published_attestation_requires_frozen_release_identity(self) -> None:
        VERIFIER.verify_attestation(valid_wallet_attestation("published"))

    def test_wallet_candidate_cannot_contain_release_identity(self) -> None:
        changed = valid_wallet_attestation()
        changed["target"]["release_id"] = 456
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_wallet_release_ref_must_match_target_version(self) -> None:
        changed = valid_wallet_attestation("published")
        changed["target"]["release_ref"] = "reallyme-wallet-v9.9.9"
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_duplicate_artifact_identifier_is_rejected(self) -> None:
        changed = valid_attestation()
        changed["artifacts"].append(copy.deepcopy(changed["artifacts"][0]))
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_failed_check_is_rejected(self) -> None:
        changed = valid_attestation()
        changed["checks"][0]["result"] = "failed"
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_sensitive_evidence_is_rejected(self) -> None:
        changed = valid_attestation()
        changed["evidence_policy"]["contains_sensitive_data"] = True
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_path_traversal_source_ref_is_rejected(self) -> None:
        changed = valid_attestation()
        changed["release"]["source_ref"] = "refs/../unsafe"
        with self.assertRaises(VERIFIER.AttestationError):
            VERIFIER.verify_attestation(changed)

    def test_ambiguous_source_ref_is_rejected(self) -> None:
        for source_ref in ("/main", "main/", "refs//heads/main"):
            with self.subTest(source_ref=source_ref):
                changed = valid_attestation()
                changed["release"]["source_ref"] = source_ref
                with self.assertRaises(VERIFIER.AttestationError):
                    VERIFIER.verify_attestation(changed)


if __name__ == "__main__":
    unittest.main()
