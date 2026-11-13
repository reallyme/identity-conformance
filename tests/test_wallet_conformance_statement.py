# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
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


WALLET_RESULT = load_script(
    "wallet_result_fixture", "tests/test_eudi_wallet_conformance.py"
)
STATEMENT = load_script(
    "build_wallet_conformance_statement",
    "scripts/build_wallet_conformance_statement.py",
)


def framework_selection() -> dict[str, object]:
    return {
        "schema": "reallyme.identity.published_framework_selection.v1",
        "release_version": "0.3.1",
        "release_tag": "v0.3.1",
        "release_url": (
            "https://github.com/reallyme/identity-conformance/releases/tag/v0.3.1"
        ),
        "repository_commit": "2" * 40,
        "manifest_sha256": "b" * 64,
        "input_set_sha256": "c" * 64,
    }


def publication_evidence(result: dict[str, object]) -> dict[str, object]:
    target = result["target"]
    crates = result["package_evidence"]["crates"]
    assets = [
        {"name": "crates-preflight.json", "size": 100, "sha256": "d" * 64},
        {
            "name": "crates-publication-ledger.json",
            "size": 100,
            "sha256": "e" * 64,
        },
        *(
            {
                "name": crate["file"],
                "size": crate["size"],
                "sha256": crate["sha256"],
            }
            for crate in crates
        ),
    ]
    assets.sort(key=lambda item: item["name"])
    registry = [
        {
            "name": crate["name"],
            "version": target["version"],
            "checksum": crate["sha256"],
            "yanked": False,
        }
        for crate in crates
    ]
    registry.sort(key=lambda item: item["name"])
    return {
        "schema": "reallyme.identity.wallet_publication_evidence.v1",
        "release": {
            "id": target["release_id"],
            "ref": target["release_ref"],
            "version": target["version"],
            "commit": target["commit"],
        },
        "release_assets": assets,
        "release_asset_inventory_sha256": (
            STATEMENT.publication_verifier.canonical_inventory_digest(assets)
        ),
        "registry_packages": registry,
        "registry_package_inventory_sha256": (
            STATEMENT.publication_verifier.canonical_inventory_digest(registry)
        ),
    }


class WalletConformanceStatementTests(unittest.TestCase):
    def build(
        self,
        result: dict[str, object],
        publication_evidence: dict[str, object] | None = None,
    ) -> dict[str, object]:
        result_bytes = (json.dumps(result, sort_keys=True) + "\n").encode("utf-8")
        return STATEMENT.build_statement(
            framework_selection(),
            result,
            result_bytes,
            "eudi-wallet-engineering-v1",
            "reallyme/wallet",
            "3" * 40,
            123,
            1,
            publication_evidence,
        )

    def test_candidate_statement_names_exact_profile_and_framework(self) -> None:
        statement = self.build(WALLET_RESULT.valid_result())
        self.assertEqual(statement["target"]["mode"], "candidate")
        self.assertEqual(statement["badge"]["label"], "EU Wallet Engineering")
        self.assertEqual(statement["badge"]["framework_version"], "0.3.1")
        self.assertNotIn("release_ref", statement["target"])

    def test_published_statement_preserves_frozen_release_identity(self) -> None:
        result = WALLET_RESULT.valid_result()
        result["target"].update(
            {
                "mode": "published",
                "release_id": 456,
                "release_ref": "reallyme-wallet-v1.0.0",
            }
        )
        deployment = WALLET_RESULT.valid_deployment()
        deployment["target"] = result["target"]
        result["candidate_sha256"] = WALLET_RESULT.RUNNER.candidate_digest(deployment)
        evidence = publication_evidence(result)
        statement = self.build(result, evidence)
        self.assertEqual(statement["target"]["release_id"], 456)
        self.assertEqual(statement["publication_evidence"], evidence)

    def test_published_statement_rejects_incomplete_publication_evidence(self) -> None:
        result = WALLET_RESULT.valid_result()
        result["target"].update(
            {
                "mode": "published",
                "release_id": 456,
                "release_ref": "reallyme-wallet-v1.0.0",
            }
        )
        deployment = WALLET_RESULT.valid_deployment()
        deployment["target"] = result["target"]
        result["candidate_sha256"] = WALLET_RESULT.RUNNER.candidate_digest(deployment)
        evidence = publication_evidence(result)
        evidence["registry_packages"] = []
        with self.assertRaises(STATEMENT.WalletStatementError):
            self.build(result, evidence)

    def test_unsupported_profile_is_rejected(self) -> None:
        result = WALLET_RESULT.valid_result()
        with self.assertRaises(STATEMENT.WalletStatementError):
            STATEMENT.build_statement(
                framework_selection(),
                result,
                b"{}\n",
                "arbitrary-subset",
                "reallyme/wallet",
                "3" * 40,
                123,
                1,
            )

    def test_mixed_framework_and_result_are_rejected(self) -> None:
        selection = framework_selection()
        selection["repository_commit"] = "f" * 40
        result = WALLET_RESULT.valid_result()
        with self.assertRaises(STATEMENT.WalletStatementError):
            STATEMENT.build_statement(
                selection,
                result,
                b"{}\n",
                "eudi-wallet-engineering-v1",
                "reallyme/wallet",
                "3" * 40,
                123,
                1,
            )

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "statement.json"
            output.write_text("reserved\n", encoding="utf-8")
            with self.assertRaises(STATEMENT.WalletStatementError):
                STATEMENT.write_output(output, {"result": "passed"})


if __name__ == "__main__":
    unittest.main()
