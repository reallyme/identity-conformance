# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
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
    "published_wallet_result_fixture", "tests/test_eudi_wallet_conformance.py"
)
VERIFIER = load_script(
    "verify_wallet_published_target", "scripts/verify_wallet_published_target.py"
)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class WalletPublishedTargetTests(unittest.TestCase):
    def fixture(
        self, root: Path
    ) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]], Path]:
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
        assets = root / "assets"
        assets.mkdir()
        crates = result["package_evidence"]["crates"]
        for index, crate in enumerate(crates, 1):
            content = f"reviewed crate {index}\n".encode("utf-8")
            crate["size"] = len(content)
            crate["sha256"] = hashlib.sha256(content).hexdigest()
            (assets / crate["file"]).write_bytes(content)
        result["package_evidence"]["crate_inventory_sha256"] = (
            WALLET_RESULT.RUNNER.wallet_package_bundle.digest_entries(
                [
                    f"{crate['name']}|{crate['version']}|{crate['size']}|{crate['sha256']}"
                    for crate in crates
                ]
            )
        )
        manifest = {
            "schema": "reallyme.wallet.crates_preflight.v3",
            "repository": "reallyme/wallet",
            "workflow": "crates-package-preflight.yml",
            "run_id": 41,
            "run_attempt": 1,
            "release_sha": "1" * 40,
            "version": "1.0.0",
            "crates": [
                {"file": crate["file"], "sha256": crate["sha256"], "size": crate["size"]}
                for crate in crates
            ],
            "prerequisites": {"fuzz": 31, "protobuf_ci": 32, "rust_ci": 33},
        }
        write_json(assets / "crates-preflight.json", manifest)
        ledger = {
            "schema": "reallyme.wallet.crates-publication-ledger.v1",
            "repository": "reallyme/wallet",
            "source_commit": "1" * 40,
            "release_version": "1.0.0",
            "state": "completed",
            "crates": [
                {
                    "name": crate["name"],
                    "version": "1.0.0",
                    "publish_order": index,
                    "state": "published",
                    "archive_sha256": crate["sha256"],
                }
                for index, crate in enumerate(crates)
            ],
        }
        write_json(assets / "crates-publication-ledger.json", ledger)
        release_assets = []
        for path in sorted(assets.iterdir()):
            content = path.read_bytes()
            release_assets.append(
                {
                    "name": path.name,
                    "size": len(content),
                    "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                }
            )
        release = {
            "id": 456,
            "tag_name": "reallyme-wallet-v1.0.0",
            "draft": False,
            "prerelease": False,
            "assets": release_assets,
        }
        registry = [
            {
                "name": crate["name"],
                "version": "1.0.0",
                "checksum": crate["sha256"],
                "yanked": False,
            }
            for crate in crates
        ]
        return result, release, registry, assets

    def test_release_assets_ledger_and_registry_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result, release, registry, assets = self.fixture(Path(temporary_directory))
            evidence = VERIFIER.build_publication_evidence(
                result, release, assets, registry
            )
        self.assertEqual(evidence["release"]["id"], 456)
        self.assertEqual(len(evidence["registry_packages"]), 2)
        self.assertEqual(len(evidence["release_assets"]), 4)

    def test_registry_checksum_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result, release, registry, assets = self.fixture(Path(temporary_directory))
            registry[0]["checksum"] = "f" * 64
            with self.assertRaises(VERIFIER.PublishedTargetError):
                VERIFIER.build_publication_evidence(result, release, assets, registry)

    def test_yanked_registry_package_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result, release, registry, assets = self.fixture(Path(temporary_directory))
            registry[0]["yanked"] = True
            with self.assertRaises(VERIFIER.PublishedTargetError):
                VERIFIER.build_publication_evidence(result, release, assets, registry)

    def test_extra_release_asset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result, release, registry, assets = self.fixture(Path(temporary_directory))
            (assets / "unreviewed.bin").write_bytes(b"unreviewed")
            with self.assertRaises(VERIFIER.PublishedTargetError):
                VERIFIER.build_publication_evidence(result, release, assets, registry)

    def test_ledger_commit_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result, release, registry, assets = self.fixture(Path(temporary_directory))
            ledger_path = assets / "crates-publication-ledger.json"
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            ledger["source_commit"] = "f" * 40
            write_json(ledger_path, ledger)
            changed_release = copy.deepcopy(release)
            for asset in changed_release["assets"]:
                if asset["name"] == ledger_path.name:
                    content = ledger_path.read_bytes()
                    asset["size"] = len(content)
                    asset["digest"] = f"sha256:{hashlib.sha256(content).hexdigest()}"
            with self.assertRaises(VERIFIER.PublishedTargetError):
                VERIFIER.build_publication_evidence(
                    result, changed_release, assets, registry
                )


if __name__ == "__main__":
    unittest.main()
