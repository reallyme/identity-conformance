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


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "build_release_manifest",
        REPOSITORY_ROOT / "scripts/build_release_manifest.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("release manifest script could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


MANIFEST = load_script()


class ReleaseManifestTests(unittest.TestCase):
    def test_repository_release_inputs_build_deterministically(self) -> None:
        first = MANIFEST.build_manifest("1.2.3-rc.1", "a" * 40)
        second = MANIFEST.build_manifest("1.2.3-rc.1", "a" * 40)
        self.assertEqual(first, second)
        self.assertGreater(len(first["inputs"]), 10)
        paths = {item["path"] for item in first["inputs"]}
        self.assertIn("adapters/eudi-wallet/adapter.json", paths)
        self.assertIn("plans/eudi/upstream-coverage.json", paths)
        self.assertIn("schemas/eudi-upstream-sources.schema.json", paths)
        self.assertIn("scripts/verify_eudi_upstream_coverage.py", paths)
        self.assertIn("references/eudi-publications.lock.json", paths)
        self.assertIn("scripts/verify_eudi_publications.py", paths)
        self.assertIn("adapters/zk/adapter.json", paths)
        self.assertIn("adapters/wallet/README.md", paths)
        self.assertIn("scripts/java/OidfCertificationModuleSnapshot.java", paths)
        self.assertFalse(any("__pycache__" in path for path in paths))
        self.assertNotIn("references/taxonomy-advisory/taxonomy.lock.json", paths)
        self.assertEqual(MANIFEST.validate_manifest(first), first)

    def test_manifest_rejects_a_tampered_aggregate_digest(self) -> None:
        value = MANIFEST.build_manifest("1.2.3", "a" * 40)
        value["input_set_sha256"] = "f" * 64
        with self.assertRaises(MANIFEST.ManifestError):
            MANIFEST.validate_manifest(value)

    def test_manifest_rejects_an_incomplete_document(self) -> None:
        with self.assertRaises(MANIFEST.ManifestError):
            MANIFEST.validate_manifest(
                {
                    "schema": "reallyme.identity.conformance_framework_release.v1",
                    "release_kind": "framework",
                    "release_version": "1.2.3",
                }
            )

    def test_invalid_version_is_rejected(self) -> None:
        with self.assertRaises(MANIFEST.ManifestError):
            MANIFEST.build_manifest("release-latest", "a" * 40)

    def test_short_commit_is_rejected(self) -> None:
        with self.assertRaises(MANIFEST.ManifestError):
            MANIFEST.build_manifest("1.2.3", "abc123")

    def test_aggregate_digest_binds_path_hash_and_size(self) -> None:
        original = [MANIFEST.InputDigest("plans/a.json", "a" * 64, 10)]
        changed = [MANIFEST.InputDigest("plans/a.json", "a" * 64, 11)]
        self.assertNotEqual(
            MANIFEST.aggregate_digest(original), MANIFEST.aggregate_digest(changed)
        )

    def test_symlink_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(MANIFEST.ManifestError):
                MANIFEST.digest_input(link, root)

    def test_manifest_is_written_as_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "manifest.json"
            value = MANIFEST.build_manifest("1.2.3", "b" * 40)
            MANIFEST.write_manifest(output, value)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), value)


if __name__ == "__main__":
    unittest.main()
