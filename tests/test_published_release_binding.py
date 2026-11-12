# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
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


RELEASE_MANIFEST = load_script(
    "build_release_manifest_for_binding_tests", "scripts/build_release_manifest.py"
)
PUBLISHED_RELEASE = load_script(
    "verify_published_framework_release",
    "scripts/verify_published_framework_release.py",
)
STATEMENT = load_script(
    "build_product_conformance_statement",
    "scripts/build_product_conformance_statement.py",
)
WALLET_EXECUTION_FIXTURE = load_script(
    "wallet_execution_fixture_for_statement_tests",
    "tests/test_eudi_wallet_conformance.py",
)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def framework_selection(commit: str = "a" * 40) -> dict[str, object]:
    return {
        "schema": "reallyme.identity.published_framework_selection.v1",
        "release_version": "0.3.0",
        "release_tag": "v0.3.0",
        "release_url": (
            "https://github.com/reallyme/identity-conformance/releases/tag/v0.3.0"
        ),
        "repository_commit": commit,
        "manifest_sha256": "b" * 64,
        "input_set_sha256": "c" * 64,
    }


class PublishedFrameworkReleaseTests(unittest.TestCase):
    def release_fixture(
        self, root: Path, commit: str
    ) -> tuple[Path, Path, dict[str, object]]:
        version = RELEASE_MANIFEST.read_release_version(REPOSITORY_ROOT)
        metadata = {
            "tag_name": f"v{version}",
            "target_commitish": commit,
            "draft": False,
            "prerelease": False,
            "html_url": (
                "https://github.com/reallyme/identity-conformance/releases/tag/"
                f"v{version}"
            ),
        }
        metadata_path = root / "release.json"
        manifest_path = root / "conformance-framework-release.json"
        write_json(metadata_path, metadata)
        write_json(
            manifest_path,
            RELEASE_MANIFEST.build_manifest(commit, REPOSITORY_ROOT),
        )
        return metadata_path, manifest_path, metadata

    def test_exact_published_release_is_accepted(self) -> None:
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata_path, manifest_path, _metadata = self.release_fixture(root, commit)
            selection = PUBLISHED_RELEASE.verify_release(
                REPOSITORY_ROOT,
                commit,
                metadata_path,
                commit,
                manifest_path,
            )
        self.assertEqual(selection["repository_commit"], commit)
        self.assertEqual(
            selection["release_tag"],
            f"v{RELEASE_MANIFEST.read_release_version(REPOSITORY_ROOT)}",
        )
        self.assertRegex(selection["manifest_sha256"], r"^[0-9a-f]{64}$")

    def test_tag_pointing_at_another_commit_is_rejected(self) -> None:
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata_path, manifest_path, _metadata = self.release_fixture(root, commit)
            with self.assertRaises(PUBLISHED_RELEASE.PublishedReleaseError) as raised:
                PUBLISHED_RELEASE.verify_release(
                    REPOSITORY_ROOT,
                    commit,
                    metadata_path,
                    "b" * 40,
                    manifest_path,
                )
        self.assertIs(
            raised.exception.reason,
            PUBLISHED_RELEASE.PublishedReleaseErrorReason.RELEASE_TAG_MISMATCH,
        )

    def test_draft_release_is_rejected(self) -> None:
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata_path, manifest_path, metadata = self.release_fixture(root, commit)
            metadata["draft"] = True
            write_json(metadata_path, metadata)
            with self.assertRaises(PUBLISHED_RELEASE.PublishedReleaseError) as raised:
                PUBLISHED_RELEASE.verify_release(
                    REPOSITORY_ROOT,
                    commit,
                    metadata_path,
                    commit,
                    manifest_path,
                )
        self.assertIs(
            raised.exception.reason,
            PUBLISHED_RELEASE.PublishedReleaseErrorReason.RELEASE_METADATA_INVALID,
        )

    def test_manifest_from_another_candidate_is_rejected(self) -> None:
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata_path, manifest_path, _metadata = self.release_fixture(root, commit)
            changed = json.loads(manifest_path.read_text(encoding="utf-8"))
            changed["repository_commit"] = "b" * 40
            write_json(manifest_path, changed)
            with self.assertRaises(PUBLISHED_RELEASE.PublishedReleaseError) as raised:
                PUBLISHED_RELEASE.verify_release(
                    REPOSITORY_ROOT,
                    commit,
                    metadata_path,
                    commit,
                    manifest_path,
                )
        self.assertIs(
            raised.exception.reason,
            PUBLISHED_RELEASE.PublishedReleaseErrorReason.RELEASE_MANIFEST_INVALID,
        )


class ProductConformanceStatementTests(unittest.TestCase):
    def wallet_coverage(self) -> dict[str, object]:
        return {
            "authority": "internal_engineering",
            "certification_claim": False,
            "minimum_requirements": {
                "total": 14,
                "status_counts": {
                    "implemented": 6,
                    "partial": 5,
                    "operational_required": 1,
                    "delegated": 1,
                    "fixture_seeded": 1,
                },
                "incomplete": [
                    {
                        "minimum_id": f"minimum.incomplete-{index}",
                        "status": status,
                        "limitations": ["Not complete in this candidate."],
                    }
                    for index, status in enumerate(
                        [
                            "partial",
                            "partial",
                            "partial",
                            "partial",
                            "partial",
                            "operational_required",
                            "delegated",
                            "fixture_seeded",
                        ],
                        1,
                    )
                ],
            },
            "declared_cases": {
                "total": 18,
                "executable": 10,
                "non_executable": 8,
                "status_counts": {
                    "unit_covered": 9,
                    "implemented": 1,
                    "fixture_available": 2,
                    "fixture_seeded": 6,
                },
                "non_executable_cases": [
                    {
                        "case_id": f"wallet-core.fixture-{index}",
                        "status": "fixture_available" if index <= 2 else "fixture_seeded",
                    }
                    for index in range(1, 9)
                ],
            },
            "normative_boundaries": {"implemented": 2, "checks": 3},
        }

    def oidf_artifacts(self, protocol: str) -> list[dict[str, object]]:
        plan = STATEMENT.read_object(STATEMENT.OIDF_CERTIFICATION_PLAN_PATH)
        artifacts: list[dict[str, object]] = []
        for selected in plan["plans"]:
            if selected["protocol"] != protocol:
                continue
            role = selected["role"]
            for run in selected["certification_runs"]:
                prefix = f"{role}/{run['profile_id']}"
                artifacts.extend(
                    [
                        {"path": f"{prefix}/summary.json"},
                        {"path": f"{prefix}/suite-export/result.zip"},
                    ]
                )
        return artifacts

    def oidf_components(self) -> list[dict[str, object]]:
        roles = {
            "openid4vci": ["openid4vci_issuer", "openid4vci_wallet"],
            "openid4vp": ["openid4vp_verifier", "openid4vp_wallet"],
            "wallet": ["openid4vci_wallet", "openid4vp_wallet"],
            "ssi": [
                "openid4vci_issuer",
                "openid4vci_wallet",
                "openid4vp_verifier",
                "openid4vp_wallet",
            ],
            "identity": [
                "openid4vci_wallet",
                "openid4vp_verifier",
                "openid4vp_wallet",
            ],
            "cose": [
                "openid4vci_issuer",
                "openid4vci_wallet",
                "openid4vp_verifier",
                "openid4vp_wallet",
            ],
        }
        return [
            {
                "component_id": component_id,
                "repository": f"https://github.com/reallyme/{component_id}",
                "commit": "e" * 40,
                "release_ref": f"reallyme-{component_id}-v2.0.0",
                "release_artifact_sha256": "1" * 64,
                "component_attestation_sha256": "2" * 64,
                "roles": component_roles,
            }
            for component_id, component_roles in roles.items()
        ]

    def oidf_bom_digest(self) -> str:
        return STATEMENT.product_bom_validator.canonical_digest(
            {
                "schema_version": 1,
                "purpose": "reallyme-product-conformance-bom",
                "product_id": "identity",
                "product_version": "2.0.0",
                "product_release_ref": "reallyme-identity-v2.0.0",
                "components": self.oidf_components(),
            }
        )

    def wallet_result(self) -> dict[str, object]:
        result = WALLET_EXECUTION_FIXTURE.valid_result()
        result["framework_revision"] = "a" * 40
        return result

    def build_wallet_statement(self, result: dict[str, object]) -> dict[str, object]:
        return STATEMENT.build_statement(
            framework_selection(),
            (json.dumps(result) + "\n").encode("utf-8"),
            "eudi-wallet-engineering-v1",
            "wallet",
            "reallyme-wallet-v1.0.0",
            "https://github.com/reallyme/wallet",
            "1" * 40,
            "reallyme/wallet",
            "f" * 40,
            123,
            1,
        )

    def test_statement_binds_product_and_framework_releases(self) -> None:
        statement = self.build_wallet_statement(self.wallet_result())
        self.assertEqual(statement["product"]["release_version"], "1.0.0")
        self.assertEqual(
            statement["product"]["candidate_sha256"],
            self.wallet_result()["candidate_sha256"],
        )
        self.assertEqual(statement["framework"]["release_tag"], "v0.3.0")
        self.assertFalse(statement["certification_claim"])
        self.assertEqual(
            statement["coverage"]["declared_cases"]["non_executable"], 8
        )
        self.assertEqual(statement["release_evidence"]["preflight_run_id"], 41)
        self.assertEqual(statement["release_evidence"]["fuzz_run_id"], 31)

    def test_failed_result_is_rejected(self) -> None:
        result = self.wallet_result()
        result["result"] = "failed"
        with self.assertRaises(STATEMENT.StatementError) as raised:
            self.build_wallet_statement(result)
        self.assertIs(
            raised.exception.reason,
            STATEMENT.StatementErrorReason.RESULT_INVALID,
        )

    def test_substituted_product_release_is_rejected(self) -> None:
        result = self.wallet_result()
        changed = copy.deepcopy(result)
        changed["component"]["release_ref"] = "reallyme-wallet-v1.0.1"
        with self.assertRaises(STATEMENT.StatementError) as raised:
            self.build_wallet_statement(changed)
        self.assertIs(
            raised.exception.reason,
            STATEMENT.StatementErrorReason.RESULT_INVALID,
        )

    def test_wallet_statement_rejects_result_with_failed_execution_check(self) -> None:
        result = self.wallet_result()
        result["checks"][0]["result"] = "failed"
        with self.assertRaises(STATEMENT.StatementError) as raised:
            self.build_wallet_statement(result)
        self.assertIs(
            raised.exception.reason,
            STATEMENT.StatementErrorReason.RESULT_INVALID,
        )

    def test_oidf_index_must_bind_the_same_identity_release(self) -> None:
        index = {
            "schema_version": 3,
            "protocol": "openid4vp",
            "framework_revision": "a" * 40,
            "suite_revision": "23353b36957d6466010de767c812d2c91ed37638",
            "product": {
                "product_id": "identity",
                "product_version": "2.0.0",
                "release_ref": "reallyme-identity-v2.0.0",
                "repository": "https://github.com/reallyme/identity",
                "commit": "e" * 40,
            },
            "inputs": {
                "product_component_bom": {
                    "canonical_sha256": self.oidf_bom_digest()
                }
            },
            "artifacts": self.oidf_artifacts("openid4vp"),
            "components": self.oidf_components(),
        }
        statement = STATEMENT.build_statement(
            framework_selection(),
            (json.dumps(index) + "\n").encode("utf-8"),
            "oidf-openid4vp-certification",
            "identity",
            "reallyme-identity-v2.0.0",
            "https://github.com/reallyme/identity",
            "e" * 40,
            "reallyme/identity",
            "f" * 40,
            456,
            2,
        )
        self.assertEqual(statement["product"]["release_version"], "2.0.0")
        self.assertEqual(statement["coverage"]["profile_count"], 6)
        self.assertEqual(statement["coverage"]["module_execution_count"], 161)
        wallet = next(
            component
            for component in statement["composition"]
            if component["component_id"] == "wallet"
        )
        self.assertEqual(wallet["release_ref"], "reallyme-wallet-v2.0.0")

    def test_oidf_statement_rejects_missing_profile_export(self) -> None:
        result = {
            "schema_version": 3,
            "protocol": "openid4vp",
            "framework_revision": "a" * 40,
            "suite_revision": "23353b36957d6466010de767c812d2c91ed37638",
            "product": {
                "product_id": "identity",
                "product_version": "2.0.0",
                "release_ref": "reallyme-identity-v2.0.0",
                "repository": "https://github.com/reallyme/identity",
                "commit": "e" * 40,
            },
            "inputs": {
                "product_component_bom": {
                    "canonical_sha256": self.oidf_bom_digest()
                }
            },
            "artifacts": self.oidf_artifacts("openid4vp")[:-1],
            "components": self.oidf_components(),
        }
        with self.assertRaises(STATEMENT.StatementError) as raised:
            STATEMENT.build_statement(
                framework_selection(),
                (json.dumps(result) + "\n").encode("utf-8"),
                "oidf-openid4vp-certification",
                "identity",
                "reallyme-identity-v2.0.0",
                "https://github.com/reallyme/identity",
                "e" * 40,
                "reallyme/identity",
                "f" * 40,
                456,
                2,
            )
        self.assertIs(
            raised.exception.reason,
            STATEMENT.StatementErrorReason.RESULT_INVALID,
        )

    def test_openid4vci_statement_records_complete_composed_and_wallet_scope(
        self,
    ) -> None:
        result = {
            "schema_version": 3,
            "protocol": "openid4vci",
            "framework_revision": "a" * 40,
            "suite_revision": "23353b36957d6466010de767c812d2c91ed37638",
            "product": {
                "product_id": "identity",
                "product_version": "2.0.0",
                "release_ref": "reallyme-identity-v2.0.0",
                "repository": "https://github.com/reallyme/identity",
                "commit": "e" * 40,
            },
            "inputs": {
                "product_component_bom": {
                    "canonical_sha256": self.oidf_bom_digest()
                }
            },
            "artifacts": self.oidf_artifacts("openid4vci"),
            "components": self.oidf_components(),
        }
        statement = STATEMENT.build_statement(
            framework_selection(),
            (json.dumps(result) + "\n").encode("utf-8"),
            "oidf-openid4vci-certification",
            "identity",
            "reallyme-identity-v2.0.0",
            "https://github.com/reallyme/identity",
            "e" * 40,
            "reallyme/identity",
            "f" * 40,
            456,
            2,
        )
        coverage = statement["coverage"]
        self.assertEqual(coverage["profile_count"], 10)
        self.assertEqual(coverage["module_execution_count"], 390)
        wallet = next(role for role in coverage["roles"] if role["role"] == "wallet")
        self.assertEqual(wallet["profile_count"], 6)
        self.assertEqual(wallet["module_execution_count"], 138)

    def test_oidf_statement_rejects_component_composition_mixed_with_another_bom(
        self,
    ) -> None:
        components = self.oidf_components()
        components[0]["commit"] = "9" * 40
        result = {
            "schema_version": 3,
            "protocol": "openid4vci",
            "framework_revision": "a" * 40,
            "suite_revision": "23353b36957d6466010de767c812d2c91ed37638",
            "product": {
                "product_id": "identity",
                "product_version": "2.0.0",
                "release_ref": "reallyme-identity-v2.0.0",
                "repository": "https://github.com/reallyme/identity",
                "commit": "e" * 40,
            },
            "inputs": {
                "product_component_bom": {
                    "canonical_sha256": self.oidf_bom_digest()
                }
            },
            "artifacts": self.oidf_artifacts("openid4vci"),
            "components": components,
        }
        with self.assertRaises(STATEMENT.StatementError) as raised:
            STATEMENT.build_statement(
                framework_selection(),
                (json.dumps(result) + "\n").encode("utf-8"),
                "oidf-openid4vci-certification",
                "identity",
                "reallyme-identity-v2.0.0",
                "https://github.com/reallyme/identity",
                "e" * 40,
                "reallyme/identity",
                "f" * 40,
                456,
                2,
            )
        self.assertIs(
            raised.exception.reason,
            STATEMENT.StatementErrorReason.RESULT_INVALID,
        )


if __name__ == "__main__":
    unittest.main()
