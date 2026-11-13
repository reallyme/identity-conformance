# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = ROOT / "scripts/verify_eudi_identity_sdk_execution_result.py"
    specification = importlib.util.spec_from_file_location(
        "verify_eudi_identity_sdk_execution_result", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("execution-result verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()


def valid_bom(*, published: bool = False) -> dict[str, object]:
    identity: dict[str, object] = {
        "component_id": "identity",
        "repository": "https://github.com/reallyme/identity",
        "commit": "b" * 40,
        "roles": [],
        "adapter_contracts": [],
    }
    value: dict[str, object] = {
        "schema_version": 3,
        "purpose": "reallyme-product-conformance-bom",
        "product_id": "identity",
        "product_version": "0.1.1",
        "product_component_id": "identity",
        "components": [identity],
    }
    if published:
        identity["release_id"] = 123456789
        identity["release_ref"] = "reallyme-identity-v0.1.1"
        value["product_release_id"] = 123456789
        value["product_release_ref"] = "reallyme-identity-v0.1.1"
    return value


def valid_result(
    *, published: bool = False
) -> tuple[dict[str, object], dict[str, object]]:
    bom = valid_bom(published=published)
    components = [
        {
            "component_id": component,
            "repository": repository,
            "release_id": release_id,
            "release_ref": f"reallyme-{component}-v{version}",
            "commit": commit * 40,
            "roles": [],
            "adapter_contracts": [],
        }
        for component, repository, release_id, version, commit in (
            ("ssi", "https://github.com/reallyme/ssi", 101, "0.6.2", "c"),
            (
                "openid4vci",
                "https://github.com/reallyme/openid4vci",
                102,
                "0.3.2",
                "d",
            ),
            (
                "openid4vp",
                "https://github.com/reallyme/openid4vp",
                103,
                "0.3.1",
                "e",
            ),
        )
    ]
    bom["components"].extend(copy.deepcopy(components))
    result_components = [
        {
            key: value
            for key, value in component.items()
            if key not in {"roles", "adapter_contracts"}
        }
        | {"source_archive_sha256": f"{index + 2:x}" * 64}
        for index, component in enumerate(components)
    ]
    candidate: dict[str, object] = {
        "mode": "published" if published else "candidate",
        "repository": "https://github.com/reallyme/identity",
        "version": "0.1.1",
        "commit": "b" * 40,
        "source_archive_sha256": "8" * 64,
    }
    if published:
        candidate["release_id"] = 123456789
        candidate["release_ref"] = "reallyme-identity-v0.1.1"
    result = {
        "schema": "reallyme.identity.eudi_identity_sdk_execution_result.v1",
        "plan_id": "eudi-identity-sdk-v1",
        "result": "passed",
        "created_at": "2026-11-13T07:00:00Z",
        "framework": {
            "version": "0.3.2",
            "commit": "a" * 40,
            "manifest_sha256": "6" * 64,
            "input_set_sha256": "7" * 64,
        },
        "execution": {
            "workflow_repository": "reallyme/identity",
            "workflow_revision": "f" * 40,
            "run_id": 43129341459,
            "run_attempt": 1,
        },
        "candidate": candidate,
        "components": result_components,
        "product_component_bom_sha256": VERIFIER.product_bom.canonical_digest(bom),
        "candidate_cargo_lock_sha256": "1" * 64,
        "source_locks": {
            "eudi_sources_sha256": "2" * 64,
            "eudi_legal_sources_sha256": "3" * 64,
            "eudi_publications_sha256": "4" * 64,
            "normative_sources_sha256": "5" * 64,
        },
        "coverage": dict(VERIFIER.EXPECTED_COVERAGE),
        "lanes": sorted(VERIFIER.EXPECTED_LANES),
        "evidence_policy": dict(VERIFIER.EXPECTED_POLICY),
    }
    return result, bom


class EudiIdentitySdkExecutionResultTests(unittest.TestCase):
    def test_valid_candidate_result_passes(self) -> None:
        result, bom = valid_result()
        VERIFIER.validate_result(result, bom)

    def test_valid_published_result_passes(self) -> None:
        result, bom = valid_result(published=True)
        VERIFIER.validate_result(result, bom)

    def test_substituted_component_repository_is_rejected(self) -> None:
        result, bom = valid_result()
        result["components"][0]["repository"] = "https://github.com/example/ssi"
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.ResultErrorReason.COMPONENT_BINDING_INVALID,
        )

    def test_duplicate_component_is_rejected(self) -> None:
        result, bom = valid_result()
        result["components"][2] = copy.deepcopy(result["components"][1])
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.ResultErrorReason.COMPONENT_BINDING_INVALID,
        )

    def test_component_bom_digest_cannot_be_substituted(self) -> None:
        result, bom = valid_result()
        result["components"][0]["commit"] = "9" * 40
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.ResultErrorReason.COMPONENT_BINDING_INVALID,
        )

    def test_component_bom_digest_is_order_independent(self) -> None:
        result, bom = valid_result()
        result["components"].reverse()
        VERIFIER.validate_result(result, bom)

    def test_workflow_revision_is_separate_from_candidate_commit(self) -> None:
        result, bom = valid_result()
        self.assertNotEqual(
            result["execution"]["workflow_revision"], result["candidate"]["commit"]
        )
        VERIFIER.validate_result(result, bom)

    def test_missing_lane_is_rejected(self) -> None:
        result, bom = valid_result()
        result["lanes"].pop()
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason, VERIFIER.ResultErrorReason.RESULT_INVALID
        )

    def test_external_evidence_cannot_be_counted_as_code(self) -> None:
        result, bom = valid_result()
        result["evidence_policy"][
            "external_evidence_rows_counted_as_code_passes"
        ] = True
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason, VERIFIER.ResultErrorReason.RESULT_INVALID
        )

    def test_published_ref_must_match_candidate_version(self) -> None:
        result, bom = valid_result(published=True)
        result["candidate"]["release_ref"] = "reallyme-identity-v0.1.0"
        with self.assertRaises(VERIFIER.ResultError) as raised:
            VERIFIER.validate_result(result, bom)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.ResultErrorReason.CANDIDATE_BINDING_INVALID,
        )

    def test_schema_is_current_json_schema(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/eudi-identity-sdk-execution-result.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )


if __name__ == "__main__":
    unittest.main()
