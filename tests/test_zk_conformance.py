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


ADAPTER = load_script("verify_zk_adapter", "scripts/verify_zk_adapter.py")
RUNNER = load_script("run_zk_conformance", "scripts/run_zk_conformance.py")
RESULT = load_script(
    "verify_zk_execution_result", "scripts/verify_zk_execution_result.py"
)


def valid_deployment() -> dict[str, object]:
    _plan, adapter = ADAPTER.load_contract()
    requirement = adapter["component_requirement"]
    return {
        "schema": "reallyme.identity.zk_deployment_manifest.v1",
        "plan_id": "zk-presentation-proofs-v1",
        "component": {
            "component_id": requirement["component_id"],
            "repository": requirement["repository"],
            "release_ref": "v1.0.0",
            "commit": "1" * 40,
        },
        "release_artifact": {
            "artifact_id": "zk-release-bundle",
            "kind": "archive",
            "sha256": "a" * 64,
        },
        "component_attestation_sha256": "b" * 64,
        "evidence_policy": ADAPTER.EXPECTED_POLICY,
    }


def valid_result() -> dict[str, object]:
    plan, adapter = ADAPTER.load_contract()
    check_kinds = {
        "source.toolchain-lock": "source",
        "source.provider-manifest": "source",
        "source.cargo-lock": "source",
        "artifact.release-bundle": "artifact",
        **{
            f"attestation.{category}": "attestation"
            for category in ADAPTER.EXPECTED_ATTESTATION_CATEGORIES
        },
        **{f"cargo.{package}": "cargo" for package in ADAPTER.EXPECTED_PACKAGES},
    }
    deployment = valid_deployment()
    result = {
        "schema": "reallyme.identity.zk_execution_result.v1",
        "plan_id": "zk-presentation-proofs-v1",
        "result": "passed",
        "created_at": "2026-11-11T12:00:00Z",
        "framework_revision": "2" * 40,
        "workflow_revision": "3" * 40,
        "candidate_sha256": "0" * 64,
        "component": deployment["component"],
        "release_artifact_sha256": "a" * 64,
        "component_attestation_sha256": "b" * 64,
        "checks": [
            {"check_id": check_id, "kind": kind, "result": "passed"}
            for check_id, kind in sorted(check_kinds.items())
        ],
        "assertions": [
            {
                "assertion_id": assertion["assertion_id"],
                "check_ids": assertion["required_checks"],
                "result": "passed",
            }
            for assertion in plan["assertions"]
        ],
        "evidence_policy": ADAPTER.EXPECTED_POLICY,
    }
    candidate = {
        "plan_id": result["plan_id"],
        "component": result["component"],
        "release_artifact": deployment["release_artifact"],
        "component_attestation_sha256": result["component_attestation_sha256"],
    }
    result["candidate_sha256"] = RUNNER.candidate_digest(candidate)
    return result


class ZkConformanceTests(unittest.TestCase):
    def test_checked_plan_and_adapter_are_valid(self) -> None:
        plan, adapter = ADAPTER.load_contract()
        self.assertEqual(
            plan["required_components"], [adapter["component_requirement"]]
        )

    def test_valid_deployment_is_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        artifact = RUNNER.validate_deployment(valid_deployment(), adapter)
        self.assertEqual(artifact["artifact_id"], "zk-release-bundle")

    def test_two_caller_selected_zk_commits_are_accepted(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        first = valid_deployment()
        second = copy.deepcopy(first)
        second["component"]["commit"] = "f" * 40
        RUNNER.validate_deployment(first, adapter)
        RUNNER.validate_deployment(second, adapter)

    def test_sensitive_evidence_policy_is_rejected(self) -> None:
        _plan, adapter = ADAPTER.load_contract()
        changed = valid_deployment()
        changed["evidence_policy"] = copy.deepcopy(changed["evidence_policy"])
        changed["evidence_policy"]["witness_material_retained"] = True
        with self.assertRaises(RUNNER.ZkRunnerError):
            RUNNER.validate_deployment(changed, adapter)

    def test_valid_execution_result_is_accepted(self) -> None:
        RESULT.verify_result(valid_result())

    def test_failed_check_is_rejected(self) -> None:
        changed = valid_result()
        changed["checks"][0]["result"] = "failed"
        with self.assertRaises(RESULT.runner.ZkRunnerError):
            RESULT.verify_result(changed)

    def test_assertion_cannot_drop_required_check(self) -> None:
        changed = valid_result()
        changed["assertions"][0]["check_ids"] = ["source.toolchain-lock"]
        with self.assertRaises(RESULT.runner.ZkRunnerError):
            RESULT.verify_result(changed)


if __name__ == "__main__":
    unittest.main()
