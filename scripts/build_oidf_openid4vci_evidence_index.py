#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Create a bounded evidence index for complete OpenID4VCI certification runs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import build_oidf_evidence_index as common  # noqa: E402


def write_index(
    result_root: Path,
    framework_revision: str,
    workflow_revision: str,
    suite_revision: str,
    product_bom: Path,
    deployment_manifest: Path,
    certification_plan: Path,
    profile_matrix: Path,
    issuer_config: Path,
    wallet_config: Path,
    issuer_binary: Path,
    wallet_binary: Path,
    issuer_deployment_artifact: Path,
    wallet_deployment_artifact: Path,
    issuer_base_url: str,
    wallet_harness_endpoint: str,
    wallet_harness_health_endpoint: str,
) -> None:
    if common.GIT_COMMIT.fullmatch(framework_revision) is None:
        common.fail("framework_revision_invalid")
    if common.GIT_COMMIT.fullmatch(workflow_revision) is None:
        common.fail("workflow_revision_invalid")
    if common.GIT_COMMIT.fullmatch(suite_revision) is None:
        common.fail("suite_revision_invalid")
    issuer_binary_digest, issuer_binary_size = common.hash_file(
        issuer_binary, common.MAX_ARTIFACT_BYTES
    )
    wallet_binary_digest, wallet_binary_size = common.hash_file(
        wallet_binary, common.MAX_ARTIFACT_BYTES
    )
    issuer_deployment_digest, issuer_deployment_size = common.hash_file(
        issuer_deployment_artifact, common.MAX_ARTIFACT_BYTES
    )
    wallet_deployment_digest, wallet_deployment_size = common.hash_file(
        wallet_deployment_artifact, common.MAX_ARTIFACT_BYTES
    )
    artifacts = common.collect_artifacts(result_root)
    deployment_digest = common.retained_deployment_digest(
        result_root, deployment_manifest, artifacts
    )
    product_bom_digest = common.retained_product_bom_digest(
        result_root, product_bom, artifacts
    )
    value: dict[str, object] = {
        "schema_version": 2,
        "protocol": "openid4vci",
        "framework_revision": framework_revision,
        "workflow_revision": workflow_revision,
        "suite_revision": suite_revision,
        "inputs": {
            "product_component_bom": product_bom_digest,
            "deployment_manifest": deployment_digest,
            "certification_plan": common.input_digest(certification_plan),
            "openid4vci_profile_matrix": common.input_digest(profile_matrix),
            "issuer_config": common.input_digest(issuer_config),
            "wallet_config": common.input_digest(wallet_config),
            "issuer_binary": {
                "sha256": issuer_binary_digest,
                "size_bytes": issuer_binary_size,
            },
            "wallet_binary": {
                "sha256": wallet_binary_digest,
                "size_bytes": wallet_binary_size,
            },
            "issuer_deployment_artifact": {
                "sha256": issuer_deployment_digest,
                "size_bytes": issuer_deployment_size,
            },
            "wallet_deployment_artifact": {
                "sha256": wallet_deployment_digest,
                "size_bytes": wallet_deployment_size,
            },
        },
        "deployment": {
            "issuer_base_url": common.deployment_endpoint(issuer_base_url),
            "wallet_harness_endpoint": common.deployment_endpoint(
                wallet_harness_endpoint
            ),
            "wallet_harness_health_endpoint": common.deployment_endpoint(
                wallet_harness_health_endpoint
            ),
        },
        "artifacts": artifacts,
    }
    common.write_new_index(result_root / common.INDEX_FILENAME, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", required=True, type=Path)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--product-component-bom", required=True, type=Path)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--certification-plan", required=True, type=Path)
    parser.add_argument("--profile-matrix", required=True, type=Path)
    parser.add_argument("--issuer-config", required=True, type=Path)
    parser.add_argument("--wallet-config", required=True, type=Path)
    parser.add_argument("--issuer-binary", required=True, type=Path)
    parser.add_argument("--wallet-binary", required=True, type=Path)
    parser.add_argument("--issuer-deployment-artifact", required=True, type=Path)
    parser.add_argument("--wallet-deployment-artifact", required=True, type=Path)
    parser.add_argument("--issuer-base-url", required=True)
    parser.add_argument("--wallet-harness-endpoint", required=True)
    parser.add_argument("--wallet-harness-health-endpoint", required=True)
    args = parser.parse_args()
    if not args.result_root.is_dir() or args.result_root.is_symlink():
        common.fail("evidence_directory_invalid")
    write_index(
        args.result_root,
        args.framework_revision,
        args.workflow_revision,
        args.suite_revision,
        args.product_component_bom,
        args.deployment_manifest,
        args.certification_plan,
        args.profile_matrix,
        args.issuer_config,
        args.wallet_config,
        args.issuer_binary,
        args.wallet_binary,
        args.issuer_deployment_artifact,
        args.wallet_deployment_artifact,
        args.issuer_base_url,
        args.wallet_harness_endpoint,
        args.wallet_harness_health_endpoint,
    )
    print("OpenID4VCI evidence index created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
