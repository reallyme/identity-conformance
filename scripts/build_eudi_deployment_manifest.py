#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a digest-bound deployment manifest for the EUDI adapter."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_eudi_relying_party_conformance as runner  # noqa: E402
import verify_eudi_adapter as adapter_verifier  # noqa: E402


def build_manifest(
    mode: str,
    candidate_source: Path,
    platform_source: Path,
    ssi_source: Path,
    binary: Path,
    trust_artifact: Path,
    credential_authority_artifact: Path,
    component_attestation: Path,
) -> dict[str, object]:
    sources = {
        "candidate": candidate_source.resolve(),
        "platform": platform_source.resolve(),
        "ssi": ssi_source.resolve(),
    }
    if mode not in {"engineering", "deployed", "live_ts5"}:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    if len({source.parent for source in sources.values()}) != 1:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_COMPONENT_LAYOUT)
    components: list[dict[str, str]] = []
    for component_id in ("candidate", "platform", "ssi"):
        source = sources[component_id]
        commit = adapter_verifier.git_output(source, "rev-parse", "HEAD")
        adapter_verifier.verify_checkout(source, commit)
        if component_id == "candidate":
            repository = adapter_verifier.git_output(
                source, "config", "--get", "remote.origin.url"
            )
            if runner.CANDIDATE_REPOSITORY.fullmatch(repository) is None:
                raise runner.RunnerError(
                    runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST
                )
        else:
            repository = runner.EXPECTED_COMPONENT_REPOSITORIES[component_id]
        components.append(
            {
                "component_id": component_id,
                "repository": repository,
                "commit": commit,
            }
        )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "purpose": "eudi-relying-party-conformance-deployment",
        "plan_id": "eudi-relying-party-control-plane-v1",
        "mode": mode,
        "components": components,
        "artifact": {"kind": "binary", "sha256": runner.hash_regular_file(binary)},
        "trust_artifact": {
            "kind": "binary",
            "sha256": runner.hash_regular_file(trust_artifact),
        },
        "credential_authority_artifact": {
            "kind": "deployment_bundle",
            "sha256": runner.hash_regular_file(credential_authority_artifact),
        },
        "component_attestation_sha256": runner.hash_regular_file(
            component_attestation
        ),
        "upstream_lock_sha256": runner.hash_regular_file(
            adapter_verifier.UPSTREAM_LOCK_PATH
        ),
        "legal_sources_lock_sha256": runner.hash_regular_file(
            adapter_verifier.LEGAL_SOURCES_LOCK_PATH
        ),
        "publications_lock_sha256": runner.hash_regular_file(
            adapter_verifier.PUBLICATIONS_LOCK_PATH
        ),
        "evidence_policy": {
            "raw_process_output_retained": False,
            "transaction_content_retained": False,
            "private_key_material_retained": False,
            "credentials_retained": False,
        },
    }
    runner.validate_deployment_manifest(manifest)
    return manifest


def write_manifest(output: Path, manifest: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise runner.RunnerError(runner.RunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".eudi-deployment-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise runner.RunnerError(runner.RunnerErrorReason.RESULT_WRITE_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("engineering", "deployed", "live_ts5"), required=True
    )
    parser.add_argument("--candidate-source", required=True, type=Path)
    parser.add_argument("--platform-source", required=True, type=Path)
    parser.add_argument("--ssi-source", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--trust-artifact", required=True, type=Path)
    parser.add_argument("--credential-authority-artifact", required=True, type=Path)
    parser.add_argument("--component-attestation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = build_manifest(
            args.mode,
            args.candidate_source,
            args.platform_source,
            args.ssi_source,
            args.binary,
            args.trust_artifact,
            args.credential_authority_artifact,
            args.component_attestation,
        )
        write_manifest(args.output, manifest)
    except adapter_verifier.AdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.RunnerError as error:
        runner.fail(error.reason)
    print("wrote EUDI deployment manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
