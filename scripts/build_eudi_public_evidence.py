#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Create a public-safe commitment from a reviewed private EUDI result."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_eudi_relying_party_conformance as runner  # noqa: E402
import build_release_manifest as framework_release  # noqa: E402
import verify_eudi_adapter as adapter_verifier  # noqa: E402
import verify_eudi_execution_result as result_verifier  # noqa: E402


REVIEWER_ROLE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
RELEASE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"
)
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


def require_review(role: str, reviewed_at: str) -> dict[str, object]:
    if REVIEWER_ROLE.fullmatch(role) is None or TIMESTAMP.fullmatch(reviewed_at) is None:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    return {"completed": True, "reviewer_role": role, "reviewed_at": reviewed_at}


def verify_public_evidence(evidence: dict[str, object]) -> None:
    if set(evidence) != {
        "schema",
        "classification",
        "authority",
        "certification_claim",
        "plan_id",
        "framework",
        "candidate",
        "execution",
        "source_locks",
        "upstream_sources",
        "assertions",
        "redaction_review",
        "public_disclosure_review",
    }:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    if (
        evidence["schema"] != "reallyme.identity.eudi_public_evidence.v1"
        or evidence["classification"] != "public"
        or evidence["authority"] != "internal_non_certification_evidence"
        or evidence["certification_claim"] is not False
        or evidence["plan_id"] != "eudi-relying-party-control-plane-v1"
    ):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    framework = evidence["framework"]
    candidate = evidence["candidate"]
    execution = evidence["execution"]
    if (
        not isinstance(framework, dict)
        or set(framework) != {"release_version", "manifest_sha256"}
        or not isinstance(framework["release_version"], str)
        or RELEASE_VERSION.fullmatch(framework["release_version"]) is None
        or not isinstance(candidate, dict)
        or set(candidate)
        != {
            "artifact_sha256",
            "trust_artifact_sha256",
            "credential_authority_artifact_sha256",
            "private_source_attestation_sha256",
        }
        or not isinstance(execution, dict)
        or set(execution) != {"mode", "private_result_sha256"}
        or execution["mode"] not in runner.EXECUTION_MODES
    ):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    digests = [
        framework["manifest_sha256"],
        candidate["artifact_sha256"],
        candidate["trust_artifact_sha256"],
        candidate["credential_authority_artifact_sha256"],
        candidate["private_source_attestation_sha256"],
        execution["private_result_sha256"],
    ]
    if any(not isinstance(value, str) or runner.SHA256.fullmatch(value) is None for value in digests):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    source_locks = evidence["source_locks"]
    if (
        not isinstance(source_locks, dict)
        or set(source_locks)
        != {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
        }
        or any(
            not isinstance(value, str) or runner.SHA256.fullmatch(value) is None
            for value in source_locks.values()
        )
    ):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    bundle = adapter_verifier.load_contract_bundle()
    expected_upstream = [
        {
            "source_id": source_id,
            "repository": bundle.upstream_sources[source_id]["repository"],
            "ref": bundle.upstream_sources[source_id]["ref"],
            "commit": bundle.upstream_sources[source_id]["commit"],
        }
        for source_id in sorted(adapter_verifier.EXPECTED_EXECUTION_SOURCES)
    ]
    if evidence["upstream_sources"] != expected_upstream:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    assertions = evidence["assertions"]
    expected_families = {
        assertion["assertion_id"]: family["family_id"]
        for family in bundle.plan["assertion_families"]
        for assertion in family["assertions"]
    }
    if not isinstance(assertions, list) or len(assertions) != len(expected_families):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    observed_assertions: set[str] = set()
    for assertion in assertions:
        if (
            not isinstance(assertion, dict)
            or set(assertion) != {"family_id", "assertion_id", "result", "evidence_strength"}
            or not isinstance(assertion["assertion_id"], str)
            or assertion["assertion_id"] in observed_assertions
            or assertion["family_id"] != expected_families.get(assertion["assertion_id"])
            or assertion["result"] != "passed"
            or assertion["evidence_strength"] != "attestation_only"
        ):
            raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
        observed_assertions.add(assertion["assertion_id"])
    if observed_assertions != set(expected_families):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    for review_name in ("redaction_review", "public_disclosure_review"):
        review = evidence[review_name]
        if (
            not isinstance(review, dict)
            or set(review) != {"completed", "reviewer_role", "reviewed_at"}
            or review["completed"] is not True
            or not isinstance(review["reviewer_role"], str)
            or REVIEWER_ROLE.fullmatch(review["reviewer_role"]) is None
            or not isinstance(review["reviewed_at"], str)
            or TIMESTAMP.fullmatch(review["reviewed_at"]) is None
        ):
            raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    encoded = json.dumps(evidence, sort_keys=True)
    if "https://github.com/reallyme/" in encoded or '"component_id"' in encoded:
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)


def build_evidence(
    result: dict[str, object],
    result_sha256: str,
    framework_manifest: dict[str, object],
    framework_manifest_sha256: str,
    private_source_attestation_sha256: str,
    redaction_review: dict[str, object],
    disclosure_review: dict[str, object],
) -> dict[str, object]:
    result_verifier.verify_result(result)
    try:
        framework_release.validate_manifest(framework_manifest)
    except framework_release.ManifestError as error:
        raise runner.RunnerError(
            runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST
        ) from error
    if any(
            runner.SHA256.fullmatch(value) is None
            for value in (
                result_sha256,
                framework_manifest_sha256,
                private_source_attestation_sha256,
            )
        ):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    assertions = result.get("assertions")
    upstream_sources = result.get("upstream_sources")
    if not isinstance(assertions, list) or not isinstance(upstream_sources, list):
        raise runner.RunnerError(runner.RunnerErrorReason.INVALID_DEPLOYMENT_MANIFEST)
    evidence = {
        "schema": "reallyme.identity.eudi_public_evidence.v1",
        "classification": "public",
        "authority": "internal_non_certification_evidence",
        "certification_claim": False,
        "plan_id": "eudi-relying-party-control-plane-v1",
        "framework": {
            "release_version": framework_manifest["release_version"],
            "manifest_sha256": framework_manifest_sha256,
        },
        "candidate": {
            "artifact_sha256": result["artifact_sha256"],
            "trust_artifact_sha256": result["trust_artifact_sha256"],
            "credential_authority_artifact_sha256": result[
                "credential_authority_artifact_sha256"
            ],
            "private_source_attestation_sha256": private_source_attestation_sha256,
        },
        "execution": {
            "mode": result["mode"],
            "private_result_sha256": result_sha256,
        },
        "source_locks": result["source_locks"],
        "upstream_sources": upstream_sources,
        "assertions": [
            {
                "family_id": assertion["family_id"],
                "assertion_id": assertion["assertion_id"],
                "result": assertion["result"],
                "evidence_strength": assertion["evidence_strength"],
            }
            for assertion in assertions
        ],
        "redaction_review": redaction_review,
        "public_disclosure_review": disclosure_review,
    }
    verify_public_evidence(evidence)
    return evidence


def write_evidence(output: Path, evidence: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise runner.RunnerError(runner.RunnerErrorReason.RESULT_PATH_EXISTS)
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=".eudi-public-evidence-", delete=False
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
    parser.add_argument("--private-result", required=True, type=Path)
    parser.add_argument("--framework-manifest", required=True, type=Path)
    parser.add_argument("--private-source-attestation", required=True, type=Path)
    parser.add_argument("--redaction-reviewer-role", required=True)
    parser.add_argument("--redaction-reviewed-at", required=True)
    parser.add_argument("--disclosure-reviewer-role", required=True)
    parser.add_argument("--disclosure-reviewed-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = adapter_verifier.load_object(args.private_result)
        framework_manifest = adapter_verifier.load_object(args.framework_manifest)
        evidence = build_evidence(
            result,
            runner.hash_regular_file(args.private_result),
            framework_manifest,
            runner.hash_regular_file(args.framework_manifest),
            runner.hash_regular_file(args.private_source_attestation),
            require_review(args.redaction_reviewer_role, args.redaction_reviewed_at),
            require_review(args.disclosure_reviewer_role, args.disclosure_reviewed_at),
        )
        write_evidence(args.output, evidence)
    except adapter_verifier.AdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.RunnerError as error:
        runner.fail(error.reason)
    print("wrote public-safe EUDI evidence commitment")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
