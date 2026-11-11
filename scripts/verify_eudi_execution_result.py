#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the closed shape and pass semantics of an EUDI execution result."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_eudi_adapter as adapter_verifier  # noqa: E402
import run_eudi_relying_party_conformance as runner  # noqa: E402


IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


def verify_result(value: dict[str, object]) -> None:
    expected_keys = {
        "schema",
        "plan_id",
        "mode",
        "result",
        "created_at",
        "components",
        "artifact_sha256",
        "trust_artifact_sha256",
        "credential_authority_artifact_sha256",
        "component_attestation_sha256",
        "source_locks",
        "upstream_sources",
        "checks",
        "assertions",
        "evidence_policy",
    }
    if set(value) != expected_keys:
        raise adapter_verifier.AdapterError(
            adapter_verifier.AdapterErrorReason.INVALID_JSON
        )
    if (
        value["schema"] != "reallyme.identity.eudi_execution_result.v1"
        or value["plan_id"] != "eudi-relying-party-control-plane-v1"
        or value["mode"] not in {"engineering", "deployed", "live_ts5"}
        or value["result"] != "passed"
        or not isinstance(value["created_at"], str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value["created_at"],
        ) is None
        or not isinstance(value["artifact_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["artifact_sha256"]) is None
        or not isinstance(value["trust_artifact_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["trust_artifact_sha256"]) is None
        or not isinstance(value["credential_authority_artifact_sha256"], str)
        or re.fullmatch(
            r"[0-9a-f]{64}", value["credential_authority_artifact_sha256"]
        )
        is None
        or not isinstance(value["component_attestation_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["component_attestation_sha256"])
        is None
    ):
        raise adapter_verifier.AdapterError(
            adapter_verifier.AdapterErrorReason.INVALID_JSON
        )
    source_locks = value["source_locks"]
    if (
        not isinstance(source_locks, dict)
        or set(source_locks)
        != {
            "eudi_sources_sha256",
            "eudi_legal_sources_sha256",
            "eudi_publications_sha256",
        }
        or any(
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in source_locks.values()
        )
    ):
        raise adapter_verifier.AdapterError(
            adapter_verifier.AdapterErrorReason.INVALID_JSON
        )
    components = value["components"]
    if not isinstance(components, list) or len(components) != 3:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    observed_components: set[str] = set()
    for raw_component in components:
        if not isinstance(raw_component, dict) or set(raw_component) != {"component_id", "repository", "commit"}:
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        component_id = raw_component["component_id"]
        if (
            not isinstance(component_id, str)
            or component_id in observed_components
            or not isinstance(raw_component["repository"], str)
            or not isinstance(raw_component["commit"], str)
            or adapter_verifier.GIT_COMMIT.fullmatch(raw_component["commit"]) is None
        ):
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        if component_id == "candidate":
            if runner.CANDIDATE_REPOSITORY.fullmatch(raw_component["repository"]) is None:
                raise adapter_verifier.AdapterError(
                    adapter_verifier.AdapterErrorReason.INVALID_JSON
                )
        elif (
            runner.EXPECTED_COMPONENT_REPOSITORIES.get(component_id)
            != raw_component["repository"]
        ):
            raise adapter_verifier.AdapterError(
                adapter_verifier.AdapterErrorReason.INVALID_JSON
            )
        observed_components.add(component_id)
    if observed_components != {"candidate", *runner.EXPECTED_COMPONENT_REPOSITORIES}:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    bundle = adapter_verifier.load_contract_bundle()
    upstream_sources = value["upstream_sources"]
    if not isinstance(upstream_sources, list) or len(upstream_sources) != 4:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    observed_sources: set[str] = set()
    for raw_source in upstream_sources:
        if not isinstance(raw_source, dict) or set(raw_source) != {"source_id", "repository", "ref", "commit"}:
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        source_id = raw_source["source_id"]
        if (
            not isinstance(source_id, str)
            or source_id in observed_sources
            or source_id not in adapter_verifier.EXPECTED_EXECUTION_SOURCES
            or any(
                raw_source.get(field) != bundle.upstream_sources[source_id].get(field)
                for field in ("repository", "ref", "commit")
            )
        ):
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        observed_sources.add(source_id)
    if observed_sources != adapter_verifier.EXPECTED_EXECUTION_SOURCES:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    checks = value["checks"]
    assertions = value["assertions"]
    if not isinstance(checks, list) or not checks or not isinstance(assertions, list) or len(assertions) != 19:
        raise adapter_verifier.AdapterError(
            adapter_verifier.AdapterErrorReason.INVALID_JSON
        )
    check_ids: set[str] = set()
    for raw_check in checks:
        if not isinstance(raw_check, dict) or set(raw_check) != {"check_id", "kind", "result"}:
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        check_id = raw_check["check_id"]
        if (
            not isinstance(check_id, str)
            or IDENTIFIER.fullmatch(check_id) is None
            or check_id in check_ids
            or raw_check["result"] != "passed"
            or raw_check["kind"]
            not in {"attestation", "binary_probe", "service_probe", "live_probe"}
        ):
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        check_ids.add(check_id)
    required_attestation_check_ids, _ = runner.required_attestation_checks(
        bundle.plan, bundle.adapter
    )
    if not required_attestation_check_ids.issubset(check_ids):
        raise adapter_verifier.AdapterError(
            adapter_verifier.AdapterErrorReason.INVALID_JSON
        )
    assertion_ids: set[str] = set()
    for raw_assertion in assertions:
        if not isinstance(raw_assertion, dict) or set(raw_assertion) != {"family_id", "assertion_id", "result", "check_ids"}:
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        assertion_id = raw_assertion["assertion_id"]
        referenced = raw_assertion["check_ids"]
        if (
            not isinstance(assertion_id, str)
            or IDENTIFIER.fullmatch(assertion_id) is None
            or assertion_id in assertion_ids
            or raw_assertion["result"] != "passed"
            or not isinstance(referenced, list)
            or not referenced
            or len(referenced) != len(set(referenced))
            or not set(referenced).issubset(check_ids)
        ):
            raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
        assertion_ids.add(assertion_id)
    if assertion_ids != adapter_verifier.plan_verifier.REQUIRED_ASSERTIONS:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    has_live_check = "live_probe.ts5_public_reads" in check_ids
    if (value["mode"] == "live_ts5") is not has_live_check:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    service_check_ids = {
        "service_probe.trust_service",
        "service_probe.credential_authority",
    }
    has_service_checks = service_check_ids.issubset(check_ids)
    if (value["mode"] in {"deployed", "live_ts5"}) is not has_service_checks:
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)
    policy = value["evidence_policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "contains_sensitive_data",
        "raw_process_output_retained",
        "transaction_content_retained",
        "private_key_material_retained",
        "credentials_retained",
    } or any(policy_value is not False for policy_value in policy.values()):
        raise adapter_verifier.AdapterError(adapter_verifier.AdapterErrorReason.INVALID_JSON)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_result(adapter_verifier.load_object(args.result))
    except adapter_verifier.AdapterError as error:
        adapter_verifier.fail(error.reason)
    print("EUDI execution result valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
