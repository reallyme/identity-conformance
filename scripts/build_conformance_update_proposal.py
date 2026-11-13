#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a versioned, review-gated proposal for upstream baseline changes."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import build_oidf_update_proposal as oidf  # noqa: E402
import check_pin_freshness as freshness  # noqa: E402
import render_conformance_catalog as catalog  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
UPDATE_POLICY = REPOSITORY_ROOT / "references/upstream-update-policy.json"


class ProposalError(Exception):
    """A stable proposal failure that does not expose upstream response data."""


def fail(reason: str) -> NoReturn:
    print(f"conformance update proposal failed: {reason}", file=sys.stderr)
    raise SystemExit(78)


def next_patch_version(version: str) -> str:
    match = catalog.SEMANTIC_VERSION.fullmatch(version)
    if match is None:
        raise ProposalError("framework_version_invalid")
    major, minor, patch = (int(part) for part in match.groups())
    if patch >= 999_999:
        raise ProposalError("framework_version_exhausted")
    return f"{major}.{minor}.{patch + 1}"


def update_policy() -> dict[str, object]:
    value = freshness.read_object(UPDATE_POLICY)
    expected_keys = {
        "$comment",
        "schema",
        "schedule",
        "source_strategies",
        "overrides",
        "candidate_requirements",
    }
    strategies = value.get("source_strategies")
    overrides = value.get("overrides")
    schedule = value.get("schedule")
    requirements = value.get("candidate_requirements")
    if (
        set(value) != expected_keys
        or value.get("schema") != "reallyme.identity.upstream_update_policy.v1"
        or schedule != {"cadence": "weekly", "automatic_publication": False}
        or strategies
        != {
            "latest_release": "tagged_release_candidate",
            "latest_tag": "tagged_release_candidate",
            "default_branch": "branch_snapshot_review",
        }
        or overrides
        != {
            "monitor_only_coverage_class": "monitor_only",
            "immutable_publication_change": "publication_integrity_review",
        }
        or not isinstance(requirements, dict)
        or set(requirements)
        != {
            "update_version_file",
            "update_all_affected_locks",
            "regenerate_source_snapshots",
            "regenerate_readme_catalog",
            "validate_normative_semantics",
            "pass_all_affected_lanes",
            "protected_promotion_required",
        }
        or not all(requirement is True for requirement in requirements.values())
    ):
        raise ProposalError("update_policy_invalid")
    return value


def eudi_source_policies(
    policy: dict[str, object]
) -> dict[str, tuple[str, str]]:
    lock = freshness.read_object(freshness.EUDI_SOURCES)
    raw_sources = lock.get("sources")
    if not isinstance(raw_sources, list):
        raise ProposalError("eudi_source_policy_invalid")
    policies: dict[str, tuple[str, str]] = {}
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            raise ProposalError("eudi_source_policy_invalid")
        source_id = raw_source.get("source_id")
        strategy = raw_source.get("update_strategy")
        coverage = raw_source.get("coverage_class")
        if (
            not isinstance(source_id, str)
            or not source_id
            or source_id in policies
            or not isinstance(policy.get("source_strategies"), dict)
            or strategy not in policy["source_strategies"]
            or not isinstance(coverage, str)
            or not coverage
        ):
            raise ProposalError("eudi_source_policy_invalid")
        policies[source_id] = (strategy, coverage)
    return policies


def classify_change(
    check: freshness.CheckResult,
    policies: dict[str, tuple[str, str]],
    policy: dict[str, object],
) -> str:
    strategies = policy.get("source_strategies")
    overrides = policy.get("overrides")
    if not isinstance(strategies, dict) or not isinstance(overrides, dict):
        raise ProposalError("update_policy_invalid")
    parts = check.check_id.split(".")
    if len(parts) >= 4 and parts[:2] == ["eudi", "source"]:
        source_policy = policies.get(parts[2])
        if source_policy is None:
            raise ProposalError("eudi_source_policy_missing")
        strategy, coverage = source_policy
        if coverage == "monitor_only":
            return str(overrides["monitor_only_coverage_class"])
        classification = strategies.get(strategy)
        if not isinstance(classification, str):
            raise ProposalError("update_policy_invalid")
        return classification
    if check.check_id.startswith("oidf.release."):
        return "tagged_release_candidate"
    if check.check_id.startswith(("oidf.master.", "oidf.engineering.")):
        return "branch_snapshot_review"
    if check.check_id.startswith(
        ("oidf.specification.", "eudi.publication.")
    ):
        return str(overrides["immutable_publication_change"])
    return "maintenance_candidate"


def build_proposal() -> dict[str, object]:
    try:
        current_version = catalog.read_version(REPOSITORY_ROOT)
        evaluation = freshness.run_checks()
        policy = update_policy()
        policies = eudi_source_policies(policy)
    except (catalog.CatalogError, freshness.FreshnessError) as error:
        raise ProposalError("authoritative_metadata_unavailable") from error
    unavailable_checks = list(evaluation.unavailable_checks)
    try:
        oidf_proposal: dict[str, object] | None = oidf.build_proposal()
    except oidf.ProposalError as error:
        oidf_proposal = None
        unavailable_checks.append(
            freshness.UnavailableCheck(
                check_id="oidf_update_proposal",
                reason=str(error),
            )
        )
    checks = list(evaluation.checks)
    stale = [check for check in checks if check.status == "stale"]
    freshness_status = (
        "stale" if stale else "unavailable" if unavailable_checks else "current"
    )
    groups: dict[str, list[dict[str, str]]] = {
        "tagged_release_candidates": [],
        "branch_snapshot_reviews": [],
        "publication_integrity_reviews": [],
        "maintenance_candidates": [],
        "monitor_only": [],
    }
    group_names = {
        "tagged_release_candidate": "tagged_release_candidates",
        "branch_snapshot_review": "branch_snapshot_reviews",
        "publication_integrity_review": "publication_integrity_reviews",
        "maintenance_candidate": "maintenance_candidates",
        "monitor_only": "monitor_only",
    }
    for check in stale:
        classification = classify_change(check, policies, policy)
        groups[group_names[classification]].append(asdict(check))
    version_eligible = bool(
        groups["tagged_release_candidates"] or groups["maintenance_candidates"]
    )
    return {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.conformance_update_proposal.v1",
        "observed_at": date.today().isoformat(),
        "review_status": "proposal_not_approved",
        "release_policy": {
            "automatic_publication": False,
            "semantic_review_required": True,
            "all_release_gates_required": True,
            "tagged_sources_can_prepare_candidates": True,
            "default_branch_commits_require_snapshot_review": True,
            "monitor_only_sources_cannot_advance_the_baseline": True,
        },
        "current_framework_version": current_version,
        "proposed_framework_version": (
            next_patch_version(current_version) if version_eligible else None
        ),
        "update_available": bool(stale),
        "version_candidate_available": version_eligible,
        "freshness_status": freshness_status,
        "changes": [asdict(check) for check in stale],
        "change_groups": groups,
        "checks": [asdict(check) for check in checks],
        "release_sources": [
            asdict(source) for source in evaluation.release_sources
        ],
        "manual_sources": list(evaluation.manual_sources),
        "unavailable_checks": [
            asdict(unavailable) for unavailable in unavailable_checks
        ],
        "oidf_candidate": oidf_proposal,
    }


def write_proposal(output: Path, proposal: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise ProposalError("output_already_exists")
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = (json.dumps(proposal, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=".conformance-update-proposal-",
            delete=False,
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output)
    except OSError as error:
        raise ProposalError("output_write_failed") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        proposal = build_proposal()
        write_proposal(args.output, proposal)
    except ProposalError as error:
        fail(str(error))
    state = "update available" if proposal["update_available"] else "baseline current"
    print(f"wrote review-gated conformance proposal: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
