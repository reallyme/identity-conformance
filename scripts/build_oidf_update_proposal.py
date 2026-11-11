#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a review-only proposal for current OIDF suite and specification pins."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import check_pin_freshness as freshness  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPECIFICATIONS_LOCK = REPOSITORY_ROOT / "upstream/oidf/specifications.lock.json"


class ProposalError(Exception):
    """Raised when an update proposal cannot be built safely."""


def fail(reason: str) -> NoReturn:
    print(f"OIDF update proposal failed: {reason}", file=sys.stderr)
    raise SystemExit(78)


def required_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ProposalError("invalid_upstream_metadata")
    return value


def build_proposal() -> dict[str, object]:
    try:
        release = freshness.fetch_json(
            "https://gitlab.com/api/v4/projects/"
            "openid%2Fconformance-suite/releases/permalink/latest"
        )
        branch = freshness.fetch_json(
            "https://gitlab.com/api/v4/projects/"
            "openid%2Fconformance-suite/repository/branches/master"
        )
        specifications = freshness.read_object(SPECIFICATIONS_LOCK)
    except freshness.FreshnessError as error:
        raise ProposalError("upstream_metadata_unavailable") from error
    if (
        not isinstance(release, dict)
        or not isinstance(release.get("commit"), dict)
        or not isinstance(branch, dict)
        or not isinstance(branch.get("commit"), dict)
    ):
        raise ProposalError("invalid_upstream_metadata")

    publications = specifications.get("publications")
    engineering_sources = specifications.get("engineering_sources")
    if not isinstance(publications, list) or not isinstance(engineering_sources, list):
        raise ProposalError("invalid_specification_lock")

    proposed_publications: list[dict[str, object]] = []
    for raw_publication in publications:
        if not isinstance(raw_publication, dict):
            raise ProposalError("invalid_specification_lock")
        specification_id = required_string(raw_publication.get("specification_id"))
        canonical_url = required_string(raw_publication.get("canonical_url"))
        try:
            content = freshness.fetch_bytes(canonical_url)
        except freshness.FreshnessError as error:
            raise ProposalError("publication_unavailable") from error
        proposal: dict[str, object] = {
            "specification_id": specification_id,
            "canonical_url": canonical_url,
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_length": len(content),
        }
        if "source_ref" in raw_publication:
            repository_url = required_string(raw_publication.get("source_repository"))
            source_ref = required_string(raw_publication.get("source_ref"))
            try:
                repository = freshness.github_repository_from_url(
                    repository_url, "OIDF specification source repository"
                )
                source_commit = freshness.resolve_github_ref(
                    repository, f"tags/{source_ref}", freshness.fetch_json
                )
            except freshness.FreshnessError as error:
                raise ProposalError("source_revision_unavailable") from error
            proposal.update(
                {
                    "source_repository": repository_url,
                    "source_ref": source_ref,
                    "source_commit": source_commit,
                }
            )
        else:
            proposal["source_repository"] = required_string(
                raw_publication.get("source_repository")
            )
            proposal["source_binding"] = required_string(
                raw_publication.get("source_binding")
            )
        proposed_publications.append(proposal)

    proposed_engineering_sources: list[dict[str, object]] = []
    for raw_source in engineering_sources:
        if not isinstance(raw_source, dict):
            raise ProposalError("invalid_specification_lock")
        repository_url = required_string(raw_source.get("repository"))
        branch_name = required_string(raw_source.get("ref"))
        try:
            repository = freshness.github_repository_from_url(
                repository_url, "OIDF engineering source repository"
            )
            commit = freshness.resolve_github_ref(
                repository, f"heads/{branch_name}", freshness.fetch_json
            )
        except freshness.FreshnessError as error:
            raise ProposalError("source_revision_unavailable") from error
        proposed_engineering_sources.append(
            {
                "specification_id": required_string(
                    raw_source.get("specification_id")
                ),
                "repository": repository_url,
                "ref": branch_name,
                "commit": commit,
                "certification_claim": False,
            }
        )

    return {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.oidf_update_proposal.v1",
        "observed_at": date.today().isoformat(),
        "review_status": "proposal_not_approved",
        "suite_release": {
            "repository": "https://gitlab.com/openid/conformance-suite.git",
            "pinned_ref": required_string(release.get("tag_name")),
            "commit": required_string(release["commit"].get("id")),
            "released_at": required_string(release.get("released_at"))[:10],
        },
        "suite_master": {
            "repository": "https://gitlab.com/openid/conformance-suite.git",
            "pinned_ref": "master",
            "commit": required_string(branch["commit"].get("id")),
        },
        "publications": proposed_publications,
        "engineering_sources": proposed_engineering_sources,
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
            mode="wb", dir=output.parent, prefix=".oidf-proposal-", delete=False
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
        write_proposal(args.output, build_proposal())
    except ProposalError as error:
        fail(str(error))
    print("wrote review-only OIDF update proposal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
