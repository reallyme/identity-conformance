# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts" / "build_oidf_update_proposal.py"
    specification = importlib.util.spec_from_file_location(
        "build_oidf_update_proposal", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("OIDF update proposal builder could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


BUILDER = load_script()


def fetch_json(url: str) -> object:
    if url.endswith("releases/permalink/latest"):
        return {
            "tag_name": "release-v9.9.9",
            "released_at": "2026-11-11T12:00:00Z",
            "commit": {"id": "a" * 40},
        }
    if url.endswith("repository/branches/master"):
        return {"commit": {"id": "b" * 40}}
    raise BUILDER.freshness.FreshnessError("unexpected_test_url")


class OidfUpdateProposalTests(unittest.TestCase):
    def test_proposal_contains_unapproved_current_metadata(self) -> None:
        with (
            patch.object(BUILDER.freshness, "fetch_json", side_effect=fetch_json),
            patch.object(
                BUILDER.freshness,
                "fetch_bytes",
                return_value=b"reviewed-publication",
            ),
            patch.object(
                BUILDER.freshness,
                "resolve_github_ref",
                return_value="c" * 40,
            ),
        ):
            proposal = BUILDER.build_proposal()
        self.assertEqual(proposal["review_status"], "proposal_not_approved")
        self.assertEqual(proposal["suite_release"]["commit"], "a" * 40)
        self.assertEqual(proposal["suite_master"]["commit"], "b" * 40)
        self.assertEqual(len(proposal["publications"]), 3)
        self.assertTrue(
            all(publication["content_length"] == 20 for publication in proposal["publications"])
        )

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "proposal.json"
            output.write_text("existing", encoding="utf-8")
            with self.assertRaises(BUILDER.ProposalError):
                BUILDER.write_proposal(output, {"review_status": "proposal_not_approved"})
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")


if __name__ == "__main__":
    unittest.main()
