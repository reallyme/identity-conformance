# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "audit_etsi_eaa_pid_trace",
        REPOSITORY_ROOT / "scripts" / "audit_etsi_eaa_pid_trace.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("trace auditor module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


AUDITOR = load_script()


class EtsiEaaPidTraceTests(unittest.TestCase):
    def test_isolated_trace_source_root_selects_each_exact_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for component_id in ("ssi", "openid4vci", "openid4vp"):
                (root / component_id).mkdir()
            with patch.dict(
                os.environ,
                {AUDITOR.TRACE_SOURCE_ROOT_ENVIRONMENT: str(root)},
                clear=False,
            ):
                components = AUDITOR.load_components()
            self.assertEqual(
                {component.checkout for component in components.values()},
                {(root / component_id).resolve() for component_id in components},
            )

    def test_current_trace_is_complete_and_keeps_claim_boundary_explicit(self) -> None:
        artifact = AUDITOR.build_artifact(
            AUDITOR.load_components(), verify_component_revision=False
        )
        summary = artifact["summary"]
        self.assertEqual(summary["total_rows"], 969)
        self.assertEqual(summary["etsi_requirement_rows"], 740)
        self.assertEqual(summary["eu_profile_rows"], 229)
        self.assertEqual(
            summary["production_registry_status"],
            "all_740_identifiers_fail_closed",
        )
        self.assertEqual(
            summary["production_registry_symbols"], list(AUDITOR.REGISTRY_SYMBOLS)
        )
        self.assertEqual(summary["product_conformance_status"], "external_evidence_still_required")
        self.assertEqual(
            summary["disposition_counts"], AUDITOR.EXPECTED_DISPOSITION_COUNTS
        )

    def test_duplicate_requirement_is_rejected(self) -> None:
        artifact = AUDITOR.build_artifact(
            AUDITOR.load_components(), verify_component_revision=False
        )
        rows = copy.deepcopy(artifact["requirements"])
        rows.append(copy.deepcopy(rows[0]))
        seen: set[tuple[str, str]] = set()
        with self.assertRaises(AUDITOR.AuditError):
            for row in rows:
                key = (row["source"], row["requirement_id"])
                if key in seen:
                    raise AUDITOR.AuditError("duplicate")
                seen.add(key)

    def test_non_applicable_row_requires_fixed_empty_evidence_shape(self) -> None:
        artifact = AUDITOR.build_artifact(
            AUDITOR.load_components(), verify_component_revision=False
        )
        row = next(
            item
            for item in artifact["requirements"]
            if item["disposition"] == AUDITOR.NOT_APPLICABLE_DISPOSITION
        )
        changed = dict(row)
        changed["code_path"] = "crates/eudi/etsi-eaa-conformance/src/validate.rs"
        with self.assertRaises(AUDITOR.AuditError):
            AUDITOR.verify_row(
                changed,
                AUDITOR.load_components(),
            )

    def test_symbol_evidence_is_read_from_the_pinned_git_blob(self) -> None:
        components = AUDITOR.load_components()
        component, relative_path = AUDITOR.resolve_reference(
            components,
            "openid4vci/crates/issuer/src/endpoint.rs",
        )
        with patch.object(
            AUDITOR,
            "read_regular_file",
            side_effect=AssertionError("working-tree source must not be read"),
        ):
            AUDITOR.verify_symbol(
                component,
                relative_path,
                "handle_credential_request",
            )

    def test_absent_symbol_is_rejected_at_the_pinned_revision(self) -> None:
        components = AUDITOR.load_components()
        component, relative_path = AUDITOR.resolve_reference(
            components,
            "openid4vci/crates/issuer/src/endpoint.rs",
        )
        with self.assertRaises(AUDITOR.AuditError):
            AUDITOR.verify_symbol(
                component,
                relative_path,
                "symbol_added_only_after_the_pinned_revision",
            )


if __name__ == "__main__":
    unittest.main()
