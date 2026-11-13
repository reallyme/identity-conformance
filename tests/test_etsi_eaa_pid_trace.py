# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


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


def selection() -> dict[str, object]:
    return {
        "schema": "reallyme.identity.trace_source_selection.v1",
        "purpose": "caller-selected-product-sources",
        "sources": [
            {
                "component_id": component_id,
                "repository": repository,
                "commit": index * 40,
            }
            for index, (component_id, repository) in zip(
                ("1", "2", "3"),
                AUDITOR.EXPECTED_COMPONENT_REPOSITORIES.items(),
                strict=True,
            )
        ],
    }


class EtsiEaaPidTraceTests(unittest.TestCase):
    def load_selection(
        self, value: dict[str, object]
    ) -> dict[str, AUDITOR.Component]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for component_id in AUDITOR.EXPECTED_COMPONENT_REPOSITORIES:
                (root / component_id).mkdir()
            manifest = root / "selection.json"
            manifest.write_text(
                json.dumps(value, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            return AUDITOR.load_components(manifest, root)

    def test_caller_selected_commits_are_loaded_without_framework_pins(self) -> None:
        components = self.load_selection(selection())
        self.assertEqual(set(components), set(AUDITOR.EXPECTED_COMPONENT_REPOSITORIES))
        self.assertEqual(components["ssi"].commit, "3" * 40)

    def test_second_caller_selection_can_use_different_commits(self) -> None:
        first = selection()
        second = selection()
        second_sources = second["sources"]
        if not isinstance(second_sources, list) or not isinstance(
            second_sources[2], dict
        ):
            self.fail("test fixture is invalid")
        second_sources[2]["commit"] = "f" * 40
        self.assertNotEqual(
            self.load_selection(first)["ssi"].commit,
            self.load_selection(second)["ssi"].commit,
        )

    def test_missing_component_is_rejected(self) -> None:
        value = selection()
        sources = value["sources"]
        if not isinstance(sources, list):
            self.fail("test fixture is invalid")
        value["sources"] = sources[:-1]
        with self.assertRaises(AUDITOR.AuditError):
            self.load_selection(value)

    def test_repository_substitution_is_rejected(self) -> None:
        value = selection()
        sources = value["sources"]
        if not isinstance(sources, list) or not isinstance(sources[0], dict):
            self.fail("test fixture is invalid")
        sources[0]["repository"] = "https://github.com/example/openid4vci"
        with self.assertRaises(AUDITOR.AuditError):
            self.load_selection(value)

    def test_short_commit_is_rejected(self) -> None:
        value = selection()
        sources = value["sources"]
        if not isinstance(sources, list) or not isinstance(sources[0], dict):
            self.fail("test fixture is invalid")
        sources[0]["commit"] = "abc123"
        with self.assertRaises(AUDITOR.AuditError):
            self.load_selection(value)

    def test_extra_selection_field_is_rejected(self) -> None:
        value = selection()
        sources = value["sources"]
        if not isinstance(sources, list) or not isinstance(sources[0], dict):
            self.fail("test fixture is invalid")
        sources[0]["release_ref"] = "reallyme-openid4vci-v1.0.0"
        with self.assertRaises(AUDITOR.AuditError):
            self.load_selection(value)


if __name__ == "__main__":
    unittest.main()
