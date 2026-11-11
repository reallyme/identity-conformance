# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    path = REPOSITORY_ROOT / "scripts" / "strict_json.py"
    specification = importlib.util.spec_from_file_location("strict_json_tests", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("strict JSON module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


STRICT_JSON = load_script()


class StrictJsonTests(unittest.TestCase):
    def test_accepts_finite_bounded_json(self) -> None:
        self.assertEqual(
            STRICT_JSON.loads('{"enabled":true,"values":[1,2.5,null]}'),
            {"enabled": True, "values": [1, 2.5, None]},
        )

    def test_rejects_duplicate_members(self) -> None:
        with self.assertRaises(STRICT_JSON.StrictJsonError):
            STRICT_JSON.loads('{"commit":"first","commit":"second"}')

    def test_rejects_non_finite_numbers(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity", "1e400"):
            with self.subTest(value=value):
                with self.assertRaises(STRICT_JSON.StrictJsonError):
                    STRICT_JSON.loads('{"value":' + value + "}")

    def test_rejects_oversized_numeric_literal(self) -> None:
        with self.assertRaises(STRICT_JSON.StrictJsonError):
            STRICT_JSON.loads("1" * (STRICT_JSON.MAX_NUMBER_CHARACTERS + 1))

    def test_rejects_excessive_depth_and_nodes(self) -> None:
        with self.assertRaises(STRICT_JSON.StrictJsonError):
            STRICT_JSON.loads("[" * 80 + "0" + "]" * 80)
        with self.assertRaises(STRICT_JSON.StrictJsonError):
            STRICT_JSON.loads("[0,1,2]", max_nodes=3)

    def test_rejects_lone_unicode_surrogate(self) -> None:
        with self.assertRaises(STRICT_JSON.StrictJsonError):
            STRICT_JSON.loads('"\\ud800"')


if __name__ == "__main__":
    unittest.main()
