#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Emit a stable SHA-256 fingerprint for a regular certification input."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import build_oidf_evidence_index as evidence  # noqa: E402


def fingerprint(path: Path, artifact: bool = False) -> str:
    maximum_bytes = (
        evidence.MAX_ARTIFACT_BYTES if artifact else evidence.MAX_INPUT_BYTES
    )
    digest, size = evidence.hash_file(path, maximum_bytes)
    return f"{digest}:{size}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--artifact",
        action="store_true",
        help="allow the bounded artifact size limit instead of the input limit",
    )
    args = parser.parse_args()
    print(fingerprint(args.path, args.artifact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
