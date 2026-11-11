#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate an EUDI deployment manifest before source checkout or execution."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_eudi_relying_party_conformance as runner  # noqa: E402
import verify_eudi_adapter as adapter_verifier  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--candidate-repository", required=True)
    args = parser.parse_args()
    try:
        runner.validate_deployment_manifest(
            adapter_verifier.load_object(args.manifest), args.candidate_repository
        )
    except adapter_verifier.AdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.RunnerError as error:
        runner.fail(error.reason)
    print("EUDI deployment manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
