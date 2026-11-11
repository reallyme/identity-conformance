#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate a ZK deployment manifest without executing the component lane."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import run_zk_conformance as runner  # noqa: E402
import verify_zk_adapter as adapter_verifier  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        _plan, adapter = adapter_verifier.load_contract()
        runner.validate_deployment(adapter_verifier.load_object(args.manifest), adapter)
    except adapter_verifier.ZkAdapterError as error:
        adapter_verifier.fail(error.reason)
    except runner.ZkRunnerError as error:
        runner.fail(error.reason)
    print("ZK deployment manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
