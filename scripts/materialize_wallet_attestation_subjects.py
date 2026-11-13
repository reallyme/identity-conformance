#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Materialize verified Wallet package subjects for GitHub provenance checks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_eudi_wallet_execution_result as result_verifier  # noqa: E402
import verify_wallet_package_bundle as bundle_verifier  # noqa: E402


MAX_RESULT_BYTES = 16 * 1024 * 1024


def load_result(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or not 1 <= metadata.st_size <= MAX_RESULT_BYTES
        ):
            raise bundle_verifier.WalletPackageBundleError(
                bundle_verifier.WalletPackageBundleErrorReason.INVALID_BUNDLE
            )
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise bundle_verifier.WalletPackageBundleError(
            bundle_verifier.WalletPackageBundleErrorReason.INVALID_BUNDLE
        ) from error
    if not isinstance(value, dict):
        raise bundle_verifier.WalletPackageBundleError(
            bundle_verifier.WalletPackageBundleErrorReason.INVALID_BUNDLE
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = load_result(args.result)
        result_verifier.verify_result(result)
        package_evidence = result.get("package_evidence")
        if not isinstance(package_evidence, dict):
            raise bundle_verifier.WalletPackageBundleError(
                bundle_verifier.WalletPackageBundleErrorReason.INVALID_BUNDLE
            )
        crate_count = package_evidence.get("crate_count")
        if type(crate_count) is not int:
            raise bundle_verifier.WalletPackageBundleError(
                bundle_verifier.WalletPackageBundleErrorReason.INVALID_BUNDLE
            )
        subjects = bundle_verifier.materialize_attestation_subjects(
            args.bundle, args.output, crate_count
        )
    except (
        bundle_verifier.WalletPackageBundleError,
        result_verifier.runner.EudiWalletRunnerError,
    ):
        print("Wallet attestation subject materialization failed", file=sys.stderr)
        return 65
    print(f"Materialized {len(subjects)} Wallet provenance subjects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
