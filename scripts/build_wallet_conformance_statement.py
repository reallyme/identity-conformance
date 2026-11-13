#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build a statement for one successful caller-selected Wallet profile run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import build_product_conformance_statement as framework_statement  # noqa: E402
import strict_json  # noqa: E402
import verify_eudi_wallet_execution_result as result_verifier  # noqa: E402
import verify_wallet_published_target as publication_verifier  # noqa: E402


MAX_INPUT_BYTES = 16 * 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_REPOSITORY = re.compile(r"^reallyme/[A-Za-z0-9_.-]+$")
SUPPORTED_PROFILE = "eudi-wallet-engineering-v1"


class WalletStatementErrorReason(Enum):
    INVALID_FRAMEWORK = "invalid_framework"
    INVALID_RESULT = "invalid_result"
    INVALID_EXECUTION = "invalid_execution"
    OUTPUT_EXISTS = "output_exists"
    OUTPUT_FAILED = "output_failed"


@dataclass(frozen=True)
class WalletStatementError(Exception):
    reason: WalletStatementErrorReason


def fail(reason: WalletStatementErrorReason) -> NoReturn:
    print(f"Wallet conformance statement failed: {reason.value}", file=sys.stderr)
    raise SystemExit(65)


def read_object(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_INPUT_BYTES:
            raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT)
        content = path.read_bytes()
        value = strict_json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise WalletStatementError(
            WalletStatementErrorReason.INVALID_RESULT
        ) from error
    if not isinstance(value, dict):
        raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT)
    return value, content


def build_statement(
    framework_selection: dict[str, object],
    result: dict[str, object],
    result_bytes: bytes,
    profile: str,
    workflow_repository: str,
    workflow_revision: str,
    run_id: int,
    run_attempt: int,
    publication_evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    if profile != SUPPORTED_PROFILE:
        raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT)
    try:
        framework = framework_statement.validate_framework_selection(
            framework_selection
        )
    except framework_statement.StatementError as error:
        raise WalletStatementError(
            WalletStatementErrorReason.INVALID_FRAMEWORK
        ) from error
    if (
        WORKFLOW_REPOSITORY.fullmatch(workflow_repository) is None
        or COMMIT.fullmatch(workflow_revision) is None
        or not 1 <= run_id <= 9_223_372_036_854_775_807
        or not 1 <= run_attempt <= 2_147_483_647
    ):
        raise WalletStatementError(WalletStatementErrorReason.INVALID_EXECUTION)
    try:
        result_verifier.verify_result(result)
    except result_verifier.runner.EudiWalletRunnerError as error:
        raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT) from error
    component = result.get("component")
    target = result.get("target")
    coverage = result.get("coverage")
    package_evidence = result.get("package_evidence")
    if (
        result.get("result") != "passed"
        or result.get("plan_id") != profile
        or result.get("framework_revision") != framework.get("repository_commit")
        or not isinstance(component, dict)
        or component.get("component_id") != "wallet"
        or component.get("repository") != "https://github.com/reallyme/wallet"
        or not isinstance(target, dict)
        or target.get("commit") != component.get("commit")
        or not isinstance(coverage, dict)
        or not isinstance(package_evidence, dict)
        or not isinstance(result.get("candidate_sha256"), str)
    ):
        raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT)
    mode = target.get("mode")
    if mode == "published":
        try:
            publication_verifier.validate_publication_evidence(
                publication_evidence, target, package_evidence["crates"]
            )
        except (KeyError, publication_verifier.PublishedTargetError) as error:
            raise WalletStatementError(
                WalletStatementErrorReason.INVALID_RESULT
            ) from error
    elif mode != "candidate" or publication_evidence is not None:
        raise WalletStatementError(WalletStatementErrorReason.INVALID_RESULT)
    statement = {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.wallet_conformance_statement.v1",
        "result": "passed",
        "certification_claim": False,
        "profile": {
            "plan_id": profile,
            "authority": "internal_engineering",
        },
        "product": {
            "product_id": "wallet",
            "repository": component["repository"],
            "commit": component["commit"],
            "candidate_sha256": result["candidate_sha256"],
        },
        "target": target,
        "coverage": coverage,
        "package_evidence": package_evidence,
        "framework": {
            key: framework[key]
            for key in (
                "release_version",
                "release_tag",
                "release_url",
                "repository_commit",
                "manifest_sha256",
                "input_set_sha256",
            )
        },
        "execution": {
            "workflow_repository": workflow_repository,
            "workflow_revision": workflow_revision,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
        "badge": {
            "label": "EU Wallet Engineering",
            "status": "passed",
            "framework_version": framework["release_version"],
            "plan_id": profile,
        },
    }
    if publication_evidence is not None:
        statement["publication_evidence"] = publication_evidence
    return statement


def write_output(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise WalletStatementError(WalletStatementErrorReason.OUTPUT_EXISTS)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".wallet-statement-", delete=False
        ) as temporary:
            os.chmod(temporary.name, 0o600)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as error:
        raise WalletStatementError(WalletStatementErrorReason.OUTPUT_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-selection", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--publication-evidence", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        framework, _framework_bytes = read_object(args.framework_selection)
        result, result_bytes = read_object(args.result)
        publication_evidence = None
        if args.publication_evidence is not None:
            publication_evidence, _publication_bytes = read_object(
                args.publication_evidence
            )
        statement = build_statement(
            framework,
            result,
            result_bytes,
            args.profile,
            args.workflow_repository,
            args.workflow_revision,
            args.run_id,
            args.run_attempt,
            publication_evidence,
        )
        write_output(args.output, statement)
    except WalletStatementError as error:
        fail(error.reason)
    print("Wallet conformance statement valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
