#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify the Wallet package preflight through independent GitHub API records."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_wallet_package_bundle as wallet_package_bundle  # noqa: E402


MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JOB_COUNT = 100
MAX_STEP_COUNT = 100
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_STEPS = tuple(
    dict.fromkeys(
        step
        for steps in wallet_package_bundle.EXPECTED_EVIDENCE_STEPS.values()
        for step in steps
    )
)
PREREQUISITE_POLICIES: dict[
    str, tuple[str, str, dict[str, tuple[str, ...]]]
] = {
    "fuzz": (
        ".github/workflows/fuzz.yml",
        "workflow_dispatch",
        {
            "fuzz target build": (
                "Build fuzz targets",
                "Upload scheduled fuzz executables",
                "Record staged fuzz executable digests",
            ),
            "scheduled fuzz (wallet_proto_decode)": (
                "Download fuzz executables",
                "Run time-boxed fuzz target",
            ),
            "scheduled fuzz (wallet_proto_json)": (
                "Download fuzz executables",
                "Run time-boxed fuzz target",
            ),
            "scheduled fuzz (wallet_identifier)": (
                "Download fuzz executables",
                "Run time-boxed fuzz target",
            ),
            "scheduled fuzz (wallet_state_machine)": (
                "Download fuzz executables",
                "Run time-boxed fuzz target",
            ),
        },
    ),
    "protobuf_ci": (
        ".github/workflows/protobuf-ci.yml",
        "push",
        {
            "schema, generation, hardening": (
                "Validate schema and locked sources",
                "Check generated protobuf freshness and hardening",
            )
        },
    ),
    "rust_ci": (
        ".github/workflows/rust-ci.yml",
        "push",
        {
            "published crates on Rust 1.99": (
                "Check published crates at the declared MSRV",
            ),
            "fmt, lint, test, documentation, dependency policy": (
                "Format",
                "Check all features with warnings denied",
                "Clippy",
                "Test native lane",
                "Test all features",
                "Build documentation",
                "Check wasm32 lane",
                "Check every intended Rust package surface",
                "Check shared release readiness policy",
                "Dependency policy",
                "Fuzz dependency policy",
                "Security advisory audit",
            ),
            "Inspect and test normalized crate archives": (
                "Inspect and test normalized crate archives",
            ),
            "Public API semver": (
                "Check public crate versions against crates.io",
            ),
        },
    ),
}


class WalletPreflightErrorReason(Enum):
    INVALID_INPUT = "invalid_input"
    RESULT_MISMATCH = "result_mismatch"
    RUN_MISMATCH = "run_mismatch"
    JOB_MISMATCH = "job_mismatch"
    REQUIRED_STEP_MISMATCH = "required_step_mismatch"
    PREREQUISITE_MISMATCH = "prerequisite_mismatch"


@dataclass(frozen=True)
class WalletPreflightError(Exception):
    reason: WalletPreflightErrorReason


@dataclass(frozen=True)
class PackageEvidenceIdentity:
    preflight_run_id: int
    preflight_job_id: int
    fuzz_run_id: int
    protobuf_ci_run_id: int
    rust_ci_run_id: int


def fail(reason: WalletPreflightErrorReason) -> NoReturn:
    print(f"Wallet package preflight verification failed: {reason.value}", file=sys.stderr)
    raise SystemExit(65)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or not 1 <= metadata.st_size <= MAX_INPUT_BYTES:
            raise WalletPreflightError(WalletPreflightErrorReason.INVALID_INPUT)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise WalletPreflightError(
            WalletPreflightErrorReason.INVALID_INPUT
        ) from error
    if not isinstance(value, dict):
        raise WalletPreflightError(WalletPreflightErrorReason.INVALID_INPUT)
    return value


def positive_identifier(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 9_007_199_254_740_991:
        raise WalletPreflightError(WalletPreflightErrorReason.INVALID_INPUT)
    return value


def result_identity(
    result: dict[str, object], expected_commit: str
) -> PackageEvidenceIdentity:
    component = result.get("component")
    target = result.get("target")
    evidence = result.get("package_evidence")
    if (
        GIT_COMMIT.fullmatch(expected_commit) is None
        or not isinstance(component, dict)
        or component.get("component_id") != "wallet"
        or component.get("repository") != "https://github.com/reallyme/wallet"
        or component.get("commit") != expected_commit
        or not isinstance(target, dict)
        or target.get("commit") != expected_commit
        or not isinstance(evidence, dict)
    ):
        raise WalletPreflightError(WalletPreflightErrorReason.RESULT_MISMATCH)
    try:
        identity = PackageEvidenceIdentity(
            preflight_run_id=positive_identifier(evidence.get("preflight_run_id")),
            preflight_job_id=positive_identifier(evidence.get("preflight_job_id")),
            fuzz_run_id=positive_identifier(evidence.get("fuzz_run_id")),
            protobuf_ci_run_id=positive_identifier(evidence.get("protobuf_ci_run_id")),
            rust_ci_run_id=positive_identifier(evidence.get("rust_ci_run_id")),
        )
    except WalletPreflightError as error:
        raise WalletPreflightError(
            WalletPreflightErrorReason.RESULT_MISMATCH
        ) from error
    if len(
        {
            identity.preflight_run_id,
            identity.fuzz_run_id,
            identity.protobuf_ci_run_id,
            identity.rust_ci_run_id,
        }
    ) != 4:
        raise WalletPreflightError(WalletPreflightErrorReason.RESULT_MISMATCH)
    if target.get("preflight_run_id") != identity.preflight_run_id:
        raise WalletPreflightError(WalletPreflightErrorReason.RESULT_MISMATCH)
    return identity


def verify_run(
    run: dict[str, object], expected_commit: str, expected_run_id: int
) -> None:
    if (
        run.get("id") != expected_run_id
        or run.get("head_sha") != expected_commit
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("path") != ".github/workflows/crates-package-preflight.yml"
    ):
        raise WalletPreflightError(WalletPreflightErrorReason.RUN_MISMATCH)


def verify_prerequisite_run(
    run: dict[str, object],
    expected_commit: str,
    expected_run_id: int,
    expected_path: str,
    expected_event: str,
) -> None:
    if (
        run.get("id") != expected_run_id
        or run.get("head_sha") != expected_commit
        or run.get("head_branch") != "main"
        or run.get("event") != expected_event
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("path") != expected_path
    ):
        raise WalletPreflightError(
            WalletPreflightErrorReason.PREREQUISITE_MISMATCH
        )


def verify_jobs(
    value: dict[str, object],
    expected_commit: str,
    expected_run_id: int,
    expected_job_id: int,
) -> None:
    jobs = value.get("jobs")
    total_count = value.get("total_count")
    if (
        type(total_count) is not int
        or not 1 <= total_count <= MAX_JOB_COUNT
        or not isinstance(jobs, list)
        or len(jobs) != total_count
    ):
        raise WalletPreflightError(WalletPreflightErrorReason.JOB_MISMATCH)
    matches = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("id") == expected_job_id
    ]
    if len(matches) != 1:
        raise WalletPreflightError(WalletPreflightErrorReason.JOB_MISMATCH)
    job = matches[0]
    steps = job.get("steps")
    if (
        job.get("run_id") != expected_run_id
        or job.get("run_attempt") != 1
        or job.get("head_sha") != expected_commit
        or job.get("name") != "Review crates.io packages"
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or not isinstance(steps, list)
        or not 1 <= len(steps) <= MAX_STEP_COUNT
    ):
        raise WalletPreflightError(WalletPreflightErrorReason.JOB_MISMATCH)
    step_numbers: set[int] = set()
    for step in steps:
        if not isinstance(step, dict):
            raise WalletPreflightError(WalletPreflightErrorReason.JOB_MISMATCH)
        number = step.get("number")
        if (
            type(number) is not int
            or number < 1
            or number in step_numbers
            or step.get("status") != "completed"
            or step.get("conclusion") not in {"success", "skipped"}
        ):
            raise WalletPreflightError(WalletPreflightErrorReason.JOB_MISMATCH)
        step_numbers.add(number)
    for required in REQUIRED_STEPS:
        matching_steps = [
            step
            for step in steps
            if isinstance(step, dict) and step.get("name") == required
        ]
        if len(matching_steps) != 1 or (
            matching_steps[0].get("status") != "completed"
            or matching_steps[0].get("conclusion") != "success"
        ):
            raise WalletPreflightError(
                WalletPreflightErrorReason.REQUIRED_STEP_MISMATCH
            )


def verify_prerequisite_jobs(
    value: dict[str, object],
    expected_commit: str,
    expected_run_id: int,
    required_jobs: dict[str, tuple[str, ...]],
) -> None:
    jobs = value.get("jobs")
    total_count = value.get("total_count")
    if (
        type(total_count) is not int
        or not 1 <= total_count <= MAX_JOB_COUNT
        or not isinstance(jobs, list)
        or len(jobs) != total_count
    ):
        raise WalletPreflightError(
            WalletPreflightErrorReason.PREREQUISITE_MISMATCH
        )
    observed_job_ids: set[int] = set()
    for job in jobs:
        if not isinstance(job, dict):
            raise WalletPreflightError(
                WalletPreflightErrorReason.PREREQUISITE_MISMATCH
            )
        job_id = job.get("id")
        steps = job.get("steps")
        conclusion = job.get("conclusion")
        if (
            type(job_id) is not int
            or job_id < 1
            or job_id in observed_job_ids
            or job.get("run_id") != expected_run_id
            or job.get("run_attempt") != 1
            or job.get("head_sha") != expected_commit
            or job.get("status") != "completed"
            or conclusion not in {"success", "skipped"}
            or not isinstance(steps, list)
            or len(steps) > MAX_STEP_COUNT
            or (conclusion == "success" and not steps)
            or (conclusion == "skipped" and steps)
        ):
            raise WalletPreflightError(
                WalletPreflightErrorReason.PREREQUISITE_MISMATCH
            )
        observed_job_ids.add(job_id)
        step_numbers: set[int] = set()
        for step in steps:
            if not isinstance(step, dict):
                raise WalletPreflightError(
                    WalletPreflightErrorReason.PREREQUISITE_MISMATCH
                )
            number = step.get("number")
            if (
                type(number) is not int
                or number < 1
                or number in step_numbers
                or step.get("status") != "completed"
                or step.get("conclusion") not in {"success", "skipped"}
            ):
                raise WalletPreflightError(
                    WalletPreflightErrorReason.PREREQUISITE_MISMATCH
                )
            step_numbers.add(number)

    for required_job_name, required_steps in required_jobs.items():
        matching_jobs = [
            job
            for job in jobs
            if isinstance(job, dict) and job.get("name") == required_job_name
        ]
        if len(matching_jobs) != 1 or matching_jobs[0].get("conclusion") != "success":
            raise WalletPreflightError(
                WalletPreflightErrorReason.PREREQUISITE_MISMATCH
            )
        steps = matching_jobs[0].get("steps")
        if not isinstance(steps, list):
            raise WalletPreflightError(
                WalletPreflightErrorReason.PREREQUISITE_MISMATCH
            )
        for required_step in required_steps:
            matching_steps = [
                step
                for step in steps
                if isinstance(step, dict) and step.get("name") == required_step
            ]
            if len(matching_steps) != 1 or (
                matching_steps[0].get("status") != "completed"
                or matching_steps[0].get("conclusion") != "success"
            ):
                raise WalletPreflightError(
                    WalletPreflightErrorReason.PREREQUISITE_MISMATCH
                )


def verify(
    result: dict[str, object],
    run: dict[str, object],
    jobs: dict[str, object],
    prerequisite_runs: dict[str, dict[str, object]],
    prerequisite_jobs: dict[str, dict[str, object]],
    expected_commit: str,
) -> PackageEvidenceIdentity:
    identity = result_identity(result, expected_commit)
    verify_run(run, expected_commit, identity.preflight_run_id)
    verify_jobs(
        jobs,
        expected_commit,
        identity.preflight_run_id,
        identity.preflight_job_id,
    )
    expected_run_ids = {
        "fuzz": identity.fuzz_run_id,
        "protobuf_ci": identity.protobuf_ci_run_id,
        "rust_ci": identity.rust_ci_run_id,
    }
    if (
        set(prerequisite_runs) != set(PREREQUISITE_POLICIES)
        or set(prerequisite_jobs) != set(PREREQUISITE_POLICIES)
    ):
        raise WalletPreflightError(
            WalletPreflightErrorReason.PREREQUISITE_MISMATCH
        )
    for prerequisite_id, (workflow_path, expected_event, required_jobs) in (
        PREREQUISITE_POLICIES.items()
    ):
        expected_run_id = expected_run_ids[prerequisite_id]
        # An extra Fuzz job is a new campaign surface, not optional evidence.
        # Review and name every campaign before it can qualify a release.
        if (
            prerequisite_id == "fuzz"
            and prerequisite_jobs[prerequisite_id].get("total_count")
            != len(required_jobs)
        ):
            raise WalletPreflightError(
                WalletPreflightErrorReason.PREREQUISITE_MISMATCH
            )
        verify_prerequisite_run(
            prerequisite_runs[prerequisite_id],
            expected_commit,
            expected_run_id,
            workflow_path,
            expected_event,
        )
        verify_prerequisite_jobs(
            prerequisite_jobs[prerequisite_id],
            expected_commit,
            expected_run_id,
            required_jobs,
        )
    return identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--jobs", required=True, type=Path)
    parser.add_argument("--fuzz-run", required=True, type=Path)
    parser.add_argument("--fuzz-jobs", required=True, type=Path)
    parser.add_argument("--protobuf-ci-run", required=True, type=Path)
    parser.add_argument("--protobuf-ci-jobs", required=True, type=Path)
    parser.add_argument("--rust-ci-run", required=True, type=Path)
    parser.add_argument("--rust-ci-jobs", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        identity = verify(
            load_object(args.result),
            load_object(args.run),
            load_object(args.jobs),
            {
                "fuzz": load_object(args.fuzz_run),
                "protobuf_ci": load_object(args.protobuf_ci_run),
                "rust_ci": load_object(args.rust_ci_run),
            },
            {
                "fuzz": load_object(args.fuzz_jobs),
                "protobuf_ci": load_object(args.protobuf_ci_jobs),
                "rust_ci": load_object(args.rust_ci_jobs),
            },
            args.expected_commit,
        )
    except WalletPreflightError as error:
        fail(error.reason)
    print(
        "Wallet package preflight and prerequisite runs verified "
        f"for run {identity.preflight_run_id} job {identity.preflight_job_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
