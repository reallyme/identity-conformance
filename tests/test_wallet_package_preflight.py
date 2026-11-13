# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "verify_wallet_package_preflight",
        REPOSITORY_ROOT / "scripts/verify_wallet_package_preflight.py",
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Wallet preflight verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script()
COMMIT = "1" * 40
RUN_ID = 41
JOB_ID = 42
PREREQUISITE_RUN_IDS = {"fuzz": 31, "protobuf_ci": 32, "rust_ci": 33}


def valid_result() -> dict[str, object]:
    return {
        "component": {
            "component_id": "wallet",
            "repository": "https://github.com/reallyme/wallet",
            "commit": COMMIT,
        },
        "target": {
            "mode": "candidate",
            "version": "0.1.2",
            "commit": COMMIT,
            "preflight_run_id": RUN_ID,
        },
        "package_evidence": {
            "preflight_run_id": RUN_ID,
            "preflight_job_id": JOB_ID,
            "fuzz_run_id": PREREQUISITE_RUN_IDS["fuzz"],
            "protobuf_ci_run_id": PREREQUISITE_RUN_IDS["protobuf_ci"],
            "rust_ci_run_id": PREREQUISITE_RUN_IDS["rust_ci"],
        },
    }


def valid_run() -> dict[str, object]:
    return {
        "id": RUN_ID,
        "head_sha": COMMIT,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/crates-package-preflight.yml",
    }


def valid_jobs() -> dict[str, object]:
    steps = [
        {
            "name": name,
            "number": number,
            "status": "completed",
            "conclusion": "success",
        }
        for number, name in enumerate(VERIFIER.REQUIRED_STEPS, start=1)
    ]
    steps.append(
        {
            "name": "Optional documentation upload",
            "number": len(steps) + 1,
            "status": "completed",
            "conclusion": "skipped",
        }
    )
    return {
        "total_count": 1,
        "jobs": [
            {
                "id": JOB_ID,
                "run_id": RUN_ID,
                "run_attempt": 1,
                "head_sha": COMMIT,
                "name": "Review crates.io packages",
                "status": "completed",
                "conclusion": "success",
                "steps": steps,
            }
        ],
    }


def valid_prerequisite_runs() -> dict[str, dict[str, object]]:
    return {
        prerequisite_id: {
            "id": PREREQUISITE_RUN_IDS[prerequisite_id],
            "head_sha": COMMIT,
            "head_branch": "main",
            "event": sorted(policy[1])[0],
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "path": policy[0],
        }
        for prerequisite_id, policy in VERIFIER.PREREQUISITE_POLICIES.items()
    }


def valid_prerequisite_jobs() -> dict[str, dict[str, object]]:
    pages: dict[str, dict[str, object]] = {}
    next_job_id = 100
    for prerequisite_id, policy in VERIFIER.PREREQUISITE_POLICIES.items():
        jobs: list[dict[str, object]] = []
        required_jobs = policy[2]
        for job_name, required_steps in required_jobs.items():
            steps = [
                {
                    "name": step_name,
                    "number": step_number,
                    "status": "completed",
                    "conclusion": "success",
                }
                for step_number, step_name in enumerate(required_steps, start=1)
            ]
            jobs.append(
                {
                    "id": next_job_id,
                    "run_id": PREREQUISITE_RUN_IDS[prerequisite_id],
                    "run_attempt": 1,
                    "head_sha": COMMIT,
                    "name": job_name,
                    "status": "completed",
                    "conclusion": "success",
                    "steps": steps,
                }
            )
            next_job_id += 1
        pages[prerequisite_id] = {"total_count": len(jobs), "jobs": jobs}
    return pages


class WalletReleasePreflightTests(unittest.TestCase):
    def assert_reason(
        self,
        result: dict[str, object],
        run: dict[str, object],
        jobs: dict[str, object],
        reason: object,
        expected_commit: str = COMMIT,
        prerequisite_runs: dict[str, dict[str, object]] | None = None,
        prerequisite_jobs: dict[str, dict[str, object]] | None = None,
    ) -> None:
        with self.assertRaises(VERIFIER.WalletPreflightError) as raised:
            VERIFIER.verify(
                result,
                run,
                jobs,
                valid_prerequisite_runs()
                if prerequisite_runs is None
                else prerequisite_runs,
                valid_prerequisite_jobs()
                if prerequisite_jobs is None
                else prerequisite_jobs,
                expected_commit,
            )
        self.assertEqual(raised.exception.reason, reason)

    def test_accepts_exact_successful_preflight(self) -> None:
        self.assertEqual(
            VERIFIER.verify(
                valid_result(),
                valid_run(),
                valid_jobs(),
                valid_prerequisite_runs(),
                valid_prerequisite_jobs(),
                COMMIT,
            ),
            VERIFIER.PackageEvidenceIdentity(
                preflight_run_id=RUN_ID,
                preflight_job_id=JOB_ID,
                fuzz_run_id=31,
                protobuf_ci_run_id=32,
                rust_ci_run_id=33,
            ),
        )

    def test_accepts_manual_protobuf_and_rust_prerequisites(self) -> None:
        runs = valid_prerequisite_runs()
        runs["protobuf_ci"]["event"] = "workflow_dispatch"
        runs["rust_ci"]["event"] = "workflow_dispatch"
        self.assertEqual(
            VERIFIER.verify(
                valid_result(),
                valid_run(),
                valid_jobs(),
                runs,
                valid_prerequisite_jobs(),
                COMMIT,
            ),
            VERIFIER.PackageEvidenceIdentity(
                preflight_run_id=RUN_ID,
                preflight_job_id=JOB_ID,
                fuzz_run_id=31,
                protobuf_ci_run_id=32,
                rust_ci_run_id=33,
            ),
        )

    def test_rejects_malformed_or_unsupported_prerequisite_events(self) -> None:
        invalid_events: tuple[object, ...] = (
            None,
            1,
            [],
            {},
            "schedule",
            "pull_request",
        )
        for prerequisite_id in VERIFIER.PREREQUISITE_POLICIES:
            for event in invalid_events:
                with self.subTest(prerequisite_id=prerequisite_id, event=event):
                    runs = valid_prerequisite_runs()
                    runs[prerequisite_id]["event"] = event
                    self.assert_reason(
                        valid_result(),
                        valid_run(),
                        valid_jobs(),
                        VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
                        prerequisite_runs=runs,
                    )

    def test_required_steps_are_derived_from_release_bundle_policy(self) -> None:
        expected = tuple(
            dict.fromkeys(
                step
                for steps in VERIFIER.wallet_package_bundle.EXPECTED_EVIDENCE_STEPS.values()
                for step in steps
            )
        )
        self.assertEqual(VERIFIER.REQUIRED_STEPS, expected)

    def test_rejects_invalid_expected_commit(self) -> None:
        self.assert_reason(
            valid_result(),
            valid_run(),
            valid_jobs(),
            VERIFIER.WalletPreflightErrorReason.RESULT_MISMATCH,
            "not-a-commit",
        )

    def test_rejects_result_identity_substitution(self) -> None:
        cases = (
            ("component", "component_id", "identity"),
            ("component", "repository", "https://github.com/reallyme/identity"),
            ("component", "commit", "2" * 40),
            ("package_evidence", "preflight_run_id", True),
            ("package_evidence", "preflight_job_id", 0),
            ("package_evidence", "fuzz_run_id", 0),
            ("package_evidence", "protobuf_ci_run_id", True),
            ("package_evidence", "rust_ci_run_id", 0),
        )
        for container_name, key, value in cases:
            with self.subTest(container=container_name, key=key):
                result = copy.deepcopy(valid_result())
                container = result[container_name]
                self.assertIsInstance(container, dict)
                container[key] = value
                self.assert_reason(
                    result,
                    valid_run(),
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.RESULT_MISMATCH,
                )

    def test_rejects_wrong_workflow_run(self) -> None:
        cases = (
            ("id", 99),
            ("head_sha", "2" * 40),
            ("head_branch", "release"),
            ("event", "push"),
            ("run_attempt", 2),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/other.yml"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                run = valid_run()
                run[key] = value
                self.assert_reason(
                    valid_result(),
                    run,
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.RUN_MISMATCH,
                )

    def test_rejects_wrong_or_incomplete_job_page(self) -> None:
        cases = (
            ("total_count", 2),
            ("total_count", 0),
            ("total_count", 101),
        )
        for key, value in cases:
            with self.subTest(value=value):
                jobs = valid_jobs()
                jobs[key] = value
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    jobs,
                    VERIFIER.WalletPreflightErrorReason.JOB_MISMATCH,
                )

    def test_rejects_wrong_preflight_job(self) -> None:
        cases = (
            ("id", 99),
            ("run_id", 99),
            ("run_attempt", 2),
            ("head_sha", "2" * 40),
            ("name", "Unrelated job"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                jobs = valid_jobs()
                job = jobs["jobs"][0]
                job[key] = value
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    jobs,
                    VERIFIER.WalletPreflightErrorReason.JOB_MISMATCH,
                )

    def test_rejects_missing_duplicated_or_failed_required_step(self) -> None:
        for mutation in ("missing", "duplicated", "failed"):
            with self.subTest(mutation=mutation):
                jobs = valid_jobs()
                job = jobs["jobs"][0]
                steps = job["steps"]
                target = VERIFIER.REQUIRED_STEPS[0]
                if mutation == "missing":
                    job["steps"] = [step for step in steps if step["name"] != target]
                elif mutation == "duplicated":
                    duplicate = copy.deepcopy(steps[0])
                    duplicate["number"] = 99
                    steps.append(duplicate)
                else:
                    steps[0]["conclusion"] = "failure"
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    jobs,
                    VERIFIER.WalletPreflightErrorReason.REQUIRED_STEP_MISMATCH
                    if mutation in {"missing", "duplicated"}
                    else VERIFIER.WalletPreflightErrorReason.JOB_MISMATCH,
                )

    def test_rejects_duplicate_step_number(self) -> None:
        jobs = valid_jobs()
        steps = jobs["jobs"][0]["steps"]
        steps[1]["number"] = steps[0]["number"]
        self.assert_reason(
            valid_result(),
            valid_run(),
            jobs,
            VERIFIER.WalletPreflightErrorReason.JOB_MISMATCH,
        )

    def test_rejects_soft_failed_nonrequired_step(self) -> None:
        jobs = valid_jobs()
        steps = jobs["jobs"][0]["steps"]
        steps[-1]["conclusion"] = "failure"
        self.assert_reason(
            valid_result(),
            valid_run(),
            jobs,
            VERIFIER.WalletPreflightErrorReason.JOB_MISMATCH,
        )

    def test_rejects_substituted_prerequisite_run(self) -> None:
        cases = (
            ("id", 99),
            ("head_sha", "2" * 40),
            ("head_branch", "release"),
            ("event", "push"),
            ("run_attempt", 2),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/other.yml"),
        )
        for key, value in cases:
            with self.subTest(key=key):
                runs = valid_prerequisite_runs()
                runs["fuzz"][key] = value
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
                    prerequisite_runs=runs,
                )

    def test_rejects_push_only_fuzz_evidence(self) -> None:
        runs = valid_prerequisite_runs()
        runs["fuzz"]["event"] = "push"
        self.assert_reason(
            valid_result(),
            valid_run(),
            valid_jobs(),
            VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
            prerequisite_runs=runs,
        )

    def test_rejects_missing_or_failed_fuzz_campaign(self) -> None:
        for mutation in ("missing", "failed"):
            with self.subTest(mutation=mutation):
                pages = valid_prerequisite_jobs()
                page = pages["fuzz"]
                target = "scheduled fuzz (wallet_state_machine)"
                matching = [job for job in page["jobs"] if job["name"] == target]
                self.assertEqual(len(matching), 1)
                if mutation == "missing":
                    page["jobs"] = [
                        job for job in page["jobs"] if job["name"] != target
                    ]
                    page["total_count"] = len(page["jobs"])
                else:
                    matching[0]["conclusion"] = "failure"
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
                    prerequisite_jobs=pages,
                )

    def test_rejects_missing_failed_or_duplicated_prerequisite_job(self) -> None:
        for mutation in ("missing", "failed", "duplicated"):
            with self.subTest(mutation=mutation):
                pages = valid_prerequisite_jobs()
                page = pages["rust_ci"]
                jobs = page["jobs"]
                if mutation == "missing":
                    jobs.pop()
                    page["total_count"] = len(jobs)
                elif mutation == "failed":
                    jobs[0]["conclusion"] = "failure"
                else:
                    duplicate = copy.deepcopy(jobs[0])
                    duplicate["id"] = 999
                    jobs.append(duplicate)
                    page["total_count"] = len(jobs)
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
                    prerequisite_jobs=pages,
                )

    def test_rejects_missing_or_soft_failed_prerequisite_step(self) -> None:
        for mutation in ("missing", "failed"):
            with self.subTest(mutation=mutation):
                pages = valid_prerequisite_jobs()
                steps = pages["protobuf_ci"]["jobs"][0]["steps"]
                if mutation == "missing":
                    steps.pop()
                else:
                    steps[0]["conclusion"] = "failure"
                self.assert_reason(
                    valid_result(),
                    valid_run(),
                    valid_jobs(),
                    VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
                    prerequisite_jobs=pages,
                )

    def test_rejects_extra_fuzz_job(self) -> None:
        pages = valid_prerequisite_jobs()
        fuzz_page = pages["fuzz"]
        fuzz_page["jobs"].append(
            {
                "id": 999,
                "run_id": PREREQUISITE_RUN_IDS["fuzz"],
                "run_attempt": 1,
                "head_sha": COMMIT,
                "name": "scheduled fuzz target",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
        )
        fuzz_page["total_count"] = len(fuzz_page["jobs"])
        self.assert_reason(
            valid_result(),
            valid_run(),
            valid_jobs(),
            VERIFIER.WalletPreflightErrorReason.PREREQUISITE_MISMATCH,
            prerequisite_jobs=pages,
        )

    def test_allows_only_completed_skipped_optional_nonfuzz_jobs(self) -> None:
        pages = valid_prerequisite_jobs()
        rust_page = pages["rust_ci"]
        rust_page["jobs"].append(
            {
                "id": 999,
                "run_id": PREREQUISITE_RUN_IDS["rust_ci"],
                "run_attempt": 1,
                "head_sha": COMMIT,
                "name": "conditional release publication",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
        )
        rust_page["total_count"] = len(rust_page["jobs"])
        VERIFIER.verify(
            valid_result(),
            valid_run(),
            valid_jobs(),
            valid_prerequisite_runs(),
            pages,
            COMMIT,
        )

    def test_rejects_reused_prerequisite_run_identity(self) -> None:
        result = valid_result()
        evidence = result["package_evidence"]
        evidence["fuzz_run_id"] = evidence["preflight_run_id"]
        self.assert_reason(
            result,
            valid_run(),
            valid_jobs(),
            VERIFIER.WalletPreflightErrorReason.RESULT_MISMATCH,
        )

    def test_loader_rejects_duplicate_members_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"id":1,"id":2}', encoding="utf-8")
            with self.assertRaises(VERIFIER.WalletPreflightError) as raised:
                VERIFIER.load_object(duplicate)
            self.assertEqual(
                raised.exception.reason,
                VERIFIER.WalletPreflightErrorReason.INVALID_INPUT,
            )
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(VERIFIER.WalletPreflightError) as raised:
                VERIFIER.load_object(link)
            self.assertEqual(
                raised.exception.reason,
                VERIFIER.WalletPreflightErrorReason.INVALID_INPUT,
            )


if __name__ == "__main__":
    unittest.main()
