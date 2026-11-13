#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify the official OIDF Wallet coverage contract and its pinned inputs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN_PATH = REPOSITORY_ROOT / "plans" / "oidf" / "wallet.json"
DEFAULT_CERTIFICATION_PLAN_PATH = (
    REPOSITORY_ROOT / "plans" / "oidf" / "certification.json"
)
DEFAULT_SUITE_LOCK_PATH = (
    REPOSITORY_ROOT / "upstream" / "oidf" / "conformance-suite.lock.json"
)
DEFAULT_MODULE_SNAPSHOT_PATH = (
    REPOSITORY_ROOT
    / "upstream"
    / "oidf"
    / "snapshots"
    / "certification-modules.json"
)
MAX_JSON_BYTES = 16_000_000
GIT_COMMIT_LENGTH = 40


class OidfWalletPlanErrorReason(Enum):
    INVALID_JSON = "invalid_json"
    INVALID_PLAN = "invalid_plan"
    SOURCE_BINDING_MISMATCH = "source_binding_mismatch"
    COMPONENT_CONTRACT_MISMATCH = "component_contract_mismatch"
    WALLET_ROLE_COVERAGE_MISMATCH = "wallet_role_coverage_mismatch"
    MODULE_INVENTORY_MISMATCH = "module_inventory_mismatch"
    EXECUTION_POLICY_MISMATCH = "execution_policy_mismatch"
    SUITE_CHECKOUT_UNAVAILABLE = "suite_checkout_unavailable"
    SUITE_CHECKOUT_MISMATCH = "suite_checkout_mismatch"


@dataclass(frozen=True)
class OidfWalletPlanError(Exception):
    reason: OidfWalletPlanErrorReason


@dataclass(frozen=True)
class WalletPlanSummary:
    profile_count: int
    module_execution_count: int
    suite_ref: str
    suite_commit: str


def fail(reason: OidfWalletPlanErrorReason) -> NoReturn:
    print(f"OIDF Wallet plan validation failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def load_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_JSON)
        if not 1 <= metadata.st_size <= MAX_JSON_BYTES:
            raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_JSON)
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.INVALID_JSON
        ) from error
    if not isinstance(value, dict):
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_JSON)
    return value


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    return value


def require_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    return value


def require_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    return value


def require_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    return value


def indexed_objects(
    values: object, key: str, error_reason: OidfWalletPlanErrorReason
) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for raw_value in require_list(values):
        if not isinstance(raw_value, dict):
            raise OidfWalletPlanError(error_reason)
        identifier = raw_value.get(key)
        if not isinstance(identifier, str) or not identifier or identifier in indexed:
            raise OidfWalletPlanError(error_reason)
        indexed[identifier] = raw_value
    return indexed


def indexed_snapshot_configurations(
    values: object,
) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for raw_value in require_list(values):
        if not isinstance(raw_value, dict):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
            )
        selected_variants = raw_value.get("selected_variants")
        if not isinstance(selected_variants, dict):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
            )
        profile_id = selected_variants.get("profile_id")
        if (
            not isinstance(profile_id, str)
            or not profile_id
            or profile_id in indexed
        ):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
            )
        indexed[profile_id] = raw_value
    return indexed


EXPECTED_ROLE_CONTRACTS: dict[str, dict[str, object]] = {
    "oid4vci-1_0-wallet-haip-test-plan": {
        "protocol": "openid4vci",
        "role": "wallet",
        "profile_count": 6,
        "module_execution_count": 138,
        "required_result_policy": "openid4vci",
        "profiles": {
            "wallet-sd-jwt-vc-wallet-initiated": 23,
            "wallet-mdoc-wallet-initiated": 23,
            "wallet-sd-jwt-vc-issuer-initiated-by-value": 23,
            "wallet-sd-jwt-vc-issuer-initiated-by-reference": 23,
            "wallet-mdoc-issuer-initiated-by-value": 23,
            "wallet-mdoc-issuer-initiated-by-reference": 23,
        },
    },
    "oid4vp-1final-wallet-haip-test-plan": {
        "protocol": "openid4vp",
        "role": "wallet",
        "profile_count": 4,
        "module_execution_count": 140,
        "required_result_policy": "openid4vp_default_with_source_bound_review",
        "profiles": {
            "wallet-sd-jwt-vc-direct-post-jwt": 21,
            "wallet-iso-mdl-direct-post-jwt": 19,
            "wallet-sd-jwt-vc-dc-api-jwt": 53,
            "wallet-iso-mdl-dc-api-jwt": 47,
        },
    },
}

EXPECTED_EXECUTION_POLICY: dict[str, object] = {
    "official_hosted_suite_required": True,
    "complete_product_deployment_required": True,
    "module_selectors_allowed": False,
    "skips_allowed": False,
    "expected_failures_allowed": False,
    "partial_reruns_allowed": False,
    "component_test_substitution_allowed": False,
    "mobile_app_required": False,
    "result_must_bind_framework_release": True,
    "result_must_bind_product_bom": True,
    "result_must_bind_deployment": True,
    "result_must_bind_module_inventory": True,
}

EXPECTED_CLAIM_POLICY: dict[str, object] = {
    "framework_inventory_check_is_product_execution": False,
    "wallet_core_engineering_result_is_oidf_result": False,
    "local_rehearsal_is_certification_evidence": False,
    "product_statement_requires_complete_execution": True,
    "external_certification_requires_oidf_submission": True,
}


def validate_source_bindings(
    plan: dict[str, object],
    certification: dict[str, object],
    suite_lock: dict[str, object],
    snapshot: dict[str, object],
) -> tuple[str, str]:
    source_bindings = exact_object(
        plan.get("source_bindings"),
        {
            "certification_plan",
            "suite_lock",
            "module_snapshot",
            "suite_repository",
            "suite_ref",
            "suite_commit",
        },
    )
    expected_paths = {
        "certification_plan": "plans/oidf/certification.json",
        "suite_lock": "upstream/oidf/conformance-suite.lock.json",
        "module_snapshot": "upstream/oidf/snapshots/certification-modules.json",
    }
    if any(source_bindings.get(key) != value for key, value in expected_paths.items()):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SOURCE_BINDING_MISMATCH
        )
    repository = require_string(suite_lock.get("repository"))
    suite_ref = require_string(suite_lock.get("pinned_ref"))
    suite_commit = require_string(suite_lock.get("commit"))
    if (
        repository != "https://gitlab.com/openid/conformance-suite.git"
        or len(suite_commit) != GIT_COMMIT_LENGTH
        or any(character not in "0123456789abcdef" for character in suite_commit)
        or source_bindings.get("suite_repository") != repository
        or source_bindings.get("suite_ref") != suite_ref
        or source_bindings.get("suite_commit") != suite_commit
        or snapshot.get("suite_ref") != suite_ref
        or snapshot.get("suite_commit") != suite_commit
    ):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SOURCE_BINDING_MISMATCH
        )
    suite_target = certification.get("suite_target")
    if not isinstance(suite_target, dict):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SOURCE_BINDING_MISMATCH
        )
    for key, lock_key in (
        ("repository", "repository"),
        ("pinned_ref", "pinned_ref"),
        ("commit", "commit"),
        ("local_checkout", "local_checkout"),
    ):
        if suite_target.get(key) != suite_lock.get(lock_key):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.SOURCE_BINDING_MISMATCH
            )
    return suite_ref, suite_commit


def validate_subject_and_selection(plan: dict[str, object]) -> None:
    subject = exact_object(
        plan.get("subject"),
        {
            "component_id",
            "repository",
            "implementation_scope",
            "app_targets",
            "non_applicable_targets",
        },
    )
    if subject != {
        "component_id": "wallet",
        "repository": "https://github.com/reallyme/wallet",
        "implementation_scope": "cross_platform_wallet_core",
        "app_targets": [],
        "non_applicable_targets": ["android_application", "ios_application"],
    }:
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    selection = exact_object(
        plan.get("selection"),
        {
            "product_kind",
            "candidate_role",
            "candidate_selected_by",
            "candidate_revision_selected_by",
        },
    )
    if selection != {
        "product_kind": "wallet",
        "candidate_role": "wallet_core",
        "candidate_selected_by": "product_component_bom",
        "candidate_revision_selected_by": "caller",
    }:
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)


def validate_component_contract(
    plan: dict[str, object], certification: dict[str, object]
) -> None:
    required_roles = plan.get("required_roles")
    required_adapter_contracts = plan.get("required_adapter_contracts")
    certification_roles = certification.get("required_roles")
    certification_adapters = certification.get("required_adapter_contracts")
    if (
        required_roles != ["openid4vci_wallet", "openid4vp_wallet"]
        or required_adapter_contracts != ["openid4vci", "openid4vp"]
        or not isinstance(certification_roles, list)
        or not set(required_roles).issubset(certification_roles)
        or certification_adapters != required_adapter_contracts
    ):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.COMPONENT_CONTRACT_MISMATCH
        )


def validate_role_contracts(
    plan: dict[str, object], certification: dict[str, object], snapshot: dict[str, object]
) -> tuple[int, int]:
    plan_roles = indexed_objects(
        plan.get("required_wallet_roles"),
        "plan_id",
        OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH,
    )
    if set(plan_roles) != set(EXPECTED_ROLE_CONTRACTS):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
        )
    certification_plans = indexed_objects(
        certification.get("plans"),
        "plan_id",
        OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH,
    )
    snapshot_plans = indexed_objects(
        snapshot.get("plans"),
        "plan_id",
        OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH,
    )
    total_profiles = 0
    total_modules = 0
    for plan_id, expected in EXPECTED_ROLE_CONTRACTS.items():
        role = exact_object(
            plan_roles[plan_id],
            {
                "protocol",
                "role",
                "plan_id",
                "profile_count",
                "module_execution_count",
                "required_result_policy",
            },
        )
        expected_role = {
            key: value for key, value in expected.items() if key != "profiles"
        }
        expected_role["plan_id"] = plan_id
        if role != expected_role:
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
            )
        certification_plan = certification_plans.get(plan_id)
        if (
            certification_plan is None
            or certification_plan.get("protocol") != expected["protocol"]
            or certification_plan.get("role") != "wallet"
        ):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
            )
        runs = indexed_objects(
            certification_plan.get("certification_runs"),
            "profile_id",
            OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH,
        )
        expected_profiles = expected["profiles"]
        if not isinstance(expected_profiles, dict) or set(runs) != set(expected_profiles):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
            )
        for run in runs.values():
            expression = require_string(run.get("expression"))
            if ":" in expression:
                raise OidfWalletPlanError(
                    OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
                )
        snapshot_plan = snapshot_plans.get(plan_id)
        if snapshot_plan is None:
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
            )
        configurations = indexed_snapshot_configurations(
            snapshot_plan.get("configurations")
        )
        if set(configurations) != set(expected_profiles):
            raise OidfWalletPlanError(
                OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
            )
        for profile_id, expected_module_count in expected_profiles.items():
            configuration = configurations[profile_id]
            selected_variants = configuration.get("selected_variants")
            modules = configuration.get("modules")
            if (
                not isinstance(selected_variants, dict)
                or selected_variants.get("profile_id") != profile_id
                or configuration.get("module_count") != expected_module_count
                or not isinstance(modules, list)
                or len(modules) != expected_module_count
            ):
                raise OidfWalletPlanError(
                    OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
                )
            module_executions: set[str] = set()
            for raw_module in modules:
                if not isinstance(raw_module, dict):
                    raise OidfWalletPlanError(
                        OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
                    )
                module_name = raw_module.get("testModule")
                if not isinstance(module_name, str) or not module_name:
                    raise OidfWalletPlanError(
                        OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
                    )
                module_execution = json.dumps(
                    raw_module, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                )
                if module_execution in module_executions:
                    raise OidfWalletPlanError(
                        OidfWalletPlanErrorReason.MODULE_INVENTORY_MISMATCH
                    )
                module_executions.add(module_execution)
        total_profiles += require_integer(expected["profile_count"])
        total_modules += require_integer(expected["module_execution_count"])
    if (
        plan.get("profile_count") != total_profiles
        or plan.get("module_execution_count") != total_modules
    ):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.WALLET_ROLE_COVERAGE_MISMATCH
        )
    return total_profiles, total_modules


def validate_execution_policy(
    plan: dict[str, object], certification: dict[str, object]
) -> None:
    if plan.get("execution_policy") != EXPECTED_EXECUTION_POLICY:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )
    if plan.get("claim_policy") != EXPECTED_CLAIM_POLICY:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )
    contract = certification.get("execution_contract")
    if not isinstance(contract, dict):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )
    required_results = contract.get("required_module_results")
    if (
        contract.get("run_every_returned_module") is not True
        or contract.get("allow_selected_modules") is not False
        or contract.get("allow_rerun_filter_for_certification_evidence") is not False
        or contract.get("allow_expected_failures") is not False
        or contract.get("allow_expected_skips") is not False
        or required_results
        != {
            "openid4vci": ["PASSED"],
            "openid4vp_default": ["PASSED"],
            "openid4vp_source_bound_review": ["REVIEW"],
        }
    ):
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.EXECUTION_POLICY_MISMATCH
        )


def validate_suite_checkout(checkout: Path, expected_commit: str) -> None:
    if checkout.is_symlink() or not checkout.is_dir():
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SUITE_CHECKOUT_UNAVAILABLE
        )
    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD^{commit}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SUITE_CHECKOUT_UNAVAILABLE
        ) from error
    if completed.returncode != 0:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SUITE_CHECKOUT_UNAVAILABLE
        )
    if completed.stdout.strip() != expected_commit:
        raise OidfWalletPlanError(
            OidfWalletPlanErrorReason.SUITE_CHECKOUT_MISMATCH
        )


def validate_paths(
    plan_path: Path,
    certification_plan_path: Path,
    suite_lock_path: Path,
    module_snapshot_path: Path,
    suite_checkout: Path | None = None,
) -> WalletPlanSummary:
    plan = load_object(plan_path)
    certification = load_object(certification_plan_path)
    suite_lock = load_object(suite_lock_path)
    snapshot = load_object(module_snapshot_path)
    exact_object(
        plan,
        {
            "$comment",
            "schema_version",
            "plan_id",
            "execution_status",
            "certification_claim",
            "subject",
            "source_bindings",
            "selection",
            "required_roles",
            "required_adapter_contracts",
            "required_wallet_roles",
            "profile_count",
            "module_execution_count",
            "execution_policy",
            "claim_policy",
        },
    )
    if (
        plan.get("schema_version") != 1
        or plan.get("plan_id") != "oidf-wallet-certification-v1"
        or plan.get("execution_status") != "external_runner_required"
        or plan.get("certification_claim") is not False
    ):
        raise OidfWalletPlanError(OidfWalletPlanErrorReason.INVALID_PLAN)
    validate_subject_and_selection(plan)
    suite_ref, suite_commit = validate_source_bindings(
        plan, certification, suite_lock, snapshot
    )
    validate_component_contract(plan, certification)
    profile_count, module_execution_count = validate_role_contracts(
        plan, certification, snapshot
    )
    validate_execution_policy(plan, certification)
    if suite_checkout is not None:
        validate_suite_checkout(suite_checkout, suite_commit)
    return WalletPlanSummary(
        profile_count=profile_count,
        module_execution_count=module_execution_count,
        suite_ref=suite_ref,
        suite_commit=suite_commit,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN_PATH)
    parser.add_argument(
        "--certification-plan", type=Path, default=DEFAULT_CERTIFICATION_PLAN_PATH
    )
    parser.add_argument("--suite-lock", type=Path, default=DEFAULT_SUITE_LOCK_PATH)
    parser.add_argument(
        "--module-snapshot", type=Path, default=DEFAULT_MODULE_SNAPSHOT_PATH
    )
    parser.add_argument("--suite-checkout", type=Path)
    args = parser.parse_args()
    try:
        summary = validate_paths(
            args.plan,
            args.certification_plan,
            args.suite_lock,
            args.module_snapshot,
            args.suite_checkout,
        )
    except OidfWalletPlanError as error:
        fail(error.reason)
    print(
        "OIDF Wallet plan covers "
        f"{summary.profile_count} configurations and "
        f"{summary.module_execution_count} module executions "
        f"from {summary.suite_ref} ({summary.suite_commit})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
