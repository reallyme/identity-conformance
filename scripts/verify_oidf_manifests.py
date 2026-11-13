#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the checked OIDF plan matrices and resolved module inventories."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLANS_ROOT = REPOSITORY_ROOT / "plans" / "oidf"
SNAPSHOTS_ROOT = REPOSITORY_ROOT / "upstream" / "oidf" / "snapshots"
SUITE_LOCK_PATH = REPOSITORY_ROOT / "upstream" / "oidf" / "conformance-suite.lock.json"
SUITE_LOCK_RELATIVE_PATH = "upstream/oidf/conformance-suite.lock.json"
ADAPTER_REGISTRY_PATH = REPOSITORY_ROOT / "adapters" / "registry.json"
RESULT_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "execution-result.schema.json"
EVIDENCE_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "certification-evidence.schema.json"
MAX_JSON_BYTES = 16_000_000
EXIT_INVALID_INPUT = 65
ENVIRONMENT_NAME = re.compile(r"^OIDF_[A-Z0-9_]+_CONFIG$")
REALLYME_REPOSITORY = re.compile(
    r"^https://github\.com/reallyme/[A-Za-z0-9_.-]+$"
)
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
OIDF_REQUIRED_ROLES = [
    "openid4vci_issuer",
    "openid4vci_wallet",
    "openid4vp_verifier",
    "openid4vp_wallet",
]
OIDF_REQUIRED_ADAPTER_CONTRACTS = ["openid4vci", "openid4vp"]


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_INVALID_INPUT)


def load_object(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            fail(f"manifest exceeds the accepted size: {path.name}")
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(f"manifest is unavailable or invalid JSON: {path.name}")
    if not isinstance(value, dict):
        fail(f"manifest must contain a JSON object: {path.name}")
    return value


def require_object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    return value


def require_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        fail(f"{context} must be an array")
    return value


def require_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty string")
    return value


def verify_suite_lock(suite_lock: dict[str, object]) -> None:
    if suite_lock.get("schema_version") != 1:
        fail("suite lock has an unsupported schema version")
    if suite_lock.get("repository") != "https://gitlab.com/openid/conformance-suite.git":
        fail("suite lock must reference the official OIDF repository")
    if suite_lock.get("local_checkout") != "upstream/oidf/openid-conformance-suite":
        fail("suite lock checkout must remain inside the upstream OIDF boundary")
    require_string(suite_lock.get("pinned_ref"), "suite_lock.pinned_ref")
    commit = require_string(suite_lock.get("commit"), "suite_lock.commit")
    if GIT_COMMIT.fullmatch(commit) is None:
        fail("suite lock commit must be a full lowercase Git commit")


def verify_suite_target(
    manifest: dict[str, object], suite_lock: dict[str, object], context: str,
    expected_lock: str = SUITE_LOCK_RELATIVE_PATH,
) -> None:
    target = require_object(manifest.get("suite_target"), f"{context}.suite_target")
    if target.get("lock_file") != expected_lock:
        fail(f"{context} does not reference the canonical suite lock")
    for key in ("repository", "local_checkout", "pinned_ref", "commit"):
        if target.get(key) != suite_lock.get(key):
            fail(f"{context} suite target disagrees with the canonical lock: {key}")


def verify_plan_runs(
    manifest: dict[str, object],
    run_key: str,
    expected: dict[str, int],
    context: str,
) -> None:
    plans = require_list(manifest.get("plans"), f"{context}.plans")
    observed: dict[str, int] = {}
    for raw_plan in plans:
        plan = require_object(raw_plan, f"{context}.plan")
        plan_id = require_string(plan.get("plan_id"), f"{context}.plan_id")
        runs = require_list(plan.get(run_key), f"{plan_id}.{run_key}")
        for raw_run in runs:
            run = require_object(raw_run, f"{plan_id}.run")
            expression = require_string(run.get("expression"), f"{plan_id}.expression")
            if ":" in expression:
                fail(f"{plan_id} contains a prohibited module selector")
        observed[plan_id] = len(runs)
    if observed != expected:
        fail(f"{context} plan coverage does not match the approved matrix")


def verify_caller_contract(manifest: dict[str, object], context: str) -> None:
    if manifest.get("required_roles") != OIDF_REQUIRED_ROLES:
        fail(f"{context} required role contract is invalid")
    if manifest.get("required_adapter_contracts") != OIDF_REQUIRED_ADAPTER_CONTRACTS:
        fail(f"{context} required adapter contract is invalid")


def verify_vp_wallet_credential_types(
    manifest: dict[str, object], run_key: str, plan_id: str
) -> None:
    expected_types = {"sd_jwt_vc": "eudi_pid", "iso_mdl": "mdl"}
    plans = require_list(manifest.get("plans"), "plans")
    matching: list[dict[str, object]] = []
    for raw_plan in plans:
        plan = require_object(raw_plan, "plan")
        if plan.get("plan_id") == plan_id:
            matching.append(plan)
    if len(matching) != 1:
        fail(f"{plan_id} must be declared exactly once")
    plan = matching[0]
    if plan.get("credential_type_by_credential_format") != expected_types:
        fail(f"{plan_id} credential type mapping is invalid")
    for raw_run in require_list(plan.get(run_key), f"{plan_id}.{run_key}"):
        run = require_object(raw_run, f"{plan_id}.run")
        credential_format = require_string(
            run.get("credential_format"), f"{plan_id}.credential_format"
        )
        expected_type = expected_types.get(credential_format)
        if expected_type is None or run.get("credential_type") != expected_type:
            fail(f"{plan_id} run has an invalid credential type")
        expression = require_string(run.get("expression"), f"{plan_id}.expression")
        if f"[credential_type={expected_type}]" not in expression:
            fail(f"{plan_id} expression omits its credential type")


def verify_certification_manifest(
    manifest: dict[str, object], suite_lock: dict[str, object]
) -> None:
    verify_caller_contract(manifest, "certification")
    verify_suite_target(manifest, suite_lock, "certification")
    verify_plan_runs(
        manifest,
        "certification_runs",
        {
            "oid4vci-1_0-issuer-haip-test-plan": 4,
            "oid4vci-1_0-wallet-haip-test-plan": 6,
            "oid4vp-1final-verifier-haip-test-plan": 2,
            "oid4vp-1final-wallet-haip-test-plan": 4,
        },
        "certification",
    )
    expected_vci_profiles = {
        "issuer-sd-jwt-vc-wallet-initiated",
        "issuer-sd-jwt-vc-issuer-initiated",
        "issuer-mdoc-wallet-initiated",
        "issuer-mdoc-issuer-initiated",
        "wallet-sd-jwt-vc-wallet-initiated",
        "wallet-sd-jwt-vc-issuer-initiated-by-value",
        "wallet-sd-jwt-vc-issuer-initiated-by-reference",
        "wallet-mdoc-wallet-initiated",
        "wallet-mdoc-issuer-initiated-by-value",
        "wallet-mdoc-issuer-initiated-by-reference",
    }
    observed_vci_profiles: list[str] = []
    for raw_plan in require_list(manifest.get("plans"), "certification.plans"):
        plan = require_object(raw_plan, "certification.plan")
        if plan.get("protocol") != "openid4vci":
            continue
        for raw_run in require_list(
            plan.get("certification_runs"), "openid4vci.certification_runs"
        ):
            run = require_object(raw_run, "openid4vci.certification_run")
            observed_vci_profiles.append(
                require_string(run.get("profile_id"), "openid4vci.profile_id")
            )
    if (
        len(observed_vci_profiles) != len(expected_vci_profiles)
        or set(observed_vci_profiles) != expected_vci_profiles
    ):
        fail("OpenID4VCI certification profile identifiers are incomplete or duplicated")
    expected_vp_profiles = {
        "verifier-sd-jwt-vc-direct-post-jwt",
        "verifier-iso-mdl-direct-post-jwt",
        "wallet-sd-jwt-vc-direct-post-jwt",
        "wallet-iso-mdl-direct-post-jwt",
        "wallet-sd-jwt-vc-dc-api-jwt",
        "wallet-iso-mdl-dc-api-jwt",
    }
    observed_vp_profiles: list[str] = []
    for raw_plan in require_list(manifest.get("plans"), "certification.plans"):
        plan = require_object(raw_plan, "certification.plan")
        if plan.get("protocol") != "openid4vp":
            continue
        for raw_run in require_list(
            plan.get("certification_runs"), "openid4vp.certification_runs"
        ):
            run = require_object(raw_run, "openid4vp.certification_run")
            observed_vp_profiles.append(
                require_string(run.get("profile_id"), "openid4vp.profile_id")
            )
    if (
        len(observed_vp_profiles) != len(expected_vp_profiles)
        or set(observed_vp_profiles) != expected_vp_profiles
    ):
        fail("OpenID4VP certification profile identifiers are incomplete or duplicated")
    verify_vp_wallet_credential_types(
        manifest,
        "certification_runs",
        "oid4vp-1final-wallet-haip-test-plan",
    )
    contract = require_object(manifest.get("execution_contract"), "execution_contract")
    production_endpoints = require_object(
        contract.get("production_endpoints"),
        "execution_contract.production_endpoints",
    )
    if production_endpoints != {
        "api": "https://www.certification.openid.net/",
        "mtls": "https://mtls-www.certification.openid.net/",
    }:
        fail("certification execution must use the official production endpoints")
    for key in (
        "allow_selected_modules",
        "allow_rerun_filter_for_certification_evidence",
        "allow_expected_failures",
        "allow_expected_skips",
    ):
        if contract.get(key) is not False:
            fail(f"execution_contract.{key} must be false")
    if contract.get("required_module_results") != {
        "openid4vci": ["PASSED"],
        "openid4vp_default": ["PASSED"],
        "openid4vp_source_bound_review": ["REVIEW"],
    }:
        fail("certification evidence has an invalid protocol result policy")
    if contract.get("openid4vp_result_policy_authority") != (
        "plans/oidf/execution/openid4vp-profile-matrix.json in the selected "
        "Identity Conformance release"
    ):
        fail("OpenID4VP review results must bind to the framework execution matrix")


def verify_engineering_manifest(
    manifest: dict[str, object], suite_lock: dict[str, object],
    expected_lock: str = SUITE_LOCK_RELATIVE_PATH,
) -> None:
    verify_caller_contract(manifest, "engineering")
    verify_suite_target(manifest, suite_lock, "engineering", expected_lock)
    if manifest.get("scope") != "non_certification_final_engineering":
        fail("engineering matrix has an invalid evidence scope")
    contract = require_object(manifest.get("scope_contract"), "scope_contract")
    if contract.get("run_every_returned_module") is not True:
        fail("engineering matrix must run every returned module")
    if contract.get("module_selector_allowed") is not False:
        fail("engineering matrix must prohibit module selectors")
    verify_plan_runs(
        manifest,
        "engineering_runs",
        {
            "oid4vci-1_0-issuer-test-plan": 4,
            "oid4vci-1_0-wallet-test-plan": 6,
            "oid4vp-1final-verifier-test-plan": 8,
            "oid4vp-1final-wallet-test-plan": 8,
        },
        "engineering",
    )
    verify_vp_wallet_credential_types(
        manifest,
        "engineering_runs",
        "oid4vp-1final-wallet-test-plan",
    )


def verify_module_snapshot(
    snapshot: dict[str, object],
    expected_commit: str,
    expected_scope: str,
    expected_configurations: int,
    expected_executions: int,
) -> set[str]:
    if snapshot.get("suite_commit") != expected_commit:
        fail(f"{expected_scope} module snapshot uses the wrong suite commit")
    if snapshot.get("inventory_scope") != expected_scope:
        fail(f"{expected_scope} module snapshot has the wrong scope")
    if snapshot.get("source_license") != "MIT":
        fail(f"{expected_scope} module snapshot does not preserve upstream licensing")
    if snapshot.get("curation_license") != "MIT OR Apache-2.0":
        fail(f"{expected_scope} module snapshot has an invalid curation license")
    if snapshot.get("plan_configuration_count") != expected_configurations:
        fail(f"{expected_scope} module snapshot has the wrong configuration count")
    if snapshot.get("module_execution_count") != expected_executions:
        fail(f"{expected_scope} module snapshot has the wrong execution count")

    module_ids: set[str] = set()
    plans = require_list(snapshot.get("plans"), f"{expected_scope}.plans")
    for raw_plan in plans:
        plan = require_object(raw_plan, f"{expected_scope}.plan")
        configurations = require_list(
            plan.get("configurations"), f"{expected_scope}.configurations"
        )
        for raw_configuration in configurations:
            configuration = require_object(
                raw_configuration, f"{expected_scope}.configuration"
            )
            modules = require_list(configuration.get("modules"), "configuration.modules")
            if not modules or configuration.get("module_count") != len(modules):
                fail(f"{expected_scope} contains an incomplete module configuration")
            for raw_module in modules:
                module = require_object(raw_module, f"{expected_scope}.module")
                module_ids.add(
                    require_string(module.get("testModule"), "module.testModule")
                )
    return module_ids


def plan_owners(*manifests: dict[str, object]) -> dict[str, tuple[str, str]]:
    owners: dict[str, tuple[str, str]] = {}
    for manifest in manifests:
        for raw_plan in require_list(manifest.get("plans"), "plans"):
            plan = require_object(raw_plan, "plan")
            plan_id = require_string(plan.get("plan_id"), "plan.plan_id")
            protocol = require_string(plan.get("protocol"), f"{plan_id}.protocol")
            role = require_string(plan.get("role"), f"{plan_id}.role")
            if plan_id in owners:
                fail(f"plan is declared more than once: {plan_id}")
            owners[plan_id] = (protocol, role)
    return owners


def verify_adapter_registry(
    registry: dict[str, object],
    expected_plans: dict[str, tuple[str, str]],
) -> None:
    if registry.get("schema_version") != 1:
        fail("adapter registry has an unsupported schema version")
    registered_adapters = require_list(registry.get("adapters"), "adapters")
    if len(registered_adapters) != 7:
        fail("adapter registry must define all seven approved adapter roles")
    expected_non_oidf_adapters = {
        "eudi_relying_party_control_plane": {
        "adapter_id": "eudi_relying_party_control_plane",
        "protocol": "eudi_wallet_relying_party_registration",
        "role": "control_plane",
        "contract_path": "adapters/eudi-relying-party",
        "component_repositories": [
            "https://github.com/reallyme/platform",
            "https://github.com/reallyme/ssi",
        ],
        "configuration_env": "EUDI_DEPLOYMENT_MANIFEST",
        "plan_ids": ["eudi-relying-party-control-plane-v1"],
        },
        "eudi_wallet_engineering": {
            "adapter_id": "eudi_wallet_engineering",
            "protocol": "eudi_wallet",
            "role": "wallet",
            "contract_path": "adapters/eudi-wallet",
            "component_repositories": ["https://github.com/reallyme/wallet"],
            "configuration_env": "EUDI_WALLET_DEPLOYMENT_MANIFEST",
            "plan_ids": ["eudi-wallet-engineering-v1"],
        },
        "zk_presentation_proofs": {
            "adapter_id": "zk_presentation_proofs",
            "protocol": "reallyme_zk_presentation",
            "role": "proof_provider",
            "contract_path": "adapters/zk",
            "component_repositories": ["https://github.com/reallyme/zk"],
            "configuration_env": "ZK_DEPLOYMENT_MANIFEST",
            "plan_ids": ["zk-presentation-proofs-v1"],
        },
    }
    non_oidf_adapters: list[object] = []
    for adapter_id, expected_adapter in expected_non_oidf_adapters.items():
        matches = [
            raw_adapter
            for raw_adapter in registered_adapters
            if isinstance(raw_adapter, dict)
            and raw_adapter.get("adapter_id") == adapter_id
        ]
        if len(matches) != 1 or matches[0] != expected_adapter:
            fail(f"adapter registry has an invalid {adapter_id} boundary")
        non_oidf_adapters.extend(matches)
    adapters = [
        raw_adapter
        for raw_adapter in registered_adapters
        if not any(raw_adapter is non_oidf for non_oidf in non_oidf_adapters)
    ]
    if len(adapters) != 4:
        fail("adapter registry must define exactly four OIDF roles")

    observed_ids: set[str] = set()
    observed_plans: set[str] = set()
    for raw_adapter in adapters:
        adapter = require_object(raw_adapter, "adapter")
        adapter_id = require_string(adapter.get("adapter_id"), "adapter.adapter_id")
        if adapter_id in observed_ids:
            fail(f"adapter is declared more than once: {adapter_id}")
        observed_ids.add(adapter_id)

        protocol = require_string(adapter.get("protocol"), f"{adapter_id}.protocol")
        role = require_string(adapter.get("role"), f"{adapter_id}.role")
        contract_path = require_string(
            adapter.get("contract_path"), f"{adapter_id}.contract_path"
        )
        if contract_path not in {
            "adapters/openid4vci",
            "adapters/openid4vp",
            "adapters/wallet",
        }:
            fail(f"{adapter_id} has an invalid adapter boundary")
        if not (REPOSITORY_ROOT / contract_path).is_dir():
            fail(f"{adapter_id} adapter boundary is unavailable")

        configuration_env = require_string(
            adapter.get("configuration_env"), f"{adapter_id}.configuration_env"
        )
        if ENVIRONMENT_NAME.fullmatch(configuration_env) is None:
            fail(f"{adapter_id} has an invalid configuration environment variable")

        repositories = require_list(
            adapter.get("component_repositories"),
            f"{adapter_id}.component_repositories",
        )
        if not repositories:
            fail(f"{adapter_id} has no component repositories")
        seen_repositories: set[str] = set()
        for raw_repository in repositories:
            repository = require_string(
                raw_repository, f"{adapter_id}.component_repository"
            )
            if REALLYME_REPOSITORY.fullmatch(repository) is None:
                fail(f"{adapter_id} references a non-ReallyMe repository")
            if repository in seen_repositories:
                fail(f"{adapter_id} repeats a component repository")
            seen_repositories.add(repository)
        plan_ids = require_list(adapter.get("plan_ids"), f"{adapter_id}.plan_ids")
        if not plan_ids:
            fail(f"{adapter_id} has no plans")
        for raw_plan_id in plan_ids:
            plan_id = require_string(raw_plan_id, f"{adapter_id}.plan_id")
            if plan_id in observed_plans:
                fail(f"plan maps to more than one adapter: {plan_id}")
            owner = expected_plans.get(plan_id)
            if owner is None:
                fail(f"adapter references an unknown plan: {plan_id}")
            if owner != (protocol, role):
                fail(f"adapter role disagrees with plan ownership: {plan_id}")
            observed_plans.add(plan_id)

    if observed_ids != {
        "openid4vci_issuer",
        "openid4vci_wallet",
        "openid4vp_verifier",
        "openid4vp_wallet",
    }:
        fail("adapter registry does not define the approved role identifiers")
    if observed_plans != set(expected_plans):
        fail("adapter registry does not cover every selected OIDF plan exactly once")


def nested_object(value: object, keys: tuple[str, ...], context: str) -> dict[str, object]:
    current = value
    for key in keys:
        current = require_object(current, context).get(key)
    return require_object(current, context)


def verify_schema_contracts(
    result_schema: dict[str, object],
    evidence_schema: dict[str, object],
    suite_lock: dict[str, object],
) -> None:
    if result_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("execution result schema must use JSON Schema 2020-12")
    sensitive = nested_object(
        result_schema, ("properties", "contains_sensitive_data"), "result schema"
    )
    if sensitive.get("const") is not True:
        fail("execution result schema must classify raw output as sensitive")
    result_commit = nested_object(
        result_schema, ("properties", "suite_commit"), "result suite commit schema"
    )
    if result_commit.get("const") != suite_lock.get("commit"):
        fail("execution result schema suite commit disagrees with the canonical lock")

    if evidence_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("certification evidence schema must use JSON Schema 2020-12")
    suite_properties = nested_object(
        evidence_schema, ("properties", "suite", "properties"), "evidence suite schema"
    )
    commit = require_object(suite_properties.get("commit"), "evidence suite commit")
    repository = require_object(
        suite_properties.get("repository"), "evidence suite repository"
    )
    if commit.get("const") != suite_lock.get("commit"):
        fail("evidence schema suite commit disagrees with the canonical lock")
    if repository.get("const") != suite_lock.get("repository"):
        fail("evidence schema suite repository disagrees with the canonical lock")
    redaction = nested_object(
        evidence_schema,
        ("properties", "redaction_review", "properties", "completed"),
        "evidence redaction schema",
    )
    if redaction.get("const") is not True:
        fail("certification evidence must require completed redaction review")
    classification = nested_object(
        evidence_schema,
        ("properties", "classification"),
        "evidence classification schema",
    )
    if classification.get("const") != "public":
        fail("certification evidence must be explicitly public")
    disclosure = nested_object(
        evidence_schema,
        ("properties", "public_disclosure_review", "properties", "completed"),
        "evidence public disclosure schema",
    )
    if disclosure.get("const") is not True:
        fail("certification evidence must require public disclosure review")


def main() -> int:
    suite_lock = load_object(SUITE_LOCK_PATH)
    certification = load_object(PLANS_ROOT / "certification.json")
    engineering = load_object(PLANS_ROOT / "engineering.json")
    certification_modules = load_object(SNAPSHOTS_ROOT / "certification-modules.json")
    engineering_modules = load_object(SNAPSHOTS_ROOT / "engineering-modules.json")
    adapters = load_object(ADAPTER_REGISTRY_PATH)
    result_schema = load_object(RESULT_SCHEMA_PATH)
    evidence_schema = load_object(EVIDENCE_SCHEMA_PATH)

    verify_suite_lock(suite_lock)
    expected_commit = require_string(suite_lock.get("commit"), "suite_lock.commit")
    verify_certification_manifest(certification, suite_lock)
    verify_engineering_manifest(engineering, suite_lock)
    master_lock_path = "upstream/oidf/engineering-master.lock.json"
    master_lock = load_object(REPOSITORY_ROOT / master_lock_path)
    verify_suite_lock(master_lock)
    verify_engineering_manifest(
        load_object(PLANS_ROOT / "engineering-master.json"),
        master_lock,
        master_lock_path,
    )
    verify_adapter_registry(adapters, plan_owners(certification, engineering))
    verify_schema_contracts(result_schema, evidence_schema, suite_lock)
    module_ids = verify_module_snapshot(
        certification_modules, expected_commit, "certification", 16, 551
    )
    module_ids.update(
        verify_module_snapshot(
            engineering_modules,
            expected_commit,
            "non_certification_final_engineering",
            26,
            318,
        )
    )
    if len(module_ids) != 118:
        fail("combined module inventory does not contain 118 unique module IDs")
    print("OIDF manifests contain 42 configurations and 869 module executions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
