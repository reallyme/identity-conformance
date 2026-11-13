#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Build OIDF adapter inputs from the framework's pinned suite inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402
import verify_product_component_bom as product_bom_validator  # noqa: E402


MAX_JSON_BYTES = 16 * 1024 * 1024
SUITE_LOCK = REPOSITORY_ROOT / "upstream/oidf/conformance-suite.lock.json"
CERTIFICATION_PLAN = REPOSITORY_ROOT / "plans/oidf/certification.json"
ENGINEERING_PLAN = REPOSITORY_ROOT / "plans/oidf/engineering.json"
CERTIFICATION_SNAPSHOT = (
    REPOSITORY_ROOT / "upstream/oidf/snapshots/certification-modules.json"
)
OPENID4VP_MATRIX = (
    REPOSITORY_ROOT / "plans/oidf/execution/openid4vp-profile-matrix.json"
)
VERSION_REF = re.compile(r"^release-v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")


class ContractErrorReason(Enum):
    INPUT_INVALID = "input_invalid"
    FRAMEWORK_INCONSISTENT = "framework_inconsistent"
    OUTPUT_INVALID = "output_invalid"


class ContractError(Exception):
    """A stable failure without caller or evidence content."""

    def __init__(self, reason: ContractErrorReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def fail(reason: ContractErrorReason) -> NoReturn:
    raise ContractError(reason)


def load_object(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAX_JSON_BYTES
        ):
            fail(ContractErrorReason.INPUT_INVALID)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(MAX_JSON_BYTES + 1)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(opened.st_mode)
            or len(raw) != before.st_size
            or any(
                getattr(before, field) != getattr(opened, field)
                or getattr(before, field) != getattr(after_open, field)
                or getattr(before, field) != getattr(after_path, field)
                for field in stable_fields
            )
        ):
            fail(ContractErrorReason.INPUT_INVALID)
        value = strict_json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError):
        fail(ContractErrorReason.INPUT_INVALID)
    if not isinstance(value, dict):
        fail(ContractErrorReason.INPUT_INVALID)
    return value


def required_array(value: object) -> list[object]:
    if not isinstance(value, list):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return value


def required_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return value


def required_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return value


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def certification_configurations(
    snapshot: dict[str, object], protocol: str | None = None
) -> dict[str, tuple[str, dict[str, object]]]:
    configurations: dict[str, tuple[str, dict[str, object]]] = {}
    for raw_plan in required_array(snapshot.get("plans")):
        plan = required_object(raw_plan)
        plan_id = required_string(plan.get("plan_id"))
        if protocol is not None and not plan_id.startswith(protocol):
            continue
        for raw_configuration in required_array(plan.get("configurations")):
            configuration = required_object(raw_configuration)
            selected = required_object(configuration.get("selected_variants"))
            profile_id = required_string(selected.get("profile_id"))
            if profile_id in configurations:
                fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
            configurations[profile_id] = (plan_id, configuration)
    return configurations


def selected_runs(
    plan: dict[str, object], protocol: str
) -> list[tuple[str, str, str, str]]:
    runs: list[tuple[str, str, str, str]] = []
    for raw_plan in required_array(plan.get("plans")):
        plan_entry = required_object(raw_plan)
        if plan_entry.get("protocol") != protocol:
            continue
        plan_id = required_string(plan_entry.get("plan_id"))
        role = required_string(plan_entry.get("role"))
        for raw_run in required_array(plan_entry.get("certification_runs")):
            run = required_object(raw_run)
            runs.append(
                (
                    required_string(run.get("profile_id")),
                    role,
                    plan_id,
                    required_string(run.get("expression")),
                )
            )
    return runs


def suite_version(suite_lock: dict[str, object]) -> str:
    match = VERSION_REF.fullmatch(required_string(suite_lock.get("pinned_ref")))
    if match is None:
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return match.group("version")


def build_openid4vci_profile_matrix(
    certification_plan: dict[str, object],
    snapshot: dict[str, object],
    adapter_repository: str,
) -> dict[str, object]:
    configurations = certification_configurations(snapshot, "oid4vci")
    profiles: list[dict[str, object]] = []
    observed: set[str] = set()
    for profile_id, role, plan_id, expression in selected_runs(
        certification_plan, "openid4vci"
    ):
        match = configurations.get(profile_id)
        if match is None or match[0] != plan_id:
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        configuration = match[1]
        if configuration.get("expression") != expression:
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        module_count = configuration.get("module_count")
        if (
            not isinstance(module_count, int)
            or isinstance(module_count, bool)
            or module_count < 1
        ):
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        profiles.append(
            {
                "profile_id": profile_id,
                "entity_under_test": (
                    "credential_issuer" if role == "issuer" else "wallet"
                ),
                "plan_id": plan_id,
                "plan_expression": expression,
                "expected_module_count": module_count,
            }
        )
        observed.add(profile_id)
    if len(profiles) != 10 or observed != set(configurations):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return {
        "schema_version": 2,
        "suite_contract": "openid4vci-suite-contract.json",
        "source_repository": adapter_repository,
        "protocol_profile": "OID4VCI-1.0-FINAL+HAIP-1.0-FINAL",
        "repository_role_scope": ["credential_issuer", "wallet"],
        "credential_format_scope": ["sd_jwt_vc", "mdoc"],
        "profiles": profiles,
    }


def build_openid4vci_suite_contract(
    certification_plan: dict[str, object],
    engineering_plan: dict[str, object],
    suite_lock: dict[str, object],
) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    for source, certification in (
        (certification_plan, True),
        (engineering_plan, False),
    ):
        for raw_plan in required_array(source.get("plans")):
            plan = required_object(raw_plan)
            if plan.get("protocol") != "openid4vci":
                continue
            role = required_string(plan.get("role"))
            plans.append(
                {
                    "plan_id": required_string(plan.get("plan_id")),
                    "entity_under_test": (
                        "credential_issuer" if role == "issuer" else "wallet"
                    ),
                    "profile": "haip" if certification else "base",
                    "certification": certification,
                }
            )
    if len(plans) != 4 or len({item["plan_id"] for item in plans}) != 4:
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    repository = required_string(suite_lock.get("repository")).removesuffix(".git")
    return {
        "schema_version": 1,
        "repository": repository,
        "commit": required_string(suite_lock.get("commit")),
        "describe": required_string(suite_lock.get("pinned_ref")),
        "plans": sorted(plans, key=lambda item: str(item["plan_id"])),
    }


def normalized_module_entries(
    configuration: dict[str, object], plan_variant_keys: set[str]
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for raw_module in required_array(configuration.get("modules")):
        module = required_object(raw_module)
        module_id = required_string(module.get("testModule"))
        variant = required_object(module.get("variant"))
        normalized_variant: dict[str, str] = {}
        for key, value in variant.items():
            if not isinstance(key, str) or not isinstance(value, str):
                fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
            if key not in plan_variant_keys:
                normalized_variant[key] = value
        entries.append({"testModule": module_id, "variant": normalized_variant})
    entries.sort(key=lambda item: (str(item["testModule"]), canonical_json(item["variant"])))
    return entries


def build_openid4vci_module_inventory(
    snapshot: dict[str, object], suite_lock: dict[str, object]
) -> dict[str, object]:
    plans: list[dict[str, object]] = []
    for raw_plan in required_array(snapshot.get("plans")):
        plan = required_object(raw_plan)
        plan_id = required_string(plan.get("plan_id"))
        if not plan_id.startswith("oid4vci"):
            continue
        configurations = [
            required_object(item)
            for item in required_array(plan.get("configurations"))
        ]
        if not configurations:
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        resolved_variants = [
            required_object(item.get("resolved_variants"))
            for item in configurations
        ]
        plan_variant_keys = set().union(
            *(set(variant).difference({"profile_id"}) for variant in resolved_variants)
        )
        defaults = {
            key: values.pop()
            for key in sorted(plan_variant_keys)
            if len(
                values := {
                    variant.get(key)
                    for variant in resolved_variants
                    if isinstance(variant.get(key), str)
                }
            )
            == 1
        }
        reference_entries = normalized_module_entries(
            configurations[0], plan_variant_keys
        )
        reference_encoding = canonical_json(reference_entries)
        for configuration in configurations[1:]:
            if canonical_json(
                normalized_module_entries(configuration, plan_variant_keys)
            ) != reference_encoding:
                fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        digest = hashlib.sha256(f"{reference_encoding}\n".encode("utf-8")).hexdigest()
        plans.append(
            {
                "plan_id": plan_id,
                "module_variant_sha256": digest,
                "plan_variant_keys": sorted(plan_variant_keys),
                "default_plan_variant": defaults,
                "module_ids": sorted(
                    {str(item["testModule"]) for item in reference_entries}
                ),
            }
        )
    if len(plans) != 2:
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    return {
        "schema_version": 1,
        "suite_commit": required_string(suite_lock.get("commit")),
        "suite_version": suite_version(suite_lock),
        "plans": sorted(plans, key=lambda item: str(item["plan_id"])),
    }


def module_cases(configuration: dict[str, object]) -> Counter[tuple[str, str]]:
    cases: Counter[tuple[str, str]] = Counter()
    resolved = required_object(configuration.get("resolved_variants"))
    plan_variants = {
        key: value
        for key, value in resolved.items()
        if key != "profile_id" and isinstance(key, str) and isinstance(value, str)
    }
    if len(plan_variants) != len(resolved) - (1 if "profile_id" in resolved else 0):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    for raw_module in required_array(configuration.get("modules")):
        module = required_object(raw_module)
        module_variants = required_object(module.get("variant"))
        variants = dict(plan_variants)
        for key, value in module_variants.items():
            if not isinstance(key, str) or not isinstance(value, str):
                fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
            variants[key] = value
        cases[(required_string(module.get("testModule")), canonical_json(variants))] += 1
    return cases


def matrix_cases(profile: dict[str, object]) -> Counter[tuple[str, str]]:
    cases: Counter[tuple[str, str]] = Counter()
    for raw_group in required_array(profile.get("expected_groups")):
        group = required_object(raw_group)
        variant = canonical_json(required_object(group.get("variants")))
        for module_id in required_array(group.get("modules")):
            cases[(required_string(module_id), variant)] += 1
    return cases


def validate_openid4vp_matrix(
    matrix: dict[str, object],
    certification_plan: dict[str, object],
    snapshot: dict[str, object],
    suite_lock: dict[str, object],
) -> None:
    suite = required_object(matrix.get("suite"))
    if (
        suite.get("commit") != suite_lock.get("commit")
        or suite.get("version") != suite_version(suite_lock)
    ):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    configurations = certification_configurations(snapshot, "oid4vp")
    selected = {
        profile_id: (role, plan_id, expression)
        for profile_id, role, plan_id, expression in selected_runs(
            certification_plan, "openid4vp"
        )
    }
    profiles = required_array(matrix.get("profiles"))
    observed: set[str] = set()
    for raw_profile in profiles:
        profile = required_object(raw_profile)
        profile_id = required_string(profile.get("id"))
        selection = selected.get(profile_id)
        configuration_match = configurations.get(profile_id)
        if selection is None or configuration_match is None:
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        role, plan_id, expression = selection
        snapshot_plan_id, configuration = configuration_match
        if (
            profile.get("role") != role
            or profile.get("plan_id") != plan_id
            or profile.get("expression") != expression
            or snapshot_plan_id != plan_id
            or configuration.get("expression") != expression
            or matrix_cases(profile) != module_cases(configuration)
        ):
            fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
        observed.add(profile_id)
    if len(observed) != 6 or observed != set(selected) or observed != set(configurations):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)


def write_object(output_directory: Path, name: str, value: dict[str, object]) -> None:
    path = output_directory / name
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        fail(ContractErrorReason.OUTPUT_INVALID)


def build(
    product_component_bom: Path,
    output_directory: Path,
    *,
    require_release_refs: bool = False,
) -> None:
    bom_value = product_bom_validator.load_bom(product_component_bom)
    components = product_bom_validator.validate_bom(
        bom_value, require_release_refs=require_release_refs
    )
    providers = [
        component
        for component in components.values()
        if "openid4vci" in component.adapter_contracts
    ]
    if len(providers) != 1:
        fail(ContractErrorReason.INPUT_INVALID)

    suite_lock = load_object(SUITE_LOCK)
    certification_plan = load_object(CERTIFICATION_PLAN)
    engineering_plan = load_object(ENGINEERING_PLAN)
    snapshot = load_object(CERTIFICATION_SNAPSHOT)
    openid4vp_matrix = load_object(OPENID4VP_MATRIX)
    if snapshot.get("suite_commit") != suite_lock.get("commit"):
        fail(ContractErrorReason.FRAMEWORK_INCONSISTENT)
    validate_openid4vp_matrix(
        openid4vp_matrix, certification_plan, snapshot, suite_lock
    )

    try:
        if output_directory.exists() or output_directory.is_symlink():
            fail(ContractErrorReason.OUTPUT_INVALID)
        output_directory.mkdir(mode=0o700, parents=False)
    except OSError:
        fail(ContractErrorReason.OUTPUT_INVALID)
    write_object(
        output_directory,
        "openid4vci-profile-matrix.json",
        build_openid4vci_profile_matrix(
            certification_plan, snapshot, providers[0].repository
        ),
    )
    write_object(
        output_directory,
        "openid4vci-suite-contract.json",
        build_openid4vci_suite_contract(
            certification_plan, engineering_plan, suite_lock
        ),
    )
    write_object(
        output_directory,
        "openid4vci-module-inventory.json",
        build_openid4vci_module_inventory(snapshot, suite_lock),
    )
    write_object(
        output_directory,
        "openid4vp-profile-matrix.json",
        openid4vp_matrix,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-component-bom", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--require-release-refs", action="store_true")
    arguments = parser.parse_args()
    try:
        build(
            arguments.product_component_bom,
            arguments.output_dir,
            require_release_refs=arguments.require_release_refs,
        )
    except (ContractError, SystemExit) as error:
        reason = (
            error.reason.value
            if isinstance(error, ContractError)
            else ContractErrorReason.INPUT_INVALID.value
        )
        print(f"OIDF runtime contract generation failed: {reason}", file=sys.stderr)
        return 65
    print("Built framework-owned OIDF runtime contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
