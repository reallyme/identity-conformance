#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Render the README summary and detailed standards baseline."""

from __future__ import annotations

import argparse
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

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPOSITORY_ROOT / "README.md"
STANDARDS_BASELINE_PATH = REPOSITORY_ROOT / "docs/STANDARDS_BASELINE.md"
SUMMARY_START_MARKER = "<!-- BEGIN GENERATED CONFORMANCE SUMMARY -->"
SUMMARY_END_MARKER = "<!-- END GENERATED CONFORMANCE SUMMARY -->"
BADGES_START_MARKER = "<!-- BEGIN GENERATED CONFORMANCE BADGES -->"
BADGES_END_MARKER = "<!-- END GENERATED CONFORMANCE BADGES -->"
CATALOG_START_MARKER = "<!-- BEGIN GENERATED CONFORMANCE CATALOG -->"
CATALOG_END_MARKER = "<!-- END GENERATED CONFORMANCE CATALOG -->"
MAX_INPUT_BYTES = 2 * 1024 * 1024
SEMANTIC_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_REF = re.compile(r"^[A-Za-z0-9._=/+-]{1,128}$")


class CatalogErrorReason(Enum):
    INVALID_INPUT = "invalid_input"
    INVALID_VERSION = "invalid_version"
    INCONSISTENT_BASELINE = "inconsistent_baseline"
    GENERATED_MARKERS_INVALID = "generated_markers_invalid"
    GENERATED_DOCUMENTATION_STALE = "generated_conformance_documentation_stale"
    WRITE_FAILED = "write_failed"


@dataclass(frozen=True)
class CatalogError(Exception):
    reason: CatalogErrorReason


@dataclass(frozen=True)
class CatalogRow:
    name: str
    url: str
    description: str
    enforced_value: str
    version: str
    baseline_updated: str


def fail(reason: CatalogErrorReason) -> NoReturn:
    print(f"conformance catalog failed: {reason.value}", file=sys.stderr)
    raise SystemExit(78)


def read_regular_text(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise CatalogError(CatalogErrorReason.INVALID_INPUT)
        if not 1 <= metadata.st_size <= MAX_INPUT_BYTES:
            raise CatalogError(CatalogErrorReason.INVALID_INPUT)
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT) from error


def read_object(path: Path) -> dict[str, object]:
    try:
        value = strict_json.loads(read_regular_text(path))
    except strict_json.StrictJsonError as error:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT) from error
    if not isinstance(value, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    return value


def read_version(root: Path = REPOSITORY_ROOT) -> str:
    version = read_regular_text(root / "VERSION").strip()
    if SEMANTIC_VERSION.fullmatch(version) is None:
        raise CatalogError(CatalogErrorReason.INVALID_VERSION)
    return version


def required_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    return value


def required_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    return value


def exact_source(
    lock: dict[str, object], source_id: str
) -> dict[str, object]:
    sources = lock.get("sources")
    if not isinstance(sources, list):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    matches = [
        source
        for source in sources
        if isinstance(source, dict) and source.get("source_id") == source_id
    ]
    if len(matches) != 1:
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    return matches[0]


def exact_publication(
    lock: dict[str, object], specification_id: str
) -> dict[str, object]:
    publications = lock.get("publications")
    if not isinstance(publications, list):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    matches = [
        publication
        for publication in publications
        if isinstance(publication, dict)
        and publication.get("specification_id") == specification_id
    ]
    if len(matches) != 1:
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    return matches[0]


def exact_asset(plan: dict[str, object], asset_id: str) -> dict[str, object]:
    assets = plan.get("assets")
    if not isinstance(assets, list):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("asset_id") == asset_id
    ]
    if len(matches) != 1:
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    return matches[0]


def validate_source_binding(
    source: dict[str, object], ledger: dict[str, object]
) -> tuple[str, str, str, str]:
    ledger_source = ledger.get("source")
    if not isinstance(ledger_source, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    repository = required_string(source.get("repository"))
    reference = required_string(source.get("ref"))
    commit = required_string(source.get("commit"))
    source_path = required_string(ledger_source.get("path"))
    if (
        COMMIT.fullmatch(commit) is None
        or SAFE_REF.fullmatch(reference) is None
        or ledger_source.get("source_id") != source.get("source_id")
        or ledger_source.get("ref") != reference
        or ledger_source.get("commit") != commit
        or source_path.startswith("/")
        or ".." in Path(source_path).parts
    ):
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    return repository, reference, commit, source_path


def rule_validation(rule: dict[str, object]) -> tuple[str, str]:
    expected = rule.get("expected")
    if not isinstance(expected, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    operator = required_string(expected.get("operator"))
    value = expected.get("value")
    boundary_id = required_string(rule.get("boundary_id"))
    if operator == "less_than":
        return (
            "Checks the reported Wallet value against",
            f"`{boundary_id} < {required_integer(value):,}`.",
        )
    if operator == "one_of" and isinstance(value, list) and value:
        members = [required_string(member) for member in value]
        return (
            f"Validates `{boundary_id}` against the permitted values:",
            ", ".join(f"`{member}`" for member in members) + ".",
        )
    raise CatalogError(CatalogErrorReason.INVALID_INPUT)


def build_rows(root: Path = REPOSITORY_ROOT) -> tuple[list[CatalogRow], list[CatalogRow]]:
    eudi_lock = read_object(root / "upstream/eudi/sources.lock.json")
    eudi_date = required_string(eudi_lock.get("observed_at"))
    eu_definitions = (
        (
            "eudi-arf",
            "plans/eudi/normative/arf-wallet.json",
            "Architecture and Reference Framework",
        ),
        (
            "eudi-technical-specifications",
            "plans/eudi/normative/technical-specifications-wallet.json",
            "Technical Specification 3 — Wallet Unit Attestation",
        ),
    )
    eu_rows: list[CatalogRow] = []
    for source_id, ledger_path, name in eu_definitions:
        source = exact_source(eudi_lock, source_id)
        ledger = read_object(root / ledger_path)
        repository, reference, commit, _source_path = validate_source_binding(
            source, ledger
        )
        rules = ledger.get("rules")
        if not isinstance(rules, list) or not rules:
            raise CatalogError(CatalogErrorReason.INVALID_INPUT)
        for rule in rules:
            if not isinstance(rule, dict):
                raise CatalogError(CatalogErrorReason.INVALID_INPUT)
            requirement = required_string(rule.get("source_requirement_id"))
            rule_path = required_string(rule.get("source_path"))
            if rule_path.startswith("/") or ".." in Path(rule_path).parts:
                raise CatalogError(CatalogErrorReason.INVALID_INPUT)
            description, enforced_value = rule_validation(rule)
            eu_rows.append(
                CatalogRow(
                    name=f"{name} — {requirement}",
                    url=f"{repository}/blob/{commit}/{rule_path}",
                    description=description,
                    enforced_value=enforced_value,
                    version=reference,
                    baseline_updated=eudi_date,
                )
            )

    fcaf_source = exact_source(eudi_lock, "eudi-fcaf")
    fcaf_ledger = read_object(root / "plans/eudi/normative/fcaf-wallet.json")
    repository, reference, commit, source_path = validate_source_binding(
        fcaf_source, fcaf_ledger
    )
    assessment = fcaf_ledger.get("assessment")
    if not isinstance(assessment, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    execution_state = required_string(assessment.get("execution_state"))
    executable_count = required_integer(assessment.get("executable_test_case_count"))
    if executable_count == 0:
        test_case_summary = f"No executable test cases in `{reference}`."
    else:
        test_case_summary = (
            f"`{executable_count}` executable test cases in `{reference}`."
        )
    eu_rows.append(
        CatalogRow(
            name="Functional Conformance Assessment Framework",
            url=f"{repository}/blob/{commit}/{source_path}",
            description="Wallet Solution assessment methodology.",
            enforced_value=f"`{execution_state}`. {test_case_summary}",
            version=reference,
            baseline_updated=eudi_date,
        )
    )

    asset_plan = read_object(root / "plans/eudi/upstream-assets.json")
    if asset_plan.get("product_execution_claim") is not False:
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)

    ui_asset = exact_asset(asset_plan, "wallet-ui-tests")
    ui_expected = ui_asset.get("expected")
    ui_platforms = ui_expected.get("platforms") if isinstance(ui_expected, dict) else None
    if not isinstance(ui_platforms, list) or len(ui_platforms) != 2:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    feature_count = 0
    scenario_count = 0
    for platform in ui_platforms:
        if not isinstance(platform, dict):
            raise CatalogError(CatalogErrorReason.INVALID_INPUT)
        feature_count += required_integer(platform.get("feature_file_count"))
        scenario_count += required_integer(platform.get("scenario_count"))
    ui_source = exact_source(eudi_lock, required_string(ui_asset.get("source_id")))
    ui_repository = required_string(ui_source.get("repository"))
    ui_commit = required_string(ui_source.get("commit"))
    eu_rows.append(
        CatalogRow(
            name="EUDI Wallet testing application",
            url=f"{ui_repository}/tree/{ui_commit}/src/test/resources/features",
            description=(
                f"Verifies `{feature_count}` feature files and "
                f"`{scenario_count}` scenarios."
            ),
            enforced_value="Device execution is separate.",
            version=required_string(ui_source.get("ref")),
            baseline_updated=eudi_date,
        )
    )

    itb_asset = exact_asset(asset_plan, "interoperability-testbed")
    itb_expected = itb_asset.get("expected")
    itb_suites = itb_expected.get("suites") if isinstance(itb_expected, dict) else None
    if not isinstance(itb_suites, list) or not itb_suites:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    itb_case_count = 0
    for suite in itb_suites:
        if not isinstance(suite, dict) or not isinstance(suite.get("test_case_ids"), list):
            raise CatalogError(CatalogErrorReason.INVALID_INPUT)
        itb_case_count += len(suite["test_case_ids"])
    itb_source = exact_source(eudi_lock, required_string(itb_asset.get("source_id")))
    itb_repository = required_string(itb_source.get("repository"))
    itb_commit = required_string(itb_source.get("commit"))
    eu_rows.append(
        CatalogRow(
            name="EUDI Interoperability Test Bed",
            url=f"{itb_repository}/tree/{itb_commit}/tests",
            description=(
                f"Verifies `{len(itb_suites)}` suites and "
                f"`{itb_case_count}` test cases."
            ),
            enforced_value="Deployed execution is separate.",
            version=required_string(itb_source.get("ref")),
            baseline_updated=eudi_date,
        )
    )

    age_asset = exact_asset(asset_plan, "age-verification-profile")
    age_expected = age_asset.get("expected")
    age_documents = age_expected.get("documents") if isinstance(age_expected, dict) else None
    if not isinstance(age_documents, list) or not age_documents:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    age_source = exact_source(eudi_lock, required_string(age_asset.get("source_id")))
    age_repository = required_string(age_source.get("repository"))
    age_commit = required_string(age_source.get("commit"))
    eu_rows.append(
        CatalogRow(
            name="Age Verification specification and ZKP profile",
            url=(
                f"{age_repository}/blob/{age_commit}/"
                "docs/annexes/annex-B/annex-B-zkp.md"
            ),
            description=f"Verifies `{len(age_documents)}` profile and annex documents.",
            enforced_value=(
                f"No executable conformance suite in "
                f"`{required_string(age_source.get('ref'))}`."
            ),
            version=required_string(age_source.get("ref")),
            baseline_updated=eudi_date,
        )
    )

    rqes_asset = exact_asset(asset_plan, "rqes-wallet-driven-tester")
    rqes_expected = rqes_asset.get("expected")
    if not isinstance(rqes_expected, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    rqes_source = exact_source(eudi_lock, required_string(rqes_asset.get("source_id")))
    rqes_repository = required_string(rqes_source.get("repository"))
    rqes_commit = required_string(rqes_source.get("commit"))
    if rqes_expected.get("dependency_installation") != "prohibited":
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    eu_rows.append(
        CatalogRow(
            name="RQES Wallet-driven tester",
            url=f"{rqes_repository}/tree/{rqes_commit}/app",
            description=(
                f"Verifies `{required_integer(rqes_expected.get('python_file_count'))}` "
                f"Python files and `{required_integer(rqes_expected.get('route_count'))}` "
                "routes."
            ),
            enforced_value="Upstream dependencies are excluded from CI.",
            version=required_string(rqes_source.get("ref")),
            baseline_updated=eudi_date,
        )
    )

    oidf_specs = read_object(root / "upstream/oidf/specifications.lock.json")
    oidf_date = required_string(oidf_specs.get("observed_at"))
    oidf_definitions = (
        (
            "openid4vci-1.0-final",
            "OpenID for Verifiable Credential Issuance",
            "Final specification for Issuer and Wallet certification plans.",
        ),
        (
            "openid4vp-1.0-final",
            "OpenID for Verifiable Presentations",
            "Final specification for Verifier and Wallet certification plans.",
        ),
        (
            "openid4vc-haip-1.0-final",
            "OpenID4VC High Assurance Interoperability Profile",
            "High-assurance profile for OID4VCI and OID4VP plans.",
        ),
    )
    oidf_rows: list[CatalogRow] = []
    for specification_id, name, description in oidf_definitions:
        publication = exact_publication(oidf_specs, specification_id)
        oidf_rows.append(
            CatalogRow(
                name=name,
                url=required_string(publication.get("canonical_url")),
                description=description,
                enforced_value=f"SHA-256 `{required_string(publication.get('sha256'))}`",
                version="1.0 Final",
                baseline_updated=oidf_date,
            )
        )

    suite = read_object(root / "upstream/oidf/conformance-suite.lock.json")
    suite_repository = required_string(suite.get("repository")).removesuffix(".git")
    suite_commit = required_string(suite.get("commit"))
    suite_ref = required_string(suite.get("pinned_ref"))
    if COMMIT.fullmatch(suite_commit) is None or SAFE_REF.fullmatch(suite_ref) is None:
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    oidf_rows.append(
        CatalogRow(
            name="OpenID Conformance Suite",
            url=f"{suite_repository}/-/tree/{suite_commit}",
            description="Executable certification suite for the plan matrix.",
            enforced_value=f"Commit `{suite_commit}`",
            version=suite_ref,
            baseline_updated=required_string(suite.get("released_at")),
        )
    )
    return eu_rows, oidf_rows


def render_table(rows: list[CatalogRow]) -> str:
    lines = [
        "| Standard or suite | Version | Validation | Baseline updated |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| [{row.name}]({row.url}) | `{row.version}` | "
            f"{row.description} {row.enforced_value} | {row.baseline_updated} |"
        )
    return "\n".join(lines)


def representative_row(rows: list[CatalogRow], name_prefix: str) -> CatalogRow:
    matches = [row for row in rows if row.name.startswith(name_prefix)]
    if not matches or any(row.version != matches[0].version for row in matches):
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    return matches[0]


def badge(label: str, message: str, color: str, target: str) -> str:
    encoded_label = label.replace(" ", "%20")
    encoded_message = message.replace(" ", "%20")
    image = (
        "https://img.shields.io/static/v1?"
        f"label={encoded_label}&message={encoded_message}&color={color}"
    )
    return f"[![{label}]({image})]({target})"


def render_badges(root: Path = REPOSITORY_ROOT) -> str:
    version = read_version(root)
    eu_rows, oidf_rows = build_rows(root)
    arf = representative_row(eu_rows, "Architecture")
    technical = representative_row(eu_rows, "Technical Specification")
    fcaf = representative_row(eu_rows, "Functional")
    oidf_suite = representative_row(oidf_rows, "OpenID Conformance Suite")
    return "\n".join(
        [
            BADGES_START_MARKER,
            "[![Release readiness](https://github.com/reallyme/identity-conformance/actions/workflows/release-readiness.yml/badge.svg)](https://github.com/reallyme/identity-conformance/actions/workflows/release-readiness.yml)",
            "[![Secret scan](https://github.com/reallyme/identity-conformance/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/reallyme/identity-conformance/actions/workflows/secret-scan.yml)",
            "[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)",
            "[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)",
            "",
            badge("Framework", f"v{version}", "475569", "VERSION"),
            badge("EU ARF", f"{arf.version} included", "0f766e", arf.url),
            badge(
                "EU technical specifications",
                "included",
                "0f766e",
                technical.url,
            ),
            badge("EU FCAF", f"{fcaf.version} included", "0f766e", fcaf.url),
            badge(
                "OIDF suite",
                f"{oidf_suite.version} included",
                "1d4ed8",
                oidf_suite.url,
            ),
            BADGES_END_MARKER,
        ]
    )


def render_summary(root: Path = REPOSITORY_ROOT) -> str:
    version = read_version(root)
    eu_rows, oidf_rows = build_rows(root)
    eudi_lock = read_object(root / "upstream/eudi/sources.lock.json")
    arf = representative_row(eu_rows, "Architecture")
    technical = representative_row(eu_rows, "Technical Specification")
    fcaf = representative_row(eu_rows, "Functional")
    wallet_tests = representative_row(eu_rows, "EUDI Wallet testing application")
    itb = representative_row(eu_rows, "EUDI Interoperability Test Bed")
    oidf_suite = representative_row(oidf_rows, "OpenID Conformance Suite")
    technical_source = exact_source(eudi_lock, "eudi-technical-specifications")
    technical_commit = required_string(technical_source.get("commit"))
    itb_source = exact_source(eudi_lock, "eudi-itb")
    itb_commit = required_string(itb_source.get("commit"))
    if (
        COMMIT.fullmatch(technical_commit) is None
        or COMMIT.fullmatch(itb_commit) is None
    ):
        raise CatalogError(CatalogErrorReason.INCONSISTENT_BASELINE)
    wallet_test_coverage = wallet_tests.description.removeprefix(
        "Verifies "
    ).removesuffix(".")
    itb_coverage = itb.description.removeprefix("Verifies ").removesuffix(".")

    lines = [
        SUMMARY_START_MARKER,
        "## Standards baseline",
        "",
        f"Framework version: **v{version}**",
        "",
        "| Source | Pinned version | Coverage |",
        "| --- | --- | --- |",
        f"| [EU Architecture and Reference Framework]({arf.url}) | "
        f"`{arf.version}` | Wallet requirements |",
        f"| [EU technical specifications]({technical.url}) | "
        f"`{technical.version} @ {technical_commit[:8]}` | Wallet Unit Attestation |",
        f"| [EU Functional Conformance Assessment Framework]({fcaf.url}) | "
        f"`{fcaf.version}` | Assessment methodology |",
        f"| [OpenID Conformance Suite]({oidf_suite.url}) | "
        f"`{oidf_suite.version}` | OpenID4VCI / OpenID4VP |",
        f"| [EUDI Wallet testing application]({wallet_tests.url}) | "
        f"`{wallet_tests.version}` | {wallet_test_coverage} |",
        f"| [EUDI Interoperability Test Bed]({itb.url}) | "
        f"`{itb.version} @ {itb_commit[:8]}` | {itb_coverage} |",
        "",
        "See [Standards baseline](docs/STANDARDS_BASELINE.md) for exact source",
        "revisions, requirement mappings, content digests, and validation status.",
        "",
        SUMMARY_END_MARKER,
    ]
    return "\n".join(lines)


def render_catalog(root: Path = REPOSITORY_ROOT) -> str:
    version = read_version(root)
    eu_rows, oidf_rows = build_rows(root)
    arf = representative_row(eu_rows, "Architecture")
    technical = representative_row(eu_rows, "Technical Specification")
    fcaf = representative_row(eu_rows, "Functional")
    oidf_suite = representative_row(oidf_rows, "OpenID Conformance Suite")

    lines = [
        CATALOG_START_MARKER,
        "# Standards baseline",
        "",
        f"Framework version: **v{version}**",
        "",
        "The framework pins the specifications, requirements, and test suites listed",
        "below. Each entry identifies the upstream version, the implemented validation,",
        "and when the pin was last reviewed.",
        "",
        badge("Framework", f"v{version}", "475569", "../VERSION"),
        badge("EU ARF", f"{arf.version} included", "0f766e", arf.url),
        badge(
            "EU technical specifications",
            "included",
            "0f766e",
            technical.url,
        ),
        badge("EU FCAF", f"{fcaf.version} included", "0f766e", fcaf.url),
        badge(
            "OIDF suite",
            f"{oidf_suite.version} included",
            "1d4ed8",
            oidf_suite.url,
        ),
        "",
        "Inclusion does not imply product conformance. Results are published by the",
        "repositories running these checks. Baseline dates record framework adoption or",
        "review, not upstream publication.",
        "",
        "### European Union",
        "",
        render_table(eu_rows),
        "",
        "### OpenID Foundation",
        "",
        render_table(oidf_rows),
        "",
        CATALOG_END_MARKER,
    ]
    return "\n".join(lines)


def replace_generated_section(
    document: str, start_marker: str, end_marker: str, replacement: str
) -> str:
    if document.count(start_marker) != 1 or document.count(end_marker) != 1:
        raise CatalogError(CatalogErrorReason.GENERATED_MARKERS_INVALID)
    start = document.index(start_marker)
    end = document.index(end_marker) + len(end_marker)
    if start >= end:
        raise CatalogError(CatalogErrorReason.GENERATED_MARKERS_INVALID)
    return f"{document[:start]}{replacement}{document[end:]}"


def write_atomic(path: Path, content: str) -> None:
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".conformance-catalog-",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError as error:
        raise CatalogError(CatalogErrorReason.WRITE_FAILED) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        current_readme = read_regular_text(README_PATH)
        current_baseline = read_regular_text(STANDARDS_BASELINE_PATH)
        expected_readme_with_badges = replace_generated_section(
            current_readme,
            BADGES_START_MARKER,
            BADGES_END_MARKER,
            render_badges(),
        )
        expected_readme = replace_generated_section(
            expected_readme_with_badges,
            SUMMARY_START_MARKER,
            SUMMARY_END_MARKER,
            render_summary(),
        )
        expected_baseline = replace_generated_section(
            current_baseline,
            CATALOG_START_MARKER,
            CATALOG_END_MARKER,
            render_catalog(),
        )
        if args.check:
            if current_readme != expected_readme or current_baseline != expected_baseline:
                raise CatalogError(
                    CatalogErrorReason.GENERATED_DOCUMENTATION_STALE
                )
            print("conformance catalog is current")
            return 0
        write_atomic(README_PATH, expected_readme)
        write_atomic(STANDARDS_BASELINE_PATH, expected_baseline)
    except CatalogError as error:
        fail(error.reason)
    print("updated release-bound conformance catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
