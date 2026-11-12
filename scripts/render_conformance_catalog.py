#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Render the release-bound conformance catalog in README.md."""

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
VERSION_PATH = REPOSITORY_ROOT / "VERSION"
START_MARKER = "<!-- BEGIN GENERATED CONFORMANCE CATALOG -->"
END_MARKER = "<!-- END GENERATED CONFORMANCE CATALOG -->"
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
    README_MARKERS_INVALID = "readme_markers_invalid"
    README_STALE = "readme_catalog_stale"
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


def rule_value(rule: dict[str, object]) -> str:
    expected = rule.get("expected")
    if not isinstance(expected, dict):
        raise CatalogError(CatalogErrorReason.INVALID_INPUT)
    operator = required_string(expected.get("operator"))
    value = expected.get("value")
    boundary_id = required_string(rule.get("boundary_id"))
    if operator == "less_than":
        return f"`{boundary_id} < {required_integer(value):,}`"
    if operator == "one_of" and isinstance(value, list) and value:
        members = [required_string(member) for member in value]
        return f"`{boundary_id}` = " + ", ".join(
            f"`{member}`" for member in members
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
            "Wallet requirements and normative implementation boundaries.",
        ),
        (
            "eudi-technical-specifications",
            "plans/eudi/normative/technical-specifications-wallet.json",
            "Technical Specification 3 — Wallet Unit Attestation",
            "Wallet Unit Attestation lifetime boundary.",
        ),
    )
    eu_rows: list[CatalogRow] = []
    for source_id, ledger_path, name, description in eu_definitions:
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
            eu_rows.append(
                CatalogRow(
                    name=f"{name} — {requirement}",
                    url=f"{repository}/blob/{commit}/{rule_path}",
                    description=description,
                    enforced_value=rule_value(rule),
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
    eu_rows.append(
        CatalogRow(
            name="Functional Conformance Assessment Framework",
            url=f"{repository}/blob/{commit}/{source_path}",
            description="Wallet Solution assessment methodology; not an executable certification suite.",
            enforced_value=(
                f"`{execution_state}`; `{executable_count}` executable Wallet cases"
            ),
            version=reference,
            baseline_updated=eudi_date,
        )
    )

    oidf_specs = read_object(root / "upstream/oidf/specifications.lock.json")
    oidf_date = required_string(oidf_specs.get("observed_at"))
    oidf_definitions = (
        (
            "openid4vci-1.0-final",
            "OpenID for Verifiable Credential Issuance",
            "Issuer and Wallet HAIP certification-plan variants.",
        ),
        (
            "openid4vp-1.0-final",
            "OpenID for Verifiable Presentations",
            "Verifier and Wallet HAIP certification-plan variants.",
        ),
        (
            "openid4vc-haip-1.0-final",
            "OpenID4VC High Assurance Interoperability Profile",
            "High-assurance profile applied to OID4VCI and OID4VP plans.",
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
            description="Executable certification-suite source used to derive and validate plan values.",
            enforced_value=f"Commit `{suite_commit}`",
            version=suite_ref,
            baseline_updated=required_string(suite.get("released_at")),
        )
    )
    return eu_rows, oidf_rows


def render_table(rows: list[CatalogRow]) -> str:
    lines = [
        "| Source | Description | Current enforced value | Version | Baseline updated |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| [{row.name}]({row.url}) | {row.description} | "
            f"{row.enforced_value} | `{row.version}` | {row.baseline_updated} |"
        )
    return "\n".join(lines)


def render_catalog(root: Path = REPOSITORY_ROOT) -> str:
    version = read_version(root)
    eu_rows, oidf_rows = build_rows(root)
    encoded_version = version.replace(".", "%2E")
    badge_base = "https://img.shields.io/github/actions/workflow/status/reallyme/identity-conformance"
    badges = (
        ("EU ARF", "eu-arf-normative.yml"),
        ("EU technical specifications", "eu-technical-specifications-normative.yml"),
        ("EU FCAF", "eu-fcaf-normative.yml"),
        ("OIDF", "oidf-normative-ledger.yml"),
    )
    lines = [
        START_MARKER,
        f"Current framework baseline: **v{version}**",
        "",
    ]
    for label, workflow in badges:
        encoded_label = label.replace(" ", "%20")
        lines.append(
            f"[![{label} v{version}]({badge_base}/{workflow}"
            f"?branch=main&label={encoded_label}%20v{encoded_version})]"
            f"(https://github.com/reallyme/identity-conformance/actions/workflows/{workflow})"
        )
    lines.extend(
        [
            "",
            "## Conformance enforced by this release",
            "",
            "This catalog is generated from the same immutable locks and normative ledgers",
            "that are digest-bound into framework release manifests. “Baseline updated” is",
            "the date this repository adopted or verified the pin, not an inferred publication date.",
            "",
            "### European Union",
            "",
            render_table(eu_rows),
            "",
            "### OpenID Foundation",
            "",
            render_table(oidf_rows),
            "",
            END_MARKER,
        ]
    )
    return "\n".join(lines)


def replace_catalog(readme: str, catalog: str) -> str:
    if readme.count(START_MARKER) != 1 or readme.count(END_MARKER) != 1:
        raise CatalogError(CatalogErrorReason.README_MARKERS_INVALID)
    start = readme.index(START_MARKER)
    end = readme.index(END_MARKER) + len(END_MARKER)
    if start >= end:
        raise CatalogError(CatalogErrorReason.README_MARKERS_INVALID)
    return f"{readme[:start]}{catalog}{readme[end:]}"


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
        current = read_regular_text(README_PATH)
        expected = replace_catalog(current, render_catalog())
        if args.check:
            if current != expected:
                raise CatalogError(CatalogErrorReason.README_STALE)
            print("conformance catalog is current")
            return 0
        write_atomic(README_PATH, expected)
    except CatalogError as error:
        fail(error.reason)
    print("updated release-bound conformance catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
