#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Audit the ETSI 119 472 and current EU PID/EAA requirement trace."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple, NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TRACE_SOURCE_LOCK_PATH = (
    REPOSITORY_ROOT / "references" / "reallyme" / "trace-sources.lock.json"
)
DEFAULT_OUTPUT_PATH = (
    REPOSITORY_ROOT / "references" / "etsi-eaa-pid" / "requirement-trace.json"
)
TRACE_RELATIVE_PATH = Path(
    "crates/eudi/etsi-eaa-conformance/requirements/requirement-trace.tsv"
)
INDEX_RELATIVE_PATH = Path(
    "crates/eudi/etsi-eaa-conformance/requirements/etsi-ts-119-472.tsv"
)
EU_LEDGER_RELATIVE_PATH = Path(
    "crates/eudi/etsi-eaa-conformance/requirements/eu-2026-profile.tsv"
)
REGISTRY_RELATIVE_PATH = Path(
    "crates/eudi/etsi-eaa-conformance/src/requirements.rs"
)
REGISTRY_SYMBOLS = (
    "resolve_normative_requirement",
    "validate_normative_requirement_registry",
    "NormativeRequirementHandler",
    "NormativeRequirementApplicability",
    "NormativeEuProfileStatus",
    "ComposedEvidenceBoundary",
)
MAX_INPUT_BYTES = 8 * 1024 * 1024
EXIT_INVALID_INPUT = 65
EXIT_STALE = 66
EXPECTED_HEADER = (
    "source",
    "requirement_id",
    "source_edition",
    "applicability",
    "disposition",
    "eu_profile_status",
    "owner_repository",
    "code_path",
    "code_symbol",
    "test_path",
    "test_symbol",
    "external_evidence",
    "justification",
)
EXPECTED_SOURCE_COUNTS = {
    "ETSI-TS-119-472-1": 548,
    "ETSI-TS-119-472-2": 88,
    "ETSI-TS-119-472-3": 104,
    "CIR-2024-2977": 33,
    "CIR-2024-2979": 124,
    "CIR-2024-2982": 32,
    "ETSI-119-472-1-EU": 9,
    "ETSI-119-472-2-EU": 26,
    "ETSI-119-472-3-EU": 5,
}
EXPECTED_DISPOSITION_COUNTS = {
    "code_and_composed_evidence": 898,
    "external_evidence_required": 53,
    "not_applicable": 18,
}
OFFICIAL_SOURCE_SHA256 = {
    "ETSI-TS-119-472-1-V1.2.1": (
        "0f76ce7cad5f046802146b0c2a9cd8af9db3c1db77db5eeca86d2a4559fcfc3f"
    ),
    "ETSI-TS-119-472-2-V1.2.1": (
        "128c51ed497a82ee01a709070669e53bef4f38a0da3ec8792542f659f86e3b1f"
    ),
    "ETSI-TS-119-472-2-V1.3.1": (
        "e403e7d5a4c70d04868989cc623b57d379a5f3dfe282f9f98f7390c8e327310b"
    ),
    "ETSI-TS-119-472-3-V1.1.1": (
        "2919437478c7469881afc5acd5aa68d847a4cfdc1bbf6da9224f4c9fae7167ba"
    ),
}
CODE_DISPOSITION = "code_and_composed_evidence"
EXTERNAL_DISPOSITION = "external_evidence_required"
NOT_APPLICABLE_DISPOSITION = "not_applicable"
IDENTIFIER = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RELEASE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TRACE_SOURCE_ROOT_ENVIRONMENT = "IDENTITY_CONFORMANCE_TRACE_SOURCE_ROOT"


class Component(NamedTuple):
    component_id: str
    checkout: Path
    release_ref: str
    commit: str


class AuditError(Exception):
    """Raised when the trace cannot support a closed mapping claim."""


def fail(message: str, exit_code: int = EXIT_INVALID_INPUT) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise AuditError("audit input must be a regular file")
        if metadata.st_size < 1 or metadata.st_size > MAX_INPUT_BYTES:
            raise AuditError("audit input has an invalid size")
        return path.read_bytes()
    except (OSError, AuditError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("audit input is unavailable") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def trace_source_root() -> Path | None:
    raw_root = os.environ.get(TRACE_SOURCE_ROOT_ENVIRONMENT)
    if raw_root is None:
        return None
    root = Path(raw_root)
    if not root.is_absolute() or root.is_symlink():
        raise AuditError("trace source root is invalid")
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise AuditError("trace source root is unavailable") from error
    if not resolved.is_dir():
        raise AuditError("trace source root is invalid")
    return resolved


def load_components(path: Path = TRACE_SOURCE_LOCK_PATH) -> dict[str, Component]:
    try:
        value = strict_json.loads(read_regular_file(path).decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise AuditError("trace source lock is invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 2
        or value.get("purpose") != "etsi-eaa-pid-trace-source-lock"
        or not isinstance(value.get("sources"), list)
    ):
        raise AuditError("trace source lock has an invalid source inventory")

    component_root = trace_source_root()
    components: dict[str, Component] = {}
    for raw in value["sources"]:
        if not isinstance(raw, dict):
            raise AuditError("trace source lock entry is invalid")
        component_id = raw.get("component_id")
        relative_checkout = raw.get("local_checkout")
        release_ref = raw.get("release_ref")
        update_strategy = raw.get("update_strategy")
        commit = raw.get("commit")
        if (
            not isinstance(component_id, str)
            or not isinstance(relative_checkout, str)
            or not isinstance(release_ref, str)
            or RELEASE_REF.fullmatch(release_ref) is None
            or update_strategy != "latest_release"
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
            or component_id in components
        ):
            raise AuditError("trace source lock entry is invalid")
        if component_root is None:
            checkout = (REPOSITORY_ROOT / relative_checkout).resolve()
        else:
            checkout_candidate = component_root / component_id
            if checkout_candidate.is_symlink():
                raise AuditError("trace source checkout is invalid")
            try:
                checkout = checkout_candidate.resolve(strict=True)
                checkout.relative_to(component_root)
            except (OSError, ValueError) as error:
                raise AuditError("trace source checkout is unavailable") from error
            if not checkout.is_dir():
                raise AuditError("trace source checkout is invalid")
        components[component_id] = Component(
            component_id, checkout, release_ref, commit
        )
    return components


def git_head(checkout: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AuditError("unable to inspect the SSI checkout") from error
    if result.returncode != 0 or COMMIT.fullmatch(result.stdout.strip()) is None:
        raise AuditError("unable to inspect the SSI checkout")
    return result.stdout.strip()


def parse_tsv(path: Path) -> tuple[bytes, list[dict[str, str]]]:
    raw = read_regular_file(path)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise AuditError("requirement trace is not valid UTF-8") from error
    header: tuple[str, ...] | None = None
    rows: list[dict[str, str]] = []
    for line in lines:
        if line.startswith("# ") and line[2:].startswith("source\t"):
            if header is not None:
                raise AuditError("requirement trace repeats its header")
            header = tuple(line[2:].split("\t"))
            continue
        if line.startswith("#") or not line:
            continue
        if header is None:
            raise AuditError("requirement trace has no header")
        columns = line.split("\t")
        if len(columns) != len(header) or any(not value for value in columns):
            raise AuditError("requirement trace contains a malformed row")
        rows.append(dict(zip(header, columns, strict=True)))
    if header != EXPECTED_HEADER:
        raise AuditError("requirement trace has an unsupported schema")
    return raw, rows


def split_reference_list(value: str) -> list[str]:
    if value == "-":
        return []
    parts = value.split(";")
    if any(not part for part in parts):
        raise AuditError("requirement trace contains an empty reference")
    return parts


def resolve_reference(
    components: dict[str, Component], raw_path: str
) -> tuple[Component, Path]:
    path = Path(raw_path)
    if path.is_absolute() or ".." in path.parts:
        raise AuditError("requirement trace contains an unsafe path")
    first = path.parts[0] if path.parts else ""
    if first in components:
        component = components[first]
        relative = Path(*path.parts[1:])
    else:
        component = components["ssi"]
        relative = path
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise AuditError("requirement trace contains an unsafe path")
    return component, relative


@lru_cache(maxsize=128)
def read_git_blob(component: Component, relative_path: Path) -> bytes:
    object_name = f"{component.commit}:{relative_path.as_posix()}"
    try:
        size_result = subprocess.run(
            ["git", "-C", str(component.checkout), "cat-file", "-s", object_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if size_result.returncode != 0:
            raise AuditError(
                "requirement trace references an absent pinned source: "
                f"{component.component_id}/{relative_path.as_posix()}"
            )
        size = int(size_result.stdout.strip())
        if size < 1 or size > MAX_INPUT_BYTES:
            raise AuditError("referenced pinned source has an invalid size")
        content_result = subprocess.run(
            ["git", "-C", str(component.checkout), "show", object_name],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except ValueError as error:
        raise AuditError("referenced pinned source has an invalid size") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise AuditError("unable to inspect referenced pinned source") from error
    if content_result.returncode != 0 or len(content_result.stdout) != size:
        raise AuditError("unable to read referenced pinned source")
    return content_result.stdout


def verify_symbol(component: Component, relative_path: Path, symbol: str) -> None:
    if SYMBOL.fullmatch(symbol) is None:
        raise AuditError("requirement trace contains an invalid symbol")
    try:
        text = read_git_blob(component, relative_path).decode("utf-8")
    except UnicodeError as error:
        raise AuditError("referenced pinned source is not valid UTF-8") from error
    if re.search(rf"\b{re.escape(symbol)}\b", text) is None:
        raise AuditError(
            "requirement trace references an absent pinned symbol: "
            f"{component.component_id}/{relative_path.as_posix()}::{symbol}"
        )


def verify_row(row: dict[str, str], components: dict[str, Component]) -> None:
    if any(IDENTIFIER.fullmatch(row[field]) is None for field in EXPECTED_HEADER):
        raise AuditError("requirement trace contains an invalid field")
    disposition = row["disposition"]
    code_paths = split_reference_list(row["code_path"])
    code_symbols = split_reference_list(row["code_symbol"])
    test_paths = split_reference_list(row["test_path"])
    test_symbols = split_reference_list(row["test_symbol"])
    external = row["external_evidence"]

    if disposition == CODE_DISPOSITION:
        if not code_paths or len(code_paths) != len(code_symbols):
            raise AuditError("code-backed trace row has incomplete code references")
        if not test_paths or len(test_paths) != len(test_symbols):
            raise AuditError("code-backed trace row has incomplete test references")
        for path, symbol in zip(code_paths, code_symbols, strict=True):
            component, relative_path = resolve_reference(components, path)
            verify_symbol(component, relative_path, symbol)
        for path, symbol in zip(test_paths, test_symbols, strict=True):
            component, relative_path = resolve_reference(components, path)
            verify_symbol(component, relative_path, symbol)
    elif disposition == EXTERNAL_DISPOSITION:
        if code_paths or code_symbols or test_paths or test_symbols or external == "-":
            raise AuditError("external-evidence trace row is not closed")
    elif disposition == NOT_APPLICABLE_DISPOSITION:
        if (
            not row["applicability"].startswith("not_applicable")
            or code_paths
            or code_symbols
            or test_paths
            or test_symbols
            or external != "-"
        ):
            raise AuditError("non-applicable trace row lacks a fixed justification")
    else:
        raise AuditError("requirement trace contains an unknown disposition")


def parse_index(path: Path) -> set[tuple[str, str]]:
    source_by_part = {
        "1": "ETSI-TS-119-472-1",
        "2": "ETSI-TS-119-472-2",
        "3": "ETSI-TS-119-472-3",
    }
    rows: set[tuple[str, str]] = set()
    for line in read_regular_file(path).decode("utf-8").splitlines():
        if line.startswith("#") or not line:
            continue
        columns = line.split("\t")
        if len(columns) != 2 or columns[0] not in source_by_part:
            raise AuditError("ETSI requirement index contains a malformed row")
        key = (source_by_part[columns[0]], columns[1])
        if key in rows:
            raise AuditError("ETSI requirement index repeats an identifier")
        rows.add(key)
    return rows


def parse_eu_ledger(path: Path) -> set[tuple[str, str]]:
    rows: set[tuple[str, str]] = set()
    for line in read_regular_file(path).decode("utf-8").splitlines():
        if line.startswith("#") or not line:
            continue
        columns = line.split("\t")
        if len(columns) != 4:
            raise AuditError("EU profile ledger contains a malformed row")
        key = (columns[0], columns[1])
        if key in rows:
            raise AuditError("EU profile ledger repeats an identifier")
        rows.add(key)
    return rows


def build_artifact(
    components: dict[str, Component], *, verify_component_revision: bool = True
) -> dict[str, object]:
    required_components = {"ssi", "openid4vp", "openid4vci"}
    if not required_components.issubset(components):
        raise AuditError("trace source lock omits a trace owner")
    ssi = components["ssi"]
    if verify_component_revision and git_head(ssi.checkout) != ssi.commit:
        raise AuditError("SSI checkout does not match the pinned component revision")

    trace_path = ssi.checkout / TRACE_RELATIVE_PATH
    index_path = ssi.checkout / INDEX_RELATIVE_PATH
    eu_ledger_path = ssi.checkout / EU_LEDGER_RELATIVE_PATH
    registry_path = ssi.checkout / REGISTRY_RELATIVE_PATH
    trace_raw, rows = parse_tsv(trace_path)
    pinned_inputs = (
        (ssi, TRACE_RELATIVE_PATH, trace_raw),
        (ssi, INDEX_RELATIVE_PATH, read_regular_file(index_path)),
        (ssi, EU_LEDGER_RELATIVE_PATH, read_regular_file(eu_ledger_path)),
        (ssi, REGISTRY_RELATIVE_PATH, read_regular_file(registry_path)),
    )
    if verify_component_revision and any(
        read_git_blob(component, relative_path) != current
        for component, relative_path, current in pinned_inputs
    ):
        raise AuditError("SSI conformance inputs differ from the pinned revision")

    seen: set[tuple[str, str]] = set()
    source_counts: dict[str, int] = {}
    disposition_counts: dict[str, int] = {}
    for row in rows:
        key = (row["source"], row["requirement_id"])
        if key in seen:
            raise AuditError("requirement trace repeats a source identifier")
        seen.add(key)
        verify_row(row, components)
        source_counts[row["source"]] = source_counts.get(row["source"], 0) + 1
        disposition = row["disposition"]
        disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1

    indexed = parse_index(index_path)
    eu_indexed = parse_eu_ledger(eu_ledger_path)
    if len(indexed) != 740 or len(eu_indexed) != 229:
        raise AuditError("canonical requirement inventories have unexpected counts")
    if seen != indexed | eu_indexed:
        raise AuditError("requirement trace is not a one-to-one inventory mapping")
    if source_counts != EXPECTED_SOURCE_COUNTS:
        raise AuditError("requirement trace source counts are invalid")
    if disposition_counts != EXPECTED_DISPOSITION_COUNTS:
        raise AuditError("requirement trace disposition counts are invalid")
    for symbol in REGISTRY_SYMBOLS:
        verify_symbol(ssi, REGISTRY_RELATIVE_PATH, symbol)
    registry_raw = read_regular_file(registry_path)

    return {
        "$comment": (
            "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n"
            "SPDX-License-Identifier: MIT OR Apache-2.0"
        ),
        "schema": "reallyme.identity.etsi_eaa_pid_requirement_trace.v1",
        "scope": {
            "etsi_ts_119_472_1": "V1.2.1 (2026-02)",
            "etsi_ts_119_472_2_legal": "V1.2.1 (2026-03)",
            "etsi_ts_119_472_2_latest": "V1.3.1 (2026-07)",
            "etsi_ts_119_472_3": "V1.1.1 (2026-03)",
            "eu_consolidated_date": "2026-08-11",
            "eu_implementing_regulations": ["2024/2977", "2024/2979", "2024/2982"],
            "eu_amending_regulation": "2026/1731",
        },
        "source_integrity": {
            "ssi_repository": "https://github.com/reallyme/ssi",
            "ssi_commit": ssi.commit,
            "trace_path": TRACE_RELATIVE_PATH.as_posix(),
            "trace_sha256": sha256_bytes(trace_raw),
            "index_sha256": sha256_bytes(read_regular_file(index_path)),
            "eu_ledger_sha256": sha256_bytes(read_regular_file(eu_ledger_path)),
            "production_registry_path": REGISTRY_RELATIVE_PATH.as_posix(),
            "production_registry_sha256": sha256_bytes(registry_raw),
            "official_pdf_sha256": OFFICIAL_SOURCE_SHA256,
        },
        "summary": {
            "mapping_status": "complete",
            "product_conformance_status": "external_evidence_still_required",
            "total_rows": len(rows),
            "etsi_requirement_rows": len(indexed),
            "eu_profile_rows": len(eu_indexed),
            "production_registry_status": "all_740_identifiers_fail_closed",
            "production_registry_symbols": list(REGISTRY_SYMBOLS),
            "source_counts": source_counts,
            "disposition_counts": disposition_counts,
        },
        "claim_boundary": (
            "Complete traceability proves inventory closure only. Rows classified as "
            "external_evidence_required and external evidence named by code-backed rows "
            "must be satisfied in the applicable deployment before product conformity "
            "can be asserted."
        ),
        "requirements": rows,
    }


def serialized_artifact(artifact: dict[str, object]) -> bytes:
    return (json.dumps(artifact, indent=2, sort_keys=False) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()
    try:
        artifact = build_artifact(load_components())
        content = serialized_artifact(artifact)
        output = args.output.resolve()
        if args.check:
            if read_regular_file(output) != content:
                fail("ETSI EAA/PID trace artifact is stale", EXIT_STALE)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
    except AuditError as error:
        fail(str(error))
    print("ETSI EAA/PID requirement trace is complete and internally consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
