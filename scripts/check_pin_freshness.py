#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Compare reviewable conformance pins with authoritative upstream metadata."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import strict_json  # noqa: E402


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OIDF_RELEASE_LOCK = REPOSITORY_ROOT / "upstream/oidf/conformance-suite.lock.json"
OIDF_MASTER_LOCK = REPOSITORY_ROOT / "upstream/oidf/engineering-master.lock.json"
EUDI_PLAN = REPOSITORY_ROOT / "plans/eudi/relying-party-control-plane.json"
EUDI_SOURCES = REPOSITORY_ROOT / "upstream/eudi/sources.lock.json"
EUDI_PUBLICATIONS = REPOSITORY_ROOT / "references/eudi-publications.lock.json"
OIDF_SPECIFICATIONS = REPOSITORY_ROOT / "upstream/oidf/specifications.lock.json"
PIN_POLICY = REPOSITORY_ROOT / "references/pin-policy.json"
TRACE_SOURCES = REPOSITORY_ROOT / "references/reallyme/trace-sources.lock.json"
MAX_LOCAL_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 20
MAX_FETCH_ATTEMPTS = 4
RETRY_BASE_DELAY_SECONDS = 1.0
RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
EXIT_STALE = 2
EXIT_UNAVAILABLE = 3
SHA1 = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUST_VERSION = re.compile(
    r'^version = "([0-9]+\.[0-9]+\.[0-9]+) \(', re.MULTILINE
)
MAVEN_RELEASE = re.compile(r"<release>([^<]{1,128})</release>")
PYTHON_VERSION = re.compile(r"^([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})$")
PYTHON_RELEASE_NAME = re.compile(
    r"^Python ([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})$"
)
PYTHON_SERIES = re.compile(r"^([0-9]{1,2})\.([0-9]{1,2})$")
FetchJson = Callable[[str], object]
FetchBytes = Callable[[str], bytes]


class FreshnessError(Exception):
    """Raised when authoritative freshness metadata cannot be evaluated safely."""


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: str
    expected: str
    observed: str


@dataclass(frozen=True)
class UnavailableCheck:
    check_id: str
    reason: str


CheckOperation = Callable[[], tuple[list[CheckResult], list[str]]]


def fail(message: str, exit_code: int) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def read_object(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise FreshnessError("pin input must be a regular file")
        if metadata.st_size < 1 or metadata.st_size > MAX_LOCAL_BYTES:
            raise FreshnessError("pin input has an invalid size")
        value = strict_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, strict_json.StrictJsonError) as error:
        raise FreshnessError("pin input is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise FreshnessError("pin input must contain an object")
    return value


def required_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise FreshnessError(f"{context} must be a non-empty string")
    return value


def required_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise FreshnessError(f"{context} must be an array")
    return value


def rust_toolchain_version(manifest: bytes) -> str:
    try:
        rust_section = manifest.decode("utf-8").split("[pkg.rust]", maxsplit=1)[1]
    except (UnicodeError, IndexError) as error:
        raise FreshnessError("Rust toolchain metadata is invalid") from error
    match = RUST_VERSION.search(rust_section)
    if match is None:
        raise FreshnessError("Rust toolchain version is unavailable")
    return match.group(1)


def maven_release_version(metadata: bytes) -> str:
    try:
        document = metadata.decode("utf-8")
    except UnicodeError as error:
        raise FreshnessError("Maven release metadata is invalid") from error
    match = MAVEN_RELEASE.search(document)
    if match is None:
        raise FreshnessError("Maven release version is unavailable")
    return match.group(1)


def parse_python_version(value: object, context: str) -> tuple[int, int, int]:
    version = required_string(value, context)
    match = PYTHON_VERSION.fullmatch(version)
    if match is None:
        raise FreshnessError(f"{context} is invalid")
    return tuple(int(part) for part in match.groups())


def check_python_releases(
    policy: dict[str, object], fetcher: FetchJson
) -> list[CheckResult]:
    metadata = fetcher(
        "https://www.python.org/api/v2/downloads/release/"
        "?version=3&format=json"
    )
    if not isinstance(metadata, list):
        raise FreshnessError("Python release metadata is invalid")
    stable_versions: set[tuple[int, int, int]] = set()
    for raw_release in metadata:
        if (
            not isinstance(raw_release, dict)
            or raw_release.get("is_published") is not True
            or raw_release.get("pre_release") is not False
            or not isinstance(raw_release.get("name"), str)
        ):
            continue
        match = PYTHON_RELEASE_NAME.fullmatch(raw_release["name"])
        if match is not None:
            stable_versions.add(tuple(int(part) for part in match.groups()))
    if not stable_versions:
        raise FreshnessError("Python release metadata contains no stable releases")

    results: list[CheckResult] = []
    monitors = required_list(
        policy.get("python_release_monitors"), "Python release monitors"
    )
    for raw_monitor in monitors:
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("Python release monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "Python monitor id")
        expected_text = required_string(
            raw_monitor.get("version"), "Python monitor version"
        )
        expected_version = parse_python_version(
            expected_text, "Python monitor version"
        )
        latest_stable = raw_monitor.get("latest_stable")
        if latest_stable is True:
            if "series" in raw_monitor:
                raise FreshnessError(
                    "latest Python monitor must not constrain a release series"
                )
            observed_version = max(stable_versions)
        elif latest_stable is None:
            series_text = required_string(
                raw_monitor.get("series"), "Python monitor series"
            )
            series_match = PYTHON_SERIES.fullmatch(series_text)
            if series_match is None:
                raise FreshnessError("Python monitor series is invalid")
            series = tuple(int(part) for part in series_match.groups())
            if expected_version[:2] != series:
                raise FreshnessError(
                    "Python monitor version does not match its release series"
                )
            candidates = [
                version for version in stable_versions if version[:2] == series
            ]
            if not candidates:
                raise FreshnessError("Python release series has no stable release")
            observed_version = max(candidates)
        else:
            raise FreshnessError("Python monitor latest-stable flag is invalid")
        observed_text = ".".join(str(part) for part in observed_version)
        results.append(
            status_result(f"{check_id}.version", expected_text, observed_text)
        )
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "Python release consumers"
        ):
            consumer = required_string(raw_consumer, "Python release consumer")
            if expected_text not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=expected_text,
                        observed="absent",
                    )
                )
    return results


def fetch_json(url: str) -> object:
    headers = {
        "Accept": "application/json",
        "User-Agent": (
            "ReallyMe-Identity-Conformance/1.0 "
            "(+https://github.com/reallyme/identity-conformance)"
        ),
    }
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    body = fetch_response_bytes(
        request,
        f"authoritative metadata request failed for {url}",
    )
    if len(body) > MAX_RESPONSE_BYTES:
        raise FreshnessError("authoritative metadata response exceeds the size limit")
    try:
        return strict_json.loads(body.decode("utf-8"))
    except (UnicodeError, strict_json.StrictJsonError) as error:
        raise FreshnessError("authoritative metadata response is invalid JSON") from error


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/octet-stream;q=0.9",
            "User-Agent": (
                "ReallyMe-Identity-Conformance/1.0 "
                "(+https://github.com/reallyme/identity-conformance)"
            ),
        },
        method="GET",
    )
    body = fetch_response_bytes(
        request,
        f"authoritative publication request failed for {url}",
    )
    if len(body) > MAX_RESPONSE_BYTES:
        raise FreshnessError("authoritative publication exceeds the size limit")
    return body


def fetch_response_bytes(
    request: urllib.request.Request,
    failure_message: str,
) -> bytes:
    """Fetch a bounded response while tolerating transient publisher failures."""

    for attempt in range(MAX_FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(
                request, timeout=HTTP_TIMEOUT_SECONDS
            ) as response:
                return response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            status_code = error.code
            error.close()
            if status_code not in RETRYABLE_HTTP_STATUS_CODES:
                raise FreshnessError(failure_message) from error
            last_error: Exception = error
        except (
            http.client.HTTPException,
            OSError,
            urllib.error.URLError,
            TimeoutError,
        ) as error:
            last_error = error

        if attempt + 1 == MAX_FETCH_ATTEMPTS:
            raise FreshnessError(failure_message) from last_error

        # Authoritative standards publishers occasionally reset or throttle
        # otherwise valid downloads. A short deterministic backoff prevents a
        # transient transport failure from invalidating a release candidate.
        time.sleep(RETRY_BASE_DELAY_SECONDS * (2**attempt))

    raise FreshnessError(failure_message)


def github_api(repository: str, suffix: str) -> str:
    if repository.count("/") != 1:
        raise FreshnessError("GitHub repository identifier is invalid")
    owner, name = repository.split("/", maxsplit=1)
    base = (
        "https://api.github.com/repos/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
    )
    return f"{base}/{suffix}" if suffix else base


def resolve_github_object(
    repository: str, object_type: str, sha: str, fetcher: FetchJson
) -> str:
    current_type = object_type
    current_sha = sha
    for _ in range(4):
        if current_type == "commit":
            if SHA1.fullmatch(current_sha) is None:
                raise FreshnessError("GitHub commit identifier is invalid")
            return current_sha
        if current_type != "tag" or SHA1.fullmatch(current_sha) is None:
            raise FreshnessError("GitHub ref target is unsupported")
        value = fetcher(github_api(repository, f"git/tags/{current_sha}"))
        if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
            raise FreshnessError("GitHub annotated tag metadata is invalid")
        target = value["object"]
        current_type = required_string(target.get("type"), "GitHub tag target type")
        current_sha = required_string(target.get("sha"), "GitHub tag target commit")
    raise FreshnessError("GitHub annotated tag chain exceeds the accepted depth")


def resolve_github_ref(repository: str, ref: str, fetcher: FetchJson) -> str:
    encoded_ref = urllib.parse.quote(ref, safe="/")
    value = fetcher(github_api(repository, f"git/ref/{encoded_ref}"))
    if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
        raise FreshnessError("GitHub ref metadata is invalid")
    target = value["object"]
    return resolve_github_object(
        repository,
        required_string(target.get("type"), "GitHub ref target type"),
        required_string(target.get("sha"), "GitHub ref target commit"),
        fetcher,
    )


def status_result(check_id: str, expected: str, observed: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status="current" if expected == observed else "stale",
        expected=expected,
        observed=observed,
    )


def check_github_release(
    check_id: str,
    repository: str,
    expected_tag: str,
    expected_commit: str | None,
    fetcher: FetchJson,
) -> list[CheckResult]:
    value = fetcher(github_api(repository, "releases/latest"))
    if not isinstance(value, dict):
        raise FreshnessError("GitHub release metadata is invalid")
    observed_tag = required_string(value.get("tag_name"), "GitHub release tag")
    results = [status_result(f"{check_id}.release", expected_tag, observed_tag)]
    if expected_commit is not None:
        observed_commit = resolve_github_ref(
            repository, f"tags/{expected_tag}", fetcher
        )
        results.append(
            status_result(f"{check_id}.commit", expected_commit, observed_commit)
        )
    return results


def check_oidf(fetcher: FetchJson) -> list[CheckResult]:
    release_lock = read_object(OIDF_RELEASE_LOCK)
    master_lock = read_object(OIDF_MASTER_LOCK)
    release = fetcher(
        "https://gitlab.com/api/v4/projects/"
        "openid%2Fconformance-suite/releases/permalink/latest"
    )
    branch = fetcher(
        "https://gitlab.com/api/v4/projects/"
        "openid%2Fconformance-suite/repository/branches/master"
    )
    if (
        not isinstance(release, dict)
        or not isinstance(release.get("commit"), dict)
        or not isinstance(branch, dict)
        or not isinstance(branch.get("commit"), dict)
    ):
        raise FreshnessError("OIDF suite metadata is invalid")
    return [
        status_result(
            "oidf.release.tag",
            required_string(release_lock.get("pinned_ref"), "OIDF release ref"),
            required_string(release.get("tag_name"), "latest OIDF release tag"),
        ),
        status_result(
            "oidf.release.commit",
            required_string(release_lock.get("commit"), "OIDF release commit"),
            required_string(release["commit"].get("id"), "OIDF release commit"),
        ),
        status_result(
            "oidf.master.commit",
            required_string(master_lock.get("commit"), "OIDF master commit"),
            required_string(branch["commit"].get("id"), "OIDF master commit"),
        ),
    ]


def check_reallyme_trace_releases(fetcher: FetchJson) -> list[CheckResult]:
    lock = read_object(TRACE_SOURCES)
    sources = required_list(lock.get("sources"), "ReallyMe trace sources")
    results: list[CheckResult] = []
    observed_components: set[str] = set()
    for raw_source in sources:
        if not isinstance(raw_source, dict):
            raise FreshnessError("ReallyMe trace source is invalid")
        component_id = required_string(
            raw_source.get("component_id"), "ReallyMe component id"
        )
        if component_id in observed_components:
            raise FreshnessError("ReallyMe trace source is duplicated")
        observed_components.add(component_id)
        if raw_source.get("update_strategy") != "latest_release":
            raise FreshnessError("ReallyMe trace source policy is invalid")
        repository = github_repository_from_url(
            raw_source.get("repository"), "ReallyMe component repository"
        )
        expected_repository = f"reallyme/{component_id}"
        if repository != expected_repository:
            raise FreshnessError("ReallyMe component repository identity is invalid")
        results.extend(
            check_github_release(
                f"reallyme.trace.{component_id}",
                repository,
                required_string(
                    raw_source.get("release_ref"), "ReallyMe component release"
                ),
                required_string(
                    raw_source.get("commit"), "ReallyMe component release commit"
                ),
                fetcher,
            )
        )
    if observed_components != {"openid4vci", "openid4vp", "ssi"}:
        raise FreshnessError("ReallyMe trace source inventory is invalid")
    return results


def github_repository_from_url(value: object, context: str) -> str:
    repository_url = required_string(value, context)
    prefix = "https://github.com/"
    if not repository_url.startswith(prefix):
        raise FreshnessError(f"{context} must use a GitHub repository URL")
    repository = repository_url.removeprefix(prefix).removesuffix(".git")
    if repository.count("/") != 1:
        raise FreshnessError(f"{context} is invalid")
    return repository


def check_oidf_specifications(
    fetcher: FetchJson, byte_fetcher: FetchBytes
) -> list[CheckResult]:
    lock = read_object(OIDF_SPECIFICATIONS)
    publications = required_list(
        lock.get("publications"), "OIDF specification publications"
    )
    results: list[CheckResult] = []
    for raw_publication in publications:
        if not isinstance(raw_publication, dict):
            raise FreshnessError("OIDF specification publication is invalid")
        specification_id = required_string(
            raw_publication.get("specification_id"), "OIDF specification identifier"
        )
        url = required_string(
            raw_publication.get("canonical_url"), "OIDF publication URL"
        )
        expected_sha256 = required_string(
            raw_publication.get("sha256"), "OIDF publication digest"
        )
        expected_length = raw_publication.get("content_length")
        if not isinstance(expected_length, int) or expected_length < 1:
            raise FreshnessError("OIDF publication length is invalid")
        content = byte_fetcher(url)
        results.extend(
            (
                status_result(
                    f"oidf.specification.{specification_id}.sha256",
                    expected_sha256,
                    hashlib.sha256(content).hexdigest(),
                ),
                status_result(
                    f"oidf.specification.{specification_id}.length",
                    str(expected_length),
                    str(len(content)),
                ),
            )
        )
        if "source_ref" in raw_publication:
            repository = github_repository_from_url(
                raw_publication.get("source_repository"),
                "OIDF specification source repository",
            )
            source_ref = required_string(
                raw_publication.get("source_ref"), "OIDF specification source ref"
            )
            expected_commit = required_string(
                raw_publication.get("source_commit"),
                "OIDF specification source commit",
            )
            observed_commit = resolve_github_ref(
                repository, f"tags/{source_ref}", fetcher
            )
            results.append(
                status_result(
                    f"oidf.specification.{specification_id}.source_commit",
                    expected_commit,
                    observed_commit,
                )
            )

    engineering_sources = required_list(
        lock.get("engineering_sources"), "OIDF engineering sources"
    )
    for raw_source in engineering_sources:
        if not isinstance(raw_source, dict):
            raise FreshnessError("OIDF engineering source is invalid")
        source_id = required_string(
            raw_source.get("specification_id"), "OIDF engineering source identifier"
        )
        repository = github_repository_from_url(
            raw_source.get("repository"), "OIDF engineering source repository"
        )
        branch = required_string(raw_source.get("ref"), "OIDF engineering source ref")
        expected_commit = required_string(
            raw_source.get("commit"), "OIDF engineering source commit"
        )
        observed_commit = resolve_github_ref(repository, f"heads/{branch}", fetcher)
        results.append(
            status_result(
                f"oidf.engineering.{source_id}.commit",
                expected_commit,
                observed_commit,
            )
        )
    return results


def check_eudi_sources(fetcher: FetchJson) -> list[CheckResult]:
    lock = read_object(EUDI_SOURCES)
    sources = required_list(lock.get("sources"), "EUDI sources")
    results: list[CheckResult] = []
    for raw_source in sources:
        if not isinstance(raw_source, dict):
            raise FreshnessError("EUDI source is invalid")
        source_id = required_string(raw_source.get("source_id"), "EUDI source id")
        repository = github_repository_from_url(
            raw_source.get("repository"), "EUDI source repository"
        )
        expected_ref = required_string(raw_source.get("ref"), "EUDI source ref")
        expected_commit = required_string(
            raw_source.get("commit"), "EUDI source commit"
        )
        strategy = required_string(
            raw_source.get("update_strategy"), "EUDI update strategy"
        )
        if strategy == "latest_release":
            release = fetcher(github_api(repository, "releases/latest"))
            if not isinstance(release, dict):
                raise FreshnessError("EUDI release metadata is invalid")
            observed_ref = required_string(
                release.get("tag_name"), "latest EUDI release tag"
            )
            observed_commit = resolve_github_ref(
                repository, f"tags/{expected_ref}", fetcher
            )
        elif strategy == "default_branch":
            metadata = fetcher(github_api(repository, ""))
            if not isinstance(metadata, dict):
                raise FreshnessError("EUDI repository metadata is invalid")
            observed_ref = required_string(
                metadata.get("default_branch"), "EUDI default branch"
            )
            observed_commit = resolve_github_ref(
                repository, f"heads/{observed_ref}", fetcher
            )
        elif strategy == "latest_tag":
            tags = fetcher(github_api(repository, "tags?per_page=1"))
            if (
                not isinstance(tags, list)
                or len(tags) != 1
                or not isinstance(tags[0], dict)
                or not isinstance(tags[0].get("commit"), dict)
            ):
                raise FreshnessError("EUDI tag metadata is invalid")
            observed_ref = required_string(tags[0].get("name"), "latest EUDI tag")
            observed_commit = required_string(
                tags[0]["commit"].get("sha"), "latest EUDI tag commit"
            )
        else:
            raise FreshnessError("EUDI update strategy is unsupported")
        results.extend(
            (
                status_result(
                    f"eudi.source.{source_id}.ref", expected_ref, observed_ref
                ),
                status_result(
                    f"eudi.source.{source_id}.commit",
                    expected_commit,
                    observed_commit,
                ),
            )
        )
    return results


def check_eudi_publications(
    byte_fetcher: FetchBytes,
) -> tuple[list[CheckResult], list[str]]:
    lock = read_object(EUDI_PUBLICATIONS)
    publications = required_list(
        lock.get("publications"), "EUDI external publications"
    )
    results: list[CheckResult] = []
    manual_sources: list[str] = []
    for raw_publication in publications:
        if not isinstance(raw_publication, dict):
            raise FreshnessError("EUDI external publication is invalid")
        publication_id = required_string(
            raw_publication.get("id"), "EUDI external publication id"
        )
        url = required_string(
            raw_publication.get("canonical_url"),
            "EUDI external publication URL",
        )
        binding = raw_publication.get("binding")
        if not isinstance(binding, dict):
            raise FreshnessError("EUDI external publication binding is invalid")
        kind = required_string(
            binding.get("kind"), "EUDI external publication binding kind"
        )
        if kind == "official_edition":
            standard_number = required_string(
                binding.get("standard_number"),
                "EUDI external publication standard number",
            )
            manual_sources.append(
                f"{publication_id}: verify that {standard_number} remains "
                "the selected published edition"
            )
            continue
        if kind != "content_sha256":
            raise FreshnessError("EUDI external publication binding is unsupported")
        expected_digest = required_string(
            binding.get("sha256"), "EUDI external publication digest"
        )
        expected_length = binding.get("content_length")
        if not isinstance(expected_length, int) or isinstance(expected_length, bool):
            raise FreshnessError("EUDI external publication length is invalid")
        content = byte_fetcher(url)
        results.extend(
            (
                status_result(
                    f"eudi.publication.{publication_id}.sha256",
                    expected_digest,
                    hashlib.sha256(content).hexdigest(),
                ),
                status_result(
                    f"eudi.publication.{publication_id}.content_length",
                    str(expected_length),
                    str(len(content)),
                ),
            )
        )
    return results, manual_sources


def check_eudi_reference(fetcher: FetchJson) -> list[CheckResult]:
    plan = read_object(EUDI_PLAN)
    sources = plan.get("sources")
    if not isinstance(sources, dict) or not isinstance(
        sources.get("legacy_reference"), dict
    ):
        raise FreshnessError("EUDI reference plan is invalid")
    reference = sources["legacy_reference"]
    repository = required_string(
        reference.get("repository"), "EUDI reference repository"
    )
    expected_commit = required_string(
        reference.get("commit"), "EUDI reference commit"
    )
    metadata = fetcher(github_api(repository, ""))
    if not isinstance(metadata, dict):
        raise FreshnessError("EUDI GitHub repository metadata is invalid")
    default_branch = required_string(
        metadata.get("default_branch"), "EUDI default branch"
    )
    commit = fetcher(
        github_api(repository, f"commits/{urllib.parse.quote(default_branch, safe='')}")
    )
    if not isinstance(commit, dict):
        raise FreshnessError("EUDI GitHub commit metadata is invalid")
    return [
        status_result(
            "eudi.reference.commit",
            expected_commit,
            required_string(commit.get("sha"), "EUDI reference commit"),
        )
    ]


def consumer_text(relative_path: str) -> str:
    path = (REPOSITORY_ROOT / relative_path).resolve()
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError as error:
        raise FreshnessError("pin consumer escapes the repository") from error
    candidates: list[Path]
    if path.is_dir():
        candidates = sorted(
            candidate
            for pattern in ("*.yml", "*.yaml")
            for candidate in path.rglob(pattern)
        )
    else:
        candidates = [path]
    if not candidates:
        raise FreshnessError("pin consumer is unavailable")
    content: list[str] = []
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
            if candidate.is_symlink() or not candidate.is_file():
                raise FreshnessError("pin consumer must be a regular file")
            if metadata.st_size > MAX_LOCAL_BYTES:
                raise FreshnessError("pin consumer exceeds the size limit")
            content.append(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as error:
            raise FreshnessError("pin consumer is unavailable") from error
    return "\n".join(content)


def check_policy(fetcher: FetchJson) -> tuple[list[CheckResult], list[str]]:
    policy = read_object(PIN_POLICY)
    if policy.get("schema") != "reallyme.identity.pin_policy.v1":
        raise FreshnessError("pin policy schema is unsupported")
    results: list[CheckResult] = []
    release_monitors = required_list(
        policy.get("github_release_monitors"), "GitHub release monitors"
    )
    for raw_monitor in release_monitors:
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("GitHub release monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "release monitor id")
        repository = required_string(
            raw_monitor.get("repository"), "release monitor repository"
        )
        tag = required_string(raw_monitor.get("tag"), "release monitor tag")
        raw_commit = raw_monitor.get("commit")
        commit = (
            required_string(raw_commit, "release monitor commit")
            if raw_commit is not None
            else None
        )
        results.extend(
            check_github_release(check_id, repository, tag, commit, fetcher)
        )
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "release monitor consumers"
        ):
            consumer = required_string(raw_consumer, "release monitor consumer")
            text = consumer_text(consumer)
            if commit is not None:
                if commit not in text:
                    results.append(
                        CheckResult(
                            check_id=f"{check_id}.consumer.{consumer}",
                            status="stale",
                            expected=commit,
                            observed="absent",
                        )
                    )
            elif tag not in text and tag.removeprefix("v") not in text:
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=f"{tag} or {tag.removeprefix('v')}",
                        observed="absent",
                    )
                )

    ref_monitors = required_list(
        policy.get("github_ref_monitors"), "GitHub ref monitors"
    )
    for raw_monitor in ref_monitors:
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("GitHub ref monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "ref monitor id")
        repository = required_string(
            raw_monitor.get("repository"), "ref monitor repository"
        )
        ref = required_string(raw_monitor.get("ref"), "monitored ref")
        commit = required_string(raw_monitor.get("commit"), "monitored ref commit")
        observed = resolve_github_ref(repository, ref, fetcher)
        results.append(status_result(f"{check_id}.commit", commit, observed))
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "ref monitor consumers"
        ):
            consumer = required_string(raw_consumer, "ref monitor consumer")
            if commit not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=commit,
                        observed="absent",
                    )
                )

    for raw_monitor in required_list(
        policy.get("docker_image_monitors"), "Docker image monitors"
    ):
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("Docker image monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "Docker image monitor id")
        namespace = required_string(raw_monitor.get("namespace"), "Docker namespace")
        repository = required_string(raw_monitor.get("repository"), "Docker repository")
        tag = required_string(raw_monitor.get("tag"), "Docker image tag")
        digest = required_string(raw_monitor.get("digest"), "Docker image digest")
        if OCI_DIGEST.fullmatch(digest) is None:
            raise FreshnessError("Docker image digest is invalid")
        encoded_namespace = urllib.parse.quote(namespace, safe="")
        encoded_repository = urllib.parse.quote(repository, safe="")
        encoded_tag = urllib.parse.quote(tag, safe="")
        metadata = fetcher(
            "https://hub.docker.com/v2/repositories/"
            f"{encoded_namespace}/{encoded_repository}/tags/{encoded_tag}"
        )
        if not isinstance(metadata, dict):
            raise FreshnessError("Docker image metadata is invalid")
        observed_digest = required_string(metadata.get("digest"), "Docker image digest")
        results.append(status_result(f"{check_id}.digest", digest, observed_digest))
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "Docker image consumers"
        ):
            consumer = required_string(raw_consumer, "Docker image consumer")
            if digest.removeprefix("sha256:") not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=digest,
                        observed="absent",
                    )
                )

    for raw_monitor in required_list(
        policy.get("pypi_release_monitors"), "PyPI release monitors"
    ):
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("PyPI release monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "PyPI monitor id")
        package = required_string(raw_monitor.get("package"), "PyPI package")
        version = required_string(raw_monitor.get("version"), "PyPI package version")
        metadata = fetcher(
            f"https://pypi.org/pypi/{urllib.parse.quote(package, safe='')}/json"
        )
        if not isinstance(metadata, dict) or not isinstance(metadata.get("info"), dict):
            raise FreshnessError("PyPI release metadata is invalid")
        observed_version = required_string(
            metadata["info"].get("version"), "PyPI release version"
        )
        results.append(status_result(f"{check_id}.version", version, observed_version))
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "PyPI release consumers"
        ):
            consumer = required_string(raw_consumer, "PyPI release consumer")
            if version not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=version,
                        observed="absent",
                    )
                )

    results.extend(check_python_releases(policy, fetcher))

    manual_sources: list[str] = []
    for raw_source in required_list(policy.get("manual_sources"), "manual sources"):
        if not isinstance(raw_source, dict):
            raise FreshnessError("manual source is invalid")
        source_id = required_string(raw_source.get("id"), "manual source id")
        reason = required_string(raw_source.get("reason"), "manual source reason")
        manual_sources.append(f"{source_id}: {reason}")
    return results, manual_sources


def check_maven_releases(byte_fetcher: FetchBytes) -> list[CheckResult]:
    policy = read_object(PIN_POLICY)
    results: list[CheckResult] = []
    for raw_monitor in required_list(
        policy.get("maven_release_monitors"), "Maven release monitors"
    ):
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("Maven release monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "Maven monitor id")
        group = required_string(raw_monitor.get("group"), "Maven group")
        artifact = required_string(raw_monitor.get("artifact"), "Maven artifact")
        version = required_string(raw_monitor.get("version"), "Maven version")
        group_path = "/".join(
            urllib.parse.quote(segment, safe="") for segment in group.split(".")
        )
        artifact_path = urllib.parse.quote(artifact, safe="")
        metadata = byte_fetcher(
            "https://repo1.maven.org/maven2/"
            f"{group_path}/{artifact_path}/maven-metadata.xml"
        )
        observed_version = maven_release_version(metadata)
        results.append(status_result(f"{check_id}.version", version, observed_version))
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "Maven release consumers"
        ):
            consumer = required_string(raw_consumer, "Maven release consumer")
            if version not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=version,
                        observed="absent",
                    )
                )
    return results


def check_rust_toolchains(byte_fetcher: FetchBytes) -> list[CheckResult]:
    policy = read_object(PIN_POLICY)
    results: list[CheckResult] = []
    for raw_monitor in required_list(
        policy.get("rust_toolchain_monitors"), "Rust toolchain monitors"
    ):
        if not isinstance(raw_monitor, dict):
            raise FreshnessError("Rust toolchain monitor is invalid")
        check_id = required_string(raw_monitor.get("id"), "Rust toolchain monitor id")
        channel = required_string(raw_monitor.get("channel"), "Rust toolchain channel")
        version = required_string(raw_monitor.get("version"), "Rust toolchain version")
        manifest = byte_fetcher(
            "https://static.rust-lang.org/dist/"
            f"channel-rust-{urllib.parse.quote(channel, safe='')}.toml"
        )
        observed_version = rust_toolchain_version(manifest)
        results.append(status_result(f"{check_id}.version", version, observed_version))
        for raw_consumer in required_list(
            raw_monitor.get("consumers"), "Rust toolchain consumers"
        ):
            consumer = required_string(raw_consumer, "Rust toolchain consumer")
            if version not in consumer_text(consumer):
                results.append(
                    CheckResult(
                        check_id=f"{check_id}.consumer.{consumer}",
                        status="stale",
                        expected=version,
                        observed="absent",
                    )
                )
    return results


def collect_check_group(
    check_id: str,
    operation: CheckOperation,
    results: list[CheckResult],
    manual_sources: list[str],
    unavailable_checks: list[UnavailableCheck],
) -> None:
    """Run an independent publisher group without hiding other observations."""

    try:
        group_results, group_manual_sources = operation()
    except FreshnessError as error:
        unavailable_checks.append(
            UnavailableCheck(check_id=check_id, reason=str(error))
        )
        return
    results.extend(group_results)
    manual_sources.extend(group_manual_sources)


def run_checks(
    fetcher: FetchJson = fetch_json, byte_fetcher: FetchBytes = fetch_bytes
) -> tuple[list[CheckResult], list[str], list[UnavailableCheck]]:
    results: list[CheckResult] = []
    manual_sources: list[str] = []
    unavailable_checks: list[UnavailableCheck] = []

    collect_check_group(
        "reallyme_trace_releases",
        lambda: (check_reallyme_trace_releases(fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "oidf_suite",
        lambda: (check_oidf(fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "oidf_specifications",
        lambda: (check_oidf_specifications(fetcher, byte_fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "eudi_sources",
        lambda: (check_eudi_sources(fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "eudi_publications",
        lambda: check_eudi_publications(byte_fetcher),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "eudi_reference",
        lambda: (check_eudi_reference(fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "pin_policy",
        lambda: check_policy(fetcher),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "maven_releases",
        lambda: (check_maven_releases(byte_fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    collect_check_group(
        "rust_toolchains",
        lambda: (check_rust_toolchains(byte_fetcher), []),
        results,
        manual_sources,
        unavailable_checks,
    )
    return results, manual_sources, unavailable_checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="select machine-readable or human-readable output",
    )
    args = parser.parse_args()
    try:
        results, manual_sources, unavailable_checks = run_checks()
    except FreshnessError as error:
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "schema": "reallyme.identity.pin_freshness_report.v1",
                        "status": "unavailable",
                        "checks": [],
                        "manual_sources": [],
                        "unavailable_checks": [
                            asdict(
                                UnavailableCheck(
                                    check_id="freshness_evaluation",
                                    reason=str(error),
                                )
                            )
                        ],
                    },
                    indent=2,
                )
            )
            return EXIT_UNAVAILABLE
        fail(str(error), EXIT_UNAVAILABLE)
    stale = [result for result in results if result.status == "stale"]
    report_status = (
        "stale" if stale else "unavailable" if unavailable_checks else "current"
    )
    if args.format == "json":
        print(
            json.dumps(
                {
                    "schema": "reallyme.identity.pin_freshness_report.v1",
                    "status": report_status,
                    "checks": [asdict(result) for result in results],
                    "manual_sources": manual_sources,
                    "unavailable_checks": [
                        asdict(unavailable) for unavailable in unavailable_checks
                    ],
                },
                indent=2,
            )
        )
    else:
        for result in results:
            print(
                f"{result.status}: {result.check_id}: "
                f"expected={result.expected} observed={result.observed}"
            )
        for source in manual_sources:
            print(f"manual: {source}")
        for unavailable in unavailable_checks:
            print(
                f"unavailable: {unavailable.check_id}: {unavailable.reason}",
                file=sys.stderr,
            )
    if stale:
        return EXIT_STALE
    if unavailable_checks:
        return EXIT_UNAVAILABLE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
