# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "check_pin_freshness", REPOSITORY_ROOT / "scripts/check_pin_freshness.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("pin freshness script could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


FRESHNESS = load_script()


class PinFreshnessTests(unittest.TestCase):
    def test_json_report_records_authoritative_source_unavailability(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()

        with (
            patch.object(
                FRESHNESS,
                "run_checks",
                side_effect=FRESHNESS.FreshnessError("source unavailable"),
            ),
            patch.object(
                sys,
                "argv",
                ["check_pin_freshness.py", "--format", "json"],
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = FRESHNESS.main()

        report = json.loads(output.getvalue())
        self.assertEqual(status, FRESHNESS.EXIT_UNAVAILABLE)
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(
            report["error"], {"code": "authoritative_source_unavailable"}
        )
        self.assertEqual(report["checks"], [])
        self.assertEqual(errors.getvalue(), "")

    def test_transient_publication_failure_is_retried(self) -> None:
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"publication"
        transient_error = urllib.error.URLError("temporary failure")

        with (
            patch.object(
                FRESHNESS.urllib.request,
                "urlopen",
                side_effect=(transient_error, response),
            ) as urlopen,
            patch.object(FRESHNESS.time, "sleep") as sleep,
        ):
            content = FRESHNESS.fetch_bytes("https://example.test/publication")

        self.assertEqual(content, b"publication")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(FRESHNESS.RETRY_BASE_DELAY_SECONDS)

    def test_transient_publication_failure_exhausts_bounded_attempts(self) -> None:
        transient_error = urllib.error.URLError("temporary failure")

        with (
            patch.object(
                FRESHNESS.urllib.request,
                "urlopen",
                side_effect=transient_error,
            ) as urlopen,
            patch.object(FRESHNESS.time, "sleep") as sleep,
            self.assertRaises(FRESHNESS.FreshnessError),
        ):
            FRESHNESS.fetch_bytes("https://example.test/publication")

        self.assertEqual(urlopen.call_count, FRESHNESS.MAX_FETCH_ATTEMPTS)
        self.assertEqual(sleep.call_count, FRESHNESS.MAX_FETCH_ATTEMPTS - 1)

    def test_permanent_http_failure_is_not_retried(self) -> None:
        permanent_error = urllib.error.HTTPError(
            "https://example.test/publication",
            404,
            "not found",
            {},
            None,
        )
        self.addCleanup(permanent_error.close)

        with (
            patch.object(
                FRESHNESS.urllib.request,
                "urlopen",
                side_effect=permanent_error,
            ) as urlopen,
            patch.object(FRESHNESS.time, "sleep") as sleep,
            self.assertRaises(FRESHNESS.FreshnessError),
        ):
            FRESHNESS.fetch_bytes("https://example.test/publication")

        urlopen.assert_called_once()
        sleep.assert_not_called()

    def test_transient_http_failure_is_retried(self) -> None:
        transient_error = urllib.error.HTTPError(
            "https://example.test/publication",
            503,
            "service unavailable",
            {},
            None,
        )
        self.addCleanup(transient_error.close)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"publication"

        with (
            patch.object(
                FRESHNESS.urllib.request,
                "urlopen",
                side_effect=(transient_error, response),
            ) as urlopen,
            patch.object(FRESHNESS.time, "sleep") as sleep,
        ):
            content = FRESHNESS.fetch_bytes("https://example.test/publication")

        self.assertEqual(content, b"publication")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(FRESHNESS.RETRY_BASE_DELAY_SECONDS)

    def test_equal_values_are_current(self) -> None:
        result = FRESHNESS.status_result("example", "v1.2.3", "v1.2.3")
        self.assertEqual(result.status, "current")

    def test_different_values_are_stale(self) -> None:
        result = FRESHNESS.status_result("example", "v1.2.3", "v1.2.4")
        self.assertEqual(result.status, "stale")

    def test_rust_stable_manifest_version_is_extracted_from_rust_package(self) -> None:
        manifest = (
            b'manifest-version = "2"\n'
            b'[pkg.cargo]\nversion = "0.100.0 (abc 2026-01-01)"\n'
            b'[pkg.rust]\nversion = "1.99.1 (abc 2026-01-01)"\n'
        )
        self.assertEqual(FRESHNESS.rust_toolchain_version(manifest), "1.99.1")

    def test_rust_stable_manifest_without_rust_package_is_rejected(self) -> None:
        with self.assertRaises(FRESHNESS.FreshnessError):
            FRESHNESS.rust_toolchain_version(b'manifest-version = "2"\n')

    def test_maven_release_version_uses_the_canonical_release_element(self) -> None:
        metadata = (
            b"<metadata><versioning><latest>33.8.0-jre</latest>"
            b"<release>33.8.0-jre</release></versioning></metadata>"
        )
        self.assertEqual(FRESHNESS.maven_release_version(metadata), "33.8.0-jre")

    def test_maven_metadata_without_release_is_rejected(self) -> None:
        with self.assertRaises(FRESHNESS.FreshnessError):
            FRESHNESS.maven_release_version(b"<metadata></metadata>")

    def test_python_monitors_select_latest_stable_and_series_security_release(
        self,
    ) -> None:
        policy = {
            "python_release_monitors": [
                {
                    "id": "python-latest",
                    "version": "3.15.2",
                    "latest_stable": True,
                    "consumers": ["latest-consumer"],
                },
                {
                    "id": "python-compatibility",
                    "version": "3.12.16",
                    "series": "3.12",
                    "consumers": ["compatibility-consumer"],
                },
            ]
        }
        metadata = [
            {
                "name": "Python 3.12.15",
                "is_published": True,
                "pre_release": False,
            },
            {
                "name": "Python 3.12.16",
                "is_published": True,
                "pre_release": False,
            },
            {
                "name": "Python 3.15.2",
                "is_published": True,
                "pre_release": False,
            },
            {
                "name": "Python 3.16.0a2",
                "is_published": True,
                "pre_release": True,
            },
        ]
        with patch.object(
            FRESHNESS,
            "consumer_text",
            return_value="Python 3.15.2 and Python 3.12.16",
        ):
            results = FRESHNESS.check_python_releases(
                policy, lambda _url: metadata
            )
        self.assertEqual([result.status for result in results], ["current", "current"])

    def test_python_latest_monitor_reports_a_new_stable_release(self) -> None:
        policy = {
            "python_release_monitors": [
                {
                    "id": "python-latest",
                    "version": "3.15.2",
                    "latest_stable": True,
                    "consumers": [],
                }
            ]
        }
        metadata = [
            {
                "name": "Python 3.15.2",
                "is_published": True,
                "pre_release": False,
            },
            {
                "name": "Python 3.15.3",
                "is_published": True,
                "pre_release": False,
            },
        ]
        results = FRESHNESS.check_python_releases(
            policy, lambda _url: metadata
        )
        self.assertEqual(results[0].status, "stale")
        self.assertEqual(results[0].observed, "3.15.3")

    def test_github_ref_resolves_a_direct_commit(self) -> None:
        commit = "a" * 40

        def fetcher(_url: str) -> object:
            return {"object": {"type": "commit", "sha": commit}}

        self.assertEqual(
            FRESHNESS.resolve_github_ref("reallyme/example", "tags/v1.0.0", fetcher),
            commit,
        )

    def test_github_ref_resolves_an_annotated_tag(self) -> None:
        tag = "a" * 40
        commit = "b" * 40
        responses = iter(
            (
                {"object": {"type": "tag", "sha": tag}},
                {"object": {"type": "commit", "sha": commit}},
            )
        )

        def fetcher(_url: str) -> object:
            return next(responses)

        self.assertEqual(
            FRESHNESS.resolve_github_ref("reallyme/example", "tags/v1.0.0", fetcher),
            commit,
        )

    def test_github_ref_rejects_an_unsupported_target(self) -> None:
        def fetcher(_url: str) -> object:
            return {"object": {"type": "tree", "sha": "a" * 40}}

        with self.assertRaises(FRESHNESS.FreshnessError):
            FRESHNESS.resolve_github_ref(
                "reallyme/example", "tags/v1.0.0", fetcher
            )

    def test_release_check_reports_a_newer_tag(self) -> None:
        def fetcher(url: str) -> object:
            if url.endswith("/releases/latest"):
                return {"tag_name": "v1.1.0"}
            raise AssertionError("unexpected metadata request")

        results = FRESHNESS.check_github_release(
            "example", "reallyme/example", "v1.0.0", None, fetcher
        )
        self.assertEqual(results[0].status, "stale")

    def test_crate_check_rejects_a_yanked_pin(self) -> None:
        lock = {
            "required_cargo_packages": {
                "reallyme-example": {
                    "version": "1.0.0",
                    "checksum": "a" * 64,
                }
            }
        }

        def fetcher(_url: str) -> object:
            return {
                "crate": {"max_stable_version": "1.0.0"},
                "versions": [
                    {"num": "1.0.0", "checksum": "a" * 64, "yanked": True}
                ],
            }

        with patch.object(FRESHNESS, "read_object", return_value=lock):
            with self.assertRaises(FRESHNESS.FreshnessError):
                FRESHNESS.check_crates(fetcher)

    def test_crate_check_detects_checksum_substitution(self) -> None:
        lock = {
            "required_cargo_packages": {
                "reallyme-example": {
                    "version": "1.0.0",
                    "checksum": "a" * 64,
                }
            }
        }

        def fetcher(_url: str) -> object:
            return {
                "crate": {"max_stable_version": "1.0.0"},
                "versions": [
                    {"num": "1.0.0", "checksum": "b" * 64, "yanked": False}
                ],
            }

        with patch.object(FRESHNESS, "read_object", return_value=lock):
            results = FRESHNESS.check_crates(fetcher)
        checksum = next(
            result for result in results if result.check_id.endswith(".checksum")
        )
        self.assertEqual(checksum.status, "stale")

    def test_repository_identifier_rejects_extra_path_segments(self) -> None:
        with self.assertRaises(FRESHNESS.FreshnessError):
            FRESHNESS.github_api("owner/repository/extra", "releases/latest")

    def test_oidf_publication_content_substitution_is_stale(self) -> None:
        lock = {
            "publications": [
                {
                    "specification_id": "example-final",
                    "canonical_url": "https://openid.net/specs/example.html",
                    "sha256": "0" * 64,
                    "content_length": 3,
                    "source_repository": "https://github.com/openid/example",
                    "source_binding": "publication_only_no_final_source_tag",
                }
            ],
            "engineering_sources": [],
        }
        with patch.object(FRESHNESS, "read_object", return_value=lock):
            results = FRESHNESS.check_oidf_specifications(
                lambda _url: {}, lambda _url: b"new"
            )
        digest = next(
            result for result in results if result.check_id.endswith(".sha256")
        )
        self.assertEqual(digest.status, "stale")

    def test_eudi_default_branch_detects_commit_drift(self) -> None:
        expected_commit = "a" * 40
        observed_commit = "b" * 40
        lock = {
            "sources": [
                {
                    "source_id": "example",
                    "repository": "https://github.com/example/source",
                    "ref": "main",
                    "commit": expected_commit,
                    "update_strategy": "default_branch",
                }
            ]
        }

        def fetcher(url: str) -> object:
            if url.endswith("/source"):
                return {"default_branch": "main"}
            return {"object": {"type": "commit", "sha": observed_commit}}

        with patch.object(FRESHNESS, "read_object", return_value=lock):
            results = FRESHNESS.check_eudi_sources(fetcher)
        commit = next(
            result for result in results if result.check_id.endswith(".commit")
        )
        self.assertEqual(commit.status, "stale")

    def test_eudi_publication_detects_content_substitution(self) -> None:
        lock = {
            "publications": [
                {
                    "id": "example",
                    "canonical_url": "https://example.test/publication",
                    "binding": {
                        "kind": "content_sha256",
                        "sha256": "0" * 64,
                        "content_length": 3,
                    },
                }
            ]
        }
        with patch.object(FRESHNESS, "read_object", return_value=lock):
            results, manual_sources = FRESHNESS.check_eudi_publications(
                lambda _url: b"new"
            )
        digest = next(
            result for result in results if result.check_id.endswith(".sha256")
        )
        self.assertEqual(digest.status, "stale")
        self.assertEqual(manual_sources, [])

    def test_iso_edition_is_reported_for_manual_review(self) -> None:
        lock = {
            "publications": [
                {
                    "id": "iso-example",
                    "canonical_url": "https://www.iso.org/standard/1.html",
                    "binding": {
                        "kind": "official_edition",
                        "standard_number": "ISO/IEC 1:2026",
                    },
                }
            ]
        }
        with patch.object(FRESHNESS, "read_object", return_value=lock):
            results, manual_sources = FRESHNESS.check_eudi_publications(
                lambda _url: b"unused"
            )
        self.assertEqual(results, [])
        self.assertEqual(len(manual_sources), 1)


if __name__ == "__main__":
    unittest.main()
