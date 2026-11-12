# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, relative_path: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        name, REPOSITORY_ROOT / relative_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("test script module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFIER = load_script(
    "verify_wallet_release_bundle", "scripts/verify_wallet_release_bundle.py"
)


COMMIT = "1" * 40
VERSION = "1.2.3"
RELEASE_REF = f"reallyme-wallet-v{VERSION}"
PACKAGES = {
    "reallyme-wallet": VERSION,
    "reallyme-wallet-types": VERSION,
}


def add_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.mode = 0o600
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


def crate_bytes(name: str, commit: str = COMMIT) -> bytes:
    output = io.BytesIO()
    root = f"{name}-{VERSION}"
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        vcs = json.dumps(
            {"git": {"sha1": commit}, "path_in_vcs": f"crates/{name}"},
            sort_keys=True,
        ).encode("utf-8")
        add_bytes(archive, f"{root}/.cargo_vcs_info.json", vcs)
        add_bytes(
            archive,
            f"{root}/Cargo.toml",
            f'[package]\nname = "{name}"\nversion = "{VERSION}"\n'.encode("utf-8"),
        )
    return output.getvalue()


def evidence_bytes(category: str, *, conclusion: str = "success") -> bytes:
    steps = [
        {
            "name": name,
            "number": index + 1,
            "status": "completed",
            "conclusion": conclusion,
        }
        for index, name in enumerate(VERIFIER.EXPECTED_EVIDENCE_STEPS[category])
    ]
    value = {
        "schema": "reallyme.wallet.eudi_release_check_evidence.v1",
        "repository": "reallyme/wallet",
        "release_sha": COMMIT,
        "run_id": 41,
        "run_attempt": 1,
        "job_id": 42,
        "category": category,
        "steps": steps,
    }
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def material(
    cargo_lock: bytes,
    *,
    crate_commit: str = COMMIT,
    failed_evidence: str | None = None,
) -> tuple[dict[str, object], dict[str, bytes]]:
    files: dict[str, bytes] = {}
    crates: list[dict[str, object]] = []
    for name in sorted(PACKAGES):
        file_name = f"{name}-{VERSION}.crate"
        content = crate_bytes(name, crate_commit)
        files[file_name] = content
        crates.append(
            {
                "file": file_name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest = {
        "schema": "reallyme.wallet.crates_preflight.v3",
        "repository": "reallyme/wallet",
        "workflow": "crates-package-preflight.yml",
        "run_id": 41,
        "run_attempt": 1,
        "release_sha": COMMIT,
        "version": VERSION,
        "crates": crates,
        "prerequisites": {"fuzz": 31, "protobuf_ci": 32, "rust_ci": 33},
    }
    files["crates-preflight.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    checks: list[dict[str, object]] = []
    for category in sorted(VERIFIER.EXPECTED_EVIDENCE_STEPS):
        content = evidence_bytes(
            category,
            conclusion="failure" if category == failed_evidence else "success",
        )
        files[f"evidence-{category}.json"] = content
        checks.append(
            {
                "check_id": f"release-preflight-{category}",
                "category": category,
                "result": "passed",
                "evidence_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    attestation = {
        "release": {"version": VERSION, "source_ref": RELEASE_REF},
        "dependency_lock": {
            "kind": "cargo",
            "sha256": hashlib.sha256(cargo_lock).hexdigest(),
        },
        "checks": checks,
    }
    return attestation, files


def write_bundle(path: Path, files: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w:") as archive:
        for name, content in files.items():
            add_bytes(archive, name, content)


class WalletReleaseBundleTests(unittest.TestCase):
    def verify(
        self,
        directory: Path,
        attestation: dict[str, object],
        files: dict[str, bytes],
        cargo_lock: bytes,
        packages: dict[str, str] | None = None,
    ) -> object:
        bundle = directory / "wallet-release"
        lock = directory / "Cargo.lock"
        write_bundle(bundle, files)
        lock.write_bytes(cargo_lock)
        return VERIFIER.verify_bundle(
            bundle,
            attestation,
            COMMIT,
            RELEASE_REF,
            PACKAGES if packages is None else packages,
            lock,
        )

    def test_complete_bundle_is_bound_to_source_release_and_preflight(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            result = self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertEqual(result.preflight_run_id, 41)
        self.assertEqual(result.preflight_job_id, 42)
        self.assertEqual(result.fuzz_run_id, 31)
        self.assertEqual(result.protobuf_ci_run_id, 32)
        self.assertEqual(result.rust_ci_run_id, 33)
        self.assertEqual(result.crate_count, len(PACKAGES))
        self.assertEqual(result.evidence_count, len(VERIFIER.EXPECTED_EVIDENCE_STEPS))
        self.assertEqual(result.cargo_lock_sha256, hashlib.sha256(cargo_lock).hexdigest())

    def test_dependency_lock_substitution_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, b"changed\n")
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )

    def test_crate_from_another_source_revision_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock, crate_commit="2" * 40)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )

    def test_failed_preflight_step_cannot_be_relabelled_as_passing(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock, failed_evidence="security")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.INVALID_EVIDENCE
        )

    def test_evidence_content_substitution_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        files["evidence-format.json"] += b" "
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.INVALID_EVIDENCE
        )

    def test_missing_publishable_crate_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        changed_packages = copy.deepcopy(PACKAGES)
        changed_packages["reallyme-wallet-provider"] = VERSION
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(
                    Path(directory),
                    attestation,
                    files,
                    cargo_lock,
                    changed_packages,
                )
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )

    def test_unexpected_bundle_member_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        files["unreviewed.txt"] = b"not evidence"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.INVALID_BUNDLE
        )

    def test_release_reference_mismatch_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        attestation["release"]["source_ref"] = "reallyme-wallet-v9.9.9"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.SOURCE_MISMATCH
        )

    def test_duplicate_manifest_member_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "wallet-release"
            lock = root / "Cargo.lock"
            lock.write_bytes(cargo_lock)
            with tarfile.open(bundle, mode="w:") as archive:
                for name, content in files.items():
                    add_bytes(archive, name, content)
                add_bytes(archive, "crates-preflight.json", files["crates-preflight.json"])
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                VERIFIER.verify_bundle(
                    bundle,
                    attestation,
                    COMMIT,
                    RELEASE_REF,
                    PACKAGES,
                    lock,
                )
        self.assertIs(
            raised.exception.reason, VERIFIER.WalletReleaseBundleErrorReason.INVALID_BUNDLE
        )

    def test_attested_manifest_and_crates_are_materialized_exactly(self) -> None:
        cargo_lock = b"version = 4\n"
        _attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "wallet-release"
            output = root / "subjects"
            write_bundle(bundle, files)
            subjects = VERIFIER.materialize_attestation_subjects(
                bundle, output, len(PACKAGES)
            )
            expected_names = {
                "crates-preflight.json",
                *(f"{name}-{VERSION}.crate" for name in PACKAGES),
            }
            self.assertEqual({path.name for path in subjects}, expected_names)
            self.assertEqual(
                {path.name for path in output.iterdir()}, expected_names
            )
            for path in subjects:
                self.assertEqual(path.read_bytes(), files[path.name])

    def test_attestation_subject_materialization_rejects_wrong_crate_count(self) -> None:
        cargo_lock = b"version = 4\n"
        _attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "wallet-release"
            output = root / "subjects"
            write_bundle(bundle, files)
            with self.assertRaises(VERIFIER.WalletReleaseBundleError):
                VERIFIER.materialize_attestation_subjects(
                    bundle, output, len(PACKAGES) + 1
                )
            self.assertFalse(output.exists())

    def test_attestation_subject_materialization_rejects_existing_destination(
        self,
    ) -> None:
        cargo_lock = b"version = 4\n"
        _attestation, files = material(cargo_lock)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "wallet-release"
            output = root / "subjects"
            output.mkdir()
            write_bundle(bundle, files)
            with self.assertRaises(VERIFIER.WalletReleaseBundleError):
                VERIFIER.materialize_attestation_subjects(
                    bundle, output, len(PACKAGES)
                )

    def test_attestation_subject_materialization_rejects_unreviewed_member(
        self,
    ) -> None:
        cargo_lock = b"version = 4\n"
        _attestation, files = material(cargo_lock)
        files["unreviewed.txt"] = b"not attested"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "wallet-release"
            output = root / "subjects"
            write_bundle(bundle, files)
            with self.assertRaises(VERIFIER.WalletReleaseBundleError):
                VERIFIER.materialize_attestation_subjects(
                    bundle, output, len(PACKAGES)
                )
            self.assertFalse(output.exists())

    def test_reused_prerequisite_run_id_is_rejected(self) -> None:
        cargo_lock = b"version = 4\n"
        attestation, files = material(cargo_lock)
        manifest = json.loads(files["crates-preflight.json"])
        manifest["prerequisites"]["fuzz"] = manifest["run_id"]
        files["crates-preflight.json"] = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VERIFIER.WalletReleaseBundleError) as raised:
                self.verify(Path(directory), attestation, files, cargo_lock)
        self.assertIs(
            raised.exception.reason,
            VERIFIER.WalletReleaseBundleErrorReason.INVALID_MANIFEST,
        )


if __name__ == "__main__":
    unittest.main()
