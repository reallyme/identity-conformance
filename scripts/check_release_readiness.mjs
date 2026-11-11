#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const coreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (typeof coreUrl !== "string" || coreUrl.length === 0) {
  console.error("release readiness check failed: pinned core URL is unavailable");
  process.exit(1);
}
const { createReleaseReadinessContext } = await import(coreUrl);

const {
  assertContains,
  assertNodeWorkflowJobsPinNode,
  assertPathsAbsent,
  assertReallyMeReleasePackagePolicy,
  assertSpdxHeaders,
  assertWorkflowActionsPinned,
  assertWorkflowRunStep,
  fail,
  loadTrackedFiles,
  run,
} = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

const workflow = ".github/workflows/release-readiness.yml";
const releaseCandidateWorkflow = ".github/workflows/release-candidate.yml";
const secretScanWorkflow = ".github/workflows/secret-scan.yml";
const openid4vciCertificationWorkflow =
  ".github/workflows/oidf-openid4vci-certification.yml";
const openid4vpCertificationWorkflow =
  ".github/workflows/oidf-openid4vp-certification.yml";
const pythonWorkflows = [
  ".github/workflows/eudi-relying-party-conformance.yml",
  ".github/workflows/eudi-wallet-conformance.yml",
  ".github/workflows/oidf-openid4vci-certification.yml",
  ".github/workflows/oidf-openid4vp-certification.yml",
  ".github/workflows/pin-freshness.yml",
  ".github/workflows/release-candidate.yml",
  ".github/workflows/release-readiness.yml",
  ".github/workflows/upstream-update-proposal.yml",
  ".github/workflows/zk-conformance.yml",
];
const sharedRevision = "18a6d91d99837e80f92e41fe04effb0b043d754e";
const gitleaksVersion = "8.30.1";
const gitleaksArchiveSha256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb";

assertReallyMeReleasePackagePolicy({
  scriptPath: "scripts/check_release_readiness.mjs",
  version: "0.7.0",
});
assertWorkflowActionsPinned();
assertNodeWorkflowJobsPinNode({ nodeVersion: "26" });
assertSpdxHeaders({
  extensions: [".java", ".mjs", ".py", ".sh", ".yaml", ".yml"],
  names: [".gitignore"],
  excludedPrefixes: [],
  copyright: "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
});

// The top-level boundary keeps third-party and ReallyMe ownership unambiguous.
assertPathsAbsent(["oidf", "reallyme", "OIDF_CERTIFICATION_READINESS.md", "LICENSE"]);

for (const path of loadTrackedFiles()) {
  if (path.startsWith("upstream/oidf/openid-conformance-suite/")) {
    fail(`third-party OIDF checkout must remain untracked: ${path}`);
  }
  if (path.toLowerCase().endsWith(".pdf")) {
    fail(`copyrighted standards and evidence PDFs must remain untracked: ${path}`);
  }
  if (
    path.startsWith("upstream/") &&
    path !== "upstream/oidf/README.md" &&
    path !== "upstream/oidf/LICENSE.txt" &&
    path !== "upstream/oidf/THIRD_PARTY_NOTICES.md" &&
    path !== "upstream/oidf/conformance-suite.lock.json" &&
    path !== "upstream/oidf/engineering-master.lock.json" &&
    path !== "upstream/oidf/specifications.lock.json" &&
    path !== "upstream/eudi/README.md" &&
    path !== "upstream/eudi/sources.lock.json" &&
    path !== "upstream/eudi/legal-sources.lock.json" &&
    !/^upstream\/oidf\/snapshots\/[A-Za-z0-9_.-]+\.json$/u.test(path)
  ) {
    fail(`tracked upstream asset is outside the OIDF pin/snapshot boundary: ${path}`);
  }
  if (
    path.startsWith("plans/") &&
    !/^plans\/oidf\/[A-Za-z0-9_.-]+\.json$/u.test(path) &&
    path !== "plans/eudi/relying-party-control-plane.json" &&
    path !== "plans/eudi/wallet.json" &&
    path !== "plans/eudi/upstream-coverage.json" &&
    path !== "plans/zk/presentation-proofs.json"
  ) {
    fail(`plan is outside a reviewed ReallyMe conformance-plan boundary: ${path}`);
  }
  if (
    path.startsWith("results/") &&
    path !== "results/.gitignore" &&
    path !== "results/README.md"
  ) {
    fail(`raw result output must remain untracked: ${path}`);
  }
}

assertContains(".gitignore", "/upstream/oidf/openid-conformance-suite/");
assertContains(".github/actionlint.yaml", "- oidf-certification");
assertContains(".github/actionlint.yaml", "- eudi-wallet-conformance");
assertContains(".github/actionlint.yaml", "- zk-conformance");
assertContains("scripts/run_actionlint.sh", 'readonly actionlint_version="1.7.12"');
assertContains(
  "scripts/run_actionlint.sh",
  'readonly archive_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
);
assertContains("LICENSE-MIT", "Copyright (c) 2026 ReallyMe Technologies Limited");
assertContains("LICENSE-APACHE", "Apache License");
assertContains("results/.gitignore", "/*");
assertContains("evidence/README.md", "pass both redaction and public-disclosure review");
assertContains("upstream/oidf/LICENSE.txt", "Copyright (c) 2019-2020 OpenID Foundation");
assertContains("upstream/oidf/THIRD_PARTY_NOTICES.md", "upstream conformance suite is distributed under the MIT License");
assertContains("upstream/oidf/snapshots/certification-modules.json", '"source_license": "MIT"');
assertContains("upstream/oidf/snapshots/engineering-modules.json", '"source_license": "MIT"');
assertContains("upstream/oidf/conformance-suite.lock.json", '"local_checkout": "upstream/oidf/openid-conformance-suite"');
assertContains("upstream/oidf/specifications.lock.json", '"specification_id": "openid4vc-haip-1.0-final"');
assertContains("upstream/eudi/sources.lock.json", '"source_id": "eudi-fcaf"');
assertContains("upstream/eudi/sources.lock.json", '"source_id": "eudi-age-verification-specification"');
assertContains("upstream/eudi/sources.lock.json", '"source_id": "eudi-rqes-wallet-driven-tester"');
assertContains("upstream/eudi/sources.lock.json", '"source_id": "eudi-documentation-site"');
assertContains("upstream/eudi/legal-sources.lock.json", '"source_id": "cir-2026-1731"');
assertContains("references/eudi-publications.lock.json", '"id": "iso-iec-ts-18013-6-2025"');
assertContains("references/eudi-publications.lock.json", '"id": "rfc-9901"');
assertContains("references/eudi-publications.lock.json", '"id": "etsi-ts-119-432-v1.3.1"');
assertContains("references/eudi-publications.lock.json", '"kind": "official_edition"');
assertContains("plans/oidf/certification.json", '"lock_file": "upstream/oidf/conformance-suite.lock.json"');
assertContains("plans/oidf/certification.json", '"license": "MIT OR Apache-2.0"');
assertContains("plans/oidf/engineering.json", '"certification_baseline": "plans/oidf/certification.json"');
assertContains("plans/eudi/relying-party-control-plane.json", '"certification_claim": false');
assertContains("plans/eudi/relying-party-control-plane.json", '"execution_status": "executable"');
assertContains("plans/eudi/relying-party-control-plane.json", '"transaction_content_non_retention"');
assertContains("plans/eudi/relying-party-control-plane.json", '"component_id": "eudi-relying-party-control-plane"');
assertContains("adapters/eudi-relying-party/adapter.json", '"adapter_id": "eudi_relying_party_control_plane"');
assertContains("adapters/eudi-relying-party/adapter.json", '"raw_process_output_retained": false');
assertContains(".github/workflows/eudi-relying-party-conformance.yml", "repository: ${{ github.repository }}");
assertContains(".github/workflows/eudi-relying-party-conformance.yml", "candidate_binary_path:");
assertContains(".github/workflows/eudi-relying-party-conformance.yml", "--candidate-repository");
assertContains(".github/workflows/eudi-relying-party-conformance.yml", "scripts/run_eudi_relying_party_conformance.py");
assertContains("schemas/eudi-public-evidence.schema.json", '"classification": {"const": "public"}');
assertContains("scripts/build_eudi_public_evidence.py", "private_source_attestation_sha256");
assertContains("plans/eudi/wallet.json", '"certification_claim": false');
assertContains("plans/eudi/wallet.json", '"execution_status": "executable"');
assertContains("plans/eudi/upstream-coverage.json", '"official_ui_suite_executed": false');
assertContains("plans/eudi/upstream-coverage.json", '"execution_state": "external_runner_required"');
assertContains("adapters/eudi-wallet/adapter.json", '"adapter_id": "eudi_wallet_engineering"');
assertContains("adapters/eudi-wallet/adapter.json", '"reallyme-wallet-conformance"');
assertContains("scripts/run_eudi_wallet_conformance.py", "execute_package");
assertContains(".github/workflows/eudi-wallet-conformance.yml", "repository: reallyme/wallet");
assertContains(".github/workflows/eudi-wallet-conformance.yml", "scripts/run_eudi_wallet_conformance.py");
assertContains(".github/workflows/eudi-wallet-conformance.yml", "release_artifact_path:");
assertContains("plans/zk/presentation-proofs.json", '"certification_claim": false');
assertContains("adapters/zk/adapter.json", '"adapter_id": "zk_presentation_proofs"');
assertContains("adapters/zk/adapter.json", '"reallyme-zk-conformance"');
assertContains("scripts/run_zk_conformance.py", "execute_package");
assertContains(".github/workflows/zk-conformance.yml", "repository: reallyme/zk");
assertContains(".github/workflows/zk-conformance.yml", "scripts/run_zk_conformance.py");
assertContains(".github/workflows/zk-conformance.yml", "release_artifact_path:");
assertContains("schemas/component-attestation.schema.json", '"classification": {"const": "internal"}');
assertContains("scripts/verify_component_attestation.py", "raw_process_output_retained");
assertContains("docs/OIDF_SUBMISSION_CHECKLIST.md", "Publish for certification");
assertContains("docs/OIDF_SUBMISSION_CHECKLIST.md", "legally binding attestation");
assertContains("docs/OIDF_CERTIFICATION.md", "Every module returned for a selected plan must run");
assertContains("adapters/registry.json", '"contract_path": "adapters/wallet"');
assertContains("components.lock.json", '"purpose": "oidf-cross-repository-release-bom"');
assertContains("components.lock.json", '"claim_status": "reference_candidate_not_conformance_evidence"');
assertContains("components.lock.json", '"reallyme-jose": {');
assertContains("components.lock.json", '"reallyme-crypto": {');
assertContains(
  "components.lock.json",
  '"checksum": "c6dcac5ae352e16530a1009e4e35b418e0f0a8e2c219c4c7106f475cf3136f16"',
);
assertContains(
  "components.lock.json",
  '"checksum": "d82736c2b7ad3a175ed1af1363d8407e44a9646d72eb6beab5527375586b9396"',
);
assertContains("components.lock.json", '"reallyme-openid4vci": {');
assertContains(
  "components.lock.json",
  '"checksum": "0040fbe176fe939d5c9580658649f71f84cfff216ab2a0a8c0053c44ccdfa31a"',
);
assertContains("components.lock.json", '"reallyme-openid4vp-types": {');
assertContains(
  "components.lock.json",
  '"checksum": "af1ab7b2cfb65b56a834092ea716b559721e3405a970cc02ff36fd8f4ed8cf83"',
);
assertContains("components.lock.json", '"reallyme-ssi-core": {');
assertContains(
  "components.lock.json",
  '"checksum": "9a597ff14992a5d5b6a98fdd695c88e8383118d7bd9da72139c87379cb8e10b4"',
);
assertContains(
  "components.lock.json",
  '"commit": "43dddafe1c9be46260c01334bcf3d9e34f5c066a"',
);
assertContains("scripts/strict_json.py", "json_duplicate_member");
assertContains("scripts/strict_json.py", "json_non_finite_number");
assertContains("scripts/strict_json.py", "json_depth_limit_exceeded");
assertContains("scripts/verify_component_lock.py", "strict_json.loads");
assertContains("scripts/run_oidf_openid4vci_certification.sh", "--evidence-release --verify-checkouts");
assertContains("scripts/run_oidf_openid4vp_certification.sh", "--evidence-release --verify-checkouts");
assertContains("scripts/audit_etsi_eaa_pid_trace.py", "external_evidence_still_required");
assertContains("scripts/verify_oidf_deployment_manifest.py", "strict_json.loads");
assertContains("scripts/hash_oidf_input.py", "evidence.hash_file");
assertContains("scripts/run_oidf_openid4vp_certification.sh", "changed during execution");
assertContains(
  "scripts/oidf-runner-requirements.lock",
  "httpx==0.28.1",
);
assertContains(
  openid4vciCertificationWorkflow,
  "name: OIDF OpenID4VCI Certification",
);
assertContains(openid4vciCertificationWorkflow, "workflow_call:");
assertContains(openid4vciCertificationWorkflow, '[[ "${GITHUB_REPOSITORY}" == "reallyme/identity" ]]');
assertContains(openid4vciCertificationWorkflow, "repository: reallyme/identity-conformance");
assertContains(openid4vciCertificationWorkflow, "ref: ${{ inputs.framework_commit }}");
assertContains(
  openid4vciCertificationWorkflow,
  "environment: oidf-certification",
);
assertContains(
  openid4vciCertificationWorkflow,
  "runs-on: [self-hosted, linux, x64, oidf-certification]",
);
assertContains(
  openid4vciCertificationWorkflow,
  "scripts/run_oidf_openid4vci_certification.sh",
);
assertContains(
  openid4vciCertificationWorkflow,
  "identity-conformance/scripts/oidf-runner-requirements.lock",
);
assertContains(
  openid4vciCertificationWorkflow,
  "Execute all OpenID4VCI certification profiles",
);
assertContains(
  openid4vciCertificationWorkflow,
  '[[ "${revision}" =~ ^[0-9a-f]{40}$ ]]',
);
assertContains(
  openid4vciCertificationWorkflow,
  '[[ "${release_ref}" =~ ^[A-Za-z0-9._-]+$ ]]',
);
assertContains(
  openid4vciCertificationWorkflow,
  "REALLYME_CI_TOKEN: ${{ secrets.REALLYME_CI_TOKEN }}",
);
assertContains(
  "scripts/oidf-maven.Dockerfile",
  "maven@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320",
);
assertContains(
  "scripts/oidf-maven.Dockerfile",
  "GUAVA_SHA256=97b79ec3f2c0a6313a0c2df51ce1abdf8907e6531803467b81efcaaf99b35161",
);
assertContains(
  "scripts/scan_oidf_maven_image.sh",
  'readonly trivy_version="0.76.2"',
);
assertContains(
  "scripts/scan_oidf_maven_image.sh",
  'readonly trivy_archive_sha256="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"',
);
assertContains(
  openid4vciCertificationWorkflow,
  "reallyme/oidf-maven:3.9.16-patched",
);
assertContains(
  openid4vciCertificationWorkflow,
  "scripts/scan_oidf_maven_image.sh",
);
assertContains(
  openid4vciCertificationWorkflow,
  "Validate protected runner artifact paths",
);
assertContains(
  openid4vpCertificationWorkflow,
  "name: OIDF OpenID4VP Certification",
);
assertContains(openid4vpCertificationWorkflow, "workflow_call:");
assertContains(openid4vpCertificationWorkflow, '[[ "${GITHUB_REPOSITORY}" == "reallyme/identity" ]]');
assertContains(openid4vpCertificationWorkflow, "repository: reallyme/identity-conformance");
assertContains(openid4vpCertificationWorkflow, "ref: ${{ inputs.framework_commit }}");
assertContains(openid4vpCertificationWorkflow, "runs-on: [self-hosted, linux, x64, oidf-certification]");
assertContains(
  openid4vpCertificationWorkflow,
  "environment: oidf-certification",
);
assertContains(
  openid4vpCertificationWorkflow,
  "scripts/run_oidf_openid4vp_certification.sh",
);
assertContains(
  openid4vpCertificationWorkflow,
  "identity-conformance/scripts/oidf-runner-requirements.lock",
);
assertContains(
  openid4vpCertificationWorkflow,
  "Execute all OpenID4VP certification profiles",
);
assertContains(
  openid4vpCertificationWorkflow,
  '[[ "${revision}" =~ ^[0-9a-f]{40}$ ]]',
);
assertContains(
  openid4vpCertificationWorkflow,
  '[[ "${release_ref}" =~ ^[A-Za-z0-9._-]+$ ]]',
);
assertContains(
  openid4vpCertificationWorkflow,
  "REALLYME_CI_TOKEN: ${{ secrets.REALLYME_CI_TOKEN }}",
);
assertContains(
  openid4vpCertificationWorkflow,
  "reallyme/oidf-maven:3.9.16-patched",
);
assertContains(
  openid4vpCertificationWorkflow,
  "scripts/scan_oidf_maven_image.sh",
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  '"certification_evidence":false',
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "assert_oidf_openid4vp_local_rehearsal.py",
);
assertContains(
  "scripts/assert_oidf_openid4vp_local_rehearsal.py",
  '"submission_authorized": False',
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "verify_oidf_local_endpoints.py",
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "CONFORMANCE_DEV_MODE must be unset",
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "CONFORMANCE_TOKEN must be unset",
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "local conformance API token creation failed",
);
assertContains(
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  '--ca-cert "${SSL_CERT_FILE}"',
);
assertContains(
  "scripts/verify_oidf_local_endpoints.py",
  "local_endpoint_must_use_loopback_authority",
);
assertContains(
  "scripts/create_oidf_loopback_tls.sh",
  'rm -- "${ca_key}" "${server_request}" "${certificate_extensions}"',
);
assertContains(
  "scripts/oidf-loopback-compose.yml",
  "host_ip: 127.0.0.1",
);
assertContains(
  "scripts/oidf-loopback-compose.yml",
  "--fintechlabs.base_url=https://localhost:8443",
);
assertContains(
  "scripts/oidf-loopback-compose.yml",
  "--fintechlabs.makeDummyUserAdminInDevMode=false",
);
assertContains(
  "scripts/run_oidf_openid4vp_certification.sh",
  "assert_oidf_openid4vp_pre_submission.py",
);
assertContains("scripts/assert_oidf_openid4vp_pre_submission.py", "strict_json.loads");
assertContains(
  "scripts/assert_oidf_openid4vp_pre_submission.py",
  "profile_export_inventory_invalid",
);
assertContains(
  "scripts/run_oidf_openid4vp_certification.sh",
  "assert_oidf_openid4vp_pre_submission.py",
);
assertContains("scripts/assert_oidf_openid4vp_pre_submission.py", "strict_json.loads");
assertContains(
  "scripts/assert_oidf_openid4vp_pre_submission.py",
  "profile_export_inventory_invalid",
);
assertContains("scripts/run_oidf_openid4vci_certification.sh", "changed during execution");
assertContains(
  "scripts/run_oidf_openid4vci_certification.sh",
  "assert_oidf_openid4vci_pre_submission.py",
);
assertContains("scripts/assert_oidf_openid4vci_pre_submission.py", "strict_json.loads");
assertContains(
  "scripts/assert_oidf_openid4vci_pre_submission.py",
  "suite_export_digest_mismatch",
);
assertContains("scripts/verify_oidf_manifests.py", "strict_json.loads");
assertContains("schemas/execution-result.schema.json", '"contains_sensitive_data": { "const": true }');
assertContains("schemas/certification-evidence.schema.json", '"redaction_review"');
assertContains("schemas/certification-evidence.schema.json", '"classification": { "const": "public" }');
assertContains("schemas/certification-evidence.schema.json", '"public_disclosure_review"');
assertContains(
  "schemas/ssi-conformance-bundle.schema.json",
  "reallyme.ssi.conformance.bundle.v1",
);
assertContains("schemas/oidf-deployment-manifest.schema.json", '"oidf-certification-deployment-bom"');
assertContains("schemas/oidf-deployment-manifest.schema.json", '"openid4vci_issuer"');
assertContains("schemas/oidf-deployment-manifest.schema.json", '"openid4vp_wallet"');
assertContains("references/normative-sources.lock.json", '"reference_only_copyrighted_source"');
assertContains("references/normative-sources.lock.json", '"83285a1069e369d225cf16a0051a46b1f9d8961b6ad5d66bb7650351309a5196"');
assertContains("references/normative-sources.lock.json", '"etsi-ts-119-472-1-v1.2.1"');
assertContains("references/normative-sources.lock.json", '"etsi-ts-119-472-2-v1.3.1"');
assertContains("references/normative-sources.lock.json", '"etsi-ts-119-472-3-v1.1.1"');
assertContains("references/etsi-ts-119-612-v2.4.1.md", "ETSI TS 119 612 V2.4.1");
assertContains("references/etsi-ts-119-472-series.md", "all 740 unique identifiers");
assertContains("references/eu-pid-2026-alignment.md", "11 August 2026");
assertContains(workflow, `release-readiness#${sharedRevision}`);
assertContains(workflow, "Resolve pinned trace source revisions");
assertContains(
  workflow,
  ".repositories[] | select(.component_id == $component)",
);
assertContains(workflow, "Checkout pinned OpenID4VCI trace sources");
assertContains(workflow, "repository: reallyme/openid4vci");
assertContains(
  workflow,
  'ref: ${{ steps.component-revisions.outputs.openid4vci }}',
);
assertContains(workflow, "path: openid4vci");
assertContains(workflow, "Checkout pinned OpenID4VP trace sources");
assertContains(workflow, "repository: reallyme/openid4vp");
assertContains(
  workflow,
  'ref: ${{ steps.component-revisions.outputs.openid4vp }}',
);
assertContains(workflow, "path: openid4vp");
assertContains(workflow, "Checkout pinned SSI trace inputs");
assertContains(workflow, "repository: reallyme/ssi");
assertContains(workflow, 'ref: ${{ steps.component-revisions.outputs.ssi }}');
assertContains(workflow, "path: ssi");
for (const candidateNeedle of [
  "Resolve pinned trace source revisions",
  "Checkout pinned OpenID4VCI trace sources",
  "repository: reallyme/openid4vci",
  'ref: ${{ steps.component-revisions.outputs.openid4vci }}',
  "path: openid4vci",
  "Checkout pinned OpenID4VP trace sources",
  "repository: reallyme/openid4vp",
  'ref: ${{ steps.component-revisions.outputs.openid4vp }}',
  "path: openid4vp",
  "Checkout pinned SSI trace inputs",
  "repository: reallyme/ssi",
  'ref: ${{ steps.component-revisions.outputs.ssi }}',
  "path: ssi",
  "RELEASE_VERSION: ${{ inputs.version }}",
  'REPOSITORY_COMMIT: ${{ github.sha }}',
  '--version "${RELEASE_VERSION}"',
  '--repository-commit "${REPOSITORY_COMMIT}"',
]) {
  assertContains(releaseCandidateWorkflow, candidateNeedle);
}
assertContains(
  workflow,
  "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
);
assertContains(workflow, 'python-version: "3.15.2"');
assertContains(workflow, 'python-version: "3.12.16"');
assertContains(workflow, "Run repository tests on latest Python");
assertContains(workflow, "Run repository tests on Python 3.12");
for (const pythonWorkflow of pythonWorkflows) {
  assertContains(
    pythonWorkflow,
    "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
  );
  assertContains(pythonWorkflow, 'python-version: "3.15.2"');
}
assertContains("references/pin-policy.json", '"id": "actions-setup-python"');
assertContains("references/pin-policy.json", '"id": "python-latest"');
assertContains("references/pin-policy.json", '"version": "3.15.2"');
assertContains("references/pin-policy.json", '"id": "python-compatibility"');
assertContains("references/pin-policy.json", '"version": "3.12.16"');
assertContains(secretScanWorkflow, `GITLEAKS_VERSION: ${gitleaksVersion}`);
assertContains(secretScanWorkflow, `GITLEAKS_ARCHIVE_SHA256: ${gitleaksArchiveSha256}`);
assertWorkflowRunStep(
  workflow,
  "Run shared release readiness",
  `npm exec --yes --allow-remote=root --package=github:reallyme/release-readiness#${sharedRevision} -- reallyme-release-readiness`,
);

run("python3", ["scripts/verify_oidf_manifests.py"]);
run("python3", ["scripts/verify_component_lock.py"]);
run("python3", ["scripts/verify_normative_sources.py"]);
run("python3", ["scripts/verify_eudi_publications.py"]);
run("python3", ["scripts/audit_etsi_eaa_pid_trace.py", "--check"]);
run("python3", ["scripts/verify_eudi_relying_party_plan.py"]);
run("python3", ["scripts/verify_eudi_legal_sources.py"]);
run("python3", ["scripts/verify_eudi_upstream_coverage.py"]);
run("python3", ["scripts/verify_eudi_adapter.py"]);
run("python3", ["scripts/verify_eudi_wallet_adapter.py"]);
run("python3", ["scripts/verify_zk_adapter.py"]);
run("python3", ["-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]);
run("bash", [
  "-n",
  "scripts/export_oidf_certification_modules.sh",
  "scripts/check_publication_readiness.sh",
  "scripts/fetch_oidf_conformance_suite.sh",
  "scripts/run_oidf_final_matrix.sh",
  "scripts/run_oidf_openid4vci_certification.sh",
  "scripts/run_oidf_openid4vp_certification.sh",
  "scripts/run_oidf_openid4vp_local_rehearsal.sh",
  "scripts/create_oidf_loopback_tls.sh",
  "scripts/scan_oidf_maven_image.sh",
]);
