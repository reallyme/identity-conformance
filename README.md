<div align="center">

# ReallyMe Identity Conformance

**Conformance testing for identity protocols and digital wallets**

<!-- BEGIN GENERATED CONFORMANCE BADGES -->
[![Release readiness](https://github.com/reallyme/identity-conformance/actions/workflows/release-readiness.yml/badge.svg)](https://github.com/reallyme/identity-conformance/actions/workflows/release-readiness.yml)
[![Secret scan](https://github.com/reallyme/identity-conformance/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/reallyme/identity-conformance/actions/workflows/secret-scan.yml)
[![Upstream monitoring](https://github.com/reallyme/identity-conformance/actions/workflows/pin-freshness.yml/badge.svg)](https://github.com/reallyme/identity-conformance/actions/workflows/pin-freshness.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[![Framework](https://img.shields.io/static/v1?label=Framework&message=v0.3.3&color=475569)](https://github.com/reallyme/identity-conformance/releases/tag/v0.3.3)
[![EU ARF](https://img.shields.io/static/v1?label=EU%20ARF&message=v3.0.0%20included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md)
[![EU technical specifications](https://img.shields.io/static/v1?label=EU%20technical%20specifications&message=included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/cfc383e44294d65cfa6cccbbff6c927f0df91f9a/docs/technical-specifications/ts3-wallet-unit-attestation.md)
[![EU FCAF](https://img.shields.io/static/v1?label=EU%20FCAF&message=v0.0.10%20included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/blob/944b8f89cc17873c47026a05dfa9d212e89b0ee3/docs/fcaf/suts/wallet_solution/index.md)
[![OIDF suite](https://img.shields.io/static/v1?label=OIDF%20suite&message=release-v5.3.4%20included&color=1d4ed8)](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638)
<!-- END GENERATED CONFORMANCE BADGES -->

</div>

## Overview

The ReallyMe conformance framework validates identity protocols, Wallet
requirements, and interoperability across ReallyMe components.

It pins upstream specifications and test suites, executes versioned checks, and
records evidence against specific source commits and deployments.

## Conformance coverage

The framework covers OpenID certification profiles, EU Wallet requirements,
upstream test assets, and ReallyMe component integrations.

| Area | Validation |
| --- | --- |
| OpenID4VCI / OpenID4VP | Runs the pinned OIDF suite against a supplied deployment. The Wallet subset contains 10 configurations and 278 module executions. |
| EU ARF / technical specifications | Validates Wallet configuration boundaries against reviewed EU requirements. |
| EU FCAF | Verifies the assessment structure and requirement ledger. |
| EU test assets | Checks pinned Wallet UI, ITB, Age Verification, and RQES test inventories. |
| Identity SDK | Audits 969 EU and ETSI requirement rows and runs the eight EUDI operations through Rust and every supported SDK. |
| Wallet / relying party | Executes Wallet code, framework-owned probes, deployment checks, and supported EU requirements. |
| Zero-knowledge proofs | Validates the public proof adapter and supplied component attestation. |

Wallet has two separate results. The Wallet repository runs the EU core
engineering plan. The composed Identity deployment runs the official OIDF
Wallet profiles. Neither result can stand in for the other. See
[Wallet assurance](docs/WALLET_ASSURANCE.md) for the evidence required for each
claim and the tests that remain outside the core-library scope.

## Results and certification

Passing framework checks does not establish product conformance.

EU ledger checks verify that reviewed requirements still match pinned upstream
sources. FCAF checks validate the published assessment structure; FCAF v0.0.10
contains no executable Wallet test cases.

Product repositories run the applicable workflows against caller-selected
commits, deployments, and attestations. A pass applies to that target, the
selected conformance profile, and one published Identity Conformance release.

The caller selects a named profile, not individual checks. Each profile is a
fixed test set in the selected framework release. A narrow profile earns only
its own badge. A combined badge requires every profile named by the combined
plan to pass against the same target and evidence set.

A product badge should name the target, profile, and framework, for example
`Wallet vX.Y.Z · EU Wallet Engineering · Identity Conformance v0.3.3 ·
passing`. It should link to a reviewed product conformance statement, not to
this repository's CI badge.
The statement records the product release and commit, framework release and
commit, profile, standards baseline digest, workflow revision, and result digest.

OIDF certification requires evidence from the approved hosted suite, an
identified deployment and framework revision, and completion of the required
evidence review. EU and ZK checks currently produce engineering evidence, not
external certification.

See [the conformance model](docs/CONFORMANCE_MODEL.md) for evidence requirements
and result handling.

## Validation model

EU requirements are maintained as reviewed, machine-readable ledgers. Each
rule identifies its upstream requirement, source statement, operator, and
expected value.

CI verifies these mappings against pinned source commits. Product runners
evaluate the corresponding implementation values.

Upstream test assets are tracked separately. An asset is considered executed
only when a runner and result validator exist and the test has completed.

Source validation establishes traceability. Product execution establishes test
results. The two are not interchangeable.

## Using the framework

Callers select a named profile. The table distinguishes executable pass-badge
profiles from engineering lanes that still depend on broad attestations.

<!-- BEGIN GENERATED PROFILE CATALOG -->
| Profile | Applies to | Normative trace | Assertion evidence | Status | Pass badge |
| --- | --- | --- | --- | --- | --- |
| [EU Wallet Engineering](.github/workflows/eudi-wallet-conformance.yml) | `wallet` | partial exact clause trace | mixed exact and candidate test inventory | Engineering run; badge unavailable | None |
| [OIDF OpenID4VCI Self-Assessment](.github/workflows/oidf-openid4vci-certification.yml) | `identity` | suite inventory trace | external suite observation | Executable | OIDF Full Self-Assessment |
| [OIDF OpenID4VP Self-Assessment](.github/workflows/oidf-openid4vp-certification.yml) | `identity` | suite inventory trace | external suite observation | Executable | OIDF Full Self-Assessment |
| [OIDF Full Self-Assessment](.github/workflows/identity-product-conformance.yml) | `identity` | suite inventory trace | external suite observation | Executable | OIDF Full Self-Assessment |
| OIDF Wallet Role Self-Assessment | `wallet` | suite inventory trace | caller runner required | Caller-owned runner required | None |
| [EU Identity SDK Engineering](.github/workflows/eudi-identity-sdk-conformance.yml) | `identity` | exact requirement registry trace | framework executed component and sdk tests | Executable | EU Identity SDK Engineering |
| [EU Relying-Party Engineering](.github/workflows/eudi-relying-party-conformance.yml) | `eudi-relying-party` | partial exact clause trace | source bound test candidates and attestation | Engineering run; badge unavailable | None |
| [ZK Presentation Proofs](.github/workflows/zk-conformance.yml) | `identity`, `zk` | framework assertion contract | candidate test inventory or linked observation | Engineering run; badge unavailable | None |
| Identity Expanded Conformity | `identity` | mixed | mixed with known gaps | Incomplete | None |
<!-- END GENERATED PROFILE CATALOG -->

SSI, OpenID4VCI, and OpenID4VP releases are inputs to the composed Identity
run; they do not need separate framework workflows.

Product repositories call their reusable workflow at an exact framework commit.
The commit must be the tag target of a published Identity Conformance release,
and the workflow reference and `framework_commit` input must match. The caller
also supplies the target commit, selected profile, deployment manifest, package
evidence, component revisions, and attestations required by the plan.

See [Running conformance](docs/RUNNING_CONFORMANCE.md) for the short caller
workflows and required inputs.

For example, a Wallet workflow invokes the shared Wallet plan with a same-run
candidate artifact:

```yaml
jobs:
  eudi-wallet-conformance:
    uses: reallyme/identity-conformance/.github/workflows/eudi-wallet-conformance.yml@FRAMEWORK_COMMIT
    with:
      framework_commit: FRAMEWORK_COMMIT
      conformance_profile: eudi-wallet-engineering-v1
      target_mode: candidate
      target_commit: ${{ github.sha }}
      target_version: ${{ needs.prepare-conformance-candidate.outputs.version }}
      preflight_run_id: ${{ needs.prepare-conformance-candidate.outputs.preflight_run_id }}
      candidate_artifact_name: eudi-wallet-candidate-${{ github.sha }}
```

The same-run artifact contains `deployment.json`, `wallet-release`, and
`wallet-attestation.json`. The filename `wallet-release` is retained for caller
compatibility; its contents are mode-neutral package evidence. See the
[adapter contracts](adapters/README.md) for the inputs required by each workflow.

<!-- BEGIN GENERATED CONFORMANCE SUMMARY -->
## Standards baseline

Framework version: **v0.3.3**

| Source | Pinned version | Coverage |
| --- | --- | --- |
| [EU Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md) | `v3.0.0` | Wallet requirements |
| [EU technical specifications](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/cfc383e44294d65cfa6cccbbff6c927f0df91f9a/docs/technical-specifications/ts3-wallet-unit-attestation.md) | `main @ cfc383e4` | Wallet Unit Attestation |
| [EU Functional Conformance Assessment Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/blob/944b8f89cc17873c47026a05dfa9d212e89b0ee3/docs/fcaf/suts/wallet_solution/index.md) | `v0.0.10` | Assessment methodology |
| [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638) | `release-v5.3.4` | OpenID4VCI / OpenID4VP |
| [EUDI Wallet testing application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application/tree/62c4ba73007ea25440e6ba24a651937bc692629b/src/test/resources/features) | `2026.Q1` | `126` feature files and `798` scenarios |
| [EUDI Interoperability Test Bed](https://github.com/eu-digital-identity-wallet/eudi-itb/tree/b0e222435401242e2a2a62181500bc2403e6e0dd/tests) | `main @ b0e22243` | `5` suites and `39` test cases |

See [Standards baseline](docs/STANDARDS_BASELINE.md) for exact source
revisions, requirement mappings, content digests, and validation status.

<!-- END GENERATED CONFORMANCE SUMMARY -->

## EU sources and test coverage

EU conformance spans multiple specifications, assessment frameworks, test
applications, and interoperability services.

The framework tracks these sources through
[`upstream/eudi/sources.lock.json`](upstream/eudi/sources.lock.json). Each source
is pinned to a reviewed revision.

| Source type | Included material | Current status |
| --- | --- | --- |
| Normative and assessment sources | [ARF](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework), [FCAF](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment), [technical specifications](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications), [attestation rulebooks](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog), and the [Age Verification specification](https://github.com/eu-digital-identity-wallet/av-doc-technical-specification) | ARF and Technical Specification 3 ledgers run in CI. FCAF structure and the Age Verification profile/ZKP inventory are verified. Age Verification and rulebook boundary tests still require dedicated runners. |
| Executable test assets | [Wallet testing application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application), [ITB](https://github.com/eu-digital-identity-wallet/eudi-itb), [issuer Wallet tester](https://github.com/eu-digital-identity-wallet/eudi-app-web-wallet-tester-py), and [RQES Wallet-driven tester](https://github.com/eu-digital-identity-wallet/eudi-app-web-walletdriven-tester-py) | CI verifies 126 Wallet UI feature files, 798 scenarios, five ITB suites, 39 ITB test cases, and the RQES service inventory. Product execution requires deployed services and device infrastructure. |
| Reference wallets | [Android Wallet UI](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui), [Android Wallet core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core), [iOS Wallet UI](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui), and [iOS Wallet Kit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit) | Pinned interoperability peers. No runner executes them yet. They do not define normative requirements. |
| Reference services | PID issuer, verifier, Wallet provider, relying-party registration, trust, status, trusted-list, and RQES services | Pinned interoperability peers. Deployed-service runners are still required. |

### Upstream test assets

The `EU conformance - upstream test assets` workflow validates pinned commits,
required files, test definitions, suite references, and service structure.

Product execution requires deployed services, credentials, and mobile devices
where applicable. RQES upstream Python dependencies are excluded from CI
pending a separate security review.

The source lock also covers mobile reference wallets, trust and status
components, the RQES reference stack, selected issuance and presentation
targets, and the official documentation portal. The portal is monitored but
does not govern results.

## OpenID Foundation

The framework pins the OpenID Conformance Suite release in
[`conformance-suite.lock.json`](upstream/oidf/conformance-suite.lock.json).

[`plans/oidf/wallet.json`](plans/oidf/wallet.json) fixes the Wallet scope at 10
configurations and 278 module executions: six OpenID4VCI Wallet configurations
and four OpenID4VP Wallet configurations. The verifier compares that contract
with the complete certification plan and generated module snapshot. Missing
profiles, changed module counts, partial runs, skips, expected failures, and
suite-pin mismatches fail validation.

Final OpenID4VCI, OpenID4VP, and HAIP specifications are pinned by URL, content
length, and SHA-256 in
[`specifications.lock.json`](upstream/oidf/specifications.lock.json).

Reusable workflows execute the profiles selected by each product's bill of
materials (BOM). Component revisions and deployment targets must be supplied
explicitly.

See [OIDF certification](docs/OIDF_CERTIFICATION.md) and the
[submission checklist](docs/OIDF_SUBMISSION_CHECKLIST.md).

## Standards that are not stored here

Certain ISO/IEC standards cannot be redistributed in this public repository.
Licensed copies used for review are kept outside the repository. The framework
records the exact edition and official ISO catalog URL:

- [ISO/IEC 18013-5:2021 — Mobile driving licence application](https://www.iso.org/standard/69084.html)
- [ISO/IEC TS 18013-6:2025 — mDL test methods](https://www.iso.org/standard/91153.html)
- [ISO/IEC TS 18013-7:2025 — mDL add-on functions](https://www.iso.org/standard/91154.html)
- [ISO/IEC TS 23220-2:2026 — Data objects and encoding rules for generic eID systems](https://www.iso.org/standard/91155.html)

Publicly downloadable IETF, W3C, ETSI, and OpenID publications are pinned by
URL and content digest. The governing eIDAS legislation is identified by its
official ELI and CELEX references.

## Releases

Upstream specifications and test suites are checked weekly. Changes are
reported for review; active pins are never updated automatically.

Baseline changes require a pull request updating `VERSION` and all affected
locks, ledgers, runners, and generated files. Relevant conformance and release
checks must pass before merge.

Release candidates are built from an exact `main` commit with a deterministic
manifest. Promotion verifies the candidate commit and manifest, then publishes
`v<VERSION>` through the protected `framework-release` environment.

Promotion refuses an existing tag or release. Product repositories upgrade
framework versions explicitly.

An Identity Conformance release is a complete conformance baseline. It versions
the runners and schemas together with the exact specifications, requirement
ledgers, reference inputs, and external test-suite revisions they enforce. A
runner change can require a new framework release even when the upstream
specifications do not change. An upstream change is proposed for review and
does not become part of the baseline until a new framework release is
published.

Two versions can therefore move independently. The framework may be reviewing
a newer upstream publication, and a product may still be tested against an
older framework release. The weekly upstream-monitoring workflow exposes the
first condition. Product badges and conformance statements expose the second by
naming the framework release used for each pass.

Release builds use pinned sources and do not depend on upstream availability.
Freshness checks run separately.

## Validation

### Tests and workflow lint

Run the repository tests and validate GitHub Actions workflows:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
scripts/run_actionlint.sh
```

### Release readiness

Run the shared readiness checks used by CI:

```sh
npm exec --yes --allow-remote=root \
  --package=github:reallyme/release-readiness#18a6d91d99837e80f92e41fe04effb0b043d754e \
  -- reallyme-release-readiness
```

### Upstream freshness

Check whether pinned upstream sources have changed:

```sh
python3 scripts/check_pin_freshness.py
```

### Publication readiness

Run the publication checks with the pinned Gitleaks 8.30.1 binary:

```sh
GITLEAKS_BIN=/trusted/path/to/gitleaks \
  scripts/check_publication_readiness.sh
```

## Security

Conformance results may contain sensitive operational data.

Store raw results in the ignored `results/` directory or protected private
storage. Never include credentials, private keys, transaction data,
presentation payloads, or customer identifiers in results or public evidence.

Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## License

Except where a third-party notice states otherwise, this repository is
available under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party material retains its original license. OIDF-derived snapshots are
covered by the upstream MIT terms recorded in `upstream/oidf/`.
