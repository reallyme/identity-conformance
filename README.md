# ReallyMe identity conformance

<!-- BEGIN GENERATED CONFORMANCE CATALOG -->
Current framework baseline: **v0.2.0**

[![EU ARF v0.2.0](https://img.shields.io/github/actions/workflow/status/reallyme/identity-conformance/eu-arf-normative.yml?branch=main&label=EU%20ARF%20v0%2E2%2E0)](https://github.com/reallyme/identity-conformance/actions/workflows/eu-arf-normative.yml)
[![EU technical specifications v0.2.0](https://img.shields.io/github/actions/workflow/status/reallyme/identity-conformance/eu-technical-specifications-normative.yml?branch=main&label=EU%20technical%20specifications%20v0%2E2%2E0)](https://github.com/reallyme/identity-conformance/actions/workflows/eu-technical-specifications-normative.yml)
[![EU FCAF v0.2.0](https://img.shields.io/github/actions/workflow/status/reallyme/identity-conformance/eu-fcaf-normative.yml?branch=main&label=EU%20FCAF%20v0%2E2%2E0)](https://github.com/reallyme/identity-conformance/actions/workflows/eu-fcaf-normative.yml)
[![OIDF v0.2.0](https://img.shields.io/github/actions/workflow/status/reallyme/identity-conformance/oidf-normative-ledger.yml?branch=main&label=OIDF%20v0%2E2%2E0)](https://github.com/reallyme/identity-conformance/actions/workflows/oidf-normative-ledger.yml)

## Conformance enforced by this release

This catalog is generated from the same immutable locks and normative ledgers
that are digest-bound into framework release manifests. “Baseline updated” is
the date this repository adopted or verified the pin, not an inferred publication date.

### European Union

| Source | Description | Current enforced value | Version | Baseline updated |
| --- | --- | --- | --- | --- |
| [Architecture and Reference Framework — WUA_33](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md) | Wallet requirements and normative implementation boundaries. | `wallet.wia.technical_validity_seconds < 86,400` | `v3.0.0` | 2026-11-11 |
| [Architecture and Reference Framework — EW-DM-44-027](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.03-high-level-requirements-by-category.md) | Wallet requirements and normative implementation boundaries. | `wallet.presentation.unregistered_attribute_policy` = `warn_and_allow_all`, `registered_only`, `reject_request` | `v3.0.0` | 2026-11-11 |
| [Technical Specification 3 — Wallet Unit Attestation — 2.2.1.1](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/cfc383e44294d65cfa6cccbbff6c927f0df91f9a/docs/technical-specifications/ts3-wallet-unit-attestation.md) | Wallet Unit Attestation lifetime boundary. | `wallet.wia.technical_validity_seconds < 86,400` | `main` | 2026-11-11 |
| [Functional Conformance Assessment Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/blob/944b8f89cc17873c47026a05dfa9d212e89b0ee3/docs/fcaf/suts/wallet_solution/index.md) | Wallet Solution assessment methodology; not an executable certification suite. | `methodology_only`; `0` executable Wallet cases | `v0.0.10` | 2026-11-11 |

### OpenID Foundation

| Source | Description | Current enforced value | Version | Baseline updated |
| --- | --- | --- | --- | --- |
| [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | Issuer and Wallet HAIP certification-plan variants. | SHA-256 `f123c3178cacd27688b15b762098a045e9eb35eccfe2f5f18a357c3815e06ba7` | `1.0 Final` | 2026-11-11 |
| [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | Verifier and Wallet HAIP certification-plan variants. | SHA-256 `e4f0abc689afd0a4f6c41b83954d7f970c5263a26143ad861216aea9918993bb` | `1.0 Final` | 2026-11-11 |
| [OpenID4VC High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) | High-assurance profile applied to OID4VCI and OID4VP plans. | SHA-256 `3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb` | `1.0 Final` | 2026-11-11 |
| [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638) | Executable certification-suite source used to derive and validate plan values. | Commit `23353b36957d6466010de767c812d2c91ed37638` | `release-v5.3.4` | 2026-10-26 |

<!-- END GENERATED CONFORMANCE CATALOG -->

This repository versions and executes ReallyMe's cross-repository identity
conformance framework. It owns the test plans, adapter contracts, runners,
result schemas, and disclosure-safe evidence formats. It does not own the
protocol implementations and it does not treat a component's self-reported
test result as proof that the assembled product conforms.

The current lanes are:

- OpenID Foundation OpenID4VCI and OpenID4VP certification profiles;
- EUDI Wallet engineering conformance;
- EUDI relying-party control-plane engineering conformance; and
- zero-knowledge presentation-proof conformance.

EU and OIDF use separate normative ledgers, source validators, workflows, and
status badges. EU conformance is an umbrella with independently reported
sub-lanes:

- ARF requirement identifiers and boundary values;
- technical-specification boundary values;
- FCAF assessment classes and, when published, executable cases; and
- official executable test assets, each with its own result contract.

A green ledger workflow means that the reviewed rules still match the exact
pinned source. It does not mean that an external certification suite ran. The
FCAF badge currently validates the published Wallet Solution assessment
methodology only because FCAF v0.0.10 contains no executable Wallet test cases.

Passing an engineering lane is not an external certification. OIDF
certification evidence is authoritative only when it comes from the approved
hosted suite, is bound to the exact deployment and framework revisions, and
passes the evidence review described in `evidence/`.

## Ownership model

Product repositories build production artifacts and issue component
attestations. An attestation identifies the source commit, dependency lock,
toolchain, artifact digests, and passed component checks. This repository then
verifies those inputs and evaluates the composed plan.

Continuous latest-release runs use the closed repository inventory in
`references/reallyme/release-sources.json`: `ssi`, `identity`, `zk`, `wallet`,
`openid4vci`, and `openid4vp`. A latest-release run resolves the current GitHub
release tag and its exact commit; it never substitutes a default branch. A
caller may still select an older release for historical or release-candidate
verification, but that is an explicit exact-BOM run and is labelled separately.

The component relationships are summarized below.

| Repository | Conformance responsibility |
| --- | --- |
| `openid4vci` | Issuer and wallet-side issuance protocol behavior |
| `openid4vp` | Verifier and wallet-side presentation protocol behavior |
| `wallet` | Wallet state, consent, storage, and EUDI Wallet component tests |
| `ssi` | Credential formats, trust, status, and revocation |
| `zk` | Proof APIs, provider artifacts, vectors, and rejection tests |
| `platform` | Deployment composition and service lifecycle |
| `identity` | Deployable composed VCI and VP drivers |
| `identity-taxonomy` | Optional coverage metadata; not yet a release prerequisite |

Private implementations use the same public adapter and evidence contracts.
Their source layout, package names, detailed test inventory, secrets, raw
results, and logs remain in the caller repository. The public framework accepts
only opaque assertion identifiers, immutable digests, and reviewed attestations.

See [`docs/CONFORMANCE_MODEL.md`](docs/CONFORMANCE_MODEL.md) for the governing
rules.

## Repository layout

- `upstream/oidf/` — OIDF suite and specification locks, notices, and generated
  source snapshots. The suite checkout is ignored.
- `upstream/eudi/` — EU architecture, assessment, technical, test, reference,
  and legal-source locks. Local checkouts are ignored.
- `plans/` — ReallyMe-owned certification and engineering matrices.
- `adapters/` — public contracts between the framework and product components.
- `results/` — raw local output; ignored by default.
- `evidence/` — redacted, reviewed evidence and submission controls.
- `schemas/` — closed validation contracts for manifests, results, and evidence.
- `references/` — pinned normative-source metadata and reviewed mappings.
- `scripts/` — runners, validators, release tooling, and readiness checks.

Third-party source remains separate from ReallyMe-owned plans and adapters.
Copyrighted standards documents and raw certification output must not be added
to the repository.

## Upstream pins

OIDF certification uses the exact suite release in
`upstream/oidf/conformance-suite.lock.json`. Engineering comparison uses the
separate master lock. `specifications.lock.json` binds the published OpenID4VCI,
OpenID4VP, and HAIP final documents by canonical URL, byte length, SHA-256, and
source tag where one exists.

The EU source lock covers the released ARF and FCAF, the technical-specification
and rulebook catalogs, Age Verification and ZKP material, official test assets,
mobile reference wallets, trust and status components, the RQES reference
stack, and selected issuance and presentation targets. The official
documentation portal is monitored as a non-governing source. This is a curated
wallet/eIDAS inventory, not a mirror of the entire EU organization.

`references/eudi-publications.lock.json` byte-pins selected public RFC, W3C, and
ETSI publications and records exact editions for copyright-restricted ISO
standards. Existing OIDF Final and ETSI 119472/119612 content bindings are
referenced from their authoritative locks. `legal-sources.lock.json` separately
records the governing eIDAS acts and amendments by CELEX and ELI, including the
current consolidated editions. Copyrighted standards and legal text are not
vendored.

Two weekly workflows support maintenance:

- `pin-freshness.yml` compares every machine-checkable pin with authoritative
  upstream metadata and fails when a reviewed baseline is stale. Temporary
  publisher unavailability produces a warning and a retained unavailable
  report rather than misreporting the baseline as stale.
- `upstream-update-proposal.yml` produces a versioned, review-only proposal that
  groups tagged releases, untagged branch snapshots, publication-integrity
  changes, maintenance updates, and monitor-only changes. Tagged releases may
  seed the next patch candidate. Default-branch movement never does so without
  an explicit snapshot review.

The scheduled workflows do not change the active baseline. An accepted proposal
is applied as a complete candidate change: update `VERSION`, locks, affected
normative ledgers and runners, generated catalog, and source snapshots. The
candidate must pass every affected EU and OIDF lane plus release readiness.
Mechanical candidate preparation may be automated; interpreting a changed
normative requirement remains a required review step.

`release-candidate.yml` accepts no caller-selected version. It reads `VERSION`,
executes the release gates, and emits a deterministic manifest for that exact
commit. `release-promotion.yml` then requires the successful candidate run, the
reviewed main commit, and approval through the protected `framework-release`
environment before it can create `v<VERSION>` and publish the manifest. Existing
framework releases are never changed, and downstream repositories remain on
their pinned framework release until they deliberately upgrade.

Framework release construction does not contact external standards publishers.
It validates and digest-binds the reviewed locks so a release is reproducible
and cannot fail solely because an ISO, ETSI, IETF, W3C, or OpenID endpoint is
temporarily unavailable. Pin freshness remains a separate maintenance gate and
must be reviewed before a baseline is promoted.

```sh
python3 scripts/check_pin_freshness.py
scripts/fetch_oidf_conformance_suite.sh
scripts/export_oidf_certification_modules.sh
scripts/export_oidf_certification_modules.sh \
  upstream/oidf/openid-conformance-suite \
  plans/oidf/engineering.json \
  upstream/oidf/snapshots/engineering-modules.json
```

## Public and private execution

Reusable workflows run in the caller repository's context. The caller pins an
exact framework commit and supplies an immutable deployment manifest,
production artifacts, and component attestations. Private callers retain their
checkout credentials, source, logs, and raw results under their own access
controls.

Public evidence is a separate artifact. It may cross into this repository only
after both redaction and public-disclosure review. A digest commitment alone
does not prove that the underlying run passed; it proves which reviewed private
result the public record refers to.

The EUDI lanes bind both `sources.lock.json` and `legal-sources.lock.json` into
their deployment manifests and results. The relying-party lane additionally
checks the selected ARF, FCAF, technical-specification, and official reference
service revisions and verifies the candidate's assertion-level attestation.
The Wallet lane verifies its component attestation and then independently
evaluates claimed implementation boundaries against the framework-owned ARF
and technical-specification ledgers. Candidate-authored tests and manifests do
not define the expected normative value. Its current machine-observable
boundary inventory covers the WIA technical-validity limit and the
unregistered-attribute policy outcomes; ReallyMe-only resource and freshness
limits are explicitly classified as product policy. Adding an implemented EU
numeric or enumerated boundary requires adding a pinned-source ledger rule and
an independent source observation before the adapter can pass. FCAF remains a
separate assessment ledger because the pinned v0.0.10 Wallet Solution material
defines test classes but does not yet publish executable Wallet test cases.
These lanes create internal engineering evidence only.

Pinning an official test asset is not a claim that it ran. The validated
`plans/eudi/upstream-coverage.json` inventory states which sources are execution
inputs, attestation-bound references, interoperability targets, legacy material,
or monitor-only material. It also records the device-farm and deployed-service
prerequisites for the official UI, ITB, Age Verification, and RQES suites. The
current claims remain false until dedicated runners execute those suites and
their result validators accept complete outputs.

The ZK lane follows the same component-attestation pattern. Updating this
framework does not require writing into the ZK repository.

## Validation

Run the local, network-independent checks from the repository root:

```sh
python3 scripts/verify_oidf_manifests.py
python3 scripts/verify_normative_sources.py
python3 scripts/verify_eudi_publications.py
python3 scripts/verify_eudi_legal_sources.py
python3 scripts/verify_eudi_upstream_coverage.py
python3 scripts/verify_eu_normative_ledgers.py
python3 scripts/verify_oidf_normative_ledger.py
python3 scripts/verify_eudi_relying_party_plan.py
python3 scripts/verify_eudi_adapter.py
python3 scripts/verify_eudi_wallet_adapter.py
python3 scripts/verify_zk_adapter.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

Caller-owned OIDF product BOMs are validated separately because the framework
does not contain a default product candidate:

```sh
python3 scripts/verify_product_component_bom.py \
  --bom /protected-inputs/product-component-bom.json \
  --require-release-refs
```

The CI release gate uses Node.js 26 and
[`reallyme/release-readiness`](https://github.com/reallyme/release-readiness)
v0.7.0 at its reviewed immutable commit:

```sh
npm exec --yes --allow-remote=root \
  --package=github:reallyme/release-readiness#18a6d91d99837e80f92e41fe04effb0b043d754e \
  -- reallyme-release-readiness
```

Before a public release, run the publication gate with the pinned Gitleaks
8.30.1 binary:

```sh
GITLEAKS_BIN=/trusted/path/to/gitleaks \
  scripts/check_publication_readiness.sh
```

The release workflow emits a deterministic framework manifest containing the
framework version, repository commit, and SHA-256 of every plan, schema, lock,
adapter, workflow, snapshot, and runner input. Candidate construction has
read-only repository permissions. Promotion is a separate, protected operation;
it rebuilds the manifest, compares it byte-for-byte with the reviewed candidate,
creates a draft first, and publishes only after the manifest is uploaded.

OIDF execution details and the complete profile matrix are in
[`docs/OIDF_CERTIFICATION.md`](docs/OIDF_CERTIFICATION.md). Complete
[`docs/OIDF_SUBMISSION_CHECKLIST.md`](docs/OIDF_SUBMISSION_CHECKLIST.md) before
any certification submission.

## Security

Raw results can contain sensitive operational data. Keep them in the ignored
`results/` tree or protected private storage. Do not retain credentials,
private-key material, transaction content, presentation payloads, or customer
identifiers in results or public evidence. Report vulnerabilities through the
private process in [`SECURITY.md`](SECURITY.md).

## License

Except where a third-party notice states otherwise, this repository is
available under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party material retains its original license. OIDF-derived snapshots are
covered by the upstream MIT terms recorded in `upstream/oidf/`.
