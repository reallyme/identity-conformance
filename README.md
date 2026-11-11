# ReallyMe identity conformance

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

Passing an engineering lane is not an external certification. OIDF
certification evidence is authoritative only when it comes from the approved
hosted suite, is bound to the exact deployment and framework revisions, and
passes the evidence review described in `evidence/`.

## Ownership model

Product repositories build production artifacts and issue component
attestations. An attestation identifies the source commit, dependency lock,
toolchain, artifact digests, and passed component checks. This repository then
verifies those inputs and evaluates the composed plan.

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

Two scheduled workflows support maintenance:

- `pin-freshness.yml` compares every machine-checkable pin with authoritative
  upstream metadata and fails when a reviewed baseline is stale. Temporary
  publisher unavailability produces a warning and a retained unavailable
  report rather than misreporting the baseline as stale.
- `upstream-update-proposal.yml` produces a review-only OIDF proposal containing
  the current suite release, master commit, publication digests, and source-tag
  commits.

Neither workflow changes repository files, opens a pull request, publishes a
release, or promotes a new baseline. A maintainer reviews a proposal, updates
the locks, fetches the exact suite revision, regenerates the OIDF snapshots,
and runs the complete release gate.

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
The Wallet lane verifies its component attestation and repository-owned source
ledgers. Both lanes create internal engineering evidence only.

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
repository commit and SHA-256 of every plan, schema, lock, adapter, workflow,
snapshot, and runner input. It has read-only repository permissions and creates
only a candidate artifact. Publishing a tag or release is a separate operation
requiring explicit authorization.

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
