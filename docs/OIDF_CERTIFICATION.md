# OIDF certification operations

ReallyMe runs OpenID4VCI and OpenID4VP certification tests against the pinned
OIDF suite release and exact product deployment. Local rehearsals and component
tests produce engineering results only.

## Plans and pinned sources

The certification matrix is `plans/oidf/certification.json`. The broader
non-certification matrix is `plans/oidf/engineering.json`. Certification runs
use only the suite release and commit in
`upstream/oidf/conformance-suite.lock.json`; engineering comparison with the
current development branch uses the separate master lock.

`plans/oidf/wallet.json` is the Wallet-specific contract derived from the
certification matrix. It requires all six OpenID4VCI Wallet configurations and
all four OpenID4VP Wallet configurations. The pinned suite resolves those 10
configurations to 278 module executions.

`upstream/oidf/specifications.lock.json` records the canonical URL, length, and
SHA-256 of the published OpenID4VCI, OpenID4VP, and HAIP final documents. It
also records the source commit when the upstream project provides a final tag.

The generated module inventories are:

- `upstream/oidf/snapshots/certification-modules.json`; and
- `upstream/oidf/snapshots/engineering-modules.json`.

Regenerate both after changing a suite pin or matrix. Matching source and a
fresh inventory show that the plan is current; they do not show that a product
passed.

## Certification matrix

| Role | Plan | Required configurations |
| --- | --- | ---: |
| OpenID4VCI issuer | `oid4vci-1_0-issuer-haip-test-plan` | 4 |
| OpenID4VCI wallet | `oid4vci-1_0-wallet-haip-test-plan` | 6 |
| OpenID4VP verifier | `oid4vp-1final-verifier-haip-test-plan` | 2 |
| OpenID4VP wallet | `oid4vp-1final-wallet-haip-test-plan` | 4 |

The 16 configurations cover SD-JWT VC and ISO mdoc. VCI covers wallet- and
issuer-initiated flows, including both issuer-offer delivery modes where the
plan requires them. VP covers verifier `direct_post.jwt` and wallet
`direct_post.jwt`/`dc_api.jwt` behavior selected by the matrix.

Every module returned for a selected plan must run. Certification evidence may
not use module selectors, skip lists, expected-failure lists, or partial
reruns. OpenID4VCI modules must pass. OpenID4VP permits `REVIEW` only for a
module named by the pinned result policy. Any other review or incomplete result
fails.

The framework suite pin is authoritative. The OpenID4VCI suite contract,
OpenID4VP profile matrix, checked-out suite, certification plan, and module
snapshot must name the same commit. The runners stop before creating a result
directory if any of them differ.

The engineering matrix also includes the base final-spec plans. Its results are
engineering evidence, not OIDF certification results.

## Deployment and execution

The deployment manifest must match
`schemas/oidf-deployment-manifest.schema.json` and pass the executable
validator. It names the legal entity, product version, roles, source commits,
deployment-artifact digests, and public product and health endpoints.

Product repositories call the reusable workflows at the exact commit of a
published framework release and supply the complete product BOM. The BOM names
the Identity product version and `product_release_ref` as well as every
component release. The protected runner verifies the framework release, BOM,
and deployment manifest, runs the full role matrix, and stores the result under
the caller's repository access controls.

Local suite execution is for rehearsal only. It must use the scoped loopback
TLS configuration, reject TLS-disabling modes, and record both
`certification_evidence: false` and `submission_authorized: false`. Hosted OIDF
credentials must never be used with the local suite.

The Wallet subject is the cross-platform `reallyme/wallet` core. Android and
iOS applications are not part of that release, so mobile UI tests are not an
OIDF Wallet requirement for this subject. The official Wallet protocol roles
still run against the composed Identity harness and the exact Wallet release in
the BOM.

## Evidence

Private evidence must record and cryptographically bind:

- the framework release and certification matrix;
- suite release, commit, and resolved module inventories;
- component and deployment manifests;
- production artifact digests;
- private configuration digests without configuration contents;
- every complete hosted-suite export; and
- the tested product and health endpoints.

Raw exports, tokens, private configurations, screenshots, and operational logs
remain private. A public bundle is created only after schema validation,
redaction review, and public-disclosure review. It must not contain credentials,
private keys, personal data, transaction content, or internal-only endpoints.

## Submission boundary

Creating and checking the evidence package is an engineering task.
Publishing a plan for certification, paying a fee, signing a declaration, and
submitting a request are external legal or administrative actions. Automation
must stop before those actions.

Complete `docs/OIDF_SUBMISSION_CHECKLIST.md` immediately before submission. An
authorized ReallyMe representative must confirm the current OIDF instructions,
fees, product identity, profile names, evidence hashes, and disclosure review.
