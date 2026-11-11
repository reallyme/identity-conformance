# OIDF certification operations

This document defines the durable operating rules for ReallyMe OpenID4VCI and
OpenID4VP certification runs. It does not convert a local rehearsal or
component test into a certification claim.

## Authority and pins

The certification matrix is `plans/oidf/certification.json`. The broader
non-certification matrix is `plans/oidf/engineering.json`. Certification runs
use only the suite release and commit in
`upstream/oidf/conformance-suite.lock.json`; engineering comparison with the
current development branch uses the separate master lock.

`upstream/oidf/specifications.lock.json` binds the published OpenID4VCI,
OpenID4VP, and HAIP final documents by canonical URL, length, and SHA-256. Where
an upstream final tag exists, it also binds the exact source commit.

The generated module inventories are:

- `upstream/oidf/snapshots/certification-modules.json`; and
- `upstream/oidf/snapshots/engineering-modules.json`.

Regenerate both after changing the suite pin or either matrix. A source match
or regenerated inventory is a drift check, not a passing result.

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

Every module returned for a selected plan must run. Module selectors, reruns,
skip lists, and expected-failure lists are prohibited for certification
evidence. OpenID4VCI modules must pass. OpenID4VP permits `REVIEW` only for an
exact module classified by the source-bound result policy; any unclassified
review or incomplete result fails closed.

The engineering matrix adds the base final-spec plans. Those results are
release-engineering evidence and must not be represented as an OIDF
certification outcome.

## Deployment and execution

The deployment manifest must conform to
`schemas/oidf-deployment-manifest.schema.json` and pass the executable
validator. It identifies the legal entity, product version, claimed roles,
exact source commits, immutable deployment-artifact digests, and public product
and health endpoints.

Product repositories call the reusable OpenID4VCI and OpenID4VP workflows at an
exact framework commit. The caller also supplies a complete product component
BOM. The protected runner validates that BOM and the deployment manifest before
execution, runs the complete role matrix, and
retains the result under the caller repository's access controls.

Local suite execution is a pre-submission rehearsal only. It must use the
scoped loopback TLS configuration, reject TLS-disabling modes, and record both
`certification_evidence: false` and `submission_authorized: false`. Hosted OIDF
credentials must never be used with the local suite.

## Evidence

The retained private evidence set must bind:

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

Creating and validating the evidence package is an engineering operation.
Publishing a plan for certification, paying a fee, signing a declaration, and
submitting a request are external legal or administrative actions. Automation
must stop before those actions.

Complete `docs/OIDF_SUBMISSION_CHECKLIST.md` immediately before submission. An
authorized ReallyMe representative must confirm the current OIDF instructions,
fees, product identity, profile names, evidence hashes, and disclosure review.
