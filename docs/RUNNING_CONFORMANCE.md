# Running conformance

Product repositories use the applicable entry workflows. The framework's
ledger, catalog, security, freshness, candidate, and publication workflows run
in this repository and do not need to be copied into product repositories.

| Product repository | Entry workflow | Runs |
| --- | --- | --- |
| `reallyme/wallet` | `eudi-wallet-conformance.yml` | EU Wallet engineering plan |
| `reallyme/identity` | `identity-product-conformance.yml` | OpenID4VCI and OpenID4VP, including both official Wallet roles |
| `reallyme/identity` | `eudi-identity-sdk-conformance.yml` | EU Identity SDK engineering plan |
| `reallyme/zk` | `zk-conformance.yml` | ZK presentation-proof plan |
| private EUDI repository | `eudi-relying-party-conformance.yml` | EUDI relying-party control-plane plan |

`ssi`, `openid4vci`, and `openid4vp` do not run separate framework workflows.
Their published releases are selected by the Identity product BOM and tested as
part of the composed Identity run.

The relying-party caller supplies the substantive component repository as a
separate input. Starting the workflow does not make the caller the component
under test.

## Select a framework release

Choose a published Identity Conformance release and resolve its tag once:

```sh
gh api repos/reallyme/identity-conformance/commits/v0.3.3 --jq .sha
```

Use the returned full commit in both the reusable-workflow reference and the
`framework_commit` input. The workflow verifies the tag, release metadata, and
release manifest before running any product checks.

## Wallet

The Wallet caller prepares one same-run artifact containing `deployment.json`,
`wallet-release`, and `wallet-attestation.json`. Its conformance job is:

```yaml
jobs:
  eu-conformance:
    needs: prepare-conformance-candidate
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

## Identity

Identity runs the OIDF self-assessment and EU SDK profiles as separate jobs.
The OIDF wrapper runs the complete OpenID4VCI and OpenID4VP hosted suites:

```yaml
jobs:
  oidf-conformance:
    uses: reallyme/identity-conformance/.github/workflows/identity-product-conformance.yml@FRAMEWORK_COMMIT
    with:
      framework_commit: FRAMEWORK_COMMIT
    secrets: inherit
```

The EU SDK job checks the caller-selected Identity commit and the exact SSI,
OpenID4VCI, and OpenID4VP releases named in its product BOM. It audits all 969
requirement rows and executes the Rust, TypeScript, Python, Go, Kotlin, and
Swift EUDI boundaries:

```yaml
jobs:
  eu-sdk-conformance:
    needs: prepare-conformance-candidate
    uses: reallyme/identity-conformance/.github/workflows/eudi-identity-sdk-conformance.yml@FRAMEWORK_COMMIT
    with:
      framework_commit: FRAMEWORK_COMMIT
      target_mode: candidate
      target_commit: ${{ github.sha }}
      target_version: ${{ needs.prepare-conformance-candidate.outputs.version }}
      candidate_artifact_name: identity-conformance-candidate-${{ github.sha }}
```

The preparation job uploads one same-run artifact containing only
`product-component-bom.json`. The BOM names the Identity candidate and its
exact dependencies and source commits. Published dependency entries include
the exact GitHub release ID and tag selected by the caller. A candidate
Identity entry has no release identity; a published Identity entry includes
the release ID and tag also supplied to the workflow.

The framework resolves every release ID and tag, checks out every selected
commit, and computes a SHA-256 digest of each tested source archive. These
derived digests are recorded in the result. The BOM does not contain
framework-owned product versions or unverified artifact claims.

The framework does not replace missing BOM entries with reference versions or
the latest GitHub release. The caller can test a newer component set with the
same framework release by supplying a different valid BOM.

The Identity job is also the OIDF Wallet job. It tests the Wallet release named
in the BOM through the composed VCI and VP harnesses. The Wallet repository's
EU job cannot produce an OIDF Wallet result by itself.

Identity can currently earn separate OIDF Full Self-Assessment and EU Identity
SDK Engineering results. The combined Identity Expanded Conformity badge stays
unavailable until the linked ZK observations are executed against immutable
Identity and ZK releases. The private relying-party control plane is a separate
product profile and is not part of the public Identity SDK result.

## Private EUDI control plane

The private caller supplies a protected deployment manifest containing the
exact EUDI, Platform, and SSI commits. It also names the substantive component
repository explicitly. Identity Conformance does not contain a default product
commit and does not resolve the latest ReallyMe release.

The runner compares the candidate's TS5 and TS6 source files with the pinned EU
sources before it runs requirement tests. The current exact test tranche covers
two of 19 assertions. It runs seven named Rust tests and rejects a Cargo command
that matches no tests. The test mappings are candidates until a clean immutable
run produces audited receipts. The other 17 assertions have no exact test
bindings, and the profile is not badge-eligible.

An optional `taxonomy_commit` is also caller-selected. When supplied, the
workflow records Identity Conformance as the requirement producer and runner,
the private EUDI commit as the subject under test, and asks Identity Taxonomy
to audit each metadata-only observation. Every referenced checkout must be
clean and match its recorded commit.

## Results and badges

A successful Wallet run uploads `wallet-conformance-statement.json`; other
product lanes upload either a statement or a validated execution result for
their profile. Each artifact records the scope that actually ran. Callers
select a named framework profile, not a list of individual checks. A profile
pass earns only that profile's badge. EU statements retain incomplete and
fixture-only counts; OIDF statements list the exact roles, profiles, module
executions, and suite revision. After disclosure review, publish that statement
with the product release and link the badge to it. Badge text should name the
product release, lane, and framework release. For example:

```text
Wallet vX.Y.Z · EU Wallet Engineering · Identity Conformance v0.3.3 · passing
```

Do not use the framework's own green CI badges as product pass badges. They show
that the framework is internally valid, not that a product release passed. Use
separate badges for EU engineering and OIDF suite results; neither badge implies
the other lane ran.
