# Running conformance

Product repositories use one entry workflow. The framework's ledger, catalog,
security, freshness, candidate, and publication workflows run in this
repository and do not need to be copied into product repositories.

| Product repository | Entry workflow | Runs |
| --- | --- | --- |
| `reallyme/wallet` | `eudi-wallet-conformance.yml` | EU Wallet engineering plan |
| `reallyme/identity` | `identity-product-conformance.yml` | OpenID4VCI and OpenID4VP, including both official Wallet roles |
| `reallyme/zk` | `zk-conformance.yml` | ZK presentation-proof plan |
| private EUDI repository | `eudi-relying-party-conformance.yml` | EUDI relying-party control-plane plan |

`ssi`, `openid4vci`, and `openid4vp` do not run separate framework workflows.
Their published releases are selected by the Identity product BOM and tested as
part of the composed Identity run.

## Select a framework release

Choose a published Identity Conformance release and resolve its tag once:

```sh
gh api repos/reallyme/identity-conformance/commits/v0.3.2 --jq .sha
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

Identity uses one job. The wrapper runs both OIDF lanes:

```yaml
jobs:
  oidf-conformance:
    uses: reallyme/identity-conformance/.github/workflows/identity-product-conformance.yml@FRAMEWORK_COMMIT
    with:
      framework_commit: FRAMEWORK_COMMIT
    secrets: inherit
```

The repository secrets and product BOM supply the deployment-specific inputs.
The BOM must include `product_version`, `product_release_ref`, and the six exact
component releases.

The Identity job is also the OIDF Wallet job. It tests the Wallet release named
in the BOM through the composed VCI and VP harnesses. The Wallet repository's
EU job cannot produce an OIDF Wallet result by itself.

## Results and badges

A successful Wallet run uploads `wallet-conformance-statement.json`; the other
product lanes upload their applicable statements. Each statement records the
scope that actually ran. Callers select a named framework profile, not a list
of individual checks. A profile pass earns only that profile's badge. EU
statements retain incomplete
and fixture-only counts; OIDF statements list the exact roles, profiles, module
executions, and suite revision. After disclosure review, publish that statement
with the product release and link the badge to it. Badge text should name the
product release, lane, and framework release. For example:

```text
Wallet vX.Y.Z · EU Wallet Engineering · Identity Conformance v0.3.2 · passing
```

Do not use the framework's own green CI badges as product pass badges. They show
that the framework is internally valid, not that a product release passed. Use
separate badges for EU engineering and OIDF suite results; neither badge implies
the other lane ran.
