# Conformance model

Identity Conformance runs shared EU, OIDF, EUDI Wallet, relying-party, and ZK
checks across ReallyMe releases. This repository owns the plans, upstream pins,
runners, result rules, and public evidence formats. Product repositories own
their implementations.

## Source priority

When two sources conflict, use this order:

1. applicable law and adopted implementing acts;
2. the normative specification selected by the plan;
3. the external test-suite release selected by the framework;
4. the plan, adapter contract, result rules, and evidence rules in this
   repository; and
5. the component and deployment configuration used for the run.

A ReallyMe plan may select or combine requirements. It may not weaken a
normative requirement or turn a failed external result into a pass.

## Responsibilities

| Owner | Responsibility |
| --- | --- |
| Component repository | Implementation tests, release artifact, dependency lock, and component attestation |
| `identity-conformance` | Upstream pins, shared plans, adapter contracts, runners, negative tests, result evaluation, evidence schemas, and disclosure rules |
| Product release | Exact component BOM, deployment manifest, artifact digests, endpoints, and credentials required by the selected plan |
| External authority | Standards, official suite behavior, hosted results, and certification decisions |

A component attestation covers that component. An integration claim requires a
shared framework run against the assembled product.

## Run sequence

1. Each component release publishes an immutable artifact and an attestation
   tied to its source commit and dependency lock.
2. The product selects an immutable framework release and supplies the BOM,
   deployment manifest, artifacts, and attestations required by the plan.
3. The framework checks every release reference, source checkout, digest,
   adapter, configuration, upstream pin, and selected profile.
4. The framework runs the applicable external suite and ReallyMe integration
   checks against the deployed artifacts.
5. Raw results stay private. Reviewed evidence records the framework version,
   candidate BOM, source commits, artifact and attestation digests, deployment,
   test inventory, and disclosure decision.
6. A claim applies only to the exact product composition and plan named by that
   evidence.

A component repository may trigger the run. The framework produces the result.

## EU and OIDF checks

EU and OpenID Foundation checks are separate. Each has its own upstream pins,
machine-readable rules, workflows, results, and badges.

The EU checks are divided by source:

- the ARF workflow verifies selected requirement identifiers and Wallet
  boundary values against the pinned ARF release;
- the technical-specification workflow verifies values taken from the pinned
  technical specifications;
- the FCAF workflow verifies the assessment structure and reports
  `methodology_only` because FCAF v0.0.10 has no executable Wallet cases; and
- the upstream-assets workflow verifies the exact Wallet UI, ITB, Age
  Verification, and RQES source inventories.

The UI and ITB cases require a deployed Wallet and test infrastructure. The
RQES tester also requires a reviewed dependency set and supporting services.
Until those runners execute, these workflows report source validation only.

The Wallet runner reads candidate values from the selected source revision and
compares them with the EU ledger. The caller cannot supply the expected value.
A missing value, changed comparison, incomplete enumeration, or unknown rule
fails the run.

The OIDF source workflow checks every certification plan against the pinned
conformance-suite release. A pass confirms that the local matrix matches that
release. Product execution and OIDF certification are separate results.

## Releases and evidence

### Framework release

A framework release contains plans, runners, schemas, upstream pins, and result
rules. It can be released before Wallet or Identity. Its manifest has
`release_kind: framework` and makes no product claim.

### Product candidate BOM

The caller supplies the candidate BOM. The framework has no default ReallyMe
candidate and does not substitute a known-compatible version. Each plan lists
its required components. Missing, duplicate, and ambiguous entries are errors.

Wallet and ZK plans need their respective component candidates. Composed
Identity OIDF plans need the complete six-component BOM.

### Integration evidence

Integration evidence records the framework revision, caller workflow revision,
canonical BOM digest, source commits, artifact hashes, attestation hashes, and
deployment identity. Every participating component must use an immutable
release reference.

The composed run determines the integration result. Component test results do
not replace it.

### Certification evidence

OIDF certification evidence also needs complete hosted-suite results, suite
exports, submission review, redaction review, and public-disclosure review. A
local rehearsal, EU reference implementation, or ReallyMe integration result
cannot be promoted to certification evidence.

## Current coverage

### OpenID Foundation

The OIDF runners cover the fixed OpenID4VCI and OpenID4VP certification and
engineering matrices. They verify the selected module inventory, run the
applicable product roles, reject incomplete results, and build digest-bound
evidence indexes.

### EUDI relying party

The relying-party runner checks an exact candidate, Platform, and SSI BOM. It
verifies component attestations and pinned EU sources, then runs bounded probes
against the production artifact. `live_ts5` mode also performs the four-read
TS5 operation against an approved national-register deployment.

The runner produces internal engineering evidence, not an EU
conformity-assessment result.

### EUDI Wallet

The Wallet runner ties the source commit, release bundle, and component
attestation to the same candidate. It checks the EU source selection and
ledgers, evaluates observable boundary values, and runs the Wallet conformance
package.

The caller uploads `deployment.json`, `wallet-release`, and
`wallet-attestation.json` as one same-run Actions artifact. The framework
downloads that artifact on a clean GitHub-hosted runner and checks out the
manifest-selected Wallet commit. It does not depend on preinstalled files or
persistent runner state.

The result covers the ReallyMe engineering plan. External testbed and
assessment results use separate evidence.

### EU upstream assets

The EU inventory includes the Age Verification profile, Wallet UI and RQES
testers, ITB, mobile reference wallets, trust and status services, the RQES
reference stack, and the documentation portal.

`plans/eudi/upstream-assets.json` records the test definitions that CI checks.
`plans/eudi/upstream-coverage.json` records what has and has not run against a
product. A source pin, reference implementation, or component attestation
cannot be reported as an executed external suite.

Public EU publications are content-pinned in
`references/eudi-publications.lock.json`. Copyright-restricted ISO standards
are pinned by edition and official catalog URL because their full text cannot
be distributed here. Working drafts, including the Digital Credentials API,
are engineering inputs and cannot support a certification claim.

### ZK presentation proofs

The ZK runner checks the source, toolchain, provider manifest, Cargo lock,
artifact bundle, and component attestation. A product may claim ZK coverage
only when its BOM enables ZK and supplies those exact digests. Wallet and
verifier integrations must still exercise the composed presentation flow.

### Identity Taxonomy

Identity Taxonomy coverage is advisory. It may identify gaps and naming drift,
but taxonomy identifiers and the taxonomy repository revision are not required
framework-release inputs until the taxonomy is approved as a governing
contract.

## Updates

Weekly automation checks for upstream releases, changed publications,
dependency updates, and tool updates. It reports a proposed change; it does not
change the active baseline.

Tagged stable releases may be proposed for the next framework version.
Untagged default-branch commits require snapshot review. Changed bytes at an
apparently immutable publication require an integrity review. Monitor-only
sources cannot advance the baseline.

An approved update changes `VERSION`, the affected locks, ledgers, runners,
catalog, and snapshots together. Changes to normative text or values require
human review.

The release-candidate workflow reads `VERSION` and runs every affected EU and
OIDF gate against the exact candidate commit. The protected promotion workflow
rebuilds and compares the manifest before creating `v<VERSION>`. Product runs,
evidence publication, and framework publication remain separate operations.

Latest-release regression runs cover `ssi`, `identity`, `zk`, `wallet`,
`openid4vci`, and `openid4vp`. They resolve published release tags and verify
their commits; they do not use default branches. Exact-BOM runs may test an
older release or a selected release candidate, but the result must say that it
is not the latest-release lane.
