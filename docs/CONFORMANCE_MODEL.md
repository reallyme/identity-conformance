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
| Component repository | Implementation tests, package or deployment artifact, dependency lock, and component attestation |
| `identity-conformance` | Upstream pins, shared plans, adapter contracts, runners, negative tests, result evaluation, evidence schemas, and disclosure rules |
| Product target | Exact component BOM, deployment manifest, artifact digests, endpoints, and credentials required by the selected plan |
| External authority | Standards, official suite behavior, hosted results, and certification decisions |

A component attestation covers that component. An integration claim requires a
shared framework run against the assembled product.

## Run sequence

1. Each component identifies the source or release selected for the run.
2. The product selects an immutable framework release and supplies the BOM,
   deployment manifest, artifacts, and attestations required by the plan.
3. The framework checks every supplied release identity, source checkout, digest,
   adapter, configuration, upstream pin, and selected profile.
4. The framework runs the applicable external suite and ReallyMe integration
   checks against the deployed artifacts.
5. Raw results stay private. Reviewed evidence records the framework version,
   candidate BOM, tested source digests, any plan-required artifact evidence,
   deployment, test inventory, and disclosure decision.
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

The official UI cases target Android and iOS applications. They do not apply to
the cross-platform Wallet core because that release contains neither app. ITB
cases require a composed deployment. RQES cases belong to the RQES product
stack and require a QTSP, relying party, and external SCA. Until an applicable
runner executes, the corresponding workflows report source validation only.

The Wallet runner reads candidate values from the selected source revision and
compares them with the EU ledger. The caller cannot supply the expected value.
A missing value, changed comparison, incomplete enumeration, or unknown rule
fails the run.

The same runner discovers and executes the complete Wallet workspace test
inventory with all features enabled. It records the inventory digest and test
count, and confirms that every executable case declared by Wallet is present.
Source pins, ledger checks, and component attestations remain separate evidence
types; they do not count as code execution.

The OIDF source workflow checks every certification plan against the pinned
conformance-suite release. The Wallet contract requires 10 configurations and
278 module executions. A source-workflow pass confirms only that the matrix
matches the pinned suite. A Wallet OIDF result requires the hosted suite to run
against the composed Identity deployment and exact Wallet release in the BOM.

## Releases and evidence

### Framework release

A framework release contains plans, runners, schemas, upstream pins, and result
rules. It can be released before Wallet or Identity. Its manifest has
`release_kind: framework` and makes no product claim.

The release is the conformance baseline. Its version changes when an enforced
specification, ledger, test-suite revision, runner, adapter, schema, or result
rule changes. It does not follow every upstream commit. An upstream change is
reviewed before it becomes part of a new baseline.

### Product candidate BOM

The caller supplies the candidate BOM. The framework has no default ReallyMe
candidate and does not substitute a known-compatible version. OIDF plans list
the roles and adapter contracts they need. The caller chooses the components
that provide them. Missing roles, duplicate component identities, and multiple
providers for one adapter contract are errors.

Wallet and ZK plans still require their respective candidates. An Identity
OIDF BOM may contain any number of dependencies within the schema limit. It
must identify the Identity product component and cover all four OIDF roles plus
the OpenID4VCI and OpenID4VP adapter contracts.

### Integration evidence

Integration evidence records the framework revision, caller workflow revision,
canonical BOM digest, source commits, framework-derived source archive hashes,
and deployment identity. Artifact or attestation hashes are recorded only when
the plan verifies the corresponding bytes. Published components must include
their exact release ID and tag.

The composed run determines the integration result. Component test results do
not replace it.

### Product conformance statement

A passing product run creates a disclosure-safe statement for one candidate or
published product target, one named profile, and one published framework
release. The caller selects the profile; it cannot select individual checks
inside that profile. The workflow first verifies the
framework tag and release manifest. The statement then binds the product
release reference and commit, framework version and commit, framework input-set
digest, caller workflow revision, candidate digest, result digest, and the
coverage that actually ran. EU statements keep incomplete and fixture-only
areas visible by identifier, status, and limitation. OIDF statements list the
exact roles, profiles, module executions, suite revision, retained exports, and
caller-selected component BOM.
The BOM is included in the statement and checked against its canonical digest,
so a component release cannot be substituted without invalidating the result.

The statement has `certification_claim: false`. It records a framework result;
it does not turn an engineering run into an external certification decision.
Product repositories may publish a reviewed statement with a pass badge. The
badge must name the product target, profile, and framework release and link to
that statement. A combined badge is valid only when every profile in the
combined plan passed against the same target and evidence set.

A historical pass remains valid for the versions in its statement. It does not
claim that the product has passed a newer framework baseline. Product
repositories must run the newer baseline before updating their badge.

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

The framework release owns the suite pin, execution matrices, module inventory,
and result policy. Adapter code drives the product flows, but it cannot choose
the expected modules or decide which results count as passing. The framework
pin, suite checkout, generated runtime contracts, and retained exports must
agree. Component tests, the EU Wallet run, and local rehearsals cannot replace
an official OIDF Wallet module result.

### EUDI relying party

The relying-party runner checks an exact control-plane candidate, Platform,
and SSI manifest. The caller supplies every product revision. The framework
does not contain a default EUDI, Platform, or SSI commit.

The runner first verifies the component attestation and pinned EU sources. It
then compares the candidate's TS5 and TS6 source files with the framework's
pinned copies. For the two assertions that have exact requirement bindings, it
runs seven named Rust tests and records only bounded hashes and metadata. A
successful Cargo command that runs zero matching tests is rejected. The other
17 assertions still rely on component attestations, so this profile cannot
earn a product badge. `live_ts5` mode also performs the four-read TS5 operation
against an approved national-register deployment.

The runner produces internal engineering evidence, not an EU
conformity-assessment result.

This control-plane profile is not part of the public Identity SDK profile.
Identity currently reserves its hosted relying-party API and does not execute
those lifecycle operations through its local SDKs.

### EU Identity SDK

The Identity SDK profile checks eight public EUDI operations: catalogue and
requirement-registry validation, requirement lookup, and natural-person,
legal-person, issuance, allocation, and revocation PID validation. It audits
740 ETSI rows and 229 EU rows, then runs the Rust boundary, the VCI and VP
composition hosts, and the TypeScript, Python, Go, Kotlin, and Swift SDK tests.
The caller supplies the complete candidate BOM. The framework verifies the
selected Identity commit and each dependency release without choosing a
component version itself.

The evidence is split into three classes:

- Normative engineering evidence is executable. The requirement audit and the
  candidate tests must pass.
- EU reference implementations are interoperability targets, not normative
  authorities. The Identity operations have no matching official executable
  oracle. VCI and VP interoperability with the pinned PID issuer, issuer
  tester, verifier endpoint, and ITB needs deployed services and belongs in a
  separate profile. The Android and iOS reference wallets do not apply to an
  Identity SDK candidate because it contains no mobile application.
- Fifty-three rows require external evidence. They are not counted as code
  passes. This profile makes no legal-conformity or certification claim.

Source-lock validation proves which reference revisions were reviewed. It is
not behavioral parity with those implementations.

### EUDI Wallet

The Wallet runner ties the source commit, package bundle, and component
attestation to the same caller-selected target. It checks the EU source selection and
ledgers, evaluates observable boundary values, and runs every test in the
Wallet workspace with all features enabled, including tests marked ignored.
The result records the complete discovered-test inventory and binds it to the
candidate.

The package bundle is not accepted by digest alone. The runner checks its exact
file set, preflight records, Cargo lock, public crate inventory, crate digests,
and the source revision embedded in every crate.

The runner also injects five framework-owned Rust probes through Wallet's
public APIs. They check provider record identifiers, key-custody encoding,
consent context binding, flow resumption after uncertain delivery, and
lifecycle enforcement. They run independently of the candidate's own tests and
must leave the selected checkout clean.

The caller uploads `deployment.json`, `wallet-release`, and
`wallet-attestation.json` as one same-run Actions artifact. The framework
downloads that artifact on a clean GitHub-hosted runner and checks out the
manifest-selected Wallet commit. It does not depend on preinstalled files or
persistent runner state.

The EU Wallet run is not currently badge-eligible. Three normative rules have
exact clause or boundary traces and five assertions have framework-owned
probes. The remaining flow and security assertions still depend on broad
candidate test inventories and component attestations. The result also does
not cover the official OIDF Wallet suite, Android or iOS application behavior,
ITB deployment tests, RQES services, or an external conformity assessment.
Those use separate plans and evidence.

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

The base ZK runner checks the source, toolchain, provider manifest, Cargo lock,
artifact bundle, package tests, and component attestation. Those checks are
candidate test inventory, not assertion-specific observations.

The linked observation contract adds 11 exact probes and a 20-row proof matrix:
two hash lanes, public and private presentation modes, and five witness stages.
Each row records artifact, verification-key, proof, public-input, and frozen
request digests. It also records whether modified proofs and public inputs were
rejected. Witnesses, proof bytes, private keys, and machine-local paths are not
retained.

A dirty working-tree run may be recorded as local engineering evidence. It is
not release evidence. Release evidence must bind the Identity product and its
ZK provider to an immutable caller BOM, release artifacts, component
attestations, source commits, source trees, toolchain digests, all 11 probes,
and all 20 proof rows. The framework does not pin the Identity or ZK release
version.

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

The maintenance report may show the latest published releases of `ssi`,
`identity`, `zk`, `wallet`, `openid4vci`, and `openid4vp` as convenient targets.
Those observations are not framework pins and do not advance the framework
version. Product workflows test the exact commits selected by their callers.
