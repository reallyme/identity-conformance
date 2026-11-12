# Conformance authority and evidence model

This repository is an executable cross-repository conformance framework. It is
not merely a catalog of external specifications, and it is not a passive store
for test reports produced elsewhere.

## Authority order

The following sources govern in descending order:

1. binding legislation and adopted implementing acts;
2. the exact normative specification publication selected by a plan;
3. the exact external conformance-suite release selected by the framework;
4. the versioned ReallyMe plan, adapter contract, result policy, and evidence
   policy in this repository;
5. component adapters and product deployments that implement those contracts.

A ReallyMe plan may select, constrain, and compose external requirements. It
cannot weaken a normative requirement or reinterpret a failing external result
as a pass.

## Ownership boundaries

| Owner | Required responsibility |
| --- | --- |
| Component repository | Unit, integration, property, fuzz, vector, and component-adapter tests close to the implementation; immutable release artifact and component attestation |
| `identity-conformance` | External-source pins; executable cross-repository plans; adapter contracts; negative and malicious-input cases; runners; result evaluation; evidence schemas; redaction and disclosure rules |
| Product release | Exact component BOM, deployment manifest, immutable artifact digests, endpoints, and credentials needed to execute the selected framework release |
| External authority | Normative publications, official suite behavior, hosted execution results, and certification decision |

Component reports are supporting evidence. They are never accepted as proof
that independently tested components work together. Cross-repository and
deployment behavior must be exercised and evaluated by a runner controlled by
the selected `identity-conformance` framework release.

## Execution flow

1. A component release produces an immutable artifact and a component-level
   attestation bound to its source commit and dependency lock.
2. A product release candidate selects an immutable conformance-framework
   release and supplies an exact component BOM and deployment manifest.
3. The framework validates every release, checkout, artifact digest, adapter,
   configuration, external-suite revision, and selected profile before it runs.
4. The framework launches the external suites and ReallyMe-owned composed
   scenarios against the deployed artifacts. It evaluates complete positive,
   negative, and policy results itself.
5. Raw results remain private. A reviewed bundle binds the framework version,
   component attestations, source and artifact digests, deployment, external
   suite, result inventory, and redaction decision.
6. Only the reviewed bundle can substantiate that the named release composition
   passed the selected test contract. OIDF certification still depends on the
   official hosted result and the Foundation's certification process.

Component repositories may trigger this flow, but they do not determine the
outcome. A trigger is a request to run an immutable framework version, not a
report that the system is conformant.

## Release classes

### Framework release

A framework release versions plans, runners, schemas, external pins, and result
policy. It may be released before Wallet or Identity. Its deterministic
manifest carries `release_kind: framework` and makes no product-conformance or
certification claim.

### Product candidate BOM

The product caller supplies the candidate BOM for each run. The framework has
no default ReallyMe product candidate and never substitutes a known-compatible
revision. Each plan declares its required components; missing, repeated, or
ambiguous entries fail validation. The composed Identity OIDF lanes require the
complete six-component BOM, while the Wallet and ZK lanes require only their
respective candidate component.

### Integration evidence bundle

An integration evidence bundle requires immutable release references for every
participating component, including Wallet and Identity, plus exact deployment
artifacts. Component test attestations are included by digest. The composed run
is the authority for the integration result. Its evidence records the framework
revision, caller workflow revision, canonical candidate BOM digest, source
commits, artifact hashes, and attestation hashes as separate identities.

### Certification evidence bundle

Certification evidence adds complete hosted OIDF execution, suite exports,
submission review, redaction review, and public-disclosure review. A local
rehearsal or EU reference-implementation result cannot be promoted to this
class.

## Current executable scope

The OIDF lane is executable: the framework owns fixed certification and
engineering matrices, validates source-resolved module inventories, drives the
OpenID4VCI and OpenID4VP product roles, checks complete results, and constructs
digest-bound evidence indexes.

The EUDI relying-party lane is executable internal conformance engineering.
Its protected runner validates an exact candidate/Platform/SSI BOM, verifies a
component attestation for every assertion and upstream binding, checks the
pinned ARF, FCAF, TS5/TS6, legal-source, and compatibility-reference revisions,
and exercises bounded production-artifact probes. `live_ts5` mode additionally
runs the production four-read TS5 operation against an approved
national-register deployment. The lane remains explicitly non-certifying: EU
reference-service, ITB, FCAF, or ReallyMe results cannot themselves establish
an EU conformity-assessment outcome.

The EUDI Wallet lane is separate from the relying-party lane. It binds the
wallet source and release artifact to its component attestation, verifies the
committed EU source-selection and requirement ledgers, and executes the wallet
conformance package. Its result establishes only the selected internal
engineering contract; an external testbed or conformity-assessment result must
be retained as separate evidence.

The Wallet caller uploads its manifest, release bundle, and attestation as an
immutable same-run Actions artifact. The reusable framework workflow downloads
and validates that closed three-file input on a clean GitHub-hosted runner,
checks out the exact manifest-selected Wallet commit, and runs the shared plan.
No preinstalled candidate files or persistent runner state form part of the
execution contract.

The EUDI upstream inventory also pins the Age Verification profile, official
wallet UI and RQES testers, Android and iOS reference wallets, trust and status
components, the RQES reference stack, and the documentation portal. These pins
are review and reproducibility inputs. They do not expand the executable scope
of either EUDI lane. `plans/eudi/upstream-coverage.json` is the authoritative
machine-readable boundary: it prevents a monitored source, interoperability
target, component attestation, or gated external test asset from being reported
as a directly executed official suite.

Publicly downloadable wallet publications are independently content-pinned in
`references/eudi-publications.lock.json`. Copyright-restricted ISO standards are
edition-pinned rather than falsely represented as content-pinned. Dated working
drafts, including the Digital Credentials API, remain engineering inputs and
cannot support certification claims.

The ZK presentation-proof lane binds the proof provider's source, toolchain,
artifact manifest, dependency lock, release bundle, and attestation. A product
composition may claim ZK coverage only when its deployment BOM explicitly
enables the capability and supplies those exact digests. ZK component results
remain supporting evidence; wallet and verifier compositions still have to
exercise the integrated presentation behavior.

Identity Taxonomy coverage is currently advisory. Its reports can expose gaps
and naming drift, but taxonomy identifiers and the taxonomy repository revision
are not mandatory framework-release inputs until the taxonomy is approved as a
governing contract.

## Automation policy

Scheduled automation detects upstream releases, source drift, changed
publication bytes, dependency versions, and tool updates. It can produce a
review-only update proposal, but it does not change a baseline or issue a
conformance result. Pin updates require review and regeneration of affected
plans and snapshots. Framework release creation, product execution, evidence
promotion, and remote publication remain distinct operations with separate
authorization.
