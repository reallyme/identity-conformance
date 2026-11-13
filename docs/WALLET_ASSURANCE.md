# Wallet assurance

A Wallet claim must identify the release, framework, plan, and evidence. A
green framework workflow or a source inventory is not a product result.

## Evidence expected for a Wallet target

| Question | Required evidence |
| --- | --- |
| Which code was tested? | Caller-selected Wallet version and commit, target mode, preflight run, package-bundle digest, Cargo lock, and source-lock digests. Published mode also records the immutable release ID and tag. |
| Which framework was used? | Published Identity Conformance release and commit, release-manifest digest, and framework input-set digest. |
| What ran? | Result file, workflow revision and run identifier, discovered test inventory and digest, and counts for executed, passed, failed, ignored, and filtered tests. |
| Was the candidate substituted? | Deployment manifest, package-bundle digest, attestation digest, source checkout revision, and revalidation of every input. The framework opens the bundle, verifies every preflight record and crate digest, matches the Cargo lock, checks each crate's embedded source revision, and verifies GitHub provenance for the manifest and every crate. |
| Did the release gates really run? | Live GitHub records for the exact preflight, Rust CI, protobuf, and manually dispatched fuzz runs. The fuzz run must complete four five-minute campaigns: protobuf decoding, protobuf JSON, identifiers, and the Wallet state machine. The framework checks the commit, workflow, event, attempt, jobs, and required steps. These run identifiers are included in the public statement. |
| Which EU rules were checked? | Rule identifiers, pinned source commits, extracted implementation values, operators, expected values, and per-rule results. |
| What remains incomplete? | The result preserves counts for implemented, partial, delegated, operational, executable, and fixture-only areas. A passing engineering lane does not promote incomplete areas to implemented. |
| Did the official OIDF suite run? | Hosted-suite exports for every required Wallet profile, exact suite commit, resolved module inventory, terminal result for every module, and the composed product BOM and deployment digest. |
| Can the result be published? | Disclosure-safe product statement and completed redaction and public-disclosure reviews. Raw suite exports and credentials remain private. |

## Current plans

The EU core plan runs in the Wallet repository. It compiles and runs the full
workspace with all features, records the discovered tests, includes ignored
tests, evaluates the machine-readable EU boundaries implemented by the plan,
and runs five framework-owned probes against Wallet's public APIs. The probes
check provider record identifiers, key-custody encoding, consent context
binding, flow resumption after uncertain delivery, and lifecycle enforcement.
Component attestations and source inventories are recorded separately and do
not count as executed tests.

The result reports incomplete coverage explicitly. The EU minimums include
implemented, partial, delegated, operational,
and fixture-seeded areas. It lists every incomplete minimum with its stated
limitations and every fixture-only case by identifier. These details remain
visible in the public product statement after a passing run.

The OIDF Wallet plan runs from the composed Identity deployment. It contains:

- six OpenID4VCI Wallet configurations and 138 module executions; and
- four OpenID4VP Wallet configurations and 140 module executions.

All 278 module executions must complete under the result policy selected by the
certification plan. Module selectors, skips, expected failures, partial reruns,
and replacement with component tests are prohibited. The framework suite pin,
component profile matrices, suite checkout, and retained module inventories
must agree.

## Scope boundaries

`reallyme/wallet` is a cross-platform core library. It does not ship an Android
or iOS application. The EUDI Wallet UI suite and the EU Android and iOS
reference apps are therefore not application tests for this release. Their
source inventories remain framework-pinned so a future app can select them without
changing their status into a core-library pass.

The EU Interoperability Test Bed is applicable only to a composed deployed
product. The RQES tester applies to the RQES stack, not the base Wallet core.
FCAF v0.0.10 is an assessment methodology and has no executable Wallet test
cases. Age Verification supplies a profile and ZKP material but no complete
official executable suite at the pinned revision.

## Additional product tests

The following checks belong in the product composition and must not be inferred
from Wallet's in-memory unit tests:

- consent bound to the actual SD-JWT or mdoc output, with decoded disclosures
  limited to the approved scope and changed request, session, or credential
  bindings rejected;
- bounded lifecycle and reuse operation sequences checked against a reference
  model, including invalid transitions and malicious inputs;
- durable provider crash, restart, and concurrent compare-and-swap behavior in
  the Identity or Vault-backed storage integration; and
- concrete ZK backend verification when the product BOM enables ZK.

These checks use separate evidence until their owning product runner includes
them. Their absence must not be reported as a Wallet core pass.

## Badge rules

An EU Wallet engineering badge links to the EU result and product statement. An
OIDF Wallet badge links to the hosted-suite evidence statement from the
composed Identity run. That statement carries the complete component BOM, so it
must name the exact Wallet release and commit as well as the Identity product
that was exercised. The badge names both the Wallet release and Identity
Conformance release. It must not say “certified” until the external submission
and decision are complete.
