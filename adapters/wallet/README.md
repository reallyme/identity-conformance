# Product wallet adapter lane

This lane composes `reallyme/wallet`, `reallyme/ssi`, `reallyme/identity`, and the relevant
`reallyme/openid4vci` or `reallyme/openid4vp` protocol engine for OIDF wallet
profiles. It must drive the same deployable product boundary intended for
release; recorder-only or protocol-engine-only harnesses are not acceptable
certification targets.

The protocol repositories own their wallet-role engines and narrow harness
traits. `reallyme/wallet` owns reusable consent, inventory, storage, and
lifecycle state transitions. `reallyme/identity` owns the concrete composed
VCI and VP drivers that connect those boundaries to keys, attestation, network,
clock, and encrypted-storage providers. This repository owns the executable
deployment, complete matrix orchestration, and retained evidence; it must not
reimplement any of those layers.

The composed OpenID4VCI lane must cover both immediate and deferred
offer-to-storage flows through the deployed Identity wallet host and the pinned
OpenID4VCI component. These checks replace mock issuer and in-process HTTP
adapter composition tests in `reallyme/wallet`; Wallet's own suite stops at its
injected transport boundaries and resumable lifecycle invariants.

## Shared requirements and retained results

[Identity Taxonomy](https://github.com/reallyme/identity-taxonomy) owns shared
requirement vocabulary and federated coverage. Each implementation repository
supplies its scoped producer evidence and behavioral tests. Wallet retains its
Rust domain tests, capability contracts, and source-local fixtures.

Identity Conformance owns the composed run plans, component and suite pins,
deployment provenance, and retained cross-repository results. Raw engineering
runs stay ignored under `results/local/`. A disclosure-safe record may enter
`evidence/` only after an applicable public schema exists and the record passes
the redaction and public-disclosure reviews. Consumer repositories may
materialize pinned, hash-verified copies for local validation.

The source bill of materials in `components.lock.json` and the suite pin in
`upstream/oidf/conformance-suite.lock.json` must both match the intended release
candidate before a qualifying run. Local development probes may identify
integration failures, but dirty working-tree hashes and selected-module runs
cannot satisfy the complete pinned certification matrix. Promotion requires
the exact deployed artifacts, every applicable module, redacted exports, and
the evidence reviews defined in `evidence/README.md`.

## Issuance qualification prerequisites

Wallet retains authenticated issuer-nonce observations in its issuance session,
canonical request and durable snapshot. The proof verifier binds the verified
nonce digest and signed issue time; first submission checks trusted freshness,
and restoration validates the original session and proof binding. Identity's
nonce provider checks the configured endpoint against authenticated session
metadata before network I/O. Missing, substituted, expired and wrong-session
observations fail closed in Wallet's behavioral tests.

SSI 0.6.1 provides an explicit draft-07 attestation PoP signing profile whose
`iss` is the configured OAuth client identifier. Identity's pinned OIDF harness
selects that profile for PAR and token authentication. SSI's existing default
claim set is preserved. Profile selection must remain explicit; an HTTP
success cannot waive a failed suite condition.

Wallet and OpenID4VP resolve their SSI dependencies from the published 0.6.1
registry artifacts. Wallet also verifies the SSI protobuf archive checksum,
release commit, and exact imported schema bytes. Protocol artifacts must match
the registry releases and checksums in `components.lock.json`. ZK artifacts
remain separately bound inputs to the ZK and composed-presentation plans.

Local engineering runs are retained under `results/local/`. Each completed
profile records the exact module inventory returned by the pinned suite and
requires both a passing suite result and the expected composed host outcome.
Issuance success means authenticated receipt validation and encrypted atomic
storage completed; a suite result alone cannot establish that outcome.

Presentation rehearsals must keep each provisioning issuer and its signed
status resources available for the entire presentation plan. A completed local
issuer module may stop serving those resources. Use the suite's bounded
additional-request grace period for provisioning; do not replace failed live
status checks with issuance-time evidence. Provisioning modules held for this
purpose are setup dependencies, not completed certification modules.

The local suite uses a TLS proxy that reports the actual negotiated protocol
and cipher. Identity's status adapter samples its explicitly injected trusted
clock after response retrieval, rejects rollback, and retains future/expired
JWT rejection. This permits an issuer to mint status evidence while answering
a request without treating that evidence as future-dated relative to an older
pre-request timestamp. SSI is unchanged by this adapter fix.

OpenID4VP owns the current ZK `artifact_identity` schema. Wallet's imported
snapshot and Identity's generated bindings follow that canonical source.
Current wire vectors verify that manifest and artifact-set identities remain
distinct, with identical fixture bytes consumed by Rust, TypeScript, Swift and
JVM bindings. No schema migration layer is used in this composition.

A qualifying run still requires the complete applicable module matrix,
reviewed release/deployment provenance, supported device providers, and the
normal evidence review. SSI's ETSI runtime policy crate remains owned and
published by SSI; shared requirement vocabulary belongs in Identity Taxonomy,
and composed execution evidence belongs here.
