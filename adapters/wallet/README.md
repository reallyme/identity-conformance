# Product Wallet adapter

This lane runs OIDF Wallet profiles against the released product. It combines
`reallyme/wallet`, `reallyme/ssi`, `reallyme/identity`, and the applicable
`reallyme/openid4vci` or `reallyme/openid4vp` engine.

The test target must be the same product boundary intended for release. A
recorder or isolated protocol engine is not an acceptable certification target.

## Responsibilities

- `reallyme/openid4vci` and `reallyme/openid4vp` own the Wallet-side protocol
  engines and their narrow harness interfaces.
- `reallyme/wallet` owns consent, credential inventory, storage, and lifecycle
  state.
- `reallyme/identity` connects those parts to keys, attestation, network,
  clock, and encrypted storage.
- `identity-conformance` owns the deployment contract, test matrix, upstream
  pins, result rules, and evidence requirements.
- The caller owns the exact candidate BOM and release artifacts.

OpenID4VCI runs cover immediate and deferred issuance through the deployed
Identity Wallet host. Wallet's own tests stop at its injected transport
boundaries; this lane covers the assembled product.

## Candidate and results

The caller-supplied BOM and the suite pin in
`upstream/oidf/conformance-suite.lock.json` must match the intended release.
The framework does not supply a fallback product version.

Local runs may help find integration failures, but a dirty checkout or partial
module run cannot satisfy the certification matrix. A certification run needs:

- immutable release artifacts and source commits;
- the full applicable module matrix;
- the expected product outcome for each profile;
- redacted suite exports; and
- the reviews required by `evidence/README.md`.

Raw local results belong in the ignored `results/local/` directory. Public
evidence may enter `evidence/` only after schema validation, redaction review,
and disclosure review.

## Issuance requirements

Wallet stores the authenticated issuer nonce in its issuance session and
durable snapshot. The proof verifier checks the nonce digest and issue time.
Restored sessions must retain the original nonce and proof binding. Missing,
substituted, expired, and wrong-session values must fail.

SSI provides the draft-07 attestation proof-of-possession profile used for PAR
and token authentication. Its `iss` claim is the configured OAuth client ID.
Profile selection must be explicit; an HTTP success does not override a failed
suite condition.

Each completed issuance profile must record the module inventory returned by
the pinned suite and the composed host result. Issuance succeeds only after the
host authenticates the response and completes encrypted atomic storage.

## Presentation requirements

Provisioning issuers and signed status resources must remain available for the
whole presentation plan. A completed issuer module may stop serving those
resources, so provisioning may use the suite's bounded additional-request
grace period. Setup modules are dependencies, not completed certification
modules.

The local suite uses a TLS proxy that records the negotiated protocol and
cipher. Identity checks status evidence against its injected trusted clock
after the response arrives and rejects rollback, future, and expired values.

OpenID4VP owns the ZK `artifact_identity` schema. Wallet snapshots and Identity
bindings follow that source. Shared fixtures must keep manifest identity and
artifact-set identity separate across Rust, TypeScript, Swift, and JVM.

Identity Taxonomy supplies advisory requirement vocabulary. It is not yet a
mandatory input to this lane.
