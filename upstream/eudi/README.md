# EUDI upstream references

This directory records the exact public EU revisions selected for ReallyMe's
wallet and eIDAS 2.0 work. It is a curated inventory, not a mirror of every
repository in the EU Digital Identity Wallet organization. A source is included
when it governs wallet behavior, provides an official test asset, or is useful
as a concrete interoperability target.

`sources.lock.json` covers six distinct kinds of material:

- the released ARF, draft FCAF, technical-specification catalog, attestation
  rulebooks, and Age Verification specification, including its ZKP profile;
- the official wallet UI test application, ITB, issuer wallet tester, and RQES
  wallet-driven tester;
- the Android and iOS reference wallets and their core libraries;
- PID issuance, wallet-provider, verifier, trust-list, status-list, and
  status-validation reference components;
- the RQES wallet libraries, CSC libraries, QTSP, external SCA, and relying-party
  reference stack; and
- the source of the official documentation portal.

Each Git source is pinned to both a ref and its resolved commit. The weekly pin
monitor checks releases, tags, or default-branch heads according to the source's
declared update strategy. Local checkouts belong under
`upstream/eudi/checkouts/`, which is ignored.

The inventory is deliberately honest about maturity. FCAF remains a pre-1.0
assessment baseline. The issuer wallet tester targets OpenID4VCI draft 13 and is
therefore retained only for legacy compatibility; it is not evidence of
OpenID4VCI Final conformance. The documentation portal is monitored for drift
but does not govern a conformance result.

## Pinning and execution

A pin says which upstream material was reviewed. It does not say that the
upstream software or test suite ran successfully. The machine-validated matrix
in `plans/eudi/upstream-coverage.json` records that distinction for every source.

The current relying-party lane runs ReallyMe-owned TS5/TS6 controls and verifies
the selected EU checkouts. The current Wallet lane runs the wallet component
package and binds its attestation to the complete EU source lock. Neither lane
currently runs the official mobile UI suite, ITB, FCAF cases, Age Verification
profile, or RQES wallet-driven tester directly.

Those external suites need real deployment inputs:

- the UI suite needs published Android and iOS builds, device infrastructure,
  and a macOS runner for iOS;
- ITB needs a deployed wallet and testbed;
- RQES needs deployed wallet, QTSP, external-SCA, and relying-party services;
  and
- Age Verification needs a deployed profile and a dedicated adapter.

Until those adapters and environments exist, the sources remain pinned and
freshness-monitored, and the coverage plan fails closed against any claim that
the official suites were executed.

## Publications and law

`references/eudi-publications.lock.json` independently pins the wallet-relevant
RFC, W3C, and ETSI publications that are publicly downloadable. These are bound
by SHA-256 and byte length. It delegates the already reviewed OpenID Final and
ETSI 119472/119612 bindings to their existing locks instead of duplicating
them.

ISO/IEC 18013-5, 18013-6, 18013-7, and 23220-2 are copyright-restricted. They
are pinned by exact standard number, edition, publication date, and official
catalog URL; their full text is not copied here. The Digital Credentials API is
recorded as a dated Working Draft and cannot support a certification claim.

`legal-sources.lock.json` separately records the immutable ELI and CELEX
identifiers for the governing eIDAS regulation, the European Digital Identity
Framework amendment, the wallet implementing regulations, the qualified and
public-sector EAA regulation, and the 2026 amendments. Binding legislation and
adopted implementing acts take precedence over every engineering reference and
reference implementation in this directory.
