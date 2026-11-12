# EUDI upstream references

These locks select the public EU sources used for ReallyMe Wallet and eIDAS 2.0
work: governing material, test assets, and interoperability targets. They cover
the sources relevant to this framework rather than the full EU Digital Identity
Wallet organization.

`sources.lock.json` covers:

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

Each Git source records a ref and its resolved commit. The weekly check compares
it with the latest release, tag, or default branch, as specified by the source's
update policy. Local checkouts belong under
`upstream/eudi/checkouts/`, which is ignored.

FCAF remains a pre-1.0 assessment baseline. The issuer Wallet tester targets
OpenID4VCI draft 13 and is kept only for legacy compatibility. The documentation
portal is monitored for changes but does not determine a result.

## Pinning and execution

A pin identifies the reviewed source revision.
`plans/eudi/upstream-coverage.json` records whether its software or tests ran.

The current relying-party lane runs ReallyMe-owned TS5/TS6 controls and verifies
the selected EU checkouts. The current Wallet lane runs the wallet component
package and binds its attestation to the complete EU source lock. A separate
upstream-assets lane verifies the exact Wallet UI feature inventory, ITB suite
and case references, FCAF Wallet methodology files, Age Verification profile
and ZKP annex, and RQES tester service structure.

The upstream-assets lane validates those source inventories. It does not run
their cases against a Wallet.

Those external suites need real deployment inputs:

- the UI suite needs published Android and iOS builds, device infrastructure,
  and a macOS runner for iOS;
- ITB needs a deployed wallet and testbed;
- RQES needs deployed wallet, QTSP, external-SCA, and relying-party services;
  and
- Age Verification needs a deployed profile and a dedicated adapter.

Until those adapters and environments exist, the coverage plan rejects any
claim that the external suites ran. The RQES tester's Python requirements are
not installed because they need a separate security review.

## Publications and law

`references/eudi-publications.lock.json` records the downloadable RFC, W3C, and
ETSI publications used by the Wallet work, together with their SHA-256 and byte
length. OpenID Final and ETSI 119472/119612 remain in their existing locks.

ISO/IEC 18013-5, 18013-6, 18013-7, and 23220-2 are copyright-restricted. They
are pinned by exact standard number, edition, publication date, and official
catalog URL; their full text is not copied here. The Digital Credentials API is
recorded as a dated Working Draft and cannot support a certification claim.

`legal-sources.lock.json` records the ELI and CELEX identifiers for the eIDAS
regulation, the European Digital Identity Framework amendment, Wallet
implementing regulations, qualified and public-sector EAA rules, and the 2026
amendments. Law and adopted implementing acts take priority over the engineering
references in this directory.
