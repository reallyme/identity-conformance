# EU PID alignment — 11 August 2026 consolidation

## Legal baseline

This review uses the official EUR-Lex consolidations dated 11 August 2026 for
[Commission Implementing Regulation (EU) 2024/2977](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R2977-20260811)
and
[Commission Implementing Regulation (EU) 2024/2979](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R2979-20260811),
including the changes made by
[Commission Implementing Regulation (EU) 2026/1731](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R1731).
The consolidation date is part of the implementation contract; later
amendments require a new delta review.

## PID scope and disposition

| Legal area | Implemented policy boundary |
| --- | --- |
| Natural-person mandatory data | `family_name`, `given_name`, `birth_date`, `birth_place`, `nationality`, and `portrait` are required. Portrait remains structurally present when the legal opt-out produces an empty value. |
| Natural-person optional data | Full residence address and its country/state/city/postal/street components, personal administrative number, family and given names at birth, sex, email address, and mobile phone number are recognized and encoding-checked when present. |
| Mandatory provider metadata | Issuing authority and issuing country are parsed and bounded; country syntax is enforced. Document number and jurisdiction are bounded when present. Issuance and expiry use an encoding-independent Gregorian date type that rejects impossible dates and issuance-after-expiry ordering. |
| mdoc PID | Document type and standard namespace are exactly `eu.europa.ec.eudi.pid.1`; the holder key is WSCD-protected; protected CB-AdES headers establish `x5u` and SHA-256 `x5t`; deterministic CBOR, date, Unicode, and 150-character constraints are represented as required facts. |
| SD-JWT VC PID | `vct` is exactly `urn:eudi:pid:1`; mandatory validity and holder `cnf` facts are enforced; each PID data identifier is independently selectively disclosable; protected `x5u` and `x5t#S256` are required. |
| Legal-person PID | Current legal name and a persistent cross-border identifier are mandatory. Address, VAT, tax, EUID, LEI, EORI, and excise identifiers are accepted only after their external semantic validation. No common wire mapping is invented where the Annex does not define one. |
| Revocation/status adaptation | PID, QEAA, and public-body EAA status is binary revoked/not-revoked, privacy preserving, and irreversible. Suspension is not admitted. The no-status exception is limited to credentials whose technical validity is at most 24 hours. |
| ETSI incorporation | Part 1 common/formats, Part 2 presentation, and Part 3 issuance facts are kept separate from their protocol, wallet, trust, and service evidence so the incorporated standard is not reduced to one library result. |

## Evidence

The reusable policy and tests are in
`reallyme/ssi/crates/eudi/etsi-eaa-conformance`. Its README declares credential
formats, PID categories, legal-person limits, and composition boundaries. The
complete ETSI identifier inventory is in
`requirements/etsi-ts-119-472.tsv` and is count- and uniqueness-tested.
The implementation directly validates non-PII profile structure; Boolean facts
are reserved for cryptographic, trust, raw-claim, status-fetch, and protocol
properties that must be established by their production owners.

This review establishes a versioned implementation and evidence boundary. It
does not represent certification, designation, or a third-party conformity
assessment.
