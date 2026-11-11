# ETSI TS 119 472 series clause review

## Source citations

This review is bound to the exact official ETSI publications recorded in
`normative-sources.lock.json`:

| Part | Edition | Publication | Bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| 1 | V1.2.1 | February 2026 | 523,959 | `0f76ce7cad5f046802146b0c2a9cd8af9db3c1db77db5eeca86d2a4559fcfc3f` |
| 2 | V1.3.1 | July 2026 | 174,632 | `e403e7d5a4c70d04868989cc623b57d379a5f3dfe282f9f98f7390c8e327310b` |
| 3 | V1.1.1 | March 2026 | 143,808 | `2919437478c7469881afc5acd5aa68d847a4cfdc1bbf6da9224f4c9fae7167ba` |

The copyrighted PDFs are reference-only and are not vendored. The SSI
requirement index contains identifiers, editions, counts, and source digests,
but no copied normative prose.

## Clause findings and implementation boundaries

| Source clauses | Reviewed area | Production owner and evidence boundary |
| --- | --- | --- |
| Part 1 clause 4 | Common EAA semantics: type/category, issuer and subject identity, validity, use constraints, evidence, status, disclosure, key binding, and signatures. | `reallyme/ssi` directly parses and bounds non-PII identifiers and URIs, rejects duplicates, validates issuance/renewal ordering and evidence references, and applies category/status/disclosure policy in `validate.rs`. Credential parsers, signature verification, trust evaluation, and status retrieval separately evidence only the cryptographic or raw-payload properties they own. |
| Part 1 clauses 5 and 6 | SD-JWT VC and ISO/IEC mdoc realizations of the common semantics. | `reallyme/ssi` validates type, validity, disclosure, holder-key, protected certificate-reference, deterministic encoding, date, and text facts. Existing envelope and trust crates own the underlying parsing and cryptography. |
| Part 1 clauses 7 and 8 | JSON-LD W3C VC and X.509 Attribute Certificate realizations. | `reallyme/ssi` provides fail-closed profile boundaries; their format-specific production parsers and cryptographic suites remain prerequisite evidence and are not replaced by policy facts. |
| Part 2 clauses 4 and 5 | SD-JWT+KB and ISO/IEC mdoc presentation, including reader authentication, access/registration material, request information, and DeviceResponse constraints. | `reallyme/ssi` owns the reusable presentation-fact validator. `reallyme/openid4vp`, Wallet, and Identity own session, transport, request, trust, and deployed verifier behavior. |
| Part 2 clause 6 | OpenID4VC-HAIP presentation, non-API redirect requirements, encrypted responses, and optional API-mediated controls. | `reallyme/ssi` validates the cross-layer facts. `reallyme/openid4vp` owns the protocol state machine; Wallet and Identity own API privacy, lifecycle, UI, URI handling, and deployment evidence. |
| Part 2 Annexes A, C, and D | JSON-LD and X.509 Attribute Certificate presentation profiles and request projections. | SSI format policy is present. Complete product evidence additionally requires the applicable parser, transport, protocol, and trust implementations. |
| Part 3 clause 4 | Signed issuer metadata, provider access/registration information, reuse and embedded disclosure policies, credential offers, PAR, token, credential, and notification requests. | `reallyme/ssi` validates issuer, policy, flow, and proof inputs and parses the HTTPS notification endpoint, bounded opaque notification identifier, and closed event set. `reallyme/openid4vci` and the issuer/wallet compositions own wire/state-machine and access-token evidence. |
| Part 3 clauses 5 and 6 | Required cryptographic suites and inherited OpenID4VCI security considerations. | SSI rejects incomplete AES-GCM support and absent policy application. Algorithm implementations, key custody, HTTP security, and operational controls remain evidence from their production owners. |
| Part 3 Annexes A and B | Issuance of X.509 Attribute Certificate and JSON-LD W3C VC EAAs. | SSI advertises and validates the selected format boundary; end-to-end issuance evidence remains format- and service-specific. |

## Requirement completeness

The SSI index records all 740 unique identifiers found in the selected
publications: 548 in Part 1, 88 in Part 2, and 104 in Part 3. It deliberately
includes optional, conditional, recommended, and void identifiers so that an
assessment must make applicability explicit.

Identifier completeness is not the same as whole-system conformity. A
product-level claim requires an evidence disposition for every applicable
identifier and composition of the relevant parser, cryptographic, trust,
status, protocol, service, wallet, negative-test, and operational evidence.

## EU legal alignment

The implementation baseline also applies Commission Implementing Regulations
(EU) 2024/2977 and 2024/2979 in their consolidations of 11 August 2026, as
amended by Commission Implementing Regulation (EU) 2026/1731. The detailed
PID and status adaptation review is recorded in `eu-pid-2026-alignment.md`.
