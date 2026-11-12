<!-- BEGIN GENERATED CONFORMANCE CATALOG -->
# Standards baseline

Framework version: **v0.3.0**

The framework pins the specifications, requirements, and test suites listed
below. Each entry identifies the upstream version, the implemented validation,
and when the pin was last reviewed.

[![Framework](https://img.shields.io/static/v1?label=Framework&message=v0.3.0&color=475569)](../VERSION)
[![EU ARF](https://img.shields.io/static/v1?label=EU%20ARF&message=v3.0.0%20included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md)
[![EU technical specifications](https://img.shields.io/static/v1?label=EU%20technical%20specifications&message=included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/cfc383e44294d65cfa6cccbbff6c927f0df91f9a/docs/technical-specifications/ts3-wallet-unit-attestation.md)
[![EU FCAF](https://img.shields.io/static/v1?label=EU%20FCAF&message=v0.0.10%20included&color=0f766e)](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/blob/944b8f89cc17873c47026a05dfa9d212e89b0ee3/docs/fcaf/suts/wallet_solution/index.md)
[![OIDF suite](https://img.shields.io/static/v1?label=OIDF%20suite&message=release-v5.3.4%20included&color=1d4ed8)](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638)

Inclusion does not imply product conformance. Results are published by the
repositories running these checks. Baseline dates record framework adoption or
review, not upstream publication.

### European Union

| Standard or suite | Version | Validation | Baseline updated |
| --- | --- | --- | --- |
| [Architecture and Reference Framework — WUA_33](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md) | `v3.0.0` | Checks the reported Wallet value against `wallet.wia.technical_validity_seconds < 86,400`. | 2026-11-12 |
| [Architecture and Reference Framework — EW-DM-44-027](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/annexes/annex-2/annex-2.03-high-level-requirements-by-category.md) | `v3.0.0` | Validates `wallet.presentation.unregistered_attribute_policy` against the permitted values: `warn_and_allow_all`, `registered_only`, `reject_request`. | 2026-11-12 |
| [Technical Specification 3 — Wallet Unit Attestation — 2.2.1.1](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/cfc383e44294d65cfa6cccbbff6c927f0df91f9a/docs/technical-specifications/ts3-wallet-unit-attestation.md) | `main` | Checks the reported Wallet value against `wallet.wia.technical_validity_seconds < 86,400`. | 2026-11-12 |
| [Functional Conformance Assessment Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/blob/944b8f89cc17873c47026a05dfa9d212e89b0ee3/docs/fcaf/suts/wallet_solution/index.md) | `v0.0.10` | Wallet Solution assessment methodology. `methodology_only`. No executable test cases in `v0.0.10`. | 2026-11-12 |
| [EUDI Wallet testing application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application/tree/62c4ba73007ea25440e6ba24a651937bc692629b/src/test/resources/features) | `2026.Q1` | Verifies `126` feature files and `798` scenarios. Device execution is separate. | 2026-11-12 |
| [EUDI Interoperability Test Bed](https://github.com/eu-digital-identity-wallet/eudi-itb/tree/b0e222435401242e2a2a62181500bc2403e6e0dd/tests) | `main` | Verifies `5` suites and `39` test cases. Deployed execution is separate. | 2026-11-12 |
| [Age Verification specification and ZKP profile](https://github.com/eu-digital-identity-wallet/av-doc-technical-specification/blob/febecb892435c544e539f44d0adefd580076dd3e/docs/annexes/annex-B/annex-B-zkp.md) | `v1.0.6` | Verifies `3` profile and annex documents. No executable conformance suite in `v1.0.6`. | 2026-11-12 |
| [RQES Wallet-driven tester](https://github.com/eu-digital-identity-wallet/eudi-app-web-walletdriven-tester-py/tree/bdfdd85295abb0eeed5c63f3958731c6a344bd57/app) | `v0.3` | Verifies `23` Python files and `22` routes. Upstream dependencies are excluded from CI. | 2026-11-12 |

### OpenID Foundation

| Standard or suite | Version | Validation | Baseline updated |
| --- | --- | --- | --- |
| [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | `1.0 Final` | Final specification for Issuer and Wallet certification plans. SHA-256 `f123c3178cacd27688b15b762098a045e9eb35eccfe2f5f18a357c3815e06ba7` | 2026-11-11 |
| [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | `1.0 Final` | Final specification for Verifier and Wallet certification plans. SHA-256 `e4f0abc689afd0a4f6c41b83954d7f970c5263a26143ad861216aea9918993bb` | 2026-11-11 |
| [OpenID4VC High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) | `1.0 Final` | High-assurance profile for OID4VCI and OID4VP plans. SHA-256 `3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb` | 2026-11-11 |
| [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638) | `release-v5.3.4` | Executable certification suite. The Wallet subset contains `10` configurations and `278` module executions. Commit `23353b36957d6466010de767c812d2c91ed37638` | 2026-10-26 |

<!-- END GENERATED CONFORMANCE CATALOG -->
