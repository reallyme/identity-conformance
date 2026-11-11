# Public conformance evidence

This directory is reserved for reviewed, disclosure-safe evidence. Raw runner
output, suite exports, screenshots, logs, deployment records, and internal
attestations belong in ignored `results/local/` storage or an approved private
evidence store.

A public bundle must:

- conform to the applicable schema in `../schemas/`;
- identify the framework release, plan, and upstream source revisions, and
  either name a publicly disclosable product release or bind the reviewed
  private release through opaque digests defined by the applicable schema;
- bind every retained artifact by SHA-256;
- contain only the minimum information needed to substantiate its claim;
- pass both redaction and public-disclosure review; and
- pass the repository publication and secret-scanning gates.

Component attestations are supporting evidence. They do not replace the
composed execution result. For OIDF certification, the authoritative technical
result is the official hosted-suite result for the exact submitted deployment.

EUDI relying-party public evidence must conform to
`../schemas/eudi-public-evidence.schema.json`. The private execution result and
component attestation remain outside this repository. The public commitment may
contain framework, source-lock, artifact, attestation, and private-result
digests plus assertion outcomes and completed reviews. It must not disclose
private repository identities, commits, test inventories, endpoints,
credentials, transaction content, customer identifiers, or key material.

EUDI Wallet and ZK results are internal engineering records. They require a
separately reviewed public-evidence schema before promotion into this tree.

The presence of a plan, reference mapping, passing component test, or this
directory does not establish certification or product conformity.
