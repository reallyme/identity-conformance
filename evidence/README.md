# Public conformance evidence

Only evidence approved for public release belongs here. Keep raw output, suite
exports, screenshots, logs, deployment records, and internal attestations in
ignored `results/local/` storage or an approved restricted evidence store.

A public bundle must:

- match the applicable schema in `../schemas/`;
- identify the framework release, plan, and upstream source revisions, and
  either name a public product release or identify a non-public release through
  the opaque digests allowed by the schema;
- bind every retained artifact by SHA-256;
- contain only what is needed to support the claim;
- pass both redaction and public-disclosure review; and
- pass the repository publication and secret-scanning gates.

Component attestations support a result but do not replace the integration run.
For OIDF certification, the official hosted-suite result for the submitted
deployment is the technical result that matters.

EUDI relying-party public evidence must match
`../schemas/eudi-public-evidence.schema.json`. The private execution result and
component attestation remain outside this repository. The public record may
contain framework, source-lock, artifact, attestation, and result digests, plus
assertion outcomes and completed reviews. It must not disclose non-public
repository names, commits, test inventories, endpoints, credentials,
transaction content, customer identifiers, or key material.

EUDI Wallet and ZK results remain internal until a public-evidence schema has
been reviewed for them.

Certification and product-conformity claims require the complete evidence set,
not an individual plan, reference map, component test, or file.
