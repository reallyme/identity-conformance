# EUDI relying-party control-plane adapter

This adapter is the contract between the framework and the relying-party
implementation. The framework owns the assertions, EU pins, execution rules,
result schemas, and public evidence format. The implementation repository owns
its code, build, and detailed test records.

The caller supplies a clean candidate checkout, three release artifacts, and a
component attestation. Their digests must match the candidate commit and every
source required by the plan. The runner checks the attestation and EU source
revisions, runs bounded probes against the production binary, and can also
check service health and the live TS5 read profile.

The reusable workflow runs in the caller's repository. Source, secrets, logs,
and raw results remain under that repository's access controls. Only
evidence that passes redaction and disclosure review may enter `evidence/`.

The workflow reference and `framework_commit` input must use the same full
commit. Typed inputs provide the candidate, trust-service,
credential-authority, CA-certificate, and journal paths. Protected values are:

- `REALLYME_CI_TOKEN`
- `EUDI_DEPLOYMENT_MANIFEST_B64`
- `EUDI_COMPONENT_ATTESTATION_B64`

Deployed and live modes also require the service endpoints and bearer tokens
defined by the workflow. Live TS5 mode needs its protected configuration and
opaque relying-party identifier.

Only a manual or release-controlled event may start this workflow. Never run
untrusted pull-request code on its self-hosted runner. Use an ephemeral runner
and destroy its storage after the job.

This lane creates internal engineering evidence. It does not claim EU
certification. Inputs must use synthetic fixtures and must not contain wallet
transaction content, presented attributes, raw presentations, customer
registration data, private keys, or credential archives.
