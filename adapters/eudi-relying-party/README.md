# EUDI relying-party control-plane adapter

This adapter is the public contract between the conformance framework and a
private ReallyMe implementation. The framework owns the assertions, pinned EU
sources, execution protocol, result schemas, and disclosure-safe evidence. The
implementation repository owns its source layout, build process, and detailed
test records.

The caller supplies a clean candidate checkout, three digest-bound release
artifacts, and a component attestation. The attestation binds the candidate
commit and artifacts to every assertion and upstream-source binding required by
the plan. The public runner validates that attestation, verifies the pinned EU
checkouts, exercises bounded production-binary probes, and optionally checks
deployed service health and the live TS5 read profile.

The reusable workflow runs in the caller's repository context. Consequently,
private source, secrets, logs, and short-lived raw results remain under the
private repository's access controls. Only evidence that has passed both a
redaction review and a public-disclosure review may be copied into `evidence/`.

The caller must pin the workflow and `framework_commit` to the same reviewed
40-character commit. It supplies candidate, trust-service, credential-authority,
CA-certificate, and journal filesystem locations through the workflow's typed
inputs. Those paths are runner configuration, not secrets. The caller must
provide the following protected values explicitly:

- `REALLYME_CI_TOKEN`
- `EUDI_DEPLOYMENT_MANIFEST_B64`
- `EUDI_COMPONENT_ATTESTATION_B64`

Deployed and live modes additionally require the protected service endpoints
and bearer tokens defined by the workflow. Live TS5 mode also requires the
protected live configuration and opaque relying-party identifier.

The workflow must be reachable only from a manual or release-controlled event.
It must not run untrusted pull-request code on a self-hosted runner. Use an
ephemeral runner whose storage boundary is destroyed after the job.

This lane creates internal engineering evidence. It does not claim EU
certification. Inputs must use synthetic fixtures and must not contain wallet
transaction content, presented attributes, raw presentations, customer
registration data, private keys, or credential archives.
