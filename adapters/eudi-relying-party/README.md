# EUDI relying-party control-plane adapter

This adapter is the contract between the framework and the relying-party
implementation. The framework owns the assertions, EU pins, execution rules,
result schemas, and public evidence format. The implementation repository owns
its code, build, and detailed test records.

The caller supplies a clean candidate checkout, three release artifacts, and a
component attestation. Their digests must match the candidate commit and every
source required by the plan. The runner checks the attestation and EU source
revisions. It then compares the candidate's vendored TS5 and TS6 files with the
framework's pinned files. A version label or attestation cannot replace this
byte-for-byte check.

After the source check passes, the runner executes the exact Rust tests listed
in `plans/eudi/relying-party-requirement-tests.json`. The two mapped assertions
are the service-to-service intermediary relationship and the strict
TS5 signed response. Each test is tied to one assertion, evidence class, source
clause, source-file digest, and normalized statement digest. These mappings are
test candidates, not evidence. They become execution observations only after a
clean immutable run and Taxonomy audit. The other 17 assertions have no exact
test bindings. All 19 remain non-evidentiary in the framework baseline, so this
profile cannot earn a product badge.

The reusable workflow runs in the caller's repository. The caller supplies the
substantive control-plane repository separately; the caller and the component
under test do not have to be the same repository. Source, secrets, logs, and
raw results remain under the caller's access controls. Only evidence that
passes redaction and disclosure review may enter `evidence/`.

The workflow reference and `framework_commit` input must use the same full
commit. The `candidate_repository` input names the component under test and
must match the repository in the protected deployment manifest. The current
requirement-test plan applies to `reallyme/eudi`; it does not select or pin an
EUDI product commit. Typed inputs provide the candidate, trust-service,
credential-authority, CA-certificate, and journal paths. Protected values are:

- `REALLYME_CI_TOKEN`
- `EUDI_DEPLOYMENT_MANIFEST_B64`
- `EUDI_COMPONENT_ATTESTATION_B64`

Deployed and live modes also require the service endpoints and bearer tokens
defined by the workflow. Live TS5 mode needs its protected configuration and
opaque relying-party identifier.

The caller may also supply an exact `taxonomy_commit`. When present, the
workflow checks out that caller-selected Taxonomy revision, binds each test to
its requirement inventory, and asks Taxonomy to audit a metadata-only receipt.
The framework does not choose a default Taxonomy revision. Without this input,
the tests still run but no Taxonomy receipt is produced.

Only a manual or release-controlled event may start this workflow. Never run
untrusted pull-request code on its self-hosted runner. Use an ephemeral runner
and destroy its storage after the job.

This lane creates internal engineering evidence. It does not claim EU
certification. Inputs must use synthetic fixtures and must not contain wallet
transaction content, presented attributes, raw presentations, customer
registration data, private keys, or credential archives.
