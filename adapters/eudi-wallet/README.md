# EUDI Wallet engineering adapter

SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
SPDX-License-Identifier: MIT OR Apache-2.0

This adapter executes the committed `reallyme-wallet-conformance` package against an exact wallet source revision and exact conformance-input digests. It also binds the tested wallet release bundle to the component's release attestation.

The caller selects the Wallet candidate in the deployment manifest. The runner
requires the checked-out source, release artifact, and component attestation to
identify that same commit. The framework never substitutes a reference Wallet
revision when the caller omits or changes the candidate.

The lane is engineering evidence. It does not claim EU certification, EUDI Wallet certification, or successful interoperability with an external testbed. Such claims require separately reviewed external evidence.

The framework's broader EU inventory is defined in
`plans/eudi/upstream-coverage.json`. The official mobile UI suite, ITB, Age
Verification profile, RQES tester, and public reference implementations are not
silently folded into this adapter. They remain explicit gated or
interoperability-only targets until a dedicated runner validates their complete
native result formats against a deployed wallet release.

The reusable workflow must be called from `reallyme/wallet`. Raw command output, credential payloads, private key material, and deployment secrets are not retained by this repository.

## GitHub-hosted execution

The reusable workflow runs on GitHub's `ubuntu-26.04` runner. The caller supplies
`framework_commit` and `candidate_artifact_name`; the named Actions artifact
must come from the same workflow run and contain `deployment.json`,
`wallet-release`, and `wallet-attestation.json`. The framework validates these
inputs, checks out the exact manifest-selected Wallet commit, executes its plan,
and validates the result before uploading it. It requires no self-hosted runner,
preinstalled absolute paths, deployment secret, or publishing credential.

Wallet owns preparation of its public release inputs and verification of their
signed release provenance. The framework validates the supplied component
identity, artifact and attestation digests, framework locks, and execution
result. A caller must not turn unverified metadata into a release attestation.

The caller must upload the three files in a preceding job and make the reusable
workflow job depend on that job. Use the same immutable framework commit in the
workflow reference and `framework_commit` input:

```yaml
permissions:
  actions: read
  contents: read

jobs:
  prepare-conformance-candidate:
    runs-on: ubuntu-26.04
    steps:
      # Build and validate deployment.json, wallet-release, and
      # wallet-attestation.json from this exact Wallet candidate.
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: eudi-wallet-candidate-${{ github.sha }}
          path: |
            deployment.json
            wallet-release
            wallet-attestation.json
          if-no-files-found: error
          retention-days: 1

  eudi-wallet-conformance:
    needs: prepare-conformance-candidate
    uses: reallyme/identity-conformance/.github/workflows/eudi-wallet-conformance.yml@FRAMEWORK_COMMIT
    with:
      framework_commit: FRAMEWORK_COMMIT
      candidate_artifact_name: eudi-wallet-candidate-${{ github.sha }}
```

`FRAMEWORK_COMMIT` is a documentation placeholder and must be replaced in both
locations with the same full 40-character identity-conformance commit. GitHub
does not permit expressions in a reusable workflow's `uses` value.
