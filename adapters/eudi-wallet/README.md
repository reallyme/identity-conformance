# EUDI Wallet engineering adapter

SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
SPDX-License-Identifier: MIT OR Apache-2.0

This adapter runs the committed `reallyme-wallet-conformance` package against
an exact Wallet source revision. It also checks that the release bundle and
component attestation describe that same revision.

The deployment manifest selects the Wallet candidate. The source checkout,
release artifact, and attestation must all name that commit. A missing or
different candidate is an error; the framework does not substitute a reference
Wallet version.

The result is engineering evidence. EU certification and external
interoperability require separate external evidence.

The framework's broader EU inventory is defined in
`plans/eudi/upstream-coverage.json`. The mobile UI suite, ITB, Age Verification
profile, RQES tester, and reference implementations are separate targets. They
do not count as executed until a dedicated runner checks their full results
against a deployed Wallet.

Only `reallyme/wallet` may call the reusable workflow. This repository does not
retain raw command output, credential payloads, private keys, or deployment
secrets.

## GitHub-hosted execution

The workflow runs on GitHub's `ubuntu-26.04` runner. The caller supplies
`framework_commit` and `candidate_artifact_name`. That artifact must come from
the same workflow run and contain `deployment.json`, `wallet-release`, and
`wallet-attestation.json`. The framework checks the inputs, checks out the
selected Wallet commit, runs the plan, and checks the result. It does not need a
self-hosted runner, preinstalled files, or publishing credentials.

Wallet prepares its release inputs and verifies their signed provenance. The
framework checks the component identity, digests, framework locks, and result.
Unverified metadata must not be used to create an attestation.

Upload the three files in an earlier job and make the reusable workflow depend
on that job. Use the same framework commit in the workflow reference and the
`framework_commit` input:

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

Replace `FRAMEWORK_COMMIT` in both places with the same full
identity-conformance commit. GitHub does not allow an expression in a reusable
workflow's `uses` value.
