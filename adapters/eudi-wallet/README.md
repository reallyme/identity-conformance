# EUDI Wallet engineering adapter

SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
SPDX-License-Identifier: MIT OR Apache-2.0

This adapter runs every Wallet workspace test, with every feature enabled,
against an exact Wallet source revision. The result records the discovered test
count and inventory digest. It also proves that each executable case declared
in `conformance/eudi/test-cases.json` was present in Cargo's test inventory.
The package bundle and component attestation must describe the same revision.
The runner opens the bundle and independently checks its exact file set,
preflight records, Cargo lock, public crate inventory, crate digests, and each
crate's embedded source revision. It then verifies GitHub provenance for the
preflight manifest and every crate, and checks the exact Rust CI, protobuf, and
manually dispatched fuzz workflow run named by the preflight manifest. That run
must complete all four time-boxed Wallet fuzz campaigns; the shorter push smoke
run is not package evidence.

The deployment manifest selects a candidate or published target by exact
version, commit, and preflight run. Candidate mode does not use GitHub release
or crates.io metadata. Published mode also requires an exact release ID and tag
and verifies the release assets, publication ledger, and registry checksums.
The framework never selects a Wallet version for the caller.

Source locks, normative ledgers, and component attestations are reported
separately from code execution. They are not counted as executed tests. The
framework also injects five independent Rust probes into the selected source
checkout. They test provider record identifiers, key-custody encoding, consent
context binding, flow resumption after uncertain delivery, and lifecycle
enforcement. The probes use Wallet's public APIs and do not rely on the
candidate's own test assertions.

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

The workflow runs on GitHub's `ubuntu-26.04` runner. The caller supplies the
framework commit, conformance profile, target mode, target commit, target
version, preflight run ID, and artifact name. The artifact must come from
the same workflow run and contain `deployment.json`, `wallet-release`, and
`wallet-attestation.json`. The framework checks the inputs, checks out the
selected Wallet commit, runs the plan, and checks the result. It does not need a
self-hosted runner, preinstalled files, or publishing credentials.

Wallet prepares its package inputs and verifies their signed provenance. The
framework checks the component identity, digests, framework locks, and result.
Unverified metadata must not be used to create an attestation.

Upload the three files in an earlier job and make the reusable workflow depend
on that job. Use the same framework commit in the workflow reference and the
`framework_commit` input:

```yaml
permissions:
  actions: read
  attestations: read
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
      conformance_profile: eudi-wallet-engineering-v1
      target_mode: candidate
      target_commit: ${{ github.sha }}
      target_version: ${{ needs.prepare-conformance-candidate.outputs.version }}
      preflight_run_id: ${{ needs.prepare-conformance-candidate.outputs.preflight_run_id }}
      candidate_artifact_name: eudi-wallet-candidate-${{ github.sha }}
```

Replace `FRAMEWORK_COMMIT` in both places with the same full commit from a
published Identity Conformance release. The workflow verifies the release tag
and manifest before running the plan. GitHub does not allow an expression in a
reusable workflow's `uses` value.
