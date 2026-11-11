# Upstream Conformance Source

`openid-conformance-suite/` is a local, ignored Git checkout of the OpenID
Foundation conformance suite. Keep it at the release and commit recorded in
`conformance-suite.lock.json`; do not commit the third-party checkout
or its credentials, generated configuration, database, or test output into this
repository.

`conformance-suite.lock.json` is the sole source of truth for the repository,
release tag, and commit. Keeping those values out of this narrative avoids a
second pin that can drift from the executable lock.

`specifications.lock.json` separately binds the official OpenID4VCI,
OpenID4VP, and HAIP 1.0 Final publications by URL, byte length, and SHA-256.
Where the specification repository exposes a matching final tag, the lock also
records its exact source commit. HAIP has no final source tag, so its official
published Final document—not the working repository—is the certification
authority. The current HAIP working revision is retained only as a
non-certification engineering reference.

Verify it from the repository root with:

```sh
scripts/fetch_oidf_conformance_suite.sh
```

The fetcher clones the pinned tag only when the checkout is absent; it refuses
to replace or reset an existing checkout. The verifier is read-only. Generate
the exact source-resolved plan/module inventories with:

```sh
scripts/export_oidf_certification_modules.sh
scripts/export_oidf_certification_modules.sh \
  upstream/oidf/openid-conformance-suite \
  plans/oidf/engineering.json \
  upstream/oidf/snapshots/engineering-modules.json
```

The scheduled upstream-update workflow creates a review-only proposal for the
latest suite release, master commit, specification publication digests, and
source-tag commits. It does not edit these locks. After approving a proposed
baseline, update the locks in a dedicated review, fetch the exact suite commit,
regenerate both snapshots, and run release readiness before merging.

Running the suite itself requires its documented MongoDB, Java/Maven, Python,
TLS, and product-under-test configuration.

After configuring a local or hosted suite and the four role-specific product
configuration files, run the complete selected matrices through the upstream
`scripts/run-test-plan.py` with:

```sh
scripts/run_oidf_final_matrix.sh all
```

## Licensing

The ignored suite checkout and the source-derived metadata in `snapshots/` are
subject to the upstream OpenID Foundation MIT License. See `LICENSE.txt` and
`THIRD_PARTY_NOTICES.md`. ReallyMe's plan selection and packaging are licensed
under `MIT OR Apache-2.0`.

## Current-master engineering assessment

`engineering-master.lock.json` pins the reviewed master revision. The separate
`plans/oidf/engineering-master.json` matrix has the same 26
engineering configurations as the released-suite matrix. Check its source
contract with:

```sh
python3 scripts/verify_oidf_certification_parameters.py /path/to/conformance-suite \
  --manifest plans/oidf/engineering-master.json
```

Run it with the role configurations and suite endpoint required by the runner:

```sh
OIDF_CONFORMANCE_SUITE_DIR=/path/to/conformance-suite \
  scripts/run_oidf_final_matrix.sh engineering-master
```
 A verified manifest is a test target,
not passing product evidence. Certification and the recorded release snapshots
continue to use the official release lock.
