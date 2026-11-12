# OIDF upstream source

`openid-conformance-suite/` is an ignored local checkout of the OpenID
Foundation conformance suite. Keep it at the release and commit in
`conformance-suite.lock.json`. Do not commit the checkout, credentials,
configuration, database, or test output.

`conformance-suite.lock.json` is the only source for the repository, release
tag, and commit. They are not repeated here because duplicate pins drift.

`specifications.lock.json` separately records the official OpenID4VCI,
OpenID4VP, and HAIP 1.0 Final publications by URL, byte length, and SHA-256.
Where the specification repository exposes a matching final tag, the lock also
records its exact source commit. HAIP has no final source tag, so its official
published Final document—not the working repository—is the certification
authority. The current HAIP working revision is retained only as a
non-certification engineering reference.

Fetch and verify the checkout from the repository root:

```sh
scripts/fetch_oidf_conformance_suite.sh
```

The fetcher clones the pinned tag only when the checkout is missing. It will not
replace or reset an existing checkout. Generate the plan and module inventories
with:

```sh
scripts/export_oidf_certification_modules.sh
scripts/export_oidf_certification_modules.sh \
  upstream/oidf/openid-conformance-suite \
  plans/oidf/engineering.json \
  upstream/oidf/snapshots/engineering-modules.json
```

The weekly update workflow reports the latest suite release, master commit,
publication digests, and source-tag commits. It does not edit the locks. After
review, update the locks, fetch the selected commit, regenerate both snapshots,
and run release readiness.

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

## Development-branch engineering assessment

`engineering-master.lock.json` pins the reviewed master revision. The separate
`plans/oidf/engineering-master.json` matrix has the same 26
engineering configurations as the released-suite matrix. Verify that the
matrix matches the pinned revision:

```sh
python3 scripts/verify_oidf_certification_parameters.py /path/to/conformance-suite \
  --manifest plans/oidf/engineering-master.json
```

Run it with the role configurations and suite endpoint required by the runner:

```sh
OIDF_CONFORMANCE_SUITE_DIR=/path/to/conformance-suite \
  scripts/run_oidf_final_matrix.sh engineering-master
```
The verified manifest defines a test target, not a product result.
Certification and the recorded release snapshots use the official release
lock.
