# Conformance adapter contracts

This directory owns orchestration metadata, not protocol implementations. Each
entry in `registry.json` maps a versioned plan to the ReallyMe repositories
that implement the exercised role and to the environment variable containing
the runner's deployment configuration. OIDF, EUDI Wallet, EUDI relying-party,
and ZK lanes remain separate because they have different owners, evidence
classes, and release artifacts.

Configuration files contain deployment-specific endpoints and credentials.
They must stay outside this repository and must never be copied into evidence.
