# Conformance adapter contracts

Adapter contracts connect a conformance plan to a product. Protocol
implementations stay in their product repositories.

Each entry in `registry.json` names the plan, the repositories that implement
the tested role, and the environment variable that supplies deployment
configuration. OIDF, EUDI Wallet, EUDI relying-party, and ZK use separate
contracts because they have different inputs, results, and release artifacts.

Deployment configuration may contain endpoints and credentials. Keep it out of
this repository and out of public evidence.
