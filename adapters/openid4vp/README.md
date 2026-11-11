# OpenID4VP adapter lane

This lane describes conformance orchestration for the OpenID4VP verifier role.
The wire protocol, DCQL behavior, state machine, HAIP policy, and protocol-local
adapter remain in `reallyme/openid4vp`. The deployable verifier harness composes
those boundaries with product providers in `reallyme/identity`; this repository
owns only the plan-to-product binding and retained evidence.

Wallet-side presentation is composed through the product wallet lane so that
consent, credential selection, key access, and protocol behavior are tested as
the released product exposes them.
