# OpenID4VP adapter lane

This lane connects the OpenID4VP verifier plan to the released product. The
wire protocol, DCQL behavior, state machine, HAIP policy, and protocol adapter
stay in `reallyme/openid4vp`. The deployable verifier in `reallyme/identity`
connects those parts to the product. This repository owns the shared plan and
evidence rules.

Wallet presentation uses the product Wallet lane so the run covers consent,
credential selection, key access, and protocol behavior together.
