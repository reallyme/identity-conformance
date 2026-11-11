# OpenID4VCI adapter lane

This lane describes conformance orchestration for the OpenID4VCI issuer role.
The wire protocol, state machine, HAIP policy, and executable adapter remain in
`reallyme/openid4vci`; this repository owns only the plan-to-product binding.

Wallet-side issuance is composed through the product wallet lane because OIDF
must exercise the deployable product rather than an isolated protocol engine.
