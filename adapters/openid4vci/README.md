# OpenID4VCI adapter lane

This lane connects the OpenID4VCI issuer plan to the released product. The wire
protocol, state machine, HAIP policy, and executable adapter stay in
`reallyme/openid4vci`.

Wallet issuance uses the product Wallet lane so OIDF tests the deployable
product, not an isolated protocol engine.
