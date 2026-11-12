# ZK presentation-proof conformance lane

This lane checks a ReallyMe ZK release against its source revision, Noir and
Barretenberg versions, provider manifest, Cargo lock, release bundle, and
component attestation. It runs the public API, artifact, protobuf, codec, and
canonical conformance packages with all features enabled.

The component attestation must record successful formatting, lint, integration,
vector, security, and build checks. The framework runner cannot rebuild every
native provider or sealed release artifact.

A pass is internal ZK release evidence, not OIDF certification. An OpenID4VP
deployment that uses ReallyMe ZK must name the same source, bundle, and
attestation in its deployment manifest and pass the composed OpenID4VP role.
