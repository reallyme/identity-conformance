# ZK presentation-proof conformance lane

This lane binds a ReallyMe ZK release to its exact source revision, Noir and
Barretenberg toolchain lock, provider manifest, Cargo lock, release artifact
bundle, and component attestation. It runs the public API, artifact, protobuf,
codec, and canonical conformance packages with all features enabled.

The component attestation must independently record successful formatting,
lint, integration, vector, security, and build checks. This is necessary
because platform-specific native providers and sealed release artifacts cannot
all be reproduced inside the framework runner.

Passing this lane establishes internal proof-system release evidence. It is not
an OIDF certification. An OpenID4VP deployment that enables ReallyMe ZK must
also bind the same ZK source, artifact bundle, and attestation in its OIDF
deployment manifest and pass the composed OpenID4VP role.
