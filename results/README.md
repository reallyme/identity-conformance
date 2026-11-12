# Raw conformance results

Runners write raw output under `local/`. It may contain tokens, endpoints,
identifiers, request bodies, and other sensitive data. Git ignores this
directory. Raw output is not public or certification evidence.

After a complete run, redact the output, hash each retained artifact, and create
a schema-valid public record under `../evidence/`.
