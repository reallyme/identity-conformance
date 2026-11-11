# Raw conformance results

The OIDF runner writes raw exports beneath `local/`. These files may contain
tokens, endpoints, identifiers, request bodies, and other sensitive material.
The directory is ignored by Git and must not be used as certification evidence.

After a complete run, review and redact the output, hash every retained
artifact, and create a schema-valid disclosure record under `../evidence/`.
