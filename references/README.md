# Normative source references

This directory records reviewable citations for normative sources used across
ReallyMe identity repositories. `normative-sources.lock.json` pins the official
publication URL, edition, byte length, and SHA-256 digest of each reviewed
artifact. Copyrighted standards documents are reference-only and must not be
committed here.

Clause reviews distinguish requirements stated by a source from ReallyMe
implementation decisions and from evidence that only exercises one layer of a
larger conformance claim. A source reference or passing parser test is not, by
itself, a certification or a claim of complete conformity.

`pin-policy.json` records the release and immutable-ref monitors used by the
scheduled freshness workflow. It also identifies sources that require manual
review because a mechanical update would be unverifiable or would bypass a
required clause review.

The ETSI TS 119 472 series review is in `etsi-ts-119-472-series.md`. Its EU PID
legal alignment and current consolidated implementing-act baseline are in
`eu-pid-2026-alignment.md`.

The generated, fail-closed ETSI/EU requirement mapping is retained under
`etsi-eaa-pid/` because it is a source trace rather than an execution result.
Taxonomy inputs under `taxonomy-advisory/` support manual coverage analysis;
they are not framework-release inputs or evidence of product conformity.
