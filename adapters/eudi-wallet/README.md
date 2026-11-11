# EUDI Wallet engineering adapter

SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
SPDX-License-Identifier: MIT OR Apache-2.0

This adapter executes the committed `reallyme-wallet-conformance` package against an exact wallet source revision and exact conformance-input digests. It also binds the tested wallet release bundle to the component's release attestation.

The lane is engineering evidence. It does not claim EU certification, EUDI Wallet certification, or successful interoperability with an external testbed. Such claims require separately reviewed external evidence.

The framework's broader EU inventory is defined in
`plans/eudi/upstream-coverage.json`. The official mobile UI suite, ITB, Age
Verification profile, RQES tester, and public reference implementations are not
silently folded into this adapter. They remain explicit gated or
interoperability-only targets until a dedicated runner validates their complete
native result formats against a deployed wallet release.

The reusable workflow must be called from `reallyme/wallet`. Raw command output, credential payloads, private key material, and deployment secrets are not retained by this repository.
