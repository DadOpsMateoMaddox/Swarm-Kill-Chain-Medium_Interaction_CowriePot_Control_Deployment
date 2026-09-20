# Test fixtures

## live-deployed-template-20260919.yaml

Verbatim `aws cloudformation get-template` output for stack
`patriotpot-2026-control-prod`
(`arn:aws:cloudformation:us-east-1:706162601288:stack/patriotpot-2026-control-prod/90c016a0-af23-11f1-8878-0affff84d99f`),
retrieved read-only 2026-09-19T23:19:39.617344+00:00.

SHA-256: `f583e85c0dde0ed4c108d271c6f34e5c6af97af80459dd05cec2894f8266e28e`
(matches `AUTH_PARITY_ACTIVE_VERIFIED` / the auth-parity candidate template
byte-for-byte).

**Deliberately not a git commit reference.** H2's feature commit (`3f2c115`)
is chronologically *before* every AuthParity commit in this repo's git
history, so every commit reachable from `main` that has AuthParity content
already has H2 content merged into the same file -- there is no commit that
reflects "AuthParity deployed, H2 absent," which is the actual live state.
Using a git commit as a stand-in for "the deployed baseline" (as the
auth-parity test suite does with `32d89ee`, which predates H2) works only by
chronological coincidence; it does not work here. This file is the live
template's real retrieved bytes instead, consistent with the project-wide
invariant that deployed state is established from CloudFormation, never
inferred from Git.

Confirmed at retrieval time:
`HAS_AUTHPARITY_ASSOC=True`, `HAS_AUTHPARITY_INSTRUMENTATION_FIX=False`,
`HAS_H2_INTEL_PARAM=False`, `HAS_H2_THREATINTEL=False`.
