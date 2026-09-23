# Next Steps — updated 2026-09-23 (was: paused 2026-09-20)

## Current state

Control deployed. AuthParity closed. H2 closed. Live enrichment verified.
Credential-exposure incident remediated and closed. Details:
`evidence/AUTH-PARITY-GATE.md`, `evidence/H2-GATE.md`.

**On 2026-09-23 the sensor was found to have been producing zero
post-authentication telemetry.** 16,070 successful logins had yielded zero
`cowrie.command.input`. Three independent defects (P0A/P0B1/P0B2) were root-
caused and live-repaired; the full post-auth pipeline is now proven end to
end, including enriched Discord delivery. See
`evidence/2026-09-23-p0-recovery/` and
`evidence/2026-09-23-p0c-characterization/`.

This changes the meaning of the 2026-09-20 pause tag: the gates were closed
correctly, but H2's real-world *input* was empty for that window. No
conclusion about attacker behaviour may be drawn from pre-2026-09-23
enrichment output.

## Open ledger

| ID | Item | Status | Notes |
| --- | --- | --- | --- |
| P0A/P0B1/P0B2 | Host keys, `[shell] processes`, tty ownership | **FIXED (live only)** | Verified both SSH paths + full command telemetry |
| **DRIFT-01** | Encode all three P0 fixes into IaC | **OPEN — highest priority** | Live host diverges from every template. `evidence/2026-09-23-p0-recovery/live-drift.yaml` has exact required changes. Must ship via **SSM Association** — `bootstrap-native.sh` is `BootstrapBundleId` → UserData → **instance replacement** |
| **DEPLOY-01** | Sub-second duration renderer not deployed | **OPEN** | Fix committed `e3a500a`; live sidecar still renders `Duration: 0s`. Requires an H2 bundle republish |
| P0C-C | Deception filesystem characterization | **CLOSED 2026-09-23** | `evidence/2026-09-23-p0c-characterization/09-...md` |
| P0C-R | Namespace deltas → `fs.pickle` | OPEN | Only paths marked `allowed: true` in `08-...yaml`. Must revise the hash pin at `native/bootstrap-native.sh:287` in the same change or it fails closed |
| P0C-R2 | Shell emulation (`~`, `ls -d`, `ps`) | OPEN | **Not** an `fs.pickle` fix — Cowrie command implementations |
| P0C-R3 | `/test2` removal, `/etc/passwd` ↔ `/home` consistency | OPEN | Honeypot fingerprint reduction |
| P0C-V | Attacker-view verification on fresh deployment | BLOCKED on P0C-R | |
| **HIST-01** | Sep-18 16,070/0 attribution | OPEN | Narrow question: which of P0A/P0B1/P0B2 were *active* during the Sep-18 burst. Use only the frozen tracebacks — no reconstructed error strings. Target: `cowrie.json.2026-09-18` |

**Standing constraint (operator, 2026-09-23):** no further live-only repairs.
Additional surgical fixes would destroy the distinction between *recovered*
state and *reproducible* state. The next change to the sensor should arrive
through the deployment path, not through SSM.

Do not conflate two claims: "P0B2 existed and is fixed" is **VERIFIED**;
"P0B2 caused the Sep-18 observation" is **NOT YET VERIFIED**.

## Deferred to next session — do not start tonight

Two more sensors, not yet begun, no design work done on either:

1. **Another Cowrie instance** (medium-interaction) — presumably a second
   independent sensor, not a modification of Control-0. Scope,
   provisioning bundle strategy, and evidence-bucket layout (shared vs.
   per-sensor) all still need deciding before any implementation.
2. **One high-interaction honeypot** — a materially different threat
   model from Cowrie's medium-interaction design (real OS/services vs.
   simulated), so this needs its own architecture/isolation review before
   any template or bootstrap work starts, not just a copy of Control-0's
   pattern.

Neither should be started as an extension of tonight's H2 momentum —
each deserves its own fresh design pass, and forcing scope onto an
already-closed gate's session risks disturbing the known-good state
recorded above for no benefit.

## Picking this back up

Read `evidence/H2-GATE.md` and `evidence/AUTH-PARITY-GATE.md` first —
both gates are closed and should not be reopened absent an actual
behavioral defect. Then scope the two new sensors as their own gates,
following the same discipline established here: live-template-derived
change sets, structural scope guards, behavioral test suites before any
AWS write, review-only change sets before execution, and evidence files
recording each step.
