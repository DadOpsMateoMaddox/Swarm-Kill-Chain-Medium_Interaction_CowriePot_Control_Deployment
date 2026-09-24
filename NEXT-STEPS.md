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

Two additional sensors are now in **design and implementation**, but neither is
deployed yet. Supporting work already completed includes preparation of the
2025 corpus, the current research corpus used for the 2026 experiment, and a
mock dashboard for the broader multi-sensor workflow.

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

## Additional sensors — design/implementation underway

Two additional honeypots are actively being designed and implemented. They are
not yet deployed:

1. **Second Cowrie sensor** (medium-interaction) — a separate experimental
   sensor derived from the Control-0 baseline. Work is underway on the
   experiment design, shared/reused corpus, dashboard workflow, provisioning
   approach, evidence layout, and deployment boundaries.
2. **High-interaction honeypot** — a materially different threat model from
   Cowrie's medium-interaction design (real OS/services vs. simulated). Design
   and implementation work is underway, including how the current research
   corpus and dashboard workflow map into the richer environment. Its
   architecture, isolation controls, and deployment gate remain distinct from
   Control-0.

The fact that supporting design artifacts and corpus preparation exist should
not be conflated with deployment. Neither additional sensor is currently live.

## Picking this back up

For Control-0, read `evidence/H2-GATE.md` and `evidence/AUTH-PARITY-GATE.md`
first — both gates are closed and should not be reopened absent an actual
behavioral defect. Reconcile `DRIFT-01` through the deployment path before any
new live-only fix.

For the two additional sensors, continue their design/implementation as their
own gated workstreams using the same discipline established here:
live-template-derived change sets where applicable, structural scope guards,
behavioral test suites before AWS writes, review-only change sets before
execution, and evidence files recording each step.
