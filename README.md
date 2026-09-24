# PatriotPot 2026 Control-0

This repository contains the 2026 PatriotPot **Control-0** Cowrie sensor and its deployment, validation, recovery, and evidence artifacts.

## Current state — 2026-09-23

Control-0 is **deployed and live** in `us-east-1`.

- Cowrie v2.5.0 is running natively on Amazon Linux 2 under CPython `3.8.20`.
- The attacker-facing service is exposed only on **TCP/2222 over IPv4**. TCP/22 and TCP/2223 remain disabled, and there is no IPv6 ingress.
- Administrative access is SSM-only; host `sshd` remains disabled/masked.
- Local `cowrie.json` remains the authoritative event source, with independent content-addressed S3 archival and CloudWatch retained as an operational copy.
- AuthParity is closed, H2 is closed, and live enrichment is verified.
- The credential-exposure incident is remediated and closed.

### September 23 P0 recovery

On 2026-09-23, Control-0 was found to have recorded **16,070 successful logins and zero `cowrie.command.input` events**. Three independent post-authentication defects were root-caused:

- **P0A** — SSH host-key slot corruption
- **P0B1** — invalid `[shell] processes` configuration
- **P0B2** — TTY log directory ownership

All three were repaired on the live host and the post-authentication pipeline was then verified end to end, including command telemetry and enriched Discord delivery. Evidence is under `evidence/2026-09-23-p0-recovery/` and `evidence/2026-09-23-p0c-characterization/`.

**Measurement caveat:** no attacker-behavior conclusion should be drawn from the pre-2026-09-23 H2 enrichment window because its real-world post-authentication input was empty.

**Reproducibility caveat:** the P0A/P0B1/P0B2 repairs are currently live-only. `DRIFT-01` remains open to encode them into the deployment path so an instance replacement cannot recreate the defects. See `NEXT-STEPS.md` and `evidence/2026-09-23-p0-recovery/live-drift.yaml`.

## Research program status

Control-0 is the deployed baseline sensor. Two additional honeypots are already in **design and implementation**, but are **not yet deployed**:

1. **Second Cowrie sensor** — medium-interaction, intended as a separate experimental sensor derived from the Control-0 baseline.
2. **High-interaction honeypot** — a separate real-system interaction environment requiring its own isolation and threat-model controls.

Supporting research work has already begun, including preparation of the working corpus and a mock dashboard for the broader 2026 experiment. Deployment gates for both additional sensors remain pending.

`NEXT-STEPS.md` is the active implementation/deployment ledger for Control-0 and the remaining sensor work.

## Frozen control target and provenance

The original pre-exposure baseline remains preserved as historical evidence. Core recovered/reproduced properties include:

- AWS Region: `us-east-1`
- official Amazon Linux 2 x86_64 HVM EBS AMI, owner `137112412989`, pinned per deployment
- CPython `3.8.20` installed side-by-side at `/opt/python/3.8.20`
- Cowrie tag `v2.5.0`, commit `000116838246ce522b1f6953c6f108a3a4f0611c`
- native `/opt/cowrie` runtime owned as code by root and executed by locked user `cowrie`
- local authoritative `/opt/cowrie/var/log/cowrie/cowrie.json`
- local Discord monitor with durable inode/offset/dedupe state
- independent content-addressed S3 archive service and timer
- no Docker, containerd, Podman, or ECS runtime dependency
- Control-0 itself has no adaptive deception, active defense, swarm behavior, or AI-generated attacker responses

### Recovered assets

The following candidate files were recovered from deleted git blob `b63431c8`:

| File | Deployment location |
|---|---|
| `cowrie.cfg` | `/opt/cowrie/etc/cowrie.cfg` |
| `userdb.txt` | `/opt/cowrie/etc/userdb.txt` |
| `honeyfs-etc-passwd` | `/opt/cowrie/honeyfs/etc/passwd` |
| `honeyfs-home-admin-passwords.txt` | `/opt/cowrie/honeyfs/home/admin/passwords.txt` |
| `txtcmds-bin-ps` | `/opt/cowrie/share/cowrie/txtcmds/bin/ps` |
| `txtcmds-bin-netstat` | `/opt/cowrie/share/cowrie/txtcmds/bin/netstat` |

These files match the recovered deployment-script heredoc and important values are corroborated by captured telemetry. **Exact live 2025 `cowrie.cfg` provenance remains unverified**, so the cfg is labeled `RECOVERED_CANDIDATE`, not exact.

The credential-shaped strings in the honeyfs bait file are inert deception content. Deployment preflight scans published assets for private keys, Discord webhook URLs, and AWS access-key patterns.

## Approved filesystem substitution

The 2025 `fs.pickle` was not recovered. The deployment uses the stock file from the pinned Cowrie v2.5.0 commit:

```text
06f0ed527bdc133b3fabca5def3db084b120bdf6b8e47736a85cd12e98b36da9
```

This is an approved, explicitly documented substitution — not a recovered artifact. Ongoing P0C work is characterizing and reducing attacker-visible namespace deltas without rewriting provenance history.

## Native deployment assets

`native/bootstrap-native.sh` downloads direct assets from a content-addressed, versioned S3 prefix and verifies SHA-256 before use. CloudFormation independently verifies the bootstrap script itself.

Important files:

- `gmu-honeypot-stack-2026-control.yaml` — Control-0 infrastructure definition
- `Invoke-PatriotPot.ps1` — fixed-profile preflight, asset publishing, change-set creation/review, and guarded execution
- `native/cowrie-requirements.lock` — fully version-pinned Python dependency set
- `native/archive-requirements.lock` — isolated, pinned boto3/botocore archive SDK environment
- `native/discord-monitor.py` — local JSON tailer with persistent state, clustered H2 presentation, enrichment, and bounded delivery handling
- `native/s3-archive.py` — conditional-create immutable segment archive with exact-version GET and downloaded-body SHA-256 verification
- `validate-native-baseline.py` — static controls and direct-asset self-tests
- `validate-behavioral-equivalence.py` — recovered contract and attacker-facing behavior checks

## Credential handling

The Discord monitor reads credentials through SSM SecureString parameters rather than repository files, CloudFormation parameters, process arguments, or log fields. Supplying or rotating those credentials is treated as a separate authorized credential operation.

## Deployment safety

The deployment path is change-set-driven and evidence-gated. The operator reviews the exact CloudFormation delta before execution, and unexpected replacements or changes outside the authorized scope are rejected.

A key current constraint is that **no further live-only repair should be used to advance Control-0**. The next changes must reconcile live state back into the reproducible deployment path, beginning with `DRIFT-01`.

Deployment success is an implementation claim only. Runtime validation, captured evidence, provenance labeling, and explicit claim boundaries remain required before research conclusions are accepted.

## Evidence and status entry points

- `NEXT-STEPS.md` — active ledger and current implementation state
- `evidence/AUTH-PARITY-GATE.md` — authentication-parity gate
- `evidence/H2-GATE.md` — enrichment/presentation gate
- `evidence/EXPOSURE-GATE-E1.md` — transition from pre-exposure to live TCP/2222 exposure
- `evidence/2026-09-23-p0-recovery/` — P0A/P0B1/P0B2 root cause, repair, and verification
- `evidence/2026-09-23-p0c-characterization/` — deception-filesystem characterization
