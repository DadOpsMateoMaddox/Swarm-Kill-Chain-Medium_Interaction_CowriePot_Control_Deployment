# PatriotPot 2026 Native Control

This directory defines the pre-exposure control sensor for mission
`patriotpot-2026-control-pre-exposure-20260915`.

## Frozen control target

- AWS Region: `us-east-1`
- official Amazon Linux 2 x86_64 HVM EBS AMI, owner `137112412989`, pinned per deployment
- CPython `3.8.20` installed side-by-side at `/opt/python/3.8.20`
- Cowrie tag `v2.5.0`, commit
  `000116838246ce522b1f6953c6f108a3a4f0611c`
- native `/opt/cowrie` runtime owned as code by root and executed by locked user `cowrie`
- attacker SSH listener at local TCP/2222
- TCP/22 and TCP/2223 disabled; the security group has no IPv4 or IPv6 ingress
- SSM-only management
- local authoritative `/opt/cowrie/var/log/cowrie/cowrie.json`
- local Discord monitor with durable inode/offset/dedupe state
- independent content-addressed S3 archive service and timer
- CloudWatch as an operational/log copy, not the evidence authority
- no Docker, containerd, Podman, ECS, adaptive deception, active defense, swarm
  behavior, or AI attacker responses

## Recovered assets and provenance

The following candidate files were recovered from deleted git blob `b63431c8`:

| File | Deployment location |
|---|---|
| `cowrie.cfg` | `/opt/cowrie/etc/cowrie.cfg` |
| `userdb.txt` | `/opt/cowrie/etc/userdb.txt` |
| `honeyfs-etc-passwd` | `/opt/cowrie/honeyfs/etc/passwd` |
| `honeyfs-home-admin-passwords.txt` | `/opt/cowrie/honeyfs/home/admin/passwords.txt` |
| `txtcmds-bin-ps` | `/opt/cowrie/share/cowrie/txtcmds/bin/ps` |
| `txtcmds-bin-netstat` | `/opt/cowrie/share/cowrie/txtcmds/bin/netstat` |

These files match the recovered deployment-script heredoc and important values
are corroborated by captured telemetry. **Exact live 2025 `cowrie.cfg`
provenance remains unverified**, so the cfg is labeled `RECOVERED_CANDIDATE`,
not exact.

The credential-shaped strings in the honeyfs bait file are inert deception
content. Deployment preflight scans every published asset for private keys,
Discord webhook URLs, and AWS access-key patterns.

## Approved filesystem substitution

The 2025 `fs.pickle` was not recovered. The deployment uses the stock file from
the pinned Cowrie v2.5.0 commit:

```text
06f0ed527bdc133b3fabca5def3db084b120bdf6b8e47736a85cd12e98b36da9
```

This is an approved, explicitly documented substitution—not a recovered
artifact.

## Native deployment assets

`native/bootstrap-native.sh` downloads each direct asset from a
content-addressed, versioned S3 prefix and verifies its SHA-256 before use.
CloudFormation independently verifies the bootstrap script itself.

Important files:

- `gmu-honeypot-stack-2026-control.yaml` — zero-ingress infrastructure and
  replacement instance
- `Invoke-PatriotPot.ps1` — fixed-profile preflight, asset publishing,
  change-set creation/review, and optional execution
- `native/cowrie-requirements.lock` — fully version-pinned Python dependency set
- `native/archive-requirements.lock` — isolated, pinned boto3/botocore archive
  SDK environment
- `native/discord-monitor.py` — local JSON tailer with persistent state and
  bounded delivery retries
- `native/s3-archive.py` — conditional-create immutable segment archive with
  exact-version GET and downloaded-body SHA-256 verification
- `validate-native-baseline.py` — static controls and direct-asset self-tests
- `validate-behavioral-equivalence.py` — recovered contract and exact banner
  checks

## Discord credential

The monitor reads only the SSM SecureString path
`/patriotpot/2026-control/discord-webhook`. The value is not a CloudFormation
parameter, repository file, process argument, or log field. If the SecureString
does not exist, the monitor remains installed and active but cannot demonstrate
delivery. Supplying or rotating the Discord credential is a separate authorized
credential operation.

## Deployment safety

The orchestrator defaults to creating and reviewing a change set without
executing it:

```powershell
.\Invoke-PatriotPot.ps1
```

After inspecting the listed replacements:

```powershell
.\Invoke-PatriotPot.ps1 -ExecuteChangeSet
```

Any changed immutable native bundle deliberately produces the one permitted
replacement, `PatriotPotInstanceV2`; otherwise, a running host would retain
the old UserData assets. The Elastic IP and all network-policy resources must
remain non-replacing.

Every AWS CLI operation is fixed to `--profile patriotpot --region us-east-1`.
The script rejects any other profile or Region. It also rejects unexpected
resource replacements and any replacement of the retained Elastic IP.

Deployment success is an implementation claim only. A separate
`Runtime-Validator` pass is still required before the sensor is considered
independently validated or before any future exposure decision.
