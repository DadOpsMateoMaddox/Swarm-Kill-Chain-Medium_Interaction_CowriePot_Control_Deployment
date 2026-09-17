# PatriotPot Native Build and Deployment

## Fixed mission boundary

All commands in this runbook use:

```text
AWS profile: patriotpot
AWS Region:  us-east-1
Stack:       patriotpot-2026-control-prod
```

Do not use a default or alternate profile. Do not add ingress. TCP/22,
TCP/2222, and TCP/2223 remain absent for both IPv4 and IPv6.

## Local validation

```powershell
python .\validate-native-baseline.py
python .\validate-behavioral-equivalence.py --static-only

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\Invoke-PatriotPot.ps1),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors

aws cloudformation validate-template `
  --template-body file://gmu-honeypot-stack-2026-control.yaml `
  --profile patriotpot `
  --region us-east-1
```

The native validator verifies:

- direct-asset SHA-256 pins;
- no deployable private key, Discord webhook URL, or AWS access key;
- no security-group ingress or container declaration;
- native systemd identities and paths;
- the recovered behavioral contract;
- explicit TCP/2223 disablement;
- the approved stock v2.5.0 `fs.pickle` substitution.

## Credential prerequisites

### Cowrie host key

The existing secret is:

```text
patriotpot/2026-control/cowrie-host-key
```

The compromised private key must be replaced with a newly generated Ed25519
key before creating the change set. Never display private material or put it in
the repository. The deployment pins the exact AWSCURRENT version ID and emits
only a public fingerprint.

### Discord webhook

The monitor reads this secure path:

```text
/patriotpot/2026-control/discord-webhook
```

It must be an SSM `SecureString`. Do not pass the webhook value through
CloudFormation or place it in a command shown in logs. If it is absent, native
sensor deployment may proceed pre-exposure, but Discord delivery remains an
explicit blocker and cannot be claimed as verified.

## Prepare a reviewed change set

The orchestrator:

1. rejects any profile/Region other than the fixed mission boundary;
2. resolves `/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2`;
3. verifies AWS owner `137112412989`, alias `amazon`, x86_64, HVM, EBS, and
   `available`;
4. pins the concrete AMI ID;
5. verifies deployable assets and their embedded hashes;
6. publishes them under a versioned content-addressed S3 prefix;
7. creates a CloudFormation change set;
8. rejects unexpected replacements and any Elastic IP replacement;
9. stops before execution by default.

```powershell
.\Invoke-PatriotPot.ps1
```

Review the displayed change set using:

```powershell
aws cloudformation describe-change-set `
  --stack-name patriotpot-2026-control-prod `
  --change-set-name <CHANGE_SET_ID> `
  --include-property-values `
  --profile patriotpot `
  --region us-east-1
```

Expected replacement:

| Logical resource | Expected |
|---|---|
| `PatriotPotInstanceV2` | `Replacement=True` when the pinned AL2 AMI or content-addressed native bundle changes |
| `PatriotPotEIP` | no replacement |
| VPC/subnet/route/SG | no replacement |
| Evidence bucket | no replacement |

Policy, bucket-control, log-group, and output modifications are expected.

## Execute

After review:

```powershell
.\Invoke-PatriotPot.ps1 -ExecuteChangeSet
```

CloudFormation permits only temporary replacement overlap. A 50-minute
`CreationPolicy` requires the new instance to complete native bootstrap and
signal success before the old instance is removed. The primary-ENI descriptor
includes the immutable bundle ID, so a bundle update cannot merely change
unexecuted UserData on the existing host. The Elastic IP remains the same
CloudFormation resource.

## Fresh post-deployment evidence

Use SSM Run Command, not SSH. Every AWS operation must retain the explicit
profile and Region.

### Stack and instance

```powershell
aws cloudformation describe-stacks `
  --stack-name patriotpot-2026-control-prod `
  --profile patriotpot `
  --region us-east-1

aws cloudformation describe-stack-resources `
  --stack-name patriotpot-2026-control-prod `
  --profile patriotpot `
  --region us-east-1

aws ssm describe-instance-information `
  --filters Key=InstanceIds,Values=<NEW_INSTANCE_ID> `
  --profile patriotpot `
  --region us-east-1
```

### Runtime checks over SSM

Collect sanitized metadata only:

- `/etc/os-release` identifies Amazon Linux 2;
- `/usr/bin/python` remains system-owned;
- `/opt/python/3.8.20/bin/python3.8 --version`;
- `/opt/cowrie/venv/bin/python -m pip freeze --all`;
- `git -C /opt/cowrie rev-parse HEAD`;
- stock `fs.pickle` and deployed cfg SHA-256;
- `systemctl is-enabled` and `is-active` for Cowrie, Discord, archive timer,
  CloudWatch, and SSM;
- Cowrie process UID/GID;
- `ss -lntp` shows local TCP/2222, no TCP/22, and no TCP/2223;
- no `docker`, `containerd`, or `podman` executable/package/unit;
- `cowrie.json` exists and is writable by `cowrie`;
- Discord and archive state file metadata (never credential contents);
- public host-key fingerprint and Secrets Manager version metadata only.

### Network matrix

Inspect the final attached ENI and every attached security group. Report:

| Address family | 22 | 2222 | 2223 |
|---|---:|---:|---:|
| IPv4 | absent | absent | absent |
| IPv6 | absent | absent | absent |

Also verify the retained Elastic IP allocation is associated with the new ENI.

### S3 evidence

Inspect object keys, versions, and downloaded-body SHA-256 without printing
evidence bodies. A successful initial archive commonly
produces:

```text
control/production/sensors/control-0/instances/<instance-id>/segments/<lineage>/<offsets>-<sha256>.json
control/production/sensors/control-0/instances/<instance-id>/segments/<lineage>/<offsets>-<sha256>.json.manifest.json
```

The writer uses `IfNoneMatch='*'`, records the returned version, GETs that exact
version (or the current version after 412), and compares the downloaded body
SHA-256 with the content-addressed key/locally expected digest. Metadata never
establishes integrity. Never use a test that truncates, moves, or replaces the
authoritative local Cowrie log.

## Behavioral validation

Public connectivity is intentionally unavailable. Run the exact banner check
locally on the instance through SSM:

```text
127.0.0.1:2222 -> SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
```

Run the repository contract test:

```powershell
python .\validate-behavioral-equivalence.py --static-only
```

Stock Cowrie v2.5.0 `fs.pickle` must be reported as
`ACCEPTABLE_DEVIATION`. Exact cfg provenance must remain
`RECOVERED_CANDIDATE`.

## Independent validation

Implementation evidence is not an independent attestation. After all checks
pass, hand the final instance, stack, EIP, ENI, SG, host-key version metadata,
and S3 object metadata to `Runtime-Validator`. Exposure remains out of scope.
