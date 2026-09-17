# PatriotPot 2026 Control Architecture

## Scope

This is a single, passive Cowrie control sensor. It preserves the reproducible
2025 application surface while remaining unexposed during implementation and
validation. It has no adaptive behavior, response generation, active defense,
swarm coordination, or AI attacker interaction.

## Runtime

```text
EC2: official Amazon Linux 2 x86_64 HVM EBS
  |
  +-- amazon-ssm-agent (management; no SSH key and host sshd disabled)
  +-- amazon-cloudwatch-agent (operational copy)
  +-- cowrie.service
  |     User=cowrie (locked, nologin)
  |     /opt/python/3.8.20 side-by-side venv
  |     /opt/cowrie @ 000116838246ce522b1f6953c6f108a3a4f0611c
  |     local TCP/2222, local cowrie.json, TCP/2223 disabled
  |
  +-- patriotpot-discord.service
  |     User=patriot-discord (locked, nologin)
  |     read-only Cowrie log access through the cowrie group
  |     state=/var/lib/patriotpot-discord/state.json
  |     SSM SecureString lookup; no credential in source or CFN
  |
  +-- patriotpot-archive.service + .timer
        User=patriot-archive (locked, nologin)
        read-only Cowrie log access through the cowrie group
        state=/var/lib/patriotpot-archive/state.json
        immutable content-addressed S3 segments and manifests
```

There is no container runtime or registry dependency.

## Network state

The stack has a public route only so the replacement can obtain packages and
reach SSM, S3, CloudWatch, and the configured Discord service. The instance
security group declares **zero inbound rules**:

| Address family | TCP/22 | TCP/2222 | TCP/2223 |
|---|---:|---:|---:|
| IPv4 | absent | absent | absent |
| IPv6 | absent | absent | absent |

The subnet has no IPv6 assignment. The retained Elastic IP is an identity and
continuity resource while exposure is disabled; it is not published as an SSH
or Telnet endpoint. CloudFormation outputs `NO_INGRESS_SSM_ONLY`.

The host `sshd` unit is disabled and stopped. SSM Session Manager is the only
management path.

## Supply-chain pins

| Component | Pin |
|---|---|
| AL2 publisher | AWS account `137112412989`, alias `amazon` |
| AL2 image | resolved from AWS public AL2 SSM parameter, then passed as a concrete AMI ID |
| CPython | 3.8.20 source archive SHA-256 `9f2d5962c2583e67ef75924cd56d0c1af78bf45ec57035cf8a2cc09f74f4bf78` |
| Cowrie | v2.5.0 commit `000116838246ce522b1f6953c6f108a3a4f0611c` |
| Cowrie dependencies | exact versions in `native/cowrie-requirements.lock` |
| stock `fs.pickle` | SHA-256 `06f0ed527bdc133b3fabca5def3db084b120bdf6b8e47736a85cd12e98b36da9` |
| direct assets | per-file SHA-256 pins inside the content-addressed bootstrap |

CPython is installed under `/opt/python/3.8.20`; neither `/usr/bin/python` nor
the system package manager's Python is replaced.

## Control behavior

The recovered candidate cfg declares:

- `hostname = gmu-server`
- `backend = shell`
- `listen_endpoints = tcp:2222:interface=0.0.0.0`
- `version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`
- `filesystem = /opt/cowrie/share/cowrie/fs.pickle`

The deployment appends only the explicit safety override:

```ini
[telnet]
enabled = false
```

The wildcard `userdb.txt`, recovered bait files, and recovered `ps`/`netstat`
text commands are copied only after asset hashing and secret-pattern checks.

### Provenance limitation

The cfg was recovered from a deleted deployment script and important behavior
is corroborated by telemetry, but exact live-file provenance is not proven.
Claims must therefore say `RECOVERED_CANDIDATE`.

### Approved `fs.pickle` substitution

The original 2025 filesystem pickle was never recovered. Stock Cowrie v2.5.0
`fs.pickle` is pinned and verified at bootstrap. This is an
`ACCEPTABLE_DEVIATION`, not an exact reconstruction.

## Host-key handling

The compromised key is replaced in the existing Secrets Manager secret.
CloudFormation receives only the secret ARN and exact AWSCURRENT version ID.
At bootstrap:

1. the instance fetches that exact version over TLS using its instance role;
2. the secret JSON is piped directly to a non-logging installer;
3. private material is validated against its public half;
4. the private file is installed `0600 cowrie:cowrie`;
5. only the public fingerprint is emitted as implementation evidence.

The role can read only the named host-key secret. Historical secret versions
remain an operational finding; they are not copied into source or reused.

## Discord monitor

The monitor reads the local `cowrie.json` directly. Its state records:

- source device and inode
- byte offset
- a bounded delivered-event digest set
- a bounded pending queue
- bounded dead-letter metadata

On the first installation it initializes at EOF. On rotation it drains the old
inode if still present and starts the new inode at offset zero. State is
atomically replaced after each complete line so service restarts do not replay
the source log. Delivery uses bounded retries and exponential backoff.

The payload preserves the recovered five fields and red embed color. Country is
read only from the event if present; there is no reputation lookup or adaptive
enrichment.

## Independent S3 archive

The archive timer is independent of Discord and CloudWatch. The archive:

- never truncates or renames Cowrie logs;
- uploads complete immutable segments from the current file;
- uploads content-addressed copies of rotated files;
- names objects with their SHA-256;
- writes a JSON SHA-256 manifest beside every evidence object;
- creates each evidence object and manifest with boto3 `PutObject`,
  `IfNoneMatch='*'`, and an SHA-256 checksum;
- records the returned S3 version after a successful create and GETs that exact
  version; after a 412 it GETs the current version;
- hashes every downloaded body and compares it with the locally expected
  digest; metadata is informational and never establishes integrity;
- persists inode/offset/rotated-file state under `/var/lib`;
- retries ambiguous timeouts/5xx and bounded 409 conflicts with the same
  conditional request, so a lost successful response followed by 412 cannot
  create another version;
- performs no S3 HEAD, list, or DynamoDB operation;
- uses only the instance role and the stable, sensor-scoped
  `control/<environment>/sensors/control-0/instances/` prefix.

The bucket is encrypted, versioned, public-access-blocked, TLS-only, and retained
on stack deletion/replacement. CloudWatch remains an operational copy and is
not substituted for local/S3 evidence.

The legacy on-demand claim table remains retained and managed but permissionless
until explicit approval is given for destructive deletion. The active writer
does not reference it, and the instance role has no DynamoDB permission.

## Egress human gate

The no-fixed-cost remediation does not alter the existing egress rule. A minimum
private replacement requires free S3 and DynamoDB gateway endpoints plus six
single-AZ interface endpoints (`ssm`, `ssmmessages`, `ec2messages`, `logs`,
`monitoring`, and `secretsmanager`) with private DNS and an endpoint security
group. Discord must move to a fixed-schema S3-to-non-VPC Lambda relay or a
dedicated relay, bootstrap and runtime egress must be separated, Parameter
Store remains available through SSM, and a host firewall is defense in depth
rather than the sole boundary. KMS is not added unless a requirement is proven.

At the supplied planning rates, six interface endpoints cost
`6 * 730 * $0.01 = $43.80/month` plus approximately `$0.01/GB`; gateway endpoint
hours are free. Lambda usage is priced and is not guaranteed to be zero. A
dedicated `t4g.nano` relay is approximately `$3.07`, 8-GiB gp3 approximately
`$0.64`, and public IPv4 approximately `$3.65`, or about `$7.36/month` plus
transfer and about `$51.16/month` with the six interface endpoints. Confirm
current prices at approval time.

Unrestricted TCP/443, Discord IP pinning, free service prefix lists, IAM alone,
or a host firewall alone cannot provide the required network exfiltration
boundary: HTTPS reaches arbitrary hosts, SaaS addresses change, prefix lists do
not cover every required service and Discord, IAM does not govern arbitrary
network destinations, and a compromised privileged host can alter local rules.

## Replacement behavior

An EC2 `ImageId` update intentionally replaces the failed AL2023 instance. A
changed content-addressed bootstrap bundle also replaces the EC2 instance: its
hash is included in the replacement-only primary network-interface declaration,
so a new UserData bundle is never falsely treated as installed on an already
running host. This changes neither ingress nor the preserved control behavior.

A CloudFormation `CreationPolicy` requires the new native bootstrap to signal
success before the old instance is removed. The existing Elastic IP resource is
updated to the new instance only after creation succeeds, avoiding a
long-lived parallel-cost architecture.

The deployment orchestrator rejects:

- any replacement other than the EC2 instance;
- replacement of the Elastic IP;
- any inbound rule for TCP/22, TCP/2222, or TCP/2223;
- any container-runtime declaration.

## Validation boundary

Repository checks, CloudFormation validation, change-set review, AWS state, and
SSM-collected runtime evidence are implementation evidence. They are not
independent validation. The configured `Runtime-Validator` must separately
verify the deployed sensor before any claim of independently verified success.
