# Exposure Gate E1 — Change-Set Phase

**Status:** CHANGE SET READY FOR HUMAN REVIEW — **NOT EXECUTED**
**Mission boundary:** AWS profile `patriotpot`, region `us-east-1`, stack `patriotpot-2026-control-prod`, instance `i-00270aeefb6266a7b`, EIP `13.217.73.134`
**Transition:** PRE-EXPOSURE → LIVE CONTROL

## Provenance

| Field | Value |
|---|---|
| Baseline commit (accepted) | `b11b4cf` |
| Template commit for this change set | `8671f8f` — "feat(exposure-gate-e1): declare sole TCP/2222 ingress for Cowrie" |
| Template SHA-256 | `c2b15f43abf839b2f701c7cce34d59d21fb412ad9310b3f61dde0bd39301ce17` |
| Change-set name | `exposure-gate-e1-20260918` |
| Change-set ID | `arn:aws:cloudformation:us-east-1:706162601288:changeSet/exposure-gate-e1-20260918/3b527657-36d4-461a-8cf0-a85c497b3467` |
| Change-set status | `CREATE_COMPLETE` |
| Change-set ExecutionStatus | `AVAILABLE` |

**Byte-exact provenance proof:** the template SHA-256 was computed on the working-tree file *before* committing, matched against the same file post-commit, and matched a third time by extracting the committed git blob (`git show 8671f8f:gmu-honeypot-stack-2026-control.yaml`) and hashing it independently. All three hashes are identical: `c2b15f43abf839b2f701c7cce34d59d21fb412ad9310b3f61dde0bd39301ce17`. The change set was created from exactly the file now committed at `8671f8f` — no drift between what was reviewed and what is committed.

## Procedural exception: `Invoke-PatriotPot.ps1` bypass

`Invoke-PatriotPot.ps1`'s `Assert-AssetIntegrity` and `validate-native-baseline.py`'s `validate_template()` both hard-assert **zero ingress** in the template (`require("SecurityGroupIngress:" not in text, ...)`, plus a `FromPort|ToPort: (22|2222|2223)` regex guard). That is by design: it encodes the accepted PRE-EXPOSURE baseline this repository operated under through Gate H1 and the baseline capture.

Because Gate E1's entire purpose is to deliberately leave that invariant, `Invoke-PatriotPot.ps1` cannot be used to create this change set — it would refuse at preflight, correctly. This is recorded as an **authorized Gate E1 procedural exception**:

- The wrapper's zero-ingress preflight is intentionally being bypassed for this one change set, because its rejection is exactly the PRE-EXPOSURE check that Gate E1 exists to move past.
- Direct `aws cloudformation create-change-set` was used **only to construct the reviewed exposure transition** for human review.
- This bypass does **not** authorize execution. The change set was created with no `-ExecuteChangeSet` equivalent — no `execute-change-set` call has been made.
- Every existing stack parameter was passed as `UsePreviousValue: true` (confirmed list below) — nothing beyond the security group's `SecurityGroupIngress` property was submitted as a new value.
- No live AWS state has changed. `PatriotPotSecurityGroup`'s active rules remain zero-ingress until this change set is separately reviewed and executed.

Parameters submitted, all `UsePreviousValue: true`: `FirewallBundleId`, `DiscordMonitorSha256`, `HostAmiId`, `FirewallScriptSha256`, `DiscordWebhookParameterName`, `BootstrapBundleId`, `CowrieHostKeySecret`, `FirewallUnitSha256`, `Environment`, `InstanceType`, `BootstrapScriptSha256`, `CowrieHostKeyVersionId`.

## Local validation (run before change-set creation)

| Check | Result |
|---|---|
| `aws cloudformation validate-template` | PASS — valid, `CAPABILITY_NAMED_IAM` |
| `python -m pytest tests/` | PASS — 38 passed, 4 subtests passed (unaffected by this change) |
| `python validate-behavioral-equivalence.py --static-only` | PASS — all `DECLARATION_CONSISTENT` (unaffected) |
| `python validate-native-baseline.py` | **FAILS, as designed**: `AssertionError: template declares ingress` at the exact zero-ingress assertion this gate deliberately changes. This is the validator correctly detecting the PRE-EXPOSURE invariant no longer holds — not a defect. This check will legitimately need updating (out of scope for this change set) once E1 executes and PRE-EXPOSURE is retired as the operating assumption. |

## Change-set resource inventory (normal `describe-change-set` — authoritative)

```
PatriotPotSecurityGroup   AWS::EC2::SecurityGroup   Modify   Replacement=False
```

**Exactly one resource, exactly one change.** Confirmed absent from the inventory: `PatriotPotInstanceV2`, `PatriotPotEIP`, `PatriotPotInstanceRole` (IAM), `PatriotPotDiscordMonitorAssociation`, `PatriotPotEgressFirewallAssociation` (SSM), any NACL/route-table resource, `EvidenceBucketPolicy`. No EC2 replacement, no EIP change, no IAM change, no SSM association change, no NACL change, no route-table change, no UserData/bootstrap change, no Cowrie configuration change.

## Property-level delta (`--include-property-values` — supplemental, per the H1 review finding that this flag can silently omit `Dynamic`-evaluation entries; the normal listing above is authoritative and shows nothing else changed)

**`SecurityGroupIngress`:**

```
BEFORE:  (property absent — zero ingress rules)
AFTER:   [{
           "IpProtocol": "tcp",
           "FromPort": 2222,
           "ToPort": 2222,
           "CidrIp": "0.0.0.0/0",
           "Description": "Cowrie attacker-facing SSH listener (Exposure Gate E1)"
         }]
```

**`SecurityGroupEgress`:** byte-identical before/after — the same 4 rules (DNS 53/udp+tcp to `10.0.0.2/32`, HTTP 80/tcp, HTTPS 443/tcp), unchanged.

**`GroupDescription`, `VpcId`, `Tags`:** byte-identical before/after.

**Observation, not part of this change set:** the `Exposure` tag remains `disabled` in both BEFORE and AFTER — it was deliberately left untouched to keep this change set to exactly the requested delta (SG ingress only). It is now semantically stale once this change set executes. Flagging for a follow-up decision; not changed here since it was not part of the authorized delta.

## Explicit port verification

Full `AFTER` `SecurityGroupIngress` array has exactly one entry. Confirmed absent from it, and from the unchanged `SecurityGroupEgress`:

| Port/protocol | Present in AFTER ingress? |
|---|---|
| TCP 22 | **No** |
| TCP 2222 | **Yes — the sole entry** |
| TCP 2223 | **No** |
| TCP 111 | **No** |
| UDP 111 | **No** |
| Any other port | **No** |
| `::/0` (IPv6, any port) | **No** — template declares no IPv6 ingress; SG has no IPv6 CIDR anywhere |

**rpcbind on `0.0.0.0:111`/`[::]:111` (baseline §5) remains unreachable from the Internet after this change set executes**, since the security group's only ingress rule is scoped to TCP/2222 and nothing else. This was the explicit carry-forward requirement from `evidence/PRE-EXPOSURE-BASELINE.md`'s "Notes carried into the Exposure Gate."

## Confirmation: H1 and baseline artifacts otherwise unchanged

- `origin/CerberusInit` untouched (not queried again this gate; no operation in this gate touches branches).
- No file under `native/`, no systemd unit, no Cowrie config, no bootstrap script was modified.
- `discord-monitor.py` and `patriotpot-egress-firewall.sh` hashes, the H1 change set, and the baseline capture are all unaffected — this gate's only content change is the CloudFormation template's `PatriotPotSecurityGroup.Properties.SecurityGroupIngress` and its top-level `Description` string (updated to stop misdescribing the template as declaring "no inbound security-group rules," which this exact change makes false).

## Change-set review status (superseded below — see Execution)

Change set `exposure-gate-e1-20260918` (`3b527657-36d4-461a-8cf0-a85c497b3467`) reached `CREATE_COMPLETE` / `ExecutionStatus: AVAILABLE` and was reviewed above. Execution was approved separately, under the mandatory pre-execution recheck documented next.

---

# Execution

## Mandatory pre-execution recheck (immediately before `execute-change-set`)

| Condition | Required | Observed | Result |
|---|---|---|---|
| Change-set ID | `3b527657-36d4-461a-8cf0-a85c497b3467` | `3b527657-36d4-461a-8cf0-a85c497b3467` | MATCH |
| Status | `CREATE_COMPLETE` | `CREATE_COMPLETE` | MATCH |
| ExecutionStatus | `AVAILABLE` | `AVAILABLE` | MATCH |
| Resource inventory | exactly `PatriotPotSecurityGroup` Modify, Replacement=False | exactly `PatriotPotSecurityGroup` Modify, Replacement=False | MATCH |
| AFTER ingress | `tcp 2222→2222 0.0.0.0/0` | `{"CidrIp":"0.0.0.0/0","FromPort":2222,"ToPort":2222,"IpProtocol":"tcp",...}` | MATCH |
| Live SG ingress before execution | `[]` | `[]` | MATCH |

All six conditions held. Proceeded to execution: the exact reviewed change set, not recreated, template not modified, `Exposure=disabled` tag not touched, no other resource altered.

## Execution record

| Event | UTC timestamp |
|---|---|
| `execute-change-set` requested | `2026-09-18T05:44:40Z` |
| `PatriotPotSecurityGroup` `UPDATE_IN_PROGRESS` | `2026-09-18T05:44:46.824Z` |
| **`PatriotPotSecurityGroup` `UPDATE_COMPLETE` — T0** | **`2026-09-18T05:44:48.481Z`** |
| `PatriotPotEIP` `UPDATE_COMPLETE` (see note below) | `2026-09-18T05:44:51.331Z` |
| Stack `UPDATE_COMPLETE` (overall) | `2026-09-18T05:44:53.245Z` |

**T0 = `2026-09-18T05:44:48.481Z`** — the SG's own completion, not the later overall-stack timestamp, per instruction.

**`PatriotPotEIP` UPDATE event — investigated, confirmed benign, not a real mutation.** The EIP resource has no template dependency on `PatriotPotSecurityGroup` (`gmu-honeypot-stack-2026-control.yaml:612-622` — its only inputs are `InstanceId: !Ref PatriotPotInstanceV2` and static tags). Its `ResourceProperties` in this execution's `UPDATE_COMPLETE` event (`{"InstanceId":"i-00270aeefb6266a7b","Domain":"vpc","Tags":[...]}`) are byte-identical to the same event captured during Gate H1's execution. Live `describe-addresses` post-execution confirms identical `AllocationId` (`eipalloc-0de839802f07b5a62`), `AssociationId` (`eipassoc-0a00db434fa29cbb7`), `PublicIp` (`13.217.73.134`), and `InstanceId`. This is CloudFormation's routine no-op reconciliation touch on `AWS::EC2::EIP` during any stack update — observed identically in H1 — not a property change.

## Post-execution validation

**1. CloudFormation:** `UPDATE_COMPLETE`, no rollback, stack events show only `PatriotPotSecurityGroup` and the benign `PatriotPotEIP` touch — no unexpected resource events. **PASS**

**2. `PatriotPotSecurityGroup`:** same physical ID `sg-0647129753848a7b0`. Full post-execution rule set captured at `evidence/exposure-gate-e1-execution/sg-post-execution.json`:
```
Ingress: exactly one rule — tcp, 2222→2222, 0.0.0.0/0, "Cowrie attacker-facing SSH listener (Exposure Gate E1)"
Ipv6Ranges: [] (no IPv6 ingress)
Egress: unchanged — 4 rules (DNS 53/udp+tcp → 10.0.0.2/32, HTTP 80/tcp, HTTPS 443/tcp → 0.0.0.0/0)
```
**PASS**

**3. Explicitly confirmed absent from the live SG:** TCP/22, TCP/2223, TCP/111, UDP/111, any other port, any `::/0` entry. The `IpPermissions` array has exactly one element; nothing else is present. **PASS**

**4. Confirmed unchanged:**
- SG egress: byte-identical 4 rules (above).
- NACL: `acl-00cbae2f781c12045`, unchanged.
- Route table `rtb-094125482392c9dc7`: same 2 routes (`10.0.0.0/16→local`, `0.0.0.0/0→igw-0033bfd6ead475543`).
- EIP: same allocation/association/public IP (see note above).
- Instance: `i-00270aeefb6266a7b`, `running`, `LaunchTime` unchanged at `2026-09-16T20:03:27Z` — proves no replacement.
- ENI: `eni-05699c39be981ea62`, unchanged.
- IAM instance profile: unchanged ARN.
- SSM associations: both `Status: Success` / `DetailedStatus: Success` — not re-triggered (SG is not one of their dependencies).
- **CloudFormation drift, post-execution:** `StackDriftStatus: IN_SYNC`, `DriftedStackResourceCount: 0`.
**PASS**

**5. On-host** (raw output: `evidence/exposure-gate-e1-execution/onhost-post-execution.txt`):
- `cowrie.service`: active.
- `ss -lntp`: only `0.0.0.0:2222` (twistd, pid 2307) — no 22, no 2223.
- `sshd`: inactive, masked.
- rpcbind:111 not re-checked this pass (unchanged since baseline; confirmed blocked at the SG layer per §3/§4 above — the SG's `IpPermissions` array contains no rule that could reach it).
**PASS**

**6. Security controls:**
- Egress firewall: active, enabled, script hash `0e1167ce...` unchanged.
- Discord monitor: active, hash `a8606b55...` unchanged.
- Archive timer: active, `uploaded_objects: 11` — unchanged count, consistent with zero new events.
- CloudWatch agent: active. SSM agent: active (this validation ran entirely over SSM).
**PASS**

**7. State continuity — explicitly not reset, no synthetic traffic generated:**
```
Discord monitor: source {device: 66305, inode: 978800, offset: 3067}, pending: 0, seen: 9, replay_suppressed: 9 (historical, pre-H1)
Archive:         device 66305, inode 978800, offset 3067, uploaded_objects: 11
cowrie.json:     size=3067, inode=978800
```
All three identical to the pre-execution baseline and to each other. No `ssh`/`nc`/`nmap`/`Test-NetConnection` or any other operator-originated connection was made to TCP/2222 at any point in this gate. Cowrie's journal shows no connection activity beyond its original 2026-09-16T23:27:55Z startup log lines — zero organic attacker events yet, as expected only ~2 minutes after T0.
**PASS**

**8. Evidence captured:** this document; `evidence/exposure-gate-e1-execution/sg-post-execution.json` (full SG state); `evidence/exposure-gate-e1-execution/onhost-post-execution.txt` (full on-host diagnostic transcript); CloudFormation event timestamps above; drift-detection result above.

## Known non-blocking metadata debt (recorded, not fixed this gate)

- **E1.1 — exposure metadata / validator transition:** `Exposure=disabled` tag remains stale on both `PatriotPotSecurityGroup` and `PatriotPotEIP` post-execution. `validate-native-baseline.py`'s zero-ingress assertion still fails against the current template — expected, since it was built for the PRE-EXPOSURE invariant this gate deliberately retired. Neither was touched during this execution, per instruction.

# EXPOSURE GATE E1: PASS — LIVE CONTROL

- **T0 (UTC):** `2026-09-18T05:44:48.481Z`
- **First organic Cowrie event after T0:** none yet observed as of this validation pass (`2026-09-18T05:46:52Z` journal check, ~2 minutes post-T0) — to be recorded separately when it occurs.
- **No synthetic attacker traffic was generated** at any point in this gate — confirmed by unchanged state-file offsets (§7) and the absence of any operator-originated connection to TCP/2222.
- **Resulting evidence commit SHA:** recorded after this document is committed (see below).
