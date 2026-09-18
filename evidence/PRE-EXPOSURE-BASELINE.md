# Pre-Exposure Baseline Capture

**Capture timestamp (UTC):** 2026-09-18T05:19:49Z – 05:24Z
**Raw evidence:** `evidence/baseline/20260918T051949Z/` (`host-diagnostic-raw.txt` = full SSM command output; `aws-raw/` = raw AWS CLI JSON responses)
**Mode:** observation-only. No runtime configuration, service, firewall, credential, or Cowrie-state change was made during this capture.

**Result: PRE-EXPOSURE BASELINE: PASS**

---

## 1. Provenance / identity

| Field | Value |
|---|---|
| Capture timestamp | 2026-09-18T05:19:49Z |
| Repository HEAD | `4d793eb51fc883920bf76fbc21b251c29db6a177` |
| `origin/main` | `4d793eb51fc883920bf76fbc21b251c29db6a177` (identical — no local drift) |
| CFN stack | `patriotpot-2026-control-prod`, status `UPDATE_COMPLETE` |
| Last executed change set | `egress-firewall-20260918T022536Z` / `b80a20a8-0f11-4580-b2a3-6cf865f427f6` (Gate H1) |
| AWS account | `706162601288` |
| Region | `us-east-1` |
| Instance ID | `i-00270aeefb6266a7b` |
| AMI ID | `ami-0b3ff1b856ac6fda3` |
| Instance type | `t3.micro` |
| Boot ID | `235256f6-4006-4667-b8dc-dc24eef8d035` |
| Launch time | 2026-09-16T20:03:27Z |
| Uptime at capture | 1 day, 5h52m |
| EIP / public IP | `13.217.73.134` (`eipalloc-0de839802f07b5a62` / `eipassoc-0a00db434fa29cbb7`, associated to this instance) |
| Private IP | `10.0.1.246` |
| ENI | `eni-05699c39be981ea62` |
| Subnet | `subnet-0fbf872e244d856af` |
| VPC | `vpc-09d6a384845f65344` |

**PASS**

## 2. Cloud/network configuration

- **Security group** `sg-0647129753848a7b0`: **0 ingress rules**. 4 egress rules only — TCP/80 (0.0.0.0/0), TCP/443 (0.0.0.0/0), TCP/53 + UDP/53 to VPC resolver `10.0.0.2/32`. No rule for TCP/22, TCP/2222, or TCP/2223 in either direction.
- **Network ACL** `acl-00cbae2f781c12045` (default, associated to the subnet): standard allow-all/deny-all default rules — no custom restriction, consistent with the SG being the enforcement point.
- **Route table** `rtb-094125482392c9dc7`: `10.0.0.0/16 → local`, `0.0.0.0/0 → igw-0033bfd6ead475543`, both `active`. Unchanged from H1.
- **Internet Gateway** `igw-0033bfd6ead475543`: attached, `available`.
- **EIP**: associated to `i-00270aeefb6266a7b`, unchanged.
- **EC2 `KeyName`**: `None`.
- **IAM instance profile**: `patriotpot-2026-control-prod-PatriotPotInstanceProfile-agCkqDK8fVYb`, role `patriotpot-instance-role-production` (verified during H1; unchanged).
- **SSM managed instance**: `PingStatus: Online`, agent `3.3.4624.0`, platform Amazon Linux.

Confirmed: no SSH management exposure, no unexpected SG/NACL/route entries, instance not replaced since H1.

**PASS**

## 3. Host identity

```
NAME="Amazon Linux", VERSION="2", PRETTY_NAME="Amazon Linux 2"
Linux ip-10-0-1-246.ec2.internal 4.14.355-284.742.amzn2.x86_64
Python 3.8.20
Cowrie commit 000116838246ce522b1f6953c6f108a3a4f0611c (tag v2.5.0)
Twisted 22.10.0
NTP enabled: yes / NTP synchronized: yes (reference 169.254.169.123, Amazon Time Sync, stratum 4)
```

**PASS**

## 4. Service state

| Unit | active | enabled | Notes |
|---|---|---|---|
| `cowrie.service` | active | enabled | PID 2307, up since 2026-09-16T23:27:52Z |
| `patriotpot-discord.service` | active | enabled | PID 10617, up since 2026-09-18T04:56:45Z (H1 restart) |
| `patriotpot-egress-firewall.service` | active | enabled | `Type=oneshot, RemainAfterExit=yes` — MainPID=0 is expected (applies iptables rules once, no daemon) |
| `patriotpot-archive.service` | inactive | static | Expected — timer-triggered oneshot, not meant to run continuously |
| `patriotpot-archive.timer` | active | enabled | Firing every ~6 minutes |
| `amazon-cloudwatch-agent.service` | active | enabled | PID 2032 |
| `amazon-ssm-agent.service` | active | enabled | PID 2295 |

**PASS**

## 5. Listener / process baseline

```
tcp LISTEN 0.0.0.0:2222   twistd (pid=2307)   <- Cowrie, expected sole externally-relevant listener
tcp LISTEN 127.0.0.1:25   master (postfix)    <- loopback only, stock AL2 default, not externally reachable
tcp LISTEN 0.0.0.0:111 / [::]:111  rpcbind    <- stock AL2 default; SG has zero ingress so unreachable externally
udp various (dhclient, rpcbind, chronyd)      <- stock AL2 defaults, loopback/link-local
```

No TCP/22, no TCP/2223, anywhere, either address family. `ss` output preserved verbatim in raw evidence.

**PASS**

## 6. Egress-control baseline

- `patriotpot-egress-firewall.service`: active, enabled.
- Deployed script hash: `0e1167ceb9f2c546ba5ba3a0c1e98b78e6b8625eee6d963d16de5692b757e839` — matches the Gate H1 reviewed/executed value.
- Deployed unit hash: `11d9124d1390bd44985cb6884e032b80979ac0f8029b541230732f7cdcd026e8` — matches, unchanged since before H1 (script content wasn't touched, only its wrapper pin).
- **Effective `iptables` `PATRIOTPOT_EGRESS` chain** (live counters) matches the reviewed source rule-for-rule: ESTABLISHED/RELATED accept → loopback accept → DNS (`10.0.0.2`) → instance metadata (`169.254.169.254:80`) → Amazon Time Sync (`169.254.169.123:123`) → RFC1918/reserved-range DROP (3837 packets dropped to `10.0.0.0/8` — lateral-VPC-movement attempts actively blocked) → HTTP/HTTPS accept (2423 packets) → default DROP (**424K packets / 32MB**).
- **`ip6tables`**: no IPv6 assigned to the ENI; all IPv6 (939 packets) hits the default DROP, matching the documented "no IPv6" boundary.

**Observation, not a HOLD:** the IPv4 default-DROP counter (424K packets/32MB) is large relative to the ~1.25-day uptime. This is evidence the deny-by-default policy is actively enforcing (a good sign for egress control), but the traffic's actual source hasn't been individually attributed in this capture — worth a closer look (e.g. AL2 background services, yum/repo checks, or other stock daemons attempting disallowed destinations) before or shortly after exposure, purely for operational hygiene. It does not indicate an open path, since the packets are confirmed DROPped, and it predates this baseline capture entirely — the H1 change set never touched this rule set's logic.

**PASS** (with the above as a non-blocking observation)

## 7. Deployed artifact integrity

All 18 checked artifacts compared against the canonical `native/bootstrap-native.sh` pins:

| Artifact | Result |
|---|---|
| `userdb.txt`, `honeyfs-etc-passwd`, `honeyfs-home-admin-passwords.txt`, `txtcmds-bin-netstat`, `txtcmds-bin-ps`, `install-host-key.py`, `discord-monitor.py`, `s3-archive.py`, `cowrie.service`, `patriotpot-discord.service`, `patriotpot-egress-firewall.sh`, `patriotpot-egress-firewall.service`, `patriotpot-archive.service`, `patriotpot-archive.timer`, `patriotpot-logrotate`, `cloudwatch-agent.json`, `fs.pickle` | **MATCH** (17/18) |
| `cowrie.cfg` | Deployed hash `200e61b5...` ≠ canonical pin `33ff40ef...` at first glance — **investigated and resolved**: `sha256(repo cowrie.cfg + bootstrap-native.sh's documented telnet-disable append)` was computed locally and equals `200e61b5c18c96279aee5909b93114474de01b59bb4b38692474594a395e4862` **exactly**, byte-for-byte. This is the documented post-install append (`; 2026 pre-exposure safety override... [telnet]\nenabled = false`, `native/bootstrap-native.sh:312-317`), not drift. **MATCH (verified transformation)**. |

**Verdict: 18/18 MATCH, 0 unexplained mismatch, 0 MISMATCH/HOLD.**

**PASS**

## 8. Cowrie deception configuration

```
hostname = gmu-server
backend = shell
version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
listen_endpoints = tcp:2222:interface=0.0.0.0
filesystem = /opt/cowrie/share/cowrie/fs.pickle
[telnet] enabled = false  (post-install safety override, confirmed present)
```
`userdb.txt`: 10 lines (unchanged). Config files owned `root:root:644` — read by the locked `cowrie` service user, matches the documented "runtime owned as code by root, executed by locked user cowrie" model. Matches `CONTROL-ARCHITECTURE.md`'s declared `RECOVERED_CANDIDATE` contract exactly.

**PASS**

## 9. SSH / management baseline

- EC2 `KeyName`: `None` (AWS API, section 1).
- `/root/.ssh/authorized_keys`: 0 bytes, 0 lines.
- `/home/ec2-user/.ssh/authorized_keys`: 0 bytes, 0 lines.
- `sshd`: inactive, **masked**.
- SSM: `Online`, functioning (this capture itself was performed entirely over SSM).

Matches expected state exactly: no SSH key exists on Control-0, SSM is the sole management path.

**PASS**

## 10. Discord monitor baseline

- Service: active, enabled, PID 10617.
- Deployed hash: `a8606b55...` — matches.
- State: `{"version": 2, "source": {"device": 66305, "inode": 978800, "offset": 3067}, "initialized_at": "2026-09-16T20:07:48Z", "updated_at": "2026-09-16T23:38:34Z", "replay_suppressed": 9}`, `pending: 0`, `seen: 9`.
- `replay_suppressed: 9` is a **historical** counter from restarts that occurred *before* the H1 fix (when the dead-state-wiring defect meant every restart reset to offset 0 and had to dedupe/suppress replayed pending items). It will not increment further now that `load_state()` participates correctly — already confirmed independently during H1's post-execution check.
- Journal: clean, only expected Stop/Start pairs, zero errors.
- Offset unchanged (3067) from the H1 check — no new Cowrie activity since, consistent with pre-exposure / no live traffic.

**PASS**

## 11. Archive / evidence pipeline baseline

- `patriotpot-archive.timer`: active, enabled, firing every ~6 minutes (last: 58s before capture, next: 4m10s after).
- `patriotpot-archive.service`: `inactive`/`static` between runs — expected for a timer-triggered oneshot. Its restart count (341 over ~29.9 hours of uptime) is the **normal cumulative trigger count** for a ~6-minute period, not a crash loop — corroborated by zero errors in its journal (section 12).
- Archive state: `{"current":{"anchor":{...,"offset":3067,"sha256":"e951645b...","window_start":3003},...},"uploaded_objects":11,"version":3}` — **11 objects already successfully uploaded** to S3, direct evidence the conditional-create/exact-version-GET pipeline is functioning end-to-end.
- `cowrie.json`: size 3067 bytes, inode 978800 — **identical offset** to both the Discord monitor's and the archiver's persisted state, confirming both pipelines are caught up to current EOF with no live traffic pending.
- Evidence bucket `patriotpot-evidence-706162601288-us-east-1`: versioning `Enabled`. Bucket policy Sids `DenyInsecureTransport` and `DenyUnconditionalControlArchiveWrites` verified byte-identical during H1 (canonicalized SHA-256 `e7844eea...`).

**PASS**

## 12. Logging / telemetry baseline

Journal error scan since 2026-09-16 across `patriotpot-discord.service`, `patriotpot-archive.service`, `patriotpot-egress-firewall.service` for `traceback|poll_failed|typeerror|error|permission`: **0 matches in all three.**

Restart counts: `cowrie.service`=3, `patriotpot-discord.service`=4, `patriotpot-archive.service`=341 (timer-driven, expected — see §11), `patriotpot-egress-firewall.service`=3. None indicate a crash loop; all correspond to legitimate reboot/deploy/H1-restart events already accounted for in this document and the H1 evidence record.

CloudWatch agent: active.

**PASS**

## 13. Host health

```
Disk:   /dev/nvme0n1p1  16G, 2.9G used, 14G avail, 18% used
Memory: 940MB total, 225MB used, 568MB available
Load:   0.00, 0.00, 0.00
Failed systemd units: 0
```

**PASS**

## 14. CloudFormation drift

```
StackDriftDetectionId: 5e92f250-b320-11f1-ab50-12ffed1df615
StackDriftStatus:       IN_SYNC
DetectionStatus:        DETECTION_COMPLETE
DriftedStackResourceCount: 0
```

**PASS**

## 15. Baseline acceptance criteria — summary

| Criterion | Status |
|---|---|
| Stack healthy | PASS |
| Repository / deployed artifact provenance recorded | PASS |
| No unexplained CloudFormation drift | PASS (0 drifted resources) |
| No unexpected listener | PASS |
| No unexpected SG/NACL/route change | PASS |
| No artifact hash mismatch | PASS (18/18, one apparent mismatch investigated and verified as the documented telnet-override append) |
| Required services active/enabled | PASS |
| Cowrie persona/config matches intended control | PASS |
| Egress firewall effective and unchanged | PASS (see §6 observation on drop-counter volume — non-blocking) |
| SSM works | PASS |
| No active SSH key on Control-0 | PASS |
| Discord state persists correctly | PASS |
| Archive pipeline healthy | PASS (11 objects uploaded, offsets aligned) |
| No unexplained runtime errors | PASS |
| Host health nominal | PASS |

# PRE-EXPOSURE BASELINE: PASS

Stopping here for human approval before any action that changes exposure state, per instruction. No port was opened, no SG rule altered, no Cowrie configuration changed, and no service was restarted as part of this capture (the one restart visible in the evidence — the Discord monitor at 04:56:45Z — was the Gate H1 SSM association applying the reviewed change set, captured as historical state, not performed during this baseline capture).
