# Control-Parity Gate: 2025 Authentication Semantics Correction

Status: **EXECUTED 2026-09-19.** Change set
`auth-parity-final-20260919T220333Z` executed after explicit approval; stack
reached `UPDATE_COMPLETE`. This gate is independent of H2 (telemetry/
enrichment/presentation only) and independent of the egress firewall (H1).
It changed exactly one thing: which SSH username/password combinations
Cowrie accepts.

**T0 (Epoch A → Epoch B boundary) = `2026-09-19T22:08:04.614016217Z`**
(`AUTH_PARITY_T_RESTART_ACTIVE`; independently corroborated by systemd's
`ActiveEnterTimestamp = Sat 2026-09-19 22:08:04 UTC`.)

Execution record: Section 12 below, plus raw captures in
`evidence/auth-parity-live-verification/`.

## 1. Provenance and corpus hashes

Evidence precedence used throughout this gate, per explicit instruction:

1. raw preserved Cowrie corpus
2. corpus integrity manifests / hashes
3. operator-confirmed provenance
4. recovered runtime evidence
5. deployment scripts / config candidates
6. sanitized public repository
7. paper / documentation summaries

**Explicit rule, not merely implied by the ordering:** the public 2025
GitHub repository (this repo's `7a268f8` history) was sanitized prior to
publication — operator-origin IPs and some runtime telemetry were
intentionally removed/redacted before it was made public. Consequently,
**absence of a source IP, session, or operator marker from that history must
not be interpreted as evidence the activity did not occur**, and nothing
from tier 6 (or tier 5, which is derived from the same sanitized history) is
permitted to override or downweight a finding that tiers 1–4 already
establish. The deployment-script candidates recovered from that history
(`honeypot-setup.sh`, `enhanced-honeypot-setup.sh`, the embedded
`gmu-honeypot-stack.yaml` UserData) sit at tier 5 and were explicitly
**not** used as authority for the target `userdb.txt` in Section 5 — every
username in the target set is there because tier-1/tier-2 telemetry shows
it, not because a script happened to contain it. This is also why `deploy`
and `webuser` are added (present in telemetry, absent from every recovered
script) and why the same tier-5 scripts' `guest`/`ubuntu`/`oracle`/`tomcat`-
style entries were **not** carried forward despite appearing in candidate
scripts — script content alone was never treated as sufficient.

**Directly verified by this session**, independent of anything supplied in
conversation text:

| Artifact | Value |
|---|---|
| `cowrie.json.2025-10-16` (single-day slice) SHA-256 | `0eb18deddf34080731e36a0a70600d1b1cee025df2afb523940d8ceca25249dc` |
| Verification method | `sha256sum` on the file at `C:\Users\MyPC\Downloads\cowrie.json.2025-10-16`, compared against the quoted `PatriotPot_2025_Corpus` manifest hash — **exact match** |
| Canonical source (as reported) | `PatriotPot_2025_Corpus/raw/cowrie.json.2025-10-16` |
| File contents independently parsed | 19 login events, 5 distinct `src_ip`, timestamp range `2025-10-16T06:15:57.396911Z`–`2025-10-16T13:46:39.419438Z` |
| All 8 quoted transition-sequence timestamps/passwords/session IDs | reproduced byte-for-byte from independent parse — no discrepancies |

**Not independently verified by this session** (taken as reported, tier-1
evidence per the precedence above, but outside what this session directly
re-derived): the full `all_cowrie_logs.json` corpus aggregate counts (Section
4), the 25-session full-corpus operator cluster count, and the two additional
self-identification strings (`"it's kevin mwahahaha"`, `"thisiskevintesting"`,
`"thisiskevin"`) — those were reported from a re-run this session did not
execute directly, because the full corpus file was not made available to this
session, only the single-day slice was. The single-day slice's own
self-identification strings (`"It's Kevin, Honeypot keylogger's working..."`,
the `gmu-honeypot-key.pem` / `ec2-user@44.218.220.47` SSH command, and the
`sudopwnr@DESKTOP-BKB4NKN:/mnt/d/School/AIT670...` pasted shell prompt) **were**
independently read directly from the hash-verified file by this session.

## 2. Auth epoch definition

| Epoch | Window (2025-10-16, UTC) | Definition |
|---|---|---|
| Epoch A (pre-transition) | earliest available — `08:30:44.648923Z` (session `d1f798840a6a` close) | Narrower/unknown-shape auth surface. Only 3 directly-observed data points: `root/password` succeeds twice (06:15:57Z, 06:19:11Z); `root/toor` fails once (08:30:43Z); `admin/admin123` fails once (08:29:58Z). Too thin to prove absence of a wildcard — equally consistent with an exact-match allow rule for `password` specifically. Not claimed as a stable characterized state. |
| **Transition boundary** | `08:30:44.648923Z` → `08:32:07.718603Z` (session-connect timestamps bracketing the change; the credential-level flip is `08:30:43.626023Z` fail → `08:32:07.903310Z` success, 84.277287s) | Same exact pair (`root:toor`), same source, same session cluster, flips outcome. Cannot be explained by a static rule of any shape — this is a real state change, not noise. Mechanism (confirmed from Cowrie v2.5.0 source, `src/cowrie/core/checkers.py::checkUserPass`): `theauth = authname()` constructs a fresh `UserDB()` **on every login attempt**, and `UserDB.__init__` calls `self.load()`, re-reading `userdb.txt` from disk each time. No caching, no reload signal, no service restart is required for an edit to take effect. This is consistent with a plain on-disk edit to `userdb.txt` during this window; it does not prove authorship, tooling, or exact prior content. |
| **Epoch B (post-transition, stable)** | `2025-10-16T08:32:07.903310Z` onward, through the end of the corpus | Wildcard-shaped allow for exactly 7 usernames, deny for all others. Confirmed same-day beyond the operator's own testing: two unrelated external source IPs (`190.121.192.214`, `91.92.241.59`) both succeed on `admin/admin` at `13:46:28Z`/`13:46:39Z`, ~5 hours after the boundary. Confirmed at corpus scale in Section 4. |

## 3. Operator exclusions

**Explicitly confirmed by the operator** (Kevin, handle `sudopwnr`), this session:
`37b0413eff18` (`admin`/`anything`), `0249484fca93` (`admin`/`letsfukcing goooooooooooo`),
`98786b8e1a89` (`admin`/`test`), `d4d870a25724` (`admin`/`welcometohellhackersmwahahaha`).

**Independently found by this session**, reading raw `cowrie.command.input`
content directly from the hash-verified file (not inferred, not
user-reported — literal typed text):

- Session `a4619dfa5499` (`06:15:57Z`, `root/password`, success): command
  input reads `"It's Kevin, Honeypot keylogger's working but I nered to check
  the backend cause this directory structure is ass"`.
- Session `d1b9ac212edb` (`06:19:11Z`, `root/password`, success): runs
  `ssh -i ~/.ssh/gmu-honeypot-key.pem ec2-user@44.218.220.47 "ls -lA
  /opt/cowrie/honeyfs/"`.
- Session `a312ca6b8668` (`08:44:08Z`, `admin/ewfreeeee`, success — outside
  the operator's original 4-session confirmation): pastes the operator's own
  terminal scrollback verbatim, including the shell prompt
  `sudopwnr@DESKTOP-BKB4NKN:/mnt/d/School/AIT670 Cloud Computing In
  Person/Group Project/AWSHoneypot$ ssh admin@44.218.220.47 -p 2222`.
  `sudopwnr` is the same handle used throughout this working session.

Given all of these trace to the same `src_ip` (`98.244.93.121`) and the same
SSH client/HASSH fingerprint already established as a single cluster, this
session's finding is: **the entire `98.244.93.121` cluster in the single-day
file — 13 sessions, `06:15:57Z`–`08:47:08Z` — is operator traffic**, not just
the 4 explicitly named.

Reported (not independently verified) for the full corpus: `98.244.93.121`
has 25 sessions total, with additional self-identification strings
(`"it's kevin mwahahaha"`, `"thisiskevintesting"`, `"thisiskevin"`) beyond
what this session directly read. Classified operator-traffic per the
operator's own confirmation; consistent with, not contradicted by, this
session's independent single-day finding.

Non-operator, same-day: `54.39.182.0` + `54.39.190.134` (`lmenendez/lmenendez`
fail, `08:48:29Z`, 11ms apart, two IPs) and `190.121.192.214` + `91.92.241.59`
(`13:46:17Z`–`13:46:39Z`, includes the two-IP `admin/admin` success pair).

## 4. Full-corpus observed outcomes (post-boundary, operator-excluded)

**Reported this turn, not independently re-run by this session** (the full
`all_cowrie_logs.json` was not made available here — only the single-day
slice was). Included per the evidence precedence in Section 1 (tier 1) and
because the single-day slice's own numbers are fully consistent with it
(see cross-check below).

Boundary used: `2025-10-16T08:32:07.903310Z`. Operator source excluded:
`98.244.93.121`.

| Username | Success | Fail | Unique successful passwords | Classification |
|---|---|---|---|---|
| root | 9,213 | 0 | 7,377 | allow-like |
| admin | 296 | 0 | 146 | allow-like |
| postgres | 27 | 0 | 13 | allow-like |
| deploy | 15 | 0 | 8 | allow-like |
| mysql | 15 | 0 | 5 | allow-like |
| backup | 8 | 0 | 6 | allow-like |
| webuser | 2 | 0 | 2 | allow-like |
| user | 0 | 82 | — | deny-like |
| test | 0 | 78 | — | deny-like |
| ubuntu | 0 | 56 | — | deny-like |
| guest | 0 | 50 | — | deny-like |
| debian | 0 | 23 | — | deny-like |
| oracle | 0 | 14 | — | deny-like |

Corpus coverage of this epoch: 108,678 / 109,491 events (99.26%),
14,296 / 14,354 login events (99.60%), 15,956 / 16,156 `session.connect`
events (98.76%).

**Cross-check against this session's own single-day parse:** no username in
the single-day file shows both a success and a failure after the boundary
(root and admin each succeed repeatedly with distinct passwords post-`08:32Z`,
zero failures) — structurally consistent with the full-corpus table's
"exactly seven usernames ever succeed, zero mixed outcomes" pattern, not
contradicted by it.

## 5. Current-vs-target userdb diff

Current (as of this gate's start — the "Epoch A reconstruction" content,
introduced whole-cloth in commit `25b4047` "stage full native deployment
suite for CerberusInit", 2026-09-16, with no earlier tracked history — i.e.
authored fresh in 2026, not carried forward from a verified 2025 source):

```
root:x:*:
admin:x:*:
user:x:*:
oracle:x:*:
mysql:x:*:
postgres:x:*:
backup:x:*:
test:x:*:
guest:x:*:
ubuntu:x:*:
```

Target (this gate, matches Section 4 exactly — 7 accounts, all wildcard):

```
root:x:*:
admin:x:*:
postgres:x:*:
mysql:x:*:
backup:x:*:
deploy:x:*:
webuser:x:*:
```

| Change | Username | Direction |
|---|---|---|
| removed | `user` | was wildcard-allow; telemetry shows 82 fail / 1 success — deny |
| removed | `oracle` | was wildcard-allow; telemetry shows 14 fail / 0 success — always deny |
| removed | `test` | was wildcard-allow; telemetry shows 78 fail / 2 success — deny (flagged by operator as possibly test-contaminated; excluded regardless, since even at face value it is deny-dominant) |
| removed | `guest` | was wildcard-allow; telemetry shows 50 fail / 0 success — always deny |
| removed | `ubuntu` | was wildcard-allow; telemetry shows 56 fail / 0 success — always deny |
| added | `deploy` | was absent (deny-by-omission); telemetry shows 15 success / 0 fail — always allow |
| added | `webuser` | was absent (deny-by-omission); telemetry shows 2 success / 0 fail — always allow |
| unchanged | `root`, `admin`, `postgres`, `mysql`, `backup` | correct in both — retained |

No usernames were added because a deployment-script candidate contained
them; `deploy` and `webuser` are added solely because the telemetry shows
unconditional acceptance, per instruction.

## 6. Scientific justification for using Epoch B

- Epoch B accounts for 99.26% of all corpus events and 99.60% of all login
  events. Epoch A (and the transition window itself) is a same-day, ~2-hour,
  single-source-IP window that this session independently confirmed is
  operator-originated (Section 3) — not a second production configuration
  competing for "steady state" status.
- The transition is a real, mechanistically-explained boundary (Section 2),
  not an artifact of aggregation: the same exact credential pair flips
  outcome within 84 seconds, and Cowrie's own source confirms a live file
  edit is sufficient to produce that flip with no restart.
- Using Epoch B as canonical means treating ~2 hours of self-identified
  configuration-validation activity, on day 1 of a multi-week deployment, as
  pre-baseline rather than as "the" production behavior — the same
  methodological move already used for gate T0 discipline elsewhere in this
  project (E1's SG-completion T0 excludes the setup/validation window around
  it).
- This does **not** claim Epoch B's userdb.txt content was static, unedited,
  for the entire remaining corpus. It claims the *observed behavior* (which 7
  usernames accept, which deny) was stable across 99%+ of the corpus, which
  is the only claim this gate depends on.

## 7. Exact proposed artifact hash

| File | Old SHA-256 (current, in-repo before this gate) | New SHA-256 (this gate's target, already written to the repo) |
|---|---|---|
| `userdb.txt` | `6d420c2099ed444581bdc4cfd4cc69a4e169a7c5174032ef88917e08fe91087e` | `8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6` |

Computed via `sha256sum userdb.txt` against the corrected 7-line file (each
line `username:x:*:`, LF line endings, trailing newline). `bootstrap-native.sh`'s
`ASSET_HASHES` pin for `userdb.txt` has been updated to the new hash (so any
future fresh instance boot gets the corrected file from first principles).
`validate-native-baseline.py`'s userdb assertions have been updated from
"10 accounts, all wildcard" to "7 accounts, all wildcard, exactly this set."
Both changes are committed to the working tree; neither has been uploaded to
S3 or referenced by a live CFN parameter value yet — the new
`AuthParityBundleId`/`UserdbTxtSha256` CFN Parameters exist in the template
with no value bound (they're populated only at change-set-creation time).

Local verification already run and passing: `python -m pytest tests/` —
146 passed, 4 subtests passed. `python validate-native-baseline.py` — PASS.

## 7a. Live baseline verification and candidate lineage (2026-09-19)

Read-only production provenance check performed via boto3 (the `aws` CLI
binary is not installed in the working environment; same `patriotpot`
profile / `us-east-1` region, same read-only API calls).

| Artifact | Value |
|---|---|
| Deployed template SHA-256 (`cloudformation:GetTemplate`) | `c2b15f43abf839b2f701c7cce34d59d21fb412ad9310b3f61dde0bd39301ce17` |
| Stack ID | `arn:aws:cloudformation:us-east-1:706162601288:stack/patriotpot-2026-control-prod/90c016a0-af23-11f1-8878-0affff84d99f` |
| Stack last updated | `2026-09-18T05:44:42.684Z` (matches E1's recorded T0 of `05:44:48.481Z`; E1 is still the last thing to touch this stack) |
| Live evidence bucket | `patriotpot-evidence-706162601288-us-east-1` |
| Published bundle (S3, verified by version-pinned GetObject) | `bootstrap/8f4f8645…/userdb.txt`, VersionId `qdTGA18YqBsROKkXI0kAr4DvyUBbIzIA` |

**Candidate lineage — note the superseded entry:**

| Candidate SHA-256 | Status |
|---|---|
| `1b14199fa940df52fb386350e47270f35e2c7eb136e2d40489c7ea716e95a24f` | **`SUPERSEDED_INVALID_CFN_TEMPLATE`** — CloudFormation rejected it at `CreateChangeSet` validation: bash local variables (`${pid_before}`, `${listener_before:-none}`, 7 occurrences) inside the association's `!Sub` block were parsed as CFN substitution variables. No offline YAML parse can catch this; only the real API did. Fixed by `${!varname}` literal-escaping in both `Invoke-PatriotPot.ps1`'s patch generator and the working-tree template. |
| `f583e85c0dde0ed4c108d271c6f34e5c6af97af80459dd05cec2894f8266e28e` | **Candidate of record.** Generated by `New-AuthParityTemplateSnapshot` from the real deployed template. |

**Deployed vs `32d89ee` reconciliation:** not byte-identical; 5 hunks, all one
family — three `Tags.Exposure` values (`live-control-tcp-2222` vs `disabled`)
and two Output strings (`ControlElasticIp` description; `ExposureState`
`LIVE_CONTROL_TCP_2222_ONLY` vs `NO_INGRESS_SSM_ONLY`). Root cause confirmed:
`8671f8f` (the executed E1 change) carried the stale strings; `32d89ee`
(E1.1) corrected them as a **documentation-only, deliberately non-deployed**
change. SecurityGroupIngress, all IAM content, Parameters and Resources are
byte-identical. `32d89ee` is corroborated as the deployed-template proxy with
that one named, cosmetic exception.

## 7b. EvidenceBucketPolicy dependency proof (2026-09-19)

The real change set contained a third resource, `EvidenceBucketPolicy`
(`Modify`, `Replacement=False`), and the guard hard-stopped on it as
designed. Rather than loosen the guard on the H2 precedent, the dependency
hypothesis was **proven** read-only. All six conjuncts pass:

| Conjunct | Result |
|---|---|
| deployed `EvidenceBucketPolicy` subtree == candidate subtree | byte-identical (`diff` exit 0) |
| candidate Principal == `!GetAtt PatriotPotInstanceRole.Arn` | confirmed in subtree text |
| `PatriotPotInstanceRole` Action=Modify, Replacement=False | confirmed from the real change set |
| role identity-bearing properties unchanged | full role-subtree diff = exactly one added ARN line; `RoleName` (`!Sub 'patriotpot-instance-role-${Environment}'`), `Path`, `AssumeRolePolicyDocument`, `ManagedPolicyArns` all identical |
| live role ARN == ARN the candidate's GetAtt resolves to | `iam:GetRole` → `arn:aws:iam::706162601288:role/patriotpot-instance-role-production`; physical name matches the template's fixed `RoleName`, role not replaced |
| live bucket policy == resolved candidate policy | `s3:GetBucketPolicy` canonicalized == resolved candidate canonicalized — **exact match** |

Verdict: `EvidenceBucketPolicy = DEPENDENCY_REEVALUATION_ONLY`. Raw capture
in `evidence/auth-parity-live-verification/dependency-proof.json`.

The guard extension is correspondingly narrow: `EvidenceBucketPolicy` is
permitted **only** when `Assert-EvidenceBucketPolicyChangeIsDependencyOnly`
passes with all proof inputs supplied. With no proof data supplied it still
hard-fails, exactly as before. Everything else still hard-fails.

**Two real defects surfaced by testing against the live API** (both fixed):
CloudFormation nests `BeforeValue`/`AfterValue` under `Target` and returns a
single `PolicyDocument` (not a `Policies` array/wrapper) — the original guard
was written against an assumed shape and would have failed closed on every
real change set; and `Remove-SingleArnOccurrence` counted only the first
match per statement, so a duplicated ARN could slip past its "exactly one"
contract.

## 8. CFN/SSM resource/property delta

**Parameter additions are not logical resource actions** and are listed
separately from the resource-level delta table below, per instruction:

- `AuthParityBundleId` — new CFN Parameter (`^[0-9a-f]{64}$`), content
  address of a dedicated S3 bundle holding only the corrected `userdb.txt`.
  No value bound yet.
- `UserdbTxtSha256` — new CFN Parameter (`^[0-9a-f]{64}$`), pinned hash for
  fetch-time verification. No value bound yet.

**Expected resource-level delta.** This is the one gate in this project's
history so far that adds new logical resources rather than only modifying
an association's fetched-file content — that is deliberate (isolation
rationale below), and every line below must appear, and *only* these lines,
in the real `describe-change-set` output (plain listing, not
`--include-property-values` alone, per the standing H1-discovered API
caveat) before any execution approval is given:

| LogicalResourceId | Action | Replacement | Property changed | Justification |
|---|---|---|---|---|
| `PatriotPotAuthParityAssociation` | `Add` | N/A (new resource) | entire resource | New `AWS::SSM::Association`, modeled on `PatriotPotDiscordMonitorAssociation`'s shape: fetches one content-addressed file, verifies SHA-256, installs it, restarts exactly one systemd unit (`cowrie.service` only). |
| `PatriotPotInstanceRole` | `Modify` | **False — hard stop if this shows `True`** | `Policies` (the `PatriotPotBootstrapRead` inline policy's `Statement` list gains one new `Resource` entry: `arn:aws:ssm...` — no, S3 object ARN: `bootstrap/${AuthParityBundleId}/userdb.txt`) | Adding a new explicit S3 object ARN to an existing inline IAM policy statement is a property-level update to the role, never a role replacement. Any `Replacement: True`, or any other property on this role changing, is a hard stop per instruction — it would mean CloudFormation intends to recreate the role (and, transitively, anything depending on its identity), which this gate must never require. |

**Expected to show zero delta** (must be independently confirmed absent
from the change set, not merely assumed):

- `PatriotPotInstanceV2` (the EC2 instance) — no property of the instance
  itself changes; `DependsOn` is a template-authoring construct, not a
  stack-level dependency that forces a diff.
- `PatriotPotEgressFirewallAssociation`, `PatriotPotDiscordMonitorAssociation`
  — neither references `AuthParityBundleId` or `UserdbTxtSha256`; both stay
  byte-identical.
- `PatriotPotSecurityGroup`, `PatriotPotEIP`, VPC/subnet/route/IGW resources
  — untouched, not referenced anywhere in this gate's changes.
- `EvidenceBucket`, `EvidenceBucketPolicy` — untouched; this gate reads from
  the bootstrap prefix under an existing bucket ARN pattern, it does not
  change bucket-level policy.

**Why a dedicated bundle instead of reusing `FirewallBundleId`:** `FirewallBundleId`
is already shared by two associations (`PatriotPotEgressFirewallAssociation`,
`PatriotPotDiscordMonitorAssociation`) and required inventing
`Test-ChangeIsHashSubstitutionOnly` to keep that two-way cross-contamination
auditable. Adding this correction as a third consumer of that same bundle
would directly contradict "do not mix this change with H2" — any future H2
republish would force-touch this gate's file identity and vice versa. A
dedicated `AuthParityBundleId` keeps this gate's change-set diff to exactly
the resources listed above, nothing from H1 or H2 in either direction.

**Known gap, disclosed rather than silently worked around:**
`Invoke-PatriotPot.ps1`'s `New-H2ChangeSet`/`New-FirewallOnlyChangeSet`
allowlist guards do not yet recognize `PatriotPotAuthParityAssociation` as an
allowed resource. A `New-AuthParityChangeSet` (or equivalent allowlist entry)
is required before any real `aws cloudformation create-change-set` can be run
for this gate — this has not been built, per "prepare, do not deploy." The
existing dual `describe-change-set` (property-values + plain) discipline
still applies once that tooling exists.

## 9. Rollback anchor

Rollback is **not** "restore the old bytes" performed by hand — it is the
same mechanism run in reverse, producing its own instrumented evidence
record, and is itself an experimental boundary in the longitudinal dataset,
not an undo that erases Epoch B from the timeline.

**Rollback procedure** (a second execution of the identical association
mechanism, pointed at the pre-gate content-address):

1. Fetch the old content-addressed `userdb.txt` artifact — the same
   `PatriotPotAuthParityAssociation` mechanism, re-parameterized with
   `UserdbTxtSha256` set back to the pre-gate hash and `AuthParityBundleId`
   pointed at an S3 bundle containing the pre-gate file.
2. Verify SHA-256 **before install**, not after: `sha256sum --check --status`
   against `6d420c2099ed444581bdc4cfd4cc69a4e169a7c5174032ef88917e08fe91087e`,
   using the identical fetch-then-verify-then-install ordering already in
   the association (verification gates installation, never the reverse).
3. Atomically install it — same `install -m 0644` pattern used forward
   (write to a `.new` path, verify, then move into place; never edit
   `/opt/cowrie/etc/userdb.txt` in place).
4. Restart Cowrie only — `systemctl try-restart cowrie.service`, same as
   forward execution. `patriotpot-discord.service` and the egress firewall
   are not touched, exactly as in the forward direction.
5. Validate listener/service/runtime health — the identical post-execution
   checks from Section 10 (PID, listener state, active-connection count,
   `systemctl is-active`), run again after the rollback restart.
6. **Record the rollback timestamp (`AUTH_PARITY_T_RESTART_ACTIVE` from the
   rollback run) as its own experimental boundary**, symmetric with Section
   11's Epoch A→B boundary: this creates a third state
   (`2026-Control Epoch C`, `AUTH_PARITY_ROLLED_BACK`, userdb reverted to
   the 10-account reconstruction), not a retroactive erasure of Epoch B.
   Any longitudinal analysis spanning a rollback must partition on this
   boundary the same way it must partition on the original one.

Repo-level (not part of the on-instance rollback mechanism, but required for
consistency): `bootstrap-native.sh`'s `ASSET_HASHES` pin and
`validate-native-baseline.py`'s userdb assertions would need to revert
together with `userdb.txt` and the template, so a future fresh instance
boot doesn't diverge from a rolled-back live instance.

**Blast radius if the association fails mid-run (forward or rollback):**
`set -euo pipefail` means a hash mismatch or fetch failure aborts before
`install`/`systemctl try-restart` runs — the live `/opt/cowrie/etc/userdb.txt`
is left untouched on failure, in either direction. If `cowrie.service` fails
to come back active after a successful install, `systemctl is-active --quiet`
fails the association (visible in SSM run output, including whatever
`AUTH_PARITY_*` lines were emitted before the failure) without CloudFormation
reporting stack failure — a known, accepted limitation of the association
mechanism generally, not new to this gate.

## 10. Pre/post validation procedure

The installation of the corrected `userdb.txt` and the `cowrie.service`
restart it triggers **is the formal 2026 Control Epoch A → Epoch B
boundary**. Every field below must be captured, none may be approximated
after the fact from unrelated side channels, and events spanning the
restart interval must not be silently merged into either epoch's dataset —
they get their own labeled transitional bucket (see the last item below).

**Pre-execution** (mirrors E1's discipline):
1. Re-verify the exact change-set ID/status/resource inventory immediately
   before `execute-change-set` (plain `describe-change-set`, not
   `--include-property-values` alone, per the H1-discovered API quirk).
2. Confirm the change set's resource inventory matches Section 8's table
   exactly — `PatriotPotAuthParityAssociation` `Add`, `PatriotPotInstanceRole`
   `Modify`/`Replacement: False` — nothing else.
3. Confirm via SSM that `/opt/cowrie/etc/userdb.txt`'s live SHA-256 on
   Control-0 currently equals the pre-gate hash
   (`6d420c2099ed444581bdc4cfd4cc69a4e169a7c5174032ef88917e08fe91087e`) —
   confirms the instance hasn't already drifted before touching it.

**Required boundary evidence fields and how each is captured** (the
association's own `commands` block now emits the `AUTH_PARITY_*` lines
inline in SSM's command output — see the CFN diff below — so these are
captured at the moment they occur, not reconstructed afterward):

| Field | Source | SSM output marker |
|---|---|---|
| UTC timestamp immediately before association execution | association script, first line executed | `AUTH_PARITY_T_PRE` |
| pre-change userdb SHA256 | association script, before fetch | `AUTH_PARITY_PRE_USERDB_SHA256` |
| Cowrie PID before | association script, `systemctl show -p MainPID` | `AUTH_PARITY_COWRIE_PID_BEFORE` |
| listener state before | association script, `ss -ltn 'sport = :2222'` | `AUTH_PARITY_LISTENER_BEFORE` |
| active session count immediately before restart (approximated — see caveat) | association script, `ss -tn state established 'sport = :2222'` count | `AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE` |
| UTC timestamp of userdb installation | association script, immediately after `install` | `AUTH_PARITY_T_INSTALL` |
| post-change userdb SHA256 | association script, immediately after install | `AUTH_PARITY_POST_USERDB_SHA256` |
| UTC timestamp of Cowrie restart (initiated) | association script, immediately before `systemctl try-restart` | `AUTH_PARITY_T_RESTART_INITIATED` |
| UTC timestamp Cowrie returns active | association script, immediately after `systemctl is-active --quiet` succeeds | `AUTH_PARITY_T_RESTART_ACTIVE` |
| Cowrie PID after | association script, post-restart `systemctl show -p MainPID` | `AUTH_PARITY_COWRIE_PID_AFTER` |
| listener state after | association script, post-restart `ss -ltn` | `AUTH_PARITY_LISTENER_AFTER` |
| active connection count after | association script, post-restart `ss -tn state established` count | `AUTH_PARITY_ACTIVE_CONNECTIONS_AFTER` |
| whether any sessions were terminated by the restart | **derived, not separately measured**: `systemctl try-restart` (not `reload`) always drops every socket the old process held — Cowrie has no hot-restart/socket-handoff path. If `AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE > 0`, those connections were unconditionally terminated by construction. `AUTH_PARITY_ACTIVE_CONNECTIONS_AFTER` reflects only connections established since the new process started. | derived from the two connection-count fields above |
| first Cowrie event timestamp after restart | **separate, out-of-band step**, not part of the association (keeps the association narrowly scoped, consistent with the existing associations never doing cross-cutting analysis): after execution, query the live `cowrie.json` (or CloudWatch Logs group `/patriotpot/2026-control/cowrie` if forwarded) via SSM for the first event with `timestamp` ≥ `AUTH_PARITY_T_RESTART_ACTIVE` | recorded manually into this file post-execution |
| first archived S3 event/object after restart | **separate, out-of-band step**: `aws s3api list-objects-v2` on the `control/${Environment}/sensors/control-0/instances/*/segments/*` prefix, filtered to `LastModified` ≥ `AUTH_PARITY_T_RESTART_ACTIVE`, sorted ascending, first result recorded | recorded manually into this file post-execution |

**Caveat on the connection-count fields:** `ss` reports TCP-level established
connections on port 2222, which is a reasonable proxy for "Cowrie sessions in
progress" but is not literally Cowrie's own internal session accounting
(Cowrie exposes no live session-count API). Treat it as an approximation,
label it as such in the filled-in evidence, and do not conflate it with the
authoritative session count that only the raw `cowrie.json`/S3 archive can
provide after the fact.

**Post-execution:**
1. Capture T0 as `AUTH_PARITY_T_RESTART_ACTIVE` from the association's own
   output — this is the Epoch A→B boundary, not the overall stack or
   association completion timestamp (consistent with E1's SG-specific-T0,
   not overall-stack, precedent).
2. Fill in every field from the table above directly from the SSM command
   output for this execution.
3. Confirm `/opt/cowrie/etc/userdb.txt`'s live SHA-256 equals
   `8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6`
   (already captured as `AUTH_PARITY_POST_USERDB_SHA256`, but re-verify
   independently via a separate SSM call rather than trusting only the
   association's own self-report).
4. Confirm `patriotpot-discord.service` and the egress firewall service are
   **unchanged** — same PID/start-time as pre-execution — proving this
   association didn't touch anything outside its own scope.
5. **Do not silently merge events spanning the restart interval.** Any
   `cowrie.json`/S3-archived event whose timestamp falls between
   `AUTH_PARITY_T_RESTART_INITIATED` and `AUTH_PARITY_T_RESTART_ACTIVE` (the
   window the listener was down) belongs to neither Epoch A nor Epoch B —
   label it `AUTH_PARITY_TRANSITION_WINDOW` in any longitudinal dataset,
   the same way this gate itself labels the 2025-10-16 08:30:44Z–08:32:07Z
   window as a boundary rather than assigning it to either adjacent epoch.
6. No synthetic login test against live TCP/2222 (standing constraint,
   unchanged) — correctness is verified by file hash + service state, not by
   attempting a real SSH login.

## 11. Observation-window segmentation plan

```
2026-Control Epoch A  (2026-09-18T05:44:48.481Z [E1 T0] -> AUTH_PARITY_T_RESTART_ACTIVE)
  10-account reconstruction (root/admin/user/oracle/mysql/postgres/backup/
  test/guest/ubuntu, all wildcard) — labeled RECONSTRUCTION_DEVIATION.
  Retained, not deleted, not silently merged with Epoch B data. Any
  cowrie.login.success/failed events recorded in this window must be
  interpreted against the 10-account surface, not the corrected one.

        |  AUTH_PARITY_TRANSITION_WINDOW
        |  (AUTH_PARITY_T_RESTART_INITIATED -> AUTH_PARITY_T_RESTART_ACTIVE:
        |   listener down, no events possible, labeled, not assigned to
        |   either epoch — see Section 10 item 5)

2026-Control Epoch B  (AUTH_PARITY_T_RESTART_ACTIVE onward)
  7-account 2025-steady-state-matched surface (root/admin/postgres/mysql/
  backup/deploy/webuser, all wildcard; all other usernames deny).
  Labeled AUTH_PARITY_CORRECTED.

        |  (only if rollback is later invoked, per Section 9)

2026-Control Epoch C  (rollback's own AUTH_PARITY_T_RESTART_ACTIVE, if ever)
  Reverted to the 10-account reconstruction. Labeled AUTH_PARITY_ROLLED_BACK
  — a distinct epoch, not an erasure of Epoch B.

        |

H2 (separate gate, already implemented+tested, not yet staged)
  Telemetry/presentation change only. No effect on accept/deny outcomes.
```

Practically: this gate's own evidence file (this document, filled in with
the actual `AUTH_PARITY_*` values once execution happens) becomes the
segmentation boundary record, exactly like `EXPOSURE-GATE-E1.md` is for the
E1 boundary. Any future longitudinal analysis of 2026 Control's
authentication outcomes must partition on `AUTH_PARITY_T_RESTART_ACTIVE`,
not treat the run as one homogeneous window, and must exclude the
transition window rather than assign it to either side.

### Four distinct quantities — do not substitute one for another

Established operationally on 2026-09-19, when an apparent "total silence"
on the Discord channel prompted a health check. Every sensor was healthy;
what had actually happened was that attacker traffic fell from a sustained
credential-validation burst (`47.109.63.110`, roughly one root credential
every ~2s) to six shallow probes. Discord looked silent because it
emphasizes *successful authentications*:

```
SENSOR_HEALTH  !=  ALERT_VOLUME  !=  ATTACK_VOLUME  !=  SUCCESSFUL_AUTH_VOLUME
```

Discord is **presentation telemetry**. Cowrie JSON (and its S3 archive) is
**measurement telemetry**. A drop in the former is not evidence about the
latter, in either direction. This is the same distinction H2's two-channel
design already encodes (`#control-raw` vs `#control-intel`, with canonical
evidence explicitly *not* Discord) — now with a live worked example.

### Non-stationarity caveat for the Epoch A/B comparison

Directly consequential for this gate: attack volume at Control-0 is
demonstrably **non-stationary on a sub-daily timescale**, independent of any
configuration change. A naive before/after comparison across
`AUTH_PARITY_T_RESTART_ACTIVE` would therefore attribute volume swings to the
userdb correction that in fact have nothing to do with it.

Two consequences:

1. Epoch A is short *and* its traffic baseline is unstable. Any Epoch A vs
   Epoch B claim must be about **per-attempt authentication outcome rates**
   (which usernames accept/deny, and at what ratio), never about raw event
   or session counts.
2. Record the ambient traffic regime alongside the boundary itself, so a
   later reader can tell a treatment effect from a traffic-volume artifact.
   The `AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE/AFTER` fields in Section 10
   capture a point sample; they are not a substitute for characterizing the
   surrounding window from the raw Cowrie JSON.

## Verdict carried forward

`2025_AUTH_PARITY_MISMATCH` (confirmed, not merely inferred) between current
2026 Control and the reconstructed Epoch B steady state — corrected by the
target `userdb.txt` above. Not yet applied.

---

## 12. Execution record (2026-09-19)

Change set executed: `auth-parity-final-20260919T220333Z`
(`arn:aws:cloudformation:us-east-1:706162601288:changeSet/auth-parity-final-20260919T220333Z/2f157f47-dd1b-4ae2-ac8d-28e1f9aed4f4`).
Executed via boto3 (`aws` CLI binary unavailable in the working
environment; same `patriotpot` / `us-east-1` profile).

### 12.1 Boundary

| Field | Value |
|---|---|
| `AUTH_PARITY_T_PRE` | `2026-09-19T22:08:03.358613997Z` |
| `AUTH_PARITY_PRE_USERDB_SHA256` | `6d420c2099ed444581bdc4cfd4cc69a4e169a7c5174032ef88917e08fe91087e` (matches the documented rollback anchor exactly — the instance had not drifted) |
| `AUTH_PARITY_T_INSTALL` | `2026-09-19T22:08:04.525555790Z` |
| `AUTH_PARITY_POST_USERDB_SHA256` | `8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6` — **target match** |
| `AUTH_PARITY_T_RESTART_INITIATED` | `2026-09-19T22:08:04.528340592Z` |
| **`AUTH_PARITY_T_RESTART_ACTIVE` (T0)** | **`2026-09-19T22:08:04.614016217Z`** |
| `AUTH_PARITY_LISTENER_BEFORE` | `LISTEN 0 50 0.0.0.0:2222 0.0.0.0:*` |
| `AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE` | `0` |
| `AUTH_PARITY_ACTIVE_CONNECTIONS_AFTER` | `0` |
| Association invocation | CommandId `4879d04c-5f7f-450f-9a53-9fed257bb8a7`, Status `Success`, ResponseCode `0` |

Independent corroboration of T0: systemd reports
`ActiveEnterTimestamp = Sat 2026-09-19 22:08:04 UTC`, `MainPID=22742`.

**Sessions terminated by the restart: zero.**
`AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE=0`, so the restart interrupted no
attacker session.

### 12.2 Invariants (all PASS)

| Invariant | Result |
|---|---|
| stack reaches `UPDATE_COMPLETE` | PASS |
| same EC2 instance ID (`i-00270aeefb6266a7b`) | PASS |
| same EIP (`13.217.73.134`) | PASS |
| same SG (`sg-0647129753848a7b0`) and rules (tcp/2222 from `0.0.0.0/0`, sole rule) | PASS |
| `EvidenceBucketPolicy` effective policy identical (canonicalized before/after) | PASS |
| `cowrie.service` active | PASS (`MainPID=22742`) |
| `0.0.0.0:2222` listening | PASS |
| deployed `userdb.txt` SHA-256 = `8f4f8645…c6365a6` | PASS (content verified: exactly the 7 approved accounts) |
| AuthParity association reports successful application | PASS |
| no H2 artifacts present | PASS (`/usr/local/libexec/threat_intel` absent; 0 occurrences of `DISCORD_INTEL_PARAMETER_NAME` in `discord.env`) |
| pre-existing services unaffected | PASS (`patriotpot-discord.service` active, `patriotpot-egress-firewall.service` active) |

Stack events for this execution: `PatriotPotInstanceRole` UPDATE_COMPLETE
(22:08:00.675Z), `PatriotPotAuthParityAssociation` CREATE_COMPLETE
(22:08:18.779Z), stack UPDATE_COMPLETE (22:08:20.765Z). `PatriotPotEIP`
also logged UPDATE_IN_PROGRESS → UPDATE_COMPLETE (22:08:02–22:08:03) without
appearing in the change-set inventory — a dependency re-evaluation of the
same class as `EvidenceBucketPolicy`; the allocation is unchanged and the
address is verified identical. `EvidenceBucketPolicy` produced no stack
event at all, consistent with the proven dependency-reevaluation-only
finding in Section 7b.

### 12.3 First post-T0 event

The first Cowrie event of any kind after T0 is the operator validation
session at `2026-09-19T22:19:32.849378Z` — i.e. **zero adversary events
were recorded between T0 and the validation**, consistent with the ongoing
traffic lull. The last pre-T0 event was `2026-09-19T18:17:07.957594Z`.

### 12.4 Operator-marked parity validation — EXCLUDE FROM CORPUS

Both attempts behaved exactly as the corrected policy predicts:

| Username | Password marker | Expected | Observed | Cowrie session | src_ip |
|---|---|---|---|---|---|
| `root` | `AUTHPARITY-OPERATOR-VALIDATION-20260919-expect-success` | SUCCESS | `cowrie.login.success` | `65c682df317d` | `OPERATOR_IP_REDACTED` |
| `guest` | `AUTHPARITY-OPERATOR-VALIDATION-20260919-expect-denial` | DENIAL | `cowrie.login.failed` | `d82d02cdde90` | `OPERATOR_IP_REDACTED` |

**Classification: `OPERATOR_TRAFFIC` — both sessions must be excluded from
the longitudinal corpus.** They are identifiable three independent ways:
the literal marker string `AUTHPARITY-OPERATOR-VALIDATION-20260919` in the
password field, the session IDs above, and the client fingerprint
(`SSH-2.0-paramiko_5.0.0`, hassh `6372ee6957562199b2fb773b0be1bf34`) which
no adversary traffic in this corpus has used. Authentication only — no
commands were issued in either session.

This is the first direct behavioural confirmation of the gate's purpose:
`guest` is now denied where the pre-correction 10-account reconstruction
would have accepted it.

### 12.5 Instrumentation defects found during execution (not affecting the change)

Two defects in the association's own evidence-capture script. Neither
affected the correctness of the userdb correction, but both degrade
boundary evidence quality and **should be fixed before the rollback path
uses the same mechanism**:

1. **`systemctl show -p MainPID --value` is unsupported on this host.**
   Amazon Linux 2 ships systemd 219; `--value` was added in systemd 230.
   The command therefore failed and both `AUTH_PARITY_COWRIE_PID_BEFORE`
   and `..._AFTER` fell through to the `|| echo unknown` fallback, making
   the PID-change check unusable. Verified root cause: the same query
   without `--value` works and returns `MainPID=22742`. Fix: drop `--value`
   and parse the `MainPID=` output.

2. **`AUTH_PARITY_LISTENER_AFTER=none` is a race, not an outage.** The
   listener check runs 86 ms after `systemctl try-restart` returns; Cowrie
   is a Twisted application that had not yet re-bound its socket at that
   instant. The listener is confirmed bound on independent verification.
   Fix: poll for the socket with a bounded timeout before recording the
   field, and derive T0 from the socket actually being bound rather than
   from `is-active` returning.

Consequence for the boundary definition: T0 as recorded
(`22:08:04.614016217Z`) is the moment systemd reported the unit active, not
the moment Cowrie resumed accepting connections, which was marginally
later and was not captured precisely. This does not create ambiguity in
the dataset — no Cowrie event can be recorded while the listener is down,
so the gap contains no events to misattribute — but the transition window
should be read as "T_RESTART_INITIATED → first verified post-restart
listener bind", not as an 86 ms window.
