# H2 Gate — Threat-Intelligence Enrichment + Discord Webhook Separation

Status as of 2026-09-20:

```
H2_ARCHITECTURE_VERIFIED
H2_BEHAVIOR_VERIFIED
H2_CHANGESET_STRUCTURALLY_VERIFIED
H2_ARTIFACT_PROVENANCE_VERIFIED
H2_EXECUTED
H2_DEPLOYED_STATE_VERIFIED
H2_CREDENTIAL_PROVISIONING_PENDING  (operational, not a code/deployment defect)
```

**Executed 2026-09-20.** `h2-final-20260920T212342Z` ran exactly as
reviewed, with no regeneration and no incidental source changes
beforehand. `PatriotPotAuthParityAssociation` and `PatriotPotInstanceV2`
never appeared in any H2 change set's resource inventory, at any point in
this gate's history, including this execution. See §7 for the full
execution record.

## 1. Architecture (REVIEWED_CANDIDATE_PRE_DEPLOYMENT)

`docs/diagrams/h2-class-REVIEWED_CANDIDATE_PRE_DEPLOYMENT.puml` and
`h2-sequence-REVIEWED_CANDIDATE_PRE_DEPLOYMENT.puml` (+ rendered PNGs),
committed `f1186d9`. Syntax-checked and rendered with `plantuml.jar`
(no errors) before commit. The sequence diagram's third flow makes the
legacy/enrichment independence visually provable, not just asserted: the
`ThreatIntelBroker`/`ThreatIntelWorker`/`EnrichmentCache` lifelines are
declared as sequence participants but never receive a single message in
that flow.

These diagrams are pre-deployment and will need a `VERIFIED_AS_DEPLOYED`
companion (or explicit annotation) after execution, with any divergence
from the reviewed candidate recorded rather than silently folded in.

## 2. Behavior

`tests/test_h2_enrichment_pipeline.py` (21 tests) proves the 10 reviewed
acceptance criteria — enrichment success, no-data (`STATUS_NOT_FOUND`,
this codebase's canonical status; not a separate `"no_data"` string),
timeout, HTTP 429, provider 5xx, cache hit (explicit provider call-count
assertions), cache expiry, duplicate event, malformed/partial Cowrie
event, and the critical invariant that enrichment failure never suppresses
the base alert — run through the real production code path
(`SessionClusterManager` → `ThreatIntelBroker` → `ThreatIntelWorker` →
`build_session_summary_payload` → discord-monitor's queue/drain), not
module-level mocks alone. One synthetic, entirely fabricated
`cowrie.session.connect`/`cowrie.login.success` fixture pair (field shape
matches the real October 16 corpus; no real attacker IP or credential
reproduced) is run through the real broker + real async worker to a mocked
webhook, and the captured POST body is asserted to contain both raw event
identity (session, src_ip, username) and enrichment fields (classification,
actor, malicious count, org, product) — proving transformation, not merely
2xx delivery.

Commits `aa2ec0f` (test suite) and `467498f` (source it validates,
resolved in §5).

## 3. Change-set structural verification

Two review-only change sets exist; **neither has been executed.**

### 3a. h2-20260920T204642Z (superseded)

Created against the live template + an early candidate that reused
`FirewallBundleId` for H2's new artifacts. Every parameter was
`UsePreviousValue=true`, so it never actually exercised publishing a new
bundle under that parameter — it proved the template *structure* was
scope-clean, not that the artifact-publish path was safe. Left in place,
unexecuted, as a forensic/review artifact; not deleted.

### 3b. h2-final-20260920T212342Z (current)

Created from the live deployed template + `gates/h2/h2-template-patch.json`
v3 (the H2BundleId design, §4), with real
`H2BundleId`/`H2DiscordMonitorSha256` values and every other parameter
frozen (`UsePreviousValue=true`).

Resource inventory (plain, authoritative):

| Logical ID | Action | Replacement |
|---|---|---|
| EvidenceBucketPolicy | Modify | False |
| PatriotPotDiscordMonitorAssociation | Modify | False |
| PatriotPotInstanceRole | Modify | False |

`PatriotPotInstanceV2` and `PatriotPotAuthParityAssociation`: both absent.
No `Replacement=True`/`Conditional` anywhere. `EvidenceBucketPolicy`
classified via its `Details[]`: `Evaluation=Dynamic`,
`ChangeSource=ResourceAttribute`, `CausingEntity=PatriotPotInstanceRole.Arn`
— dependency re-evaluation, not a content edit (same mechanism as the
AuthParity gate's own finding, confirmed via the real API response, not
assumed by pattern-matching).

`Assert-H2CandidateScope` and `Assert-H2BundleIdNotInInstanceSubtree`
(§4) both run verbatim (AST-extracted from `Invoke-PatriotPot.ps1`)
against this real result: **PASS**.

Stack confirmed unchanged after change-set creation: `StackStatus`
(`UPDATE_COMPLETE`), all 14 pre-existing parameters, and `LastUpdatedTime`
(`2026-09-19T22:07:39.679000+00:00`) identical before and after.

The association's own `discord-monitor.py` fetch now resolves to
`bootstrap/c987b11d.../discord-monitor.py` verified against
`c987b11d...` — the current H2 code, not the H1-era `a8606b55...`.

## 4. H2BundleId design (artifact-bundle separation from UserData)

**A factual correction, preserved deliberately.** An earlier ad-hoc Python
boundary check this session concluded `FirewallBundleId` was embedded in
`PatriotPotInstanceV2`'s `UserData` (the EC2 instance's replacement-
triggering property) — this was wrong, caused by using the wrong
end-marker and silently spanning into an adjacent resource
(`PatriotPotEgressFirewallAssociation`) the check didn't know existed.
Corrected using the actual production primitive,
`Get-ResourceSubtreeText`, run directly against the real live template:
`PatriotPotInstanceV2`'s subtree contains only `BootstrapBundleId`.
`FirewallBundleId`/`DiscordMonitorSha256` belong to two separate
`AWS::SSM::Association` resources (`PatriotPotEgressFirewallAssociation`,
`PatriotPotDiscordMonitorAssociation`) — no EC2 replacement semantics
apply to either.

`FirewallBundleId` being safe on the replacement axis doesn't make it
*clean* to reuse for H2, though: doing so would couple H2's publish
cadence to the firewall's (a firewall-only update would force an unrelated
discord-monitor.py/threat-intel republish, and vice versa) — the same
coupling `AuthParityBundleId` was introduced to avoid for the auth-parity
correction. `H2BundleId`/`H2DiscordMonitorSha256` (new parameters,
referenced ONLY by `PatriotPotDiscordMonitorAssociation`, never by
`PatriotPotInstanceV2`) are the corrected design, on lifecycle/cadence-
isolation grounds — not on the (retracted) instance-replacement-safety
claim.

`Assert-H2BundleIdNotInInstanceSubtree` (new, `Invoke-PatriotPot.ps1`)
checks this structurally — `H2BundleId`/`H2DiscordMonitorSha256` absent
from `PatriotPotInstanceV2`'s actual resource subtree — rather than
inferring it from "UserData is byte-identical" elsewhere. Wired into the
`$H2` flow before any AWS write. 4 dedicated Pester tests
(`tests/Invoke-PatriotPot.H2.Tests.ps1`): pass on the real reviewed
candidate, fails closed on both a planted `H2BundleId` leak and a planted
`H2DiscordMonitorSha256` leak, and does not false-positive on the
unrelated, legitimately-present `BootstrapBundleId`.

Commit `3461cff`: template (`H2BundleId`/`H2DiscordMonitorSha256`
parameters; `PatriotPotInstanceRole` gains 15 new `H2BundleId`-scoped
grants while the original 3 `FirewallBundleId`-scoped grants are left
untouched), `Invoke-PatriotPot.ps1` (`Get-H2AssetMap`, `Publish-H2Bundle`,
`Assert-H2BundleIdNotInInstanceSubtree`, `New-H2ChangeSet` rebuilt),
`gates/h2/h2-template-patch.json` v3, 31/31 H2 Pester tests (7 new).

## 5. Artifact provenance

**Resolved 2026-09-20, commit `467498f`.** Before this commit,
`native/discord-monitor.py`, `native/bootstrap-native.sh`, and
`tests/test_sidecars.py` were uncommitted working-tree state — the S3-
published H2 bundle and git history were out of sync on that point.

Verified, not assumed: `Assert-AssetIntegrity` (the real preflight,
AST-extracted and run for the first time this session — direct AWS calls
had bypassed the actual `Invoke-PatriotPot.ps1` execution path throughout,
since the `aws` CLI is unavailable in this environment) **PASSED** against
the working tree before commit, confirming `bootstrap-native.sh`'s pinned
`ASSET_HASHES` table for `discord-monitor.py` correctly matches the current
file — the invariant that table actually encodes ("matches
`Get-AssetMap`'s current working-tree files", for the separate, heavier
default/full-replacement deployment path that republishes
`BootstrapBundleId` itself) — not "matches what's published under the
live, frozen `BootstrapBundleId`" — a materially different claim this gate
never needed and `bootstrap-native.sh` is not part of the H2 bundle.

Full three-way check, all 15 H2 bundle files, git `HEAD` vs S3 object
bytes fetched fresh (not trusted from stored metadata) vs the hashes
already baked into `h2-final-20260920T212342Z`:

| file | git HEAD SHA-256 | S3 object SHA-256 | matches change-set hash |
|---|---|---|---|
| discord-monitor.py | `c987b11d...` | `c987b11d...` | ✅ (`H2BundleId` = `H2DiscordMonitorSha256`) |
| session_cluster.py | `b0ae7a61...` | `b0ae7a61...` | ✅ |
| discord_rate_governor.py | `e273bb8f...` | `e273bb8f...` | ✅ |
| threat_intel/__init__.py | `d5986e22...` | `d5986e22...` | ✅ |
| threat_intel/observables.py | `3cf65997...` | `3cf65997...` | ✅ |
| threat_intel/parameter_store.py | `e0d4b34a...` | `e0d4b34a...` | ✅ |
| threat_intel/cache.py | `cd429e9d...` | `cd429e9d...` | ✅ |
| threat_intel/provider_result.py | `2bf42c48...` | `2bf42c48...` | ✅ |
| threat_intel/http_client.py | `4aca1fa5...` | `4aca1fa5...` | ✅ |
| threat_intel/greynoise.py | `200ff0ab...` | `200ff0ab...` | ✅ |
| threat_intel/virustotal.py | `2a2a5c43...` | `2a2a5c43...` | ✅ |
| threat_intel/shodan.py | `4cb7a9d2...` | `4cb7a9d2...` | ✅ |
| threat_intel/broker.py | `7c4934aa...` | `7c4934aa...` | ✅ |
| threat_intel/rate_governor.py | `0a4b1ce9...` | `0a4b1ce9...` | ✅ |
| threat_intel/worker.py | `68d5cf8d...` | `68d5cf8d...` | ✅ |

15/15 match. Committing required **no content change** — the exact bytes
already published to S3 at `bootstrap/c987b11d.../` (2026-09-20, real
write, `head-object`-verified at publish time and re-verified here by
fetching and hashing the object bytes directly, not trusting stored
metadata) are the bytes now at `git HEAD` (commit `467498f`). Per the
content-addressed-immutability principle, no republish, no hash
recomputation, and no new change set were needed. `h2-final-20260920T212342Z`
remains the valid, current, fully-provenanced review-only artifact.

## 6. VERIFIED_AS_DEPLOYED diagrams

`docs/diagrams/h2-{class,sequence}-VERIFIED_AS_DEPLOYED.puml` (+ rendered
PNGs). Syntax-checked and rendered with `plantuml.jar` (no errors) before
commit. **No architectural delta** from `REVIEWED_CANDIDATE_PRE_DEPLOYMENT`
— every class, relationship, and flow is unchanged; only the header
provenance block and the sequence diagram's flow annotations were updated,
to record what was actually observed live (§7) rather than only reviewed.

## 7. Execution record

GO authorized 2026-09-20. `h2-final-20260920T212342Z` executed exactly as
reviewed — no regeneration, no incidental source changes beforehand.

### 7a. Pre-execution baseline

| | |
|---|---|
| T_PRE | 2026-09-20T22:03:39.534077+00:00 |
| Stack status | UPDATE_COMPLETE |
| Change set ARN | `arn:aws:cloudformation:us-east-1:706162601288:changeSet/h2-final-20260920T212342Z/11f34619-485e-45ad-ab05-af049ab034ed` |
| Change set status / execution status | CREATE_COMPLETE / AVAILABLE |
| Resource inventory (re-confirmed unchanged from §3b) | EvidenceBucketPolicy, PatriotPotDiscordMonitorAssociation, PatriotPotInstanceRole — all Modify, Replacement=False |
| Instance ID | `i-00270aeefb6266a7b` |
| EIP | `13.217.73.134` (`eipalloc-0de839802f07b5a62`) |
| Security group | `sg-0647129753848a7b0`, exactly TCP/2222 from 0.0.0.0/0 |
| Cowrie | active, PID 22742 |
| patriotpot-discord | active, PID 11336 |
| Deployed monitor SHA-256 | `a8606b55...` (H1-era, pre-H2) |
| `threat_intel`/`session_cluster.py` | confirmed absent |
| Active connections on :2222 | 0 |
| `discord.env` intel line | absent |
| userdb.txt SHA-256 | `8f4f8645...` (AuthParity 7-account baseline) |

### 7b. Three separate timestamps

Per the reviewed methodology, `H2_T0` is the deployed-monitor-verified
boundary, not the CloudFormation `UPDATE_COMPLETE` timestamp:

| | |
|---|---|
| `T_EXECUTE_REQUESTED` | 2026-09-20T22:04:15.441776+00:00 (`ExecuteChangeSet` submitted) |
| `T_ASSOCIATION_APPLY` (begin) | 2026-09-20T22:04:39.399Z (`PatriotPotDiscordMonitorAssociation` `UPDATE_IN_PROGRESS`) |
| `T_ASSOCIATION_APPLY` (complete) | 2026-09-20T22:04:56.080Z (`UPDATE_COMPLETE`) |
| CloudFormation `UPDATE_COMPLETE` | 2026-09-20T22:04:58.262Z |
| **`H2_T0`** | **2026-09-20T22:04:49 UTC** — `patriotpot-discord.service`'s own "Started PatriotPot local Cowrie JSON Discord monitor" journal entry, confirmed by `systemctl status` (PID 29536, active since that second) and independently by the real process's own ops log (`monitor_started` at `22:04:50,213Z`) |

Stack events showed `PatriotPotEIP` go through `UPDATE_IN_PROGRESS` /
`UPDATE_COMPLETE` during this execution (22:04:39–22:04:40), exactly as it
did during the AuthParity execution, despite EIP never appearing in
either change set's resource inventory. Recorded, not assumed a defect:
confirmed post-execution that the EIP (`13.217.73.134`), its allocation,
and its association to the instance are all byte-for-byte unchanged —
consistent with CloudFormation dependency-graph re-evaluation touching a
resource without mutating it, the same mechanism already established for
`EvidenceBucketPolicy`.

The association's own command execution (`AssociationId`
`7e8affa7-080b-4b98-a76b-50bac03dab3f`) completed `Success`; its captured
output is 15 S3 `head-object`-equivalent responses, one per fetched file,
each with a `Metadata.sha256` exactly matching the published bundle (§5) —
confirming the fetch-and-verify step inside the association's own script
succeeded for every file, not just that the script exited 0.

### 7c. Post-execution infrastructure verification — all PASS

| Invariant | Result |
|---|---|
| Stack status | UPDATE_COMPLETE |
| Instance ID unchanged | ✅ `i-00270aeefb6266a7b` |
| EIP unchanged, still associated to the same instance | ✅ `13.217.73.134` |
| Security group unchanged | ✅ `sg-0647129753848a7b0` |
| Ingress unchanged | ✅ exactly TCP/2222 from 0.0.0.0/0 |
| Cowrie listener | ✅ `LISTEN 0.0.0.0:2222`, same PID 22742 — **never restarted** |
| AuthParity userdb hash unchanged | ✅ `8f4f8645...` |
| H2 bundle installed | ✅ `session_cluster.py`, `discord_rate_governor.py`, all 12 `threat_intel/*.py` present |
| Deployed monitor hash == reviewed H2 hash | ✅ `c987b11d...`, confirmed by `sha256sum` on the host |
| threat-intel module hashes | ✅ all 12 files individually hash-match the published bundle exactly |
| `patriotpot-discord` active | ✅ PID 29536, active since `H2_T0` |
| Deployed code imports cleanly | ✅ `python3.8 -c "import session_cluster, discord_rate_governor, threat_intel.broker, threat_intel.worker"` → `IMPORT_OK`, run on the real host's real interpreter |
| `discord.env` intel line present | ✅ |
| No unexpected resource replacement | ✅ `Replacement=False` on all three touched resources, confirmed both pre- and post-execution |

### 7d. Deployed-path behavioral validation (kept separate from execution verification, per instruction)

A controlled, clearly-marked synthetic fixture
(`session:H2-DEPLOYED-VALIDATION-20260920`, src_ip `8.8.8.8` — Google DNS,
not an attacker; username field literally reads
`H2-DEPLOYED-PATH-VALIDATION-20260920-not-a-real-detection`) was run
through the **actual deployed** `session_cluster.py` and `threat_intel`
modules on the host — imported directly from
`/usr/local/libexec/patriotpot-discord-monitor.py`'s own module, reusing
its own constants, not reimplemented — via SSM. No traffic was generated
against Control's public listener; no line was injected into the real
Cowrie corpus.

**A real, reported finding, not a manufactured pass:** the intel webhook
parameter (`/patriotpot/2026-control/discord-intel-webhook`) and all three
provider API-key parameters (greynoise/virustotal/shodan) do not exist in
SSM Parameter Store — confirmed directly via `ssm:DescribeParameters`
(only `/patriotpot/2026-control/discord-webhook`, the pre-existing legacy
parameter, exists). This is a credential-provisioning task, outside this
gate's scope — the gate deliberately never handles provider secrets — not
a code or deployment defect.

What this proved, on the real deployed bytes:
- `ThreatIntelBroker.enrich_ip("8.8.8.8")` → `{greynoise, virustotal,
  shodan: status=missing_credential}` for all three, no exception, exactly
  the fail-open contract already unit-tested offline.
- `build_session_summary_payload` still produced a complete, valid,
  deliverable embed from that result.
- `CredentialCache("/patriotpot/2026-control/discord-intel-webhook").get()`
  correctly returned `None`; `post_payload` was correctly never called;
  the real process logged `credential_unavailable` (WARNING, no parameter
  value logged) rather than raising.
- The **legacy channel** (`/patriotpot/2026-control/discord-webhook`) is
  fully operational and unaffected by any of the above: the real running
  process's own ops log shows `credential_available` immediately after
  `H2_T0`, and `delivery_success` entries continuing both before and after
  the restart — confirming Flow 3's independence (§6) live, not just in
  the reviewed design.

Follow-up (not part of this gate, tracked separately): provision the
intel-webhook and three provider-key SSM parameters, then re-run this same
controlled-fixture validation to confirm live enriched delivery end to end.
