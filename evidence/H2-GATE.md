# H2 Gate — Threat-Intelligence Enrichment + Discord Webhook Separation

Status as of 2026-09-20:

```
H2_ARCHITECTURE_VERIFIED
H2_BEHAVIOR_VERIFIED
H2_CHANGESET_STRUCTURALLY_VERIFIED
H2_ARTIFACT_PROVENANCE_VERIFIED
EXECUTION_NOT_YET_AUTHORIZED
```

`H2_ARTIFACT_PROVENANCE_PENDING` (the label this gate carried through the
prior review round) is now resolved to `VERIFIED` — see §5. Nothing in
this gate has executed against the live stack. `PatriotPotAuthParityAssociation`
and `PatriotPotInstanceV2` have never appeared in any H2 change set's
resource inventory, at any point in this gate's history.

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

## 6. What remains before GO/NO-GO

Everything above is now verified. Execution itself is a separate,
explicit decision that has not been made. Before any `execute-change-set`
call against `h2-final-20260920T212342Z`:

- Operator confirmation this is the intended production behavior change.
- A defined runtime validation procedure for immediately after execution
  (association command output, live Discord delivery on both channels,
  no regression on the legacy alert path).
- `VERIFIED_AS_DEPLOYED` diagram regeneration/annotation (§1) as a
  post-execution step, with any divergence from the reviewed candidate
  recorded explicitly.
