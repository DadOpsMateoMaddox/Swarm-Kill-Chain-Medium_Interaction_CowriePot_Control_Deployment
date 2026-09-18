# Gate H1 Implementation Evidence

**Disposition:** H1 PASS — READY FOR PRE-EXPOSURE BASELINE CAPTURE
**Signed off:** 2026-09-18
**Mission boundary:** AWS profile `patriotpot`, region `us-east-1`, stack `patriotpot-2026-control-prod`

## Summary

| Field | Value |
|---|---|
| Gate | H1 |
| Change set | `egress-firewall-20260918T022536Z` |
| Change set ID | `b80a20a8-0f11-4580-b2a3-6cf865f427f6` |
| Stack result | `UPDATE_COMPLETE` (2026-09-18T04:57:01.516Z; initiated 04:56:20.091Z) |
| Instance | `i-00270aeefb6266a7b` (unchanged) |
| Public IP | `13.217.73.134` (unchanged) |
| Infrastructure | preserved — 0 replacements |
| Regression suite | 38/38 PASS (`tests/test_sidecars.py`, `tests/test_egress_firewall.py`) |
| Exposure state | PRE-EXPOSURE |
| Verdict | PASS |

## Implementation defects found and fixed (discovered during Gate H1, not a historical-control deviation; sensor was pre-exposure throughout, so no experimental data was affected)

1. `poll_once()` in `native/discord-monitor.py`: kept using a stale local `source` variable after initializing `state["source"]`, causing `TypeError: 'NoneType' object is not subscriptable` on every first poll after a process start.
2. `main()` called `default_state()` instead of `load_state()`, so the durable inode/offset/dedupe state built and unit-tested elsewhere in the file was never actually loaded — every restart replayed the entire Cowrie log to Discord.
3. `queue_line()` had no de-dupe check against `seen`/`pending`, so a line observed twice before delivery queued two duplicate alerts.

Also corrected: two stale SHA-256 pins in `native/bootstrap-native.sh` (`discord-monitor.py`, `patriotpot-egress-firewall.sh`), and added an explicit source comment documenting the recovered event catalogue: `cowrie.login.success`, `cowrie.command.input`, and `cowrie.session.file_download`/`file_upload` are alerted; `cowrie.login.failed` is the one intentionally-excluded class (validator traceability requirement).

Fix commit: `9dd19da` "Fix Gate H1 monitor state handling and artifact hashes" — `main` == `origin/main` at time of sign-off. `origin/CerberusInit` held at `25b4047` per instruction, to be retired after baseline capture.

## Change-set diff (reviewed, `--include-property-values` + supplemental plain `describe-change-set`)

| Resource | Action | Replacement | Change |
|---|---|---|---|
| `PatriotPotDiscordMonitorAssociation` | Modify | False | S3 prefix `bootstrap/591b6fbe.../discord-monitor.py` → `bootstrap/f1034440.../discord-monitor.py`; embedded `sha256sum --check` value `3def0b33...` → `a8606b55...` |
| `PatriotPotEgressFirewallAssociation` | Modify | False | Same pattern for `patriotpot-egress-firewall.sh`: `5add43e6...` → `0e1167ce...`. `.service` unit hash (`11d9124d...`) unchanged |
| `PatriotPotInstanceRole` | Modify | False | `PatriotPotBootstrapRead` policy's three S3 object ARNs re-pointed to the new bundle prefix; no new actions, no new statements |
| `EvidenceBucketPolicy` | Modify | False | `Evaluation: Dynamic`, `ChangeSource: ResourceAttribute`, `CausingEntity: PatriotPotInstanceRole.Arn` — pure CFN dependency propagation. Verified: canonicalized (sorted-key JSON) `Resources.EvidenceBucketPolicy` from `get-template --template-stage Processed` on both the current stack and the pending change set hashed to the identical SHA-256 `e7844eea...6ea91`. Role's `RoleName` unchanged (Modify, not Replace) so the referenced `!GetAtt PatriotPotInstanceRole.Arn` resolves identically before/after. |

No `PatriotPotInstanceV2`, no `PatriotPotEIP`, no security group, no route table, no `HostAmiId`, no `BootstrapBundleId`/`BootstrapScriptSha256`, no `CowrieHostKeySecret`/`VersionId` in the diff.

## Post-execution runtime verification (SSM, read-only + isolated in-process checks)

**CloudFormation events:** clean `UPDATE_IN_PROGRESS` → `UPDATE_COMPLETE` sequence for `PatriotPotInstanceRole`, `PatriotPotEIP`, `PatriotPotEgressFirewallAssociation`, `PatriotPotDiscordMonitorAssociation`, stack itself. No rollback, no other resources touched.

**SSM Association executions:**
- `PatriotPotDiscordMonitorAssociation` (`7e8affa7-080b-4b98-a76b-50bac03dab3f`): Status `Success` / DetailedStatus `Success`, last execution `2026-09-18T00:56:46.077-04:00`
- `PatriotPotEgressFirewallAssociation` (`ad98be8e-8f5f-42af-b06a-5e630124f6b2`): Status `Success` / DetailedStatus `Success`, last execution `2026-09-18T00:56:47.228-04:00`

**Diagnostic command 1** (SSM command `125e22d7-1cef-417f-ae21-61f282e9b4aa`, exit 0, Success):
```
firewall service:        active / enabled
firewall script hash:    0e1167ceb9f2c546ba5ba3a0c1e98b78e6b8625eee6d963d16de5692b757e839  (matches reviewed value)
discord monitor service: active / enabled
discord monitor hash:    a8606b55fad0ba9e403f690f86e1d4c1eb52b3f36c162369f0266343ce9930d9  (matches reviewed value)
cowrie service:           active
listening ports:         0.0.0.0:2222 only (twistd, pid 2307) — no 22, no 2223
discord state file:      {version: 2, source: {device: 66305, inode: 978800, offset: 3067},
                           initialized_at: 2026-09-16T20:07:48Z, updated_at: 2026-09-16T23:38:34Z,
                           replay_suppressed: 9}, pending_count: 0, seen_count: 9
journal:                 clean Stop/Start at 2026-09-18 04:56:45 UTC, zero poll_failed/TypeError entries
```

Key evidence: the SSM association's `systemctl try-restart` fired at 04:56:45 UTC, yet the persisted `offset` remained `3067` (not reset to 0) and no new `poll_failed` errors appeared — direct, on-host confirmation that the dead `load_state()` wiring defect is fixed in the running production artifact, independent of the isolated unit checks below.

**Diagnostic command 2** (SSM command `5a5070fe-b7cf-4d61-86f4-a64effbce73a`, Success) — isolated in-process checks against the deployed `/usr/local/libexec/patriotpot-discord-monitor.py`, touching neither the real state file nor `cowrie.json`:
```
WIRING_CHECK: PASS (deployed main() calls load_state())
DEDUPE_CHECK: PASS (duplicate line queued once, pending=1)
FIRST_POLL_CHECK: PASS (no crash on source=None transition, offset=0)
```

## Local implementation evidence (pre-deployment)

- `python -m pytest tests/` → 38 passed, 4 subtests passed
- `python validate-native-baseline.py` → PASS
- `python validate-behavioral-equivalence.py --static-only` → all `DECLARATION_CONSISTENT`; `fs.pickle` reported `DOCUMENTED_SUBSTITUTION`
- `Invoke-PatriotPot.ps1` PowerShell parse → no errors
- `aws cloudformation validate-template` → valid, `CAPABILITY_NAMED_IAM`

## Provenance note

`origin/main` was reset to the `CerberusInit` lineage (`25b4047`) plus the H1 fix commit (`9dd19da`) during this gate, replacing a prior unrelated `main` history that contained committed secret material (an SSH key backup and an env file) unrelated to Control-0. That legacy history is no longer reachable from `origin/main`; `origin/CerberusInit` is retained separately per instruction until baseline capture completes.
