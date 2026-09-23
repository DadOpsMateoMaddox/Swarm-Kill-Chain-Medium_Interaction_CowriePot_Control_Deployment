# P0C-C — Characterization Result

**Gate:** P0C-C (characterization only). **Status: CLOSED.**
No remediation was performed and none is authorized by this gate.

**Date:** 2026-09-23
**Instance:** i-00270aeefb6266a7b
**Backing artifact:** `fs.pickle` sha256 `06f0ed52…6da9`, byte-identical before and after both probes.

---

## Evidentiary chain

```
fs.pickle  06f0ed52…6da9           01-, 02-
        |
        v
synthetic sessions
  c304c5ea98e0 / 1e3b3654ca70      03-
        |
        v
attacker-visible PTY results       04-
        |
        v
cowrie.command.input  (35 events)  05-
        |
        v
TTY transcripts
  c1f63a3b… / ed633da4…            06-
```

Every claim in `07-` and `08-` resolves to that chain. Nothing is inferred
from Git, from the repository working tree, or from the paper.

---

## Findings

**1. The deployed namespace is STOCK Cowrie v2.5.0, unmodified.**
The hash equals the value pinned at `native/bootstrap-native.sh:287`. There is
no customized filesystem on this sensor and there never was one in this
deployment.

**2. `~/.ssh` is PRESENT — the pre-probe expectation was wrong.**
`/root/.ssh` exists with correct `0700 root:root` semantics and contains
`known_hosts`. The 2025 persistence chain targets a directory that already
exists here. **Absence of `~/.ssh` is eliminated as an explanation for any
behavioural gap.** This supersedes the implication in
`docs/diagrams/deception-filesystem-P0C-TARGET.puml`, which has been corrected.

**3. The namespace/contents split is confirmed empirically.**
`honeyfs/home/admin/passwords.txt` exists on the host and is unreachable to an
attacker, because `/home/admin` is absent from the pickle. This was previously
a documented inference; it is now a direct observation.

**4. Two attacker-detectable inconsistencies, neither previously recorded.**

- `/etc/passwd` declares `admin` with home `/home/admin`, which does not exist.
- `/test2` sits in `/` with a 2021 mtime among 2013 siblings.

**5. Command emulation is defective independently of the filesystem.**
`ls -ld ~` resolves bare `~` against the cwd (`/root/~`); `ls -d` silently
returns nothing; `ps` returns no rows *despite* the P0B1 fix. **P0B1 fixed a
crash, not output correctness.** These will not be fixed by regenerating
`fs.pickle` and must not be bundled into that change.

**6. The two paper-asserted bait artifacts are absent, and remain
non-reconstructable.**
`/tmp/rat_loader_v5.py` and `/var/backups/db_dump.sql` are confirmed absent.
Their historical status stays `INSUFFICIENT`. Observing their absence today
does **not** upgrade the paper's claim into reconstruction authority.

---

## What this gate does NOT establish

- That any of this caused the Sep-18 16,070/0 observation. That is **HIST-01**,
  open and separate.
- That restoring the 2025 namespace restores the 2025 command rate.
- Any authority to modify the live sensor. Per operator direction, **live
  repair stops here.**

---

## Carried forward

| ID | Item | Target |
|----|------|--------|
| P0C-R | Namespace deltas in `08-` with `allowed: true` | `fs.pickle` via build artifact + SSM Association; must revise the `bootstrap-native.sh:287` hash pin in the same change or it fails closed |
| P0C-R2 | Shell emulation defects (`~`, `-d`, `ps`) | Cowrie command implementations — **not** `fs.pickle` |
| P0C-R3 | `/test2` removal, `/etc/passwd` ↔ `/home` consistency | fingerprint reduction |
| P0C-V | Attacker-view verification on a fresh deployment | after P0C-R |
| HIST-01 | Sep-18 16,070/0 attribution | `cowrie.json.2026-09-18`, using the frozen tracebacks only |
