# PatriotPot 2026 Control — P0 Recovery

**Date:** 2026-09-23
**Instance:** `i-00270aeefb6266a7b`
**Status:** `P0A / P0B1 / P0B2 — CLOSED, LIVE REMEDIATION VERIFIED`
**Not yet evaluated:** `P0C — deception filesystem parity`

## The defect this bundle explains

Between the AuthParity deployment and 2026-09-23, Control-0 recorded
**16,070 successful logins and zero `cowrie.command.input` events**. The
2025 control, by contrast, produced a **80.1% post-auth command rate**
(9,621 successful-login sessions, 7,707 with at least one command, median
time login→first command ~0.464s).

The 2026 sensor was not facing a different attacker population and was not
suffering from weak deception content. It was broken in three independent,
stacked ways — all of them invisible to service-level health checks.

Every one of these defects allowed Cowrie to boot cleanly, bind its
listener, complete key exchange, authenticate the attacker, open a session
channel, and accept environment variables. The sensor only failed at the
exact moment an attacker attempted to *do something*. Every dashboard was
green while the sensor produced no usable intelligence.

## P0A — SSH Host-Key Slot Corruption

**Observed:**
- `rsa_*` configuration pointed at Ed25519 key material (both halves,
  matching fingerprint `SHA256:E4D4gLIM...`).
- No `ed25519_*` configuration existed; no RSA key existed on the host.
- Twisted raised `BadSignatureAlgorithmError: public key signature
  algorithm b'ssh-rsa' is not defined for Ed25519 keys` whenever a client
  negotiated `ssh-rsa`.
- Failure occurred during KEX (`transport.py:1585 _ssh_KEXDH_INIT`,
  `transport.py:1690 ssh_KEX_DH_GEX_INIT`), destroying the transport
  before any shell could be created.

**Remediation:**
- Copied (not moved) the existing Ed25519 pair into the proper
  `ed25519_*` slot, preserving its fingerprint so the attacker-visible
  host identity — and therefore measurement continuity — is unchanged.
- Generated a type-correct 3072-bit RSA honeypot host key.
- Configured that pair under `rsa_*`.
- Mirrored the pre-existing permission model (`cowrie:cowrie`, `600`/`644`)
  rather than inventing one.

**Verification:** both paths exercised with *forced, exact*
`HostKeyAlgorithms` (not `+ssh-rsa`, which the client silently
down-negotiated to ECDSA on an earlier attempt):

```
ssh-ed25519 : kex host key algorithm = ssh-ed25519, SHA256:E4D4gLIM...  authenticated
ssh-rsa     : kex host key algorithm = ssh-rsa,     SHA256:3+mzqUmT...  authenticated
no BadSignatureAlgorithmError on either path
```

**Status: FIXED / VERIFIED**

## P0B1 — Invalid `processes` Configuration

**Observed:**
- `[shell] processes = 5`
- Cowrie 2.5.0 interprets `processes` as the path to a JSON file
  containing canned `ps` output, and passes the value directly to
  `open()`.
- `open("5")` raised `FileNotFoundError: [Errno 2] No such file or
  directory: '5'` inside `initFileSystem`.
- `server.py` catches only `NoOptionError`, so `FileNotFoundError`
  propagated to `request_exec`, producing `SSH_MSG_CHANNEL_FAILURE`.

This value was almost certainly a transcription error in the recovered
2025 candidate config, read as "number of processes." The config's own
header warned that provenance was unverified, and the only value it
claimed telemetry support for was `backend = shell`. `processes = 5`
cannot have been what produced 9,409 commands in 2025.

**Remediation:**
`processes = /opt/cowrie/share/cowrie/cmdoutput.json` — absolute, to
eliminate relative-path ambiguity. Target verified before use: parses as
JSON, contains `["command"]["ps"]` (73 entries), readable by the `cowrie`
user.

**Verification:** traceback moved past `initFileSystem` into the next
layer, confirming this specific fault was cleared.

**Status: FIXED / VERIFIED**

## P0B2 — TTY Log Directory Ownership

**Observed:**
- `/opt/cowrie/var/lib/cowrie/tty` — owner `root:cowrie`, mode `750`.
- Every sibling directory was `cowrie:cowrie`. `tty` was the sole outlier.
- Cowrie runs as `cowrie`; group had `r-x` but **not** write.
- `ttylog = true` is the dist default and was never overridden, so every
  session opens a TTY log on `connectionMade`.
- `builtins.PermissionError: [Errno 13] Permission denied:
  'var/lib/cowrie/tty/20260923-074258-5842dde7dd2c-0e.log'`

`insults.py:47-50` sets `type = "e"` (exec) or `"i"` (interactive), but
`connectionMade` runs *upstream of that split* — so this killed both
modes identically. `insults.py:214-221` additionally requires write on the
same directory to `os.rename()` the log to its input-hash filename.

Four-way classification resolved to **permissions**: not configuration
(`ttylog_path` resolved correctly), not directory creation (it existed),
not filename construction (`insults.py:62-68` built a valid name).

**Remediation:** `chown cowrie:cowrie`, mode `750` retained.
No restart required — directory permissions are evaluated at `open()`.

**Verification:**

```
TTY_WRITABLE=YES
SSH_EXIT=0
HONEYPOT_STDOUT=[root]
error_line_count=0

session 7467e75c8448
    cowrie.session.connect
    cowrie.client.version
    cowrie.client.kex
    cowrie.login.success     user='root'
    cowrie.client.var
    cowrie.session.params            <-- previously always absent
    cowrie.command.input     input='whoami'
    cowrie.log.closed
    cowrie.session.closed    dur=0.051
```

A TTY replay log was written and successfully renamed to its input-hash
filename (`f25297859cf0...`), proving both `ttylog_open` and the
`ttylog_close`/`os.rename` path now function.

**Status: FIXED / VERIFIED**

## Validation traffic provenance

All validation sessions in this bundle are **synthetic**, generated from
`127.0.0.1` on the instance itself. No traffic was directed at Control-0's
public listener, and no fabricated events were injected into the Cowrie
corpus. Sessions are identifiable by:

```
src_ip   = 127.0.0.1
username = root
password = P0-VALIDATION-20260923
```

These session IDs must be **excluded from attacker statistics**. See
`successful-session-events.json`, which carries `"synthetic": true`.

## Open items

- **`P0C` — deception filesystem parity.** `/home` currently contains only
  `phil` (`.bash_logout`, `.bashrc`, `.profile`) from the stock Cowrie
  `fs.pickle`. The 2025 control's `~/.ssh`, `/home/admin/passwords.txt`,
  `/home/deploy/config.json` and per-user home directories are absent.
  Not yet evaluated.
- **Durable IaC repair.** All three fixes are live-only. See
  `live-drift.yaml`. `bootstrap-native.sh` still ships `processes = 5`,
  still installs Ed25519 material into the RSA slot, and still creates the
  `tty` directory without correct ownership — so **any instance
  replacement recreates all three defects.**

## Files

| File | Contents |
|---|---|
| `P0-RCA-01-host-key-slot.txt` | Host-key slot RCA, source truth, repair execution |
| `P0-RCA-02-processes-path.txt` | `processes` semantics RCA, target file validation |
| `P0-RCA-03-tty-permissions.txt` | TTY ownership RCA, four-way classification |
| `pre-repair-cowrie.cfg` | Config as deployed before any repair |
| `post-repair-cowrie.cfg` | Config after P0A + P0B1 |
| `key-fingerprints.txt` | Public fingerprints only; no private key material |
| `journal-host-key-failure.txt` | `BadSignatureAlgorithmError` tracebacks |
| `journal-processes-failure.txt` | `FileNotFoundError: '5'` tracebacks |
| `journal-tty-permission-failure.txt` | `PermissionError` traceback |
| `journal-successful-command.txt` | `CMD: whoami` / `Command found: whoami` |
| `successful-session-events.json` | Full event sequence of the verified session |
| `transport-both-paths-verified.txt` | Forced-algorithm transport proofs |
| `verification-final.txt` | Final fix + acceptance output |
| `filesystem-permissions.txt` | Directory ownership + write tests |
| `service-state.txt` | systemd state, listener, Cowrie version |
| `live-drift.yaml` | Live-vs-IaC divergence record |
| `SHA256SUMS` | Integrity manifest for this bundle |
