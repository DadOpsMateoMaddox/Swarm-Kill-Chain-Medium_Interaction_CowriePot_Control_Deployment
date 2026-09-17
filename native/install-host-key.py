#!/opt/python/3.8.20/bin/python3.8
"""Install a Cowrie host key from Secrets Manager JSON without disclosing it."""

import base64
import binascii
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path


PRIVATE_PATH = Path("/opt/cowrie/etc/ssh_host_rsa_key")
PUBLIC_PATH = Path("/opt/cowrie/etc/ssh_host_rsa_key.pub")
MAX_SECRET_BYTES = 65536


def fail(message: str) -> "NoReturn":
    print(f"host-key install failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def atomic_write(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    candidate = path.with_name(path.name + ".new")
    try:
        candidate.unlink()
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(candidate), flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(candidate), mode)
        os.chown(str(candidate), uid, gid)
        os.replace(str(candidate), str(path))
    except Exception:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_SECRET_BYTES + 1)
    if not raw or len(raw) > MAX_SECRET_BYTES:
        fail("secret payload is empty or exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("secret payload is not valid UTF-8 JSON")
    if not isinstance(payload, dict):
        fail("secret payload must be a JSON object")

    encoded_private = payload.get("private_key_b64")
    supplied_public = payload.get("public_key")
    if not isinstance(encoded_private, str) or not isinstance(supplied_public, str):
        fail("required key fields are missing")
    try:
        private_key = base64.b64decode(encoded_private, validate=True)
    except (ValueError, binascii.Error):
        fail("private key is not valid base64")
    if not private_key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        fail("private key is not an OpenSSH private key")
    supplied_parts = supplied_public.strip().split()
    if len(supplied_parts) < 2 or supplied_parts[0] != "ssh-ed25519":
        fail("public key is not an Ed25519 OpenSSH key")

    account = pwd.getpwnam("cowrie")
    PRIVATE_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    atomic_write(PRIVATE_PATH, private_key, 0o600, account.pw_uid, account.pw_gid)

    try:
        derived = subprocess.run(
            ["/usr/bin/ssh-keygen", "-y", "-f", str(PRIVATE_PATH)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        PRIVATE_PATH.unlink(missing_ok=True)
        fail("ssh-keygen rejected the private key")

    derived_parts = derived.split()
    if len(derived_parts) < 2 or derived_parts[:2] != supplied_parts[:2]:
        PRIVATE_PATH.unlink(missing_ok=True)
        fail("public and private key fields do not match")
    public_bytes = (" ".join(supplied_parts) + "\n").encode("utf-8")
    atomic_write(PUBLIC_PATH, public_bytes, 0o644, account.pw_uid, account.pw_gid)


if __name__ == "__main__":
    main()
