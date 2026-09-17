#!/opt/python/3.8.20/bin/python3.8
"""Rotation-aware, restart-safe Cowrie JSON to Discord monitor."""

import hashlib
import errno
import json
import logging
from logging.handlers import WatchedFileHandler
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
import urllib.error
import urllib.request


LOG_PATH = Path(os.environ.get("COWRIE_JSON_PATH", "/opt/cowrie/var/log/cowrie/cowrie.json"))
STATE_PATH = Path(os.environ.get("DISCORD_STATE_PATH", "/var/lib/patriotpot-discord/state.json"))
OPS_LOG = Path(os.environ.get("DISCORD_OPS_LOG", "/var/log/patriotpot/discord.log"))
PARAMETER_NAME = os.environ.get(
    "DISCORD_PARAMETER_NAME", "/patriotpot/2026-control/discord-webhook"
)
AWS_PROFILE = os.environ.get("AWS_PROFILE", "patriotpot")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
POLL_SECONDS = float(os.environ.get("DISCORD_POLL_SECONDS", "5"))
DELIVERY_DELAY_SECONDS = float(os.environ.get("DISCORD_DELIVERY_DELAY_SECONDS", "1"))
MAX_SEEN = 2048
MAX_DEAD = 128
MAX_PENDING = 256
WEBHOOK_RE = re.compile(
    r"^https://(?:discord(?:app)?\.com)/api/webhooks/[0-9]+/[A-Za-z0-9._-]+$"
)
INTERESTING_COMMANDS = (
    "wget",
    "curl",
    "nc",
    "netcat",
    "python",
    "bash",
    "sh",
    "sudo",
    "su",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "whoami",
    "id",
    "uname",
    "ps",
    "netstat",
    "nmap",
    "chmod",
    "chown",
    "rm -rf",
    "history",
)


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("patriotpot-discord")
    logger.setLevel(logging.INFO)
    if "--self-test" in sys.argv:
        handler = logging.StreamHandler(sys.stderr)
    else:
        OPS_LOG.parent.mkdir(parents=True, exist_ok=True)
        handler = WatchedFileHandler(str(OPS_LOG), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(message)s"))
    handler.formatter.converter = time.gmtime
    logger.addHandler(handler)
    return logger


LOGGER = configure_logging()


def require_read_only_source() -> None:
    """Fail closed if the monitor sandbox can open the evidence log for write."""
    try:
        descriptor = os.open(str(LOG_PATH), os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            return
        if exc.errno == errno.ENOENT:
            return
        raise
    else:
        os.close(descriptor)
        raise RuntimeError("Cowrie JSON source is writable by the Discord monitor")


def default_state() -> Dict[str, object]:
    return {
        "version": 2,
        "source": None,
        "seen": [],
        "pending": [],
        "dead_letters": [],
        "replay_suppressed": 0,
        "initialized_at": None,
        "updated_at": None,
    }


def load_state() -> Dict[str, object]:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") not in (1, 2):
            raise ValueError("unsupported state format")
        for key in ("seen", "pending", "dead_letters"):
            if not isinstance(data.get(key), list):
                raise ValueError(f"invalid {key}")
        if data.get("version") == 1:
            data["version"] = 2
            data.setdefault("replay_suppressed", 0)
        # Pending records were captured before a prior process stopped.  They
        # are deliberately never retried: a request can have reached Discord
        # before a network failure was observed.  Retrying would duplicate a
        # historic alert and change the collection procedure.
        pending = data["pending"]
        if pending:
            for item in pending:
                append_bounded(
                    data["dead_letters"],
                    {"id": item.get("id"), "reason": "restart_replay_suppressed"},
                    MAX_DEAD,
                )
                append_bounded(data["seen"], item.get("id"), MAX_SEEN)
            data["replay_suppressed"] = int(data.get("replay_suppressed", 0)) + len(pending)
            data["pending"] = []
        return data
    except FileNotFoundError:
        return default_state()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.error("state_unreadable reason=%s", type(exc).__name__)
        raise


def save_state(state: Dict[str, object]) -> None:
    STATE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    encoded = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
    candidate = STATE_PATH.with_name(STATE_PATH.name + ".new")
    try:
        candidate.unlink()
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(candidate), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(candidate), str(STATE_PATH))
    except Exception:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
        raise


def safe_value(value: object, default: str = "N/A") -> str:
    if value is None:
        return default
    text = str(value).replace("\x00", "")
    return text[:1024] if text else default


def format_alert(event: Dict[str, object]) -> Dict[str, object]:
    """Preserve the strongest recovered 2025 event and payload semantics."""
    eventid = safe_value(event.get("eventid"), "unknown")
    source_ip = safe_value(event.get("src_ip"), "unknown")
    if eventid == "cowrie.login.success":
        username = safe_value(event.get("username"), "unknown")
        password = safe_value(event.get("password"), "unknown")
        title = "🚨 SUCCESSFUL LOGIN!"
        description = (
            f"**Attacker logged in!**\n\nIP: `{source_ip}`\n"
            f"User: `{username}`\nPass: `{password}`"
        )
        color = 0xFF0000
    elif eventid == "cowrie.command.input":
        command = safe_value(event.get("input"), "unknown")
        interesting = any(candidate in command.lower() for candidate in INTERESTING_COMMANDS)
        if interesting:
            title = "⚠️ SUSPICIOUS COMMAND!"
            description = f"**Command:** `{command}`\n**IP:** `{source_ip}`"
            color = 0xFF6600
        else:
            title = "💻 Command Executed"
            description = f"Command: `{command}`\nIP: `{source_ip}`"
            color = 0x0099FF
    elif "file_upload" in eventid:
        filename = safe_value(event.get("filename"), "unknown")
        title = "📤 FILE UPLOAD!"
        description = f"**File:** `{filename}`\n**IP:** `{source_ip}`"
        color = 0xFF3300
    elif "file_download" in eventid:
        filename = safe_value(event.get("filename"), "unknown")
        title = "📥 File Download"
        description = f"File: `{filename}`\nIP: `{source_ip}`"
        color = 0xFF9900
    else:
        # The recovered default disabled failed-login alerts and selected no
        # other event classes.
        raise ValueError("unsupported_event")
    return {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "footer": {"text": "Cowrie Honeypot Alert"},
            }
        ]
    }


def monitor_started_payload() -> Dict[str, object]:
    return {
        "embeds": [
            {
                "title": "🟢 Monitor Started",
                "description": "Discord alerts are now active!",
                "color": 0x00FF00,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "footer": {"text": "Cowrie Honeypot Alert"},
            }
        ]
    }


class CredentialCache:
    def __init__(self) -> None:
        self.value: Optional[str] = None
        self.next_refresh = 0.0

    def get(self, force: bool = False) -> Optional[str]:
        now = time.monotonic()
        if not force and now < self.next_refresh:
            return self.value
        self.next_refresh = now + 300
        command = [
            "/usr/bin/aws",
            "ssm",
            "get-parameter",
            "--name",
            PARAMETER_NAME,
            "--with-decryption",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--profile",
            AWS_PROFILE,
            "--region",
            AWS_REGION,
        ]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
            check=False,
        )
        candidate = result.stdout.strip() if result.returncode == 0 else ""
        if candidate and WEBHOOK_RE.fullmatch(candidate):
            if self.value is None:
                LOGGER.info("credential_available parameter=%s", PARAMETER_NAME)
            self.value = candidate
        else:
            if self.value is not None or force:
                LOGGER.warning("credential_unavailable parameter=%s", PARAMETER_NAME)
            self.value = None
        return self.value


def post_payload(url: str, payload: Dict[str, object]) -> bool:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "PatriotPot-Control/2026",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        LOGGER.error("delivery_rejected http_status=%s", exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        LOGGER.warning("delivery_unavailable")
    return False


def append_bounded(items: List[object], value: object, limit: int) -> None:
    items.append(value)
    if len(items) > limit:
        del items[: len(items) - limit]


def queue_line(state: Dict[str, object], raw_line: bytes) -> None:
    digest = hashlib.sha256(raw_line).hexdigest()
    seen = state["seen"]
    pending = state["pending"]
    try:
        event = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        LOGGER.warning("invalid_json line_sha256=%s", digest)
        append_bounded(seen, digest, MAX_SEEN)
        return
    if not isinstance(event, dict):
        append_bounded(seen, digest, MAX_SEEN)
        return
    try:
        payload = format_alert(event)
    except ValueError:
        append_bounded(seen, digest, MAX_SEEN)
        return
    if len(pending) >= MAX_PENDING:
        dropped = pending.pop(0)
        append_bounded(
            state["dead_letters"],
            {"id": dropped.get("id"), "reason": "queue_limit"},
            MAX_DEAD,
        )
        append_bounded(seen, dropped.get("id"), MAX_SEEN)
    pending.append({"id": digest, "payload": payload})


def drain_pending(state: Dict[str, object], credentials: CredentialCache) -> None:
    pending = state["pending"]
    if not pending:
        return
    webhook = credentials.get()
    if webhook is None:
        while pending:
            item = pending.pop(0)
            append_bounded(
                state["dead_letters"],
                {"id": item["id"], "reason": "credential_unavailable"},
                MAX_DEAD,
            )
            append_bounded(state["seen"], item["id"], MAX_SEEN)
        save_state(state)
        return
    while pending:
        item = pending[0]
        save_state(state)
        if post_payload(webhook, item["payload"]):
            append_bounded(state["seen"], item["id"], MAX_SEEN)
            pending.pop(0)
            save_state(state)
            LOGGER.info("delivery_success event_sha256=%s", item["id"])
            time.sleep(DELIVERY_DELAY_SECONDS)
            continue
        append_bounded(
            state["dead_letters"],
            {"id": item["id"], "reason": "delivery_uncertain_no_replay"},
            MAX_DEAD,
        )
        append_bounded(state["seen"], item["id"], MAX_SEEN)
        pending.pop(0)
        save_state(state)
        LOGGER.error("delivery_abandoned event_sha256=%s", item["id"])


def regular_stat(path: Path) -> Optional[os.stat_result]:
    try:
        lst = path.lstat()
        if not path.is_file() or path.is_symlink():
            return None
        return lst
    except FileNotFoundError:
        return None


def consume(
    path: Path,
    state: Dict[str, object],
    start: int,
    credentials: CredentialCache,
) -> int:
    offset = start
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as handle:
        handle.seek(start)
        while True:
            line_start = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                handle.seek(line_start)
                break
            queue_line(state, line)
            offset = handle.tell()
            state["source"]["offset"] = offset
            save_state(state)
            # The recovered monitor posted each selected line serially rather
            # than batching a poll interval into one request.
            drain_pending(state, credentials)
    return offset


def locate_inode(device: int, inode: int) -> Optional[Path]:
    for candidate in LOG_PATH.parent.glob(LOG_PATH.name + "*"):
        stat_result = regular_stat(candidate)
        if stat_result and stat_result.st_dev == device and stat_result.st_ino == inode:
            return candidate
    return None


def poll_once(state: Dict[str, object], credentials: CredentialCache) -> None:
    stat_result = regular_stat(LOG_PATH)
    if stat_result is None:
        drain_pending(state, credentials)
        return
    source = state.get("source")
    if source is None:
        state["source"] = {
            "device": stat_result.st_dev,
            "inode": stat_result.st_ino,
            "offset": 0,
        }
        state["initialized_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(state)
        LOGGER.info("initialized_at_start offset=0")

    old_identity = (int(source["device"]), int(source["inode"]))
    new_identity = (stat_result.st_dev, stat_result.st_ino)
    if old_identity != new_identity:
        prior = locate_inode(*old_identity)
        if prior is not None:
            consume(prior, state, int(source["offset"]), credentials)
        state["source"] = {
            "device": stat_result.st_dev,
            "inode": stat_result.st_ino,
            "offset": 0,
        }
        save_state(state)
        LOGGER.info("rotation_detected")
    elif stat_result.st_size < int(source["offset"]):
        source["offset"] = 0
        save_state(state)
        LOGGER.warning("copytruncate_detected")

    consume(LOG_PATH, state, int(state["source"]["offset"]), credentials)
    drain_pending(state, credentials)


def self_test() -> None:
    sample = {
        "src_ip": "192.0.2.1",
        "eventid": "cowrie.command.input",
        "input": "uname -a",
        "timestamp": "2026-09-15T00:00:00Z",
    }
    payload = format_alert(sample)
    embed = payload["embeds"][0]
    assert embed["title"] == "⚠️ SUSPICIOUS COMMAND!"
    assert embed["description"] == "**Command:** `uname -a`\n**IP:** `192.0.2.1`"
    assert embed["color"] == 0xFF6600
    assert embed["footer"] == {"text": "Cowrie Honeypot Alert"}
    assert POLL_SECONDS == 5
    example_url = "https://" + "discord.com/api/" + "webhooks/123/abc_DEF-1"
    assert WEBHOOK_RE.fullmatch(example_url)
    print("discord-monitor self-test: PASS")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return
    require_read_only_source()
    # The recovered monitor began at byte zero on every process start. State
    # remains process-local so restarts retain that historically observed
    # replay behavior rather than inventing durable deduplication.
    state = default_state()
    credentials = CredentialCache()
    LOGGER.info("monitor_started source=%s state=%s", LOG_PATH, STATE_PATH)
    webhook = credentials.get(force=True)
    if webhook is not None:
        post_payload(webhook, monitor_started_payload())
    while True:
        try:
            poll_once(state, credentials)
        except Exception as exc:
            LOGGER.exception("poll_failed reason=%s", type(exc).__name__)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
