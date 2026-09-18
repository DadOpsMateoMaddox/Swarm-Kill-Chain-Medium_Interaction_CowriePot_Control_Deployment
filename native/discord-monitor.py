#!/opt/python/3.8.20/bin/python3.8
"""Rotation-aware, restart-safe Cowrie JSON to Discord monitor.

H2 adds session/IP clustering, threat-intelligence enrichment, and an
outbound rate governor as a presentation layer on top of the same
byte-offset file tailing and restart-safe dedupe this module already had.
That underlying tailing/dedupe/rotation logic is untouched from the H1-fixed
version; only "what payload gets built and when" changed.
"""

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
from typing import Dict, List, Optional, Tuple
import urllib.error
import urllib.request

# Make sibling modules (session_cluster.py, discord_rate_governor.py, the
# threat_intel package) importable both in production -- where Python
# already puts a script's own directory on sys.path -- and under the test
# harness, which loads this file via importlib.util.spec_from_file_location
# and does not do that automatically.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from session_cluster import (  # noqa: E402
    INTERESTING_COMMANDS,
    SessionCluster,
    SessionClusterManager,
    build_session_summary_payload,
)
from discord_rate_governor import DiscordRateGovernor  # noqa: E402
from threat_intel.broker import ThreatIntelBroker  # noqa: E402
from threat_intel.cache import EnrichmentCache  # noqa: E402
from threat_intel.parameter_store import ParameterRegistry  # noqa: E402
from threat_intel.worker import ThreatIntelWorker  # noqa: E402


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

# H2: session/IP clustering.
CLUSTER_WINDOW_SECONDS = float(os.environ.get("DISCORD_CLUSTER_WINDOW_SECONDS", "45"))
CLUSTER_MAX_AGE_SECONDS = float(os.environ.get("DISCORD_CLUSTER_MAX_AGE_SECONDS", "1800"))
# Off by default: every immediate alert is one more webhook call, which cuts
# directly against the anti-flood goal this whole redesign exists for. The
# code path is fully implemented and tested; an operator opts in explicitly.
IMMEDIATE_ALERTS_ENABLED = os.environ.get("DISCORD_IMMEDIATE_ALERTS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
)

# H2: threat-intelligence enrichment.
THREAT_INTEL_CACHE_DIR = Path(
    os.environ.get("THREAT_INTEL_CACHE_DIR", "/var/lib/patriotpot-discord/threat-intel")
)
THREAT_INTEL_TIMEOUT_SECONDS = float(os.environ.get("THREAT_INTEL_TIMEOUT_SECONDS", "5"))
GREYNOISE_PARAMETER_NAME = os.environ.get(
    "GREYNOISE_PARAMETER_NAME", "/patriotpot/2026-control/greynoise-api-key"
)
VIRUSTOTAL_PARAMETER_NAME = os.environ.get(
    "VIRUSTOTAL_PARAMETER_NAME", "/patriotpot/2026-control/virustotal-api-key"
)
SHODAN_PARAMETER_NAME = os.environ.get(
    "SHODAN_PARAMETER_NAME", "/patriotpot/2026-control/shodan-api-key"
)

# H2: outbound rate governor.
DISCORD_MIN_INTERVAL_SECONDS = float(os.environ.get("DISCORD_MIN_INTERVAL_SECONDS", "1"))


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
        "version": 3,
        "source": None,
        "seen": [],
        "pending": [],
        "dead_letters": [],
        "replay_suppressed": 0,
        "initialized_at": None,
        "updated_at": None,
        # H2: active (not yet flushed) session clusters, restart-safe.
        # Restart-safety property: an event is only marked `seen` after
        # queue_line has already written its cluster mutation into this
        # field, and both are then persisted in the same save_state() call
        # that persists `source.offset` -- so a crash can never advance the
        # offset (or mark a line seen) without the cluster data it produced
        # also being on disk.
        "clusters": {},
        # Flushed but not yet turned into a pending summary -- covers the
        # window where enrichment is running on a background worker thread.
        "flushed_awaiting_enrichment": {},
    }


def load_state() -> Dict[str, object]:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") not in (1, 2, 3):
            raise ValueError("unsupported state format")
        for key in ("seen", "pending", "dead_letters"):
            if not isinstance(data.get(key), list):
                raise ValueError(f"invalid {key}")
        if data.get("version") == 1:
            data["version"] = 2
            data.setdefault("replay_suppressed", 0)
        if data.get("version") == 2:
            # Pre-H2 state has no cluster data -- nothing to restore, which
            # is correct: those in-flight per-event payloads were already
            # either delivered or dead-lettered under the old model.
            data["version"] = 3
        if not isinstance(data.get("clusters"), dict):
            data["clusters"] = {}
        if not isinstance(data.get("flushed_awaiting_enrichment"), dict):
            data["flushed_awaiting_enrichment"] = {}
        # Pending records were captured before a prior process stopped.  They
        # are deliberately never retried: a request can have reached Discord
        # before a network failure was observed.  Retrying would duplicate a
        # historic alert and change the collection procedure. Under H2 a
        # "pending" item is a session summary or immediate alert rather than
        # a single raw event, but the same restart-replay-suppression logic
        # applies unchanged.
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
    """Build a compact single-event embed.

    Used for the startup ping and, when DISCORD_IMMEDIATE_ALERTS is enabled,
    for the optional immediate alert on a priority event. Session summaries
    (the default H2 presentation) are built by
    session_cluster.build_session_summary_payload instead.

    Considered event classes, per the recovered 2025 default: cowrie.login.success,
    cowrie.command.input, and cowrie.session.file_download / file_upload are
    alerted. cowrie.login.failed is deliberately not alerted; see the
    unsupported_event branch below.
    """
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


def recovery_digest_payload(suppressed_count: int) -> Dict[str, object]:
    return {
        "embeds": [
            {
                "title": "✅ Discord delivery recovered",
                "description": (
                    f"~{suppressed_count} session summaries were held back during a Discord "
                    "rate-limit window and were not individually replayed. Raw Cowrie "
                    "telemetry and the S3 archive were not affected."
                ),
                "color": 0x00FF00,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "footer": {"text": "PatriotPot H2 rate governor"},
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


def _parse_retry_after(exc: urllib.error.HTTPError) -> Optional[float]:
    try:
        body = exc.read()
    except Exception:  # noqa: BLE001 - best-effort only
        body = b""
    if body:
        try:
            parsed = json.loads(body.decode("utf-8"))
            value = parsed.get("retry_after")
            if isinstance(value, (int, float)):
                return float(value)
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            pass
    header = exc.headers.get("Retry-After") if exc.headers is not None else None
    if header is not None:
        try:
            return float(header)
        except ValueError:
            return None
    return None


def post_payload(url: str, payload: Dict[str, object]) -> Tuple[bool, Optional[int], Optional[float]]:
    """POST one payload. Returns (success, http_status, retry_after_seconds).

    Forces allowed_mentions={"parse": []} on every outbound payload here,
    centrally, rather than trusting each payload builder to set it: attacker
    or provider-supplied text (a Cowrie command, a GreyNoise tag) must never
    be able to trigger an @everyone/@here/user ping just by appearing in an
    embed string.
    """
    payload = dict(payload)
    payload["allowed_mentions"] = {"parse": []}
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
            return 200 <= response.status < 300, response.status, None
    except urllib.error.HTTPError as exc:
        retry_after = _parse_retry_after(exc)
        LOGGER.error("delivery_rejected http_status=%s", exc.code)
        return False, exc.code, retry_after
    except (urllib.error.URLError, TimeoutError, OSError):
        LOGGER.warning("delivery_unavailable")
        return False, None, None


def append_bounded(items: List[object], value: object, limit: int) -> None:
    items.append(value)
    if len(items) > limit:
        del items[: len(items) - limit]


def enqueue_pending(state: Dict[str, object], item_id: str, payload: Dict[str, object]) -> None:
    pending = state["pending"]
    seen = state["seen"]
    if item_id in seen or any(existing["id"] == item_id for existing in pending):
        return
    if len(pending) >= MAX_PENDING:
        dropped = pending.pop(0)
        append_bounded(
            state["dead_letters"],
            {"id": dropped.get("id"), "reason": "queue_limit"},
            MAX_DEAD,
        )
        append_bounded(seen, dropped.get("id"), MAX_SEEN)
    pending.append({"id": item_id, "payload": payload})


def queue_line(state: Dict[str, object], raw_line: bytes, clusters: SessionClusterManager) -> None:
    digest = hashlib.sha256(raw_line).hexdigest()
    seen = state["seen"]
    if digest in seen:
        return
    try:
        event = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        LOGGER.warning("invalid_json line_sha256=%s", digest)
        append_bounded(seen, digest, MAX_SEEN)
        return
    if not isinstance(event, dict):
        append_bounded(seen, digest, MAX_SEEN)
        return
    # The line has now been fully absorbed into cluster state (or discarded
    # as unusable); mark it seen immediately so a mid-line-batch restart
    # cannot cause the exact same bytes to be reprocessed. This mirrors the
    # pre-H2 behavior, which also resolved a line's dedupe fate within the
    # same processing cycle it was read in (delivery used to be synchronous
    # per line; clustering makes delivery async relative to absorption, but
    # dedupe identity is about the raw line, not about when/whether a
    # cluster summary is eventually sent).
    append_bounded(seen, digest, MAX_SEEN)

    # Wall-clock time, not time.monotonic(): cluster timestamps are
    # persisted and must remain meaningful after a restart, when a fresh
    # process would have a different, unrelated monotonic-clock epoch.
    now = time.time()
    key, cluster, is_new = clusters.observe(event, now)
    if is_new:
        LOGGER.info("discord_cluster_created key=%s", key)
    # Persisted in the SAME save_state() call the caller (consume()) makes
    # right after this to persist state["source"]["offset"] -- one atomic
    # write ties the cluster mutation to the offset advance that revealed it.
    state["clusters"] = clusters.to_state()

    if IMMEDIATE_ALERTS_ENABLED and cluster.is_priority_event(event):
        kind = str(event.get("eventid"))
        if kind not in cluster.alerted_event_kinds:
            cluster.alerted_event_kinds.add(kind)
            try:
                payload = format_alert(event)
            except ValueError:
                payload = None
            if payload is not None:
                enqueue_pending(state, f"{digest}:immediate", payload)
                LOGGER.info("discord_immediate_alert key=%s kind=%s", key, kind)


def _flush_item_id(cluster: SessionCluster) -> str:
    return hashlib.sha256(
        f"{cluster.key}:{cluster.created_at}:{cluster.last_activity_at}:{cluster.raw_event_count}".encode()
    ).hexdigest()


def _enqueue_summary(
    state: Dict[str, object],
    cluster: SessionCluster,
    enrichment: Optional[Dict[str, object]],
    flush_id: str,
) -> None:
    payload = build_session_summary_payload(cluster, enrichment)
    enqueue_pending(state, flush_id, payload)
    state["flushed_awaiting_enrichment"].pop(flush_id, None)
    LOGGER.info(
        "discord_cluster_flushed key=%s events=%d enrichment=%s",
        cluster.key,
        cluster.raw_event_count,
        "ok" if enrichment is not None else "unavailable",
    )


def flush_expired_clusters(
    state: Dict[str, object],
    clusters: SessionClusterManager,
    worker: Optional[ThreatIntelWorker],
) -> None:
    """Never blocks on provider latency: enrichment, if attempted at all,
    always runs on the worker's background threads. This function only
    performs non-blocking submission and non-blocking result draining."""
    now = time.time()
    to_flush = clusters.flush_expired(now)
    to_flush.extend(clusters.evict_overflow())
    if to_flush:
        for cluster in to_flush:
            flush_id = _flush_item_id(cluster)
            # Persisted before submission so a crash during -- or before --
            # background enrichment still leaves this flush recoverable at
            # startup, closing the same restart-safety gap as the
            # pre-flush cluster state.
            state["flushed_awaiting_enrichment"][flush_id] = cluster.to_dict()
            submitted = worker.try_submit(cluster) if worker is not None else False
            if not submitted:
                _enqueue_summary(state, cluster, None, flush_id)
        state["clusters"] = clusters.to_state()
        save_state(state)

    if worker is not None:
        completed = worker.drain_completed()
        if completed:
            for cluster, enrichment in completed:
                flush_id = _flush_item_id(cluster)
                if flush_id in state["flushed_awaiting_enrichment"]:
                    _enqueue_summary(state, cluster, enrichment, flush_id)
            save_state(state)


def drain_pending(state: Dict[str, object], credentials: CredentialCache, governor: DiscordRateGovernor) -> None:
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
        if not governor.can_send():
            governor.note_blocked(len(pending))
            break
        item = pending[0]
        governor.note_send_attempt()
        save_state(state)
        success, status_code, retry_after = post_payload(webhook, item["payload"])
        if success:
            recovered, suppressed = governor.note_success()
            if recovered:
                LOGGER.info("discord_recovered suppressed=%d", suppressed)
                if suppressed > 0:
                    post_payload(webhook, recovery_digest_payload(suppressed))
            append_bounded(state["seen"], item["id"], MAX_SEEN)
            pending.pop(0)
            save_state(state)
            LOGGER.info("delivery_success event_sha256=%s", item["id"])
            time.sleep(DELIVERY_DELAY_SECONDS)
            continue
        if status_code == 429:
            newly_degraded = governor.note_rate_limited(retry_after)
            if newly_degraded:
                LOGGER.warning("discord_degraded retry_after=%s", retry_after)
            break
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
    clusters: SessionClusterManager,
    governor: DiscordRateGovernor,
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
            queue_line(state, line, clusters)
            offset = handle.tell()
            state["source"]["offset"] = offset
            save_state(state)
            # Immediate alerts (if enabled) should reach Discord promptly;
            # the bulk of lines enqueue nothing here and this is a cheap
            # early-return.
            drain_pending(state, credentials, governor)
    return offset


def locate_inode(device: int, inode: int) -> Optional[Path]:
    for candidate in LOG_PATH.parent.glob(LOG_PATH.name + "*"):
        stat_result = regular_stat(candidate)
        if stat_result and stat_result.st_dev == device and stat_result.st_ino == inode:
            return candidate
    return None


def poll_once(
    state: Dict[str, object],
    credentials: CredentialCache,
    clusters: SessionClusterManager,
    governor: DiscordRateGovernor,
    worker: Optional[ThreatIntelWorker],
) -> None:
    stat_result = regular_stat(LOG_PATH)
    if stat_result is None:
        flush_expired_clusters(state, clusters, worker)
        drain_pending(state, credentials, governor)
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
        source = state["source"]

    old_identity = (int(source["device"]), int(source["inode"]))
    new_identity = (stat_result.st_dev, stat_result.st_ino)
    if old_identity != new_identity:
        prior = locate_inode(*old_identity)
        if prior is not None:
            consume(prior, state, int(source["offset"]), credentials, clusters, governor)
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

    consume(LOG_PATH, state, int(state["source"]["offset"]), credentials, clusters, governor)
    flush_expired_clusters(state, clusters, worker)
    drain_pending(state, credentials, governor)


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

    # H2 in-process sanity checks -- deterministic, no network/AWS calls.
    manager = SessionClusterManager(window_seconds=45.0)
    _key, cluster, is_new = manager.observe(sample, 0.0)
    assert is_new is True
    assert cluster.raw_event_count == 1
    summary = build_session_summary_payload(cluster, None)
    assert summary["embeds"][0]["title"] == "\U0001f6a8 ATTACK SESSION SUMMARY"

    governor = DiscordRateGovernor(min_interval_seconds=1.0, clock=lambda: 0.0)
    assert governor.can_send() is True
    governor.note_send_attempt()

    print("discord-monitor self-test: PASS")


def _recover_flushed_awaiting_enrichment(state: Dict[str, object]) -> None:
    """Startup recovery for clusters flushed by a prior process but not yet
    turned into a pending summary when it stopped (crash, deploy, restart).

    Recovered without a fresh enrichment attempt -- correctness (never
    silently losing a summary) matters more here than completeness, and
    keeps process startup itself non-blocking on provider latency.
    """
    awaiting = state.get("flushed_awaiting_enrichment") or {}
    if not awaiting:
        return
    for flush_id, cluster_data in list(awaiting.items()):
        try:
            cluster = SessionCluster.from_dict(cluster_data)
        except (KeyError, TypeError, ValueError):
            state["flushed_awaiting_enrichment"].pop(flush_id, None)
            continue
        _enqueue_summary(state, cluster, None, flush_id)
        LOGGER.info("discord_cluster_recovered_at_startup key=%s", cluster.key)
    save_state(state)


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return
    require_read_only_source()
    state = load_state()
    _recover_flushed_awaiting_enrichment(state)
    credentials = CredentialCache()
    clusters = SessionClusterManager(
        window_seconds=CLUSTER_WINDOW_SECONDS,
        max_cluster_age_seconds=CLUSTER_MAX_AGE_SECONDS,
    )
    clusters.restore_state(state.get("clusters", {}))
    governor = DiscordRateGovernor(min_interval_seconds=DISCORD_MIN_INTERVAL_SECONDS)
    parameter_registry = ParameterRegistry(
        {
            "greynoise": GREYNOISE_PARAMETER_NAME,
            "virustotal": VIRUSTOTAL_PARAMETER_NAME,
            "shodan": SHODAN_PARAMETER_NAME,
        },
        AWS_PROFILE,
        AWS_REGION,
        LOGGER,
    )
    cache = EnrichmentCache(THREAT_INTEL_CACHE_DIR / "cache.json")
    broker = ThreatIntelBroker(
        parameter_registry,
        cache,
        LOGGER,
        timeout_seconds=THREAT_INTEL_TIMEOUT_SECONDS,
    )
    worker = ThreatIntelWorker(broker)
    LOGGER.info("monitor_started source=%s state=%s", LOG_PATH, STATE_PATH)
    webhook = credentials.get(force=True)
    if webhook is not None:
        post_payload(webhook, monitor_started_payload())
    while True:
        try:
            poll_once(state, credentials, clusters, governor, worker)
        except Exception as exc:
            LOGGER.exception("poll_failed reason=%s", type(exc).__name__)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
