"""Session/IP clustering for Discord notification presentation only.

This module never touches Cowrie's raw JSON or the S3 archive. It exists
purely to turn a burst of raw events into one compact Discord summary instead
of one webhook call per event -- the exact behavior that caused rate limiting
last year. Clustering state is derived, presentation-layer data; it is never
treated as part of event identity or the SHA-256 dedupe key used elsewhere.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

DEFAULT_WINDOW_SECONDS = 45.0
DEFAULT_MAX_CLUSTER_AGE_SECONDS = 30 * 60.0
DEFAULT_MAX_COMMANDS = 50
DEFAULT_MAX_ACTIVE_CLUSTERS = 500
MAX_COMMAND_DISPLAY_LENGTH = 120
MAX_NOTABLE_COMMANDS = 8
MAX_FIELD_VALUE_LENGTH = 1000

PRIORITY_EVENT_IDS = (
    "cowrie.login.success",
    "cowrie.session.file_upload",
    "cowrie.session.file_download",
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

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_display(value: Any, max_length: int = MAX_COMMAND_DISPLAY_LENGTH) -> str:
    """Strip control chars and backticks, then truncate for safe embed display."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS_RE.sub("", text)
    text = text.replace("`", "'")
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


def is_suspicious_command(command: str) -> bool:
    lowered = command.lower()
    return any(candidate in lowered for candidate in INTERESTING_COMMANDS)


class SessionCluster:
    def __init__(self, key: str, src_ip: str, session_id: Optional[str], created_at: float) -> None:
        self.key = key
        self.src_ip = src_ip
        self.session_id = session_id
        self.created_at = created_at
        self.last_activity_at = created_at
        self.first_seen_iso: Optional[str] = None
        self.last_seen_iso: Optional[str] = None
        self.raw_event_count = 0
        self.authenticated = False
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.commands: List[str] = []
        self.suspicious_commands: List[str] = []
        self.files_downloaded: List[str] = []
        self.files_uploaded: List[str] = []
        self.alerted_event_kinds: set = set()

    def record_event(self, event: Dict[str, Any], now: float, max_commands: int) -> None:
        self.last_activity_at = now
        self.raw_event_count += 1
        timestamp = event.get("timestamp")
        if timestamp:
            if self.first_seen_iso is None:
                self.first_seen_iso = str(timestamp)
            self.last_seen_iso = str(timestamp)

        eventid = event.get("eventid", "")
        if eventid == "cowrie.login.success":
            self.authenticated = True
            self.username = sanitize_display(event.get("username"), 64)
            self.password = sanitize_display(event.get("password"), 64)
        elif eventid == "cowrie.command.input":
            if len(self.commands) < max_commands:
                command = sanitize_display(event.get("input"))
                self.commands.append(command)
                if is_suspicious_command(command) and len(self.suspicious_commands) < MAX_NOTABLE_COMMANDS:
                    self.suspicious_commands.append(command)
        elif eventid == "cowrie.session.file_download":
            if len(self.files_downloaded) < max_commands:
                self.files_downloaded.append(sanitize_display(event.get("url") or event.get("filename")))
        elif eventid == "cowrie.session.file_upload":
            if len(self.files_uploaded) < max_commands:
                self.files_uploaded.append(sanitize_display(event.get("filename")))

    def is_priority_event(self, event: Dict[str, Any]) -> bool:
        return event.get("eventid") in PRIORITY_EVENT_IDS

    def duration_seconds(self) -> float:
        return max(0.0, self.last_activity_at - self.created_at)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable snapshot for restart-safe persistence.

        Caller (discord-monitor.py) must use wall-clock time (time.time())
        for `now`/`created_at`/`last_activity_at`, not time.monotonic() --
        a monotonic clock's epoch is arbitrary per-process and is
        meaningless once reloaded in a new process after a restart.
        """
        return {
            "key": self.key,
            "src_ip": self.src_ip,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
            "first_seen_iso": self.first_seen_iso,
            "last_seen_iso": self.last_seen_iso,
            "raw_event_count": self.raw_event_count,
            "authenticated": self.authenticated,
            "username": self.username,
            "password": self.password,
            "commands": self.commands,
            "suspicious_commands": self.suspicious_commands,
            "files_downloaded": self.files_downloaded,
            "files_uploaded": self.files_uploaded,
            "alerted_event_kinds": sorted(self.alerted_event_kinds),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionCluster":
        cluster = cls(
            key=data["key"],
            src_ip=data.get("src_ip", "unknown"),
            session_id=data.get("session_id"),
            created_at=float(data.get("created_at", 0.0)),
        )
        cluster.last_activity_at = float(data.get("last_activity_at", cluster.created_at))
        cluster.first_seen_iso = data.get("first_seen_iso")
        cluster.last_seen_iso = data.get("last_seen_iso")
        cluster.raw_event_count = int(data.get("raw_event_count", 0))
        cluster.authenticated = bool(data.get("authenticated", False))
        cluster.username = data.get("username")
        cluster.password = data.get("password")
        cluster.commands = list(data.get("commands", []))
        cluster.suspicious_commands = list(data.get("suspicious_commands", []))
        cluster.files_downloaded = list(data.get("files_downloaded", []))
        cluster.files_uploaded = list(data.get("files_uploaded", []))
        cluster.alerted_event_kinds = set(data.get("alerted_event_kinds", []))
        return cluster


class SessionClusterManager:
    """Keys clusters by Cowrie session ID when available, else by src_ip.

    A src_ip-keyed cluster that has gone quiet longer than the window is
    treated as closed: the next event for that IP starts a fresh cluster
    under the same key rather than silently reopening old, already-expired
    state.
    """

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_cluster_age_seconds: float = DEFAULT_MAX_CLUSTER_AGE_SECONDS,
        max_commands: int = DEFAULT_MAX_COMMANDS,
        max_active_clusters: int = DEFAULT_MAX_ACTIVE_CLUSTERS,
    ) -> None:
        self._window_seconds = window_seconds
        self._max_cluster_age_seconds = max_cluster_age_seconds
        self._max_commands = max_commands
        self._max_active_clusters = max_active_clusters
        self._clusters: Dict[str, SessionCluster] = {}

    @staticmethod
    def cluster_key_for(event: Dict[str, Any]) -> str:
        session_id = event.get("session")
        if session_id:
            return f"session:{session_id}"
        return f"ip:{event.get('src_ip', 'unknown')}"

    def observe(self, event: Dict[str, Any], now: float):
        key = self.cluster_key_for(event)
        session_id = event.get("session")
        cluster = self._clusters.get(key)
        if (
            cluster is not None
            and not session_id
            and (now - cluster.last_activity_at) > self._window_seconds
        ):
            cluster = None
        is_new = cluster is None
        if cluster is None:
            cluster = SessionCluster(key=key, src_ip=event.get("src_ip", "unknown"), session_id=session_id, created_at=now)
            self._clusters[key] = cluster
        cluster.record_event(event, now, self._max_commands)
        return key, cluster, is_new

    def flush_expired(self, now: float) -> List[SessionCluster]:
        expired_keys = [
            key
            for key, cluster in self._clusters.items()
            if (now - cluster.last_activity_at) > self._window_seconds
            or (now - cluster.created_at) > self._max_cluster_age_seconds
        ]
        expired = []
        for key in expired_keys:
            expired.append(self._clusters.pop(key))
        return expired

    def flush_all(self) -> List[SessionCluster]:
        expired = list(self._clusters.values())
        self._clusters.clear()
        return expired

    def evict_overflow(self) -> List[SessionCluster]:
        """Force-flush the least-recently-active clusters beyond the bound.

        Defense in depth against unbounded state growth (memory and the
        persisted state file both) under a burst of many distinct attacker
        IPs. Evicted clusters are returned, not dropped, so the caller can
        still build and send their summaries.
        """
        overflow = len(self._clusters) - self._max_active_clusters
        if overflow <= 0:
            return []
        by_activity = sorted(self._clusters.items(), key=lambda item: item[1].last_activity_at)
        evicted = []
        for key, cluster in by_activity[:overflow]:
            del self._clusters[key]
            evicted.append(cluster)
        return evicted

    def active_count(self) -> int:
        return len(self._clusters)

    def to_state(self) -> Dict[str, Dict[str, Any]]:
        return {key: cluster.to_dict() for key, cluster in self._clusters.items()}

    def restore_state(self, persisted: Dict[str, Dict[str, Any]]) -> None:
        """Rebuild active clusters from a prior process's persisted state.

        Does not itself flush anything -- restored clusters simply resume
        participating in the normal observe()/flush_expired() lifecycle.
        """
        self._clusters = {}
        if not persisted:
            return
        for key, data in persisted.items():
            try:
                cluster = SessionCluster.from_dict(data)
            except (KeyError, TypeError, ValueError):
                continue
            self._clusters[key] = cluster


def _truncate_field(text: str) -> str:
    if len(text) > MAX_FIELD_VALUE_LENGTH:
        return text[: MAX_FIELD_VALUE_LENGTH - 1] + "…"
    return text


MAX_PROVIDER_FIELD_LENGTH = 200


def _p(value: Any, default: str = "unknown") -> str:
    """Sanitize one provider-supplied scalar. A threat-intel API is still
    untrusted input from Discord's perspective -- treat it exactly like an
    attacker-controlled Cowrie field, not as trusted internal data."""
    if value is None or value == "":
        return default
    return sanitize_display(value, MAX_PROVIDER_FIELD_LENGTH)


def _p_list(values: Optional[List[Any]], separator: str = ", ", default: str = "none") -> str:
    if not values:
        return default
    sanitized = [sanitize_display(v, 64) for v in values]
    joined = separator.join(sanitized)
    return sanitize_display(joined, MAX_PROVIDER_FIELD_LENGTH)


def _format_greynoise(envelope: Optional[Dict[str, Any]]) -> str:
    if envelope is None:
        return "unavailable"
    status = envelope.get("status")
    if status != "ok":
        return _p(status, "unavailable")
    normalized = envelope.get("normalized", {})
    return (
        f"Classification: {_p(normalized.get('classification'))}\n"
        f"Actor: {_p(normalized.get('actor'))}\n"
        f"Tags: {_p_list(normalized.get('tags'))}"
    )


def _format_virustotal(envelope: Optional[Dict[str, Any]]) -> str:
    if envelope is None:
        return "unavailable"
    status = envelope.get("status")
    if status != "ok":
        return _p(status, "unavailable")
    normalized = envelope.get("normalized", {})
    stats = normalized.get("last_analysis_stats", {}) or {}
    return (
        f"Malicious: {_p(stats.get('malicious', 0), '0')}\n"
        f"Suspicious: {_p(stats.get('suspicious', 0), '0')}\n"
        f"ASN: {_p(normalized.get('asn'))}\n"
        f"Owner: {_p(normalized.get('as_owner'))}"
    )


def _format_shodan(envelope: Optional[Dict[str, Any]]) -> str:
    if envelope is None:
        return "unavailable"
    status = envelope.get("status")
    if status != "ok":
        return _p(status, "unavailable")
    normalized = envelope.get("normalized", {})
    ports = _p_list([str(port) for port in (normalized.get("ports") or [])], separator=",")
    return (
        f"Org: {_p(normalized.get('org'))}\n"
        f"Ports: {ports}\n"
        f"Products: {_p_list(normalized.get('products'))}\n"
        f"Vulns: {_p_list(normalized.get('vulns'))}"
    )


def _format_duration(seconds: float) -> str:
    """Sub-second sessions are common (a single scripted probe, one failed
    auth attempt) and are themselves research-grade telemetry -- rounding
    them to "0s" silently discards exactly the timing precision an analyst
    would want. Millisecond precision below one second; whole seconds at
    or above it, where sub-second precision stops being meaningful for a
    multi-second/minute interactive session."""
    if seconds < 1.0:
        return f"{seconds * 1000:.2f}ms"
    return f"{int(seconds)}s"


def build_session_summary_payload(
    cluster: SessionCluster,
    enrichment: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build one Discord embed payload summarizing an entire cluster.

    `enrichment` is the broker's per-provider envelope dict, or None if
    enrichment was skipped (private IP, disabled, etc.) -- either way this
    always returns a valid, size-bounded payload.
    """
    enrichment = enrichment or {}
    auth_lines = ["No successful login observed"]
    if cluster.authenticated:
        auth_lines = [
            "Successful login",
            f"Username: {cluster.username or 'unknown'}",
            f"Password: {cluster.password or 'unknown'}",
        ]

    activity_lines = [
        f"Commands: {len(cluster.commands)}",
        f"Suspicious Commands: {len(cluster.suspicious_commands)}",
        f"Files Downloaded: {len(cluster.files_downloaded)}",
        f"Files Uploaded: {len(cluster.files_uploaded)}",
    ]

    notable = cluster.suspicious_commands[:MAX_NOTABLE_COMMANDS] or ["none observed"]
    notable_block = _truncate_field("\n".join(f"`{command}`" for command in notable))

    fields = [
        {"name": "Authentication", "value": _truncate_field("\n".join(auth_lines)), "inline": False},
        {"name": "Activity", "value": _truncate_field("\n".join(activity_lines)), "inline": False},
        {"name": "Notable Commands", "value": notable_block, "inline": False},
        {"name": "GreyNoise", "value": _truncate_field(_format_greynoise(enrichment.get("greynoise"))), "inline": True},
        {"name": "VirusTotal", "value": _truncate_field(_format_virustotal(enrichment.get("virustotal"))), "inline": True},
        {"name": "Shodan", "value": _truncate_field(_format_shodan(enrichment.get("shodan"))), "inline": True},
    ]

    description = (
        f"IP: `{sanitize_display(cluster.src_ip, 64)}`\n"
        f"Session: `{sanitize_display(cluster.session_id or 'n/a', 64)}`\n"
        f"Duration: {_format_duration(cluster.duration_seconds())}\n"
        f"Raw Events: {cluster.raw_event_count}\n"
        f"First Seen: {cluster.first_seen_iso or 'unknown'}\n"
        f"Last Seen: {cluster.last_seen_iso or 'unknown'}"
    )

    return {
        "embeds": [
            {
                "title": "\U0001f6a8 ATTACK SESSION SUMMARY",
                "description": _truncate_field(description),
                "color": 0xFF0000 if cluster.authenticated else 0xFF6600,
                "fields": fields[:25],
                "footer": {"text": "PatriotPot H2 session summary"},
            }
        ]
    }
