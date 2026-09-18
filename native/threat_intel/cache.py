"""Bounded, TTL-based, disk-persisted cache for threat-intelligence lookups.

One JSON file, one dict keyed by "provider:observable_type:observable".
Never stores credentials -- only provider responses and their provenance.
Atomic replace on every write so a crash never leaves a torn cache file.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_MAX_ENTRIES = 4096


def cache_key(provider: str, observable_type: str, observable: str) -> str:
    return f"{provider}:{observable_type}:{observable}"


class EnrichmentCache:
    """Not just single-process-safe: the broker queries all providers
    concurrently from a thread pool against this one cache instance, so
    every public method is guarded by a lock. Cache writes are small and
    infrequent enough that serializing them costs nothing meaningful.
    """

    def __init__(self, path: Path, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._path = path
        self._max_entries = max_entries
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._entries = {}
            return
        except (OSError, ValueError):
            self._entries = {}
            return
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            self._entries = data["entries"]
        else:
            self._entries = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if time.time() >= entry.get("expires_at_epoch", 0):
                return None
            return entry

    def set(self, key: str, entry: Dict[str, Any], ttl_seconds: float) -> None:
        with self._lock:
            now = time.time()
            entry = dict(entry)
            entry["expires_at_epoch"] = now + ttl_seconds
            self._entries[key] = entry
            self._evict_if_needed()
            self._save()

    def _evict_if_needed(self) -> None:
        if len(self._entries) <= self._max_entries:
            return
        by_expiry = sorted(self._entries.items(), key=lambda item: item[1].get("expires_at_epoch", 0))
        overflow = len(self._entries) - self._max_entries
        for key, _ in by_expiry[:overflow]:
            del self._entries[key]

    def _save(self) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps({"version": 1, "entries": self._entries}, separators=(",", ":")).encode()
        candidate = self._path.with_name(self._path.name + ".new")
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
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(candidate), str(self._path))
        except Exception:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
            raise
