"""Validation for observables (IPs, hashes) before they reach any external provider.

Attacker-controlled strings (src_ip, filenames, command text) must never be
trusted to construct a URL, choose a host, or select a scheme. This module is
the single choke point: every provider receives an already-validated
ipaddress object or a hash string matched against a strict pattern, never a
raw attacker-observed string.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_public_ip(candidate: str) -> Optional[IPAddress]:
    """Return a validated, publicly-routable IP object, or None.

    Rejects anything that is not a strict IP literal, and rejects private,
    reserved, loopback, link-local, multicast, unspecified, and documentation
    (TEST-NET) addresses. A None return means "do not query any provider for
    this value" -- callers must treat that as a hard stop, not a retry.
    """
    if not candidate or not isinstance(candidate, str):
        return None
    candidate = candidate.strip()
    if not candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if (
        address.is_private
        or address.is_reserved
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        return None
    return address


def parse_sha256(candidate: str) -> Optional[str]:
    """Return a lowercased, validated SHA-256 hex digest, or None."""
    if not candidate or not isinstance(candidate, str):
        return None
    candidate = candidate.strip()
    if not _SHA256_RE.match(candidate):
        return None
    return candidate.lower()
