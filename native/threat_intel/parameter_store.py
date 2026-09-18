"""Generic SSM SecureString value cache, shared by every H2 provider.

Modeled on discord-monitor.py's CredentialCache but generalized to any
parameter name so GreyNoise/VirusTotal/Shodan don't each duplicate the same
subprocess-and-cache logic. The Discord webhook's own credential path is left
untouched: it is already deployed and verified, and H2 must not risk it.
"""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Dict, List, Optional

REFRESH_SECONDS = 300.0
SUBPROCESS_TIMEOUT_SECONDS = 20


class SsmSecureStringCache:
    """Fetches and caches one SSM SecureString parameter value.

    Never logs, prints, or raises with the parameter value in the message. A
    missing/unreadable parameter is a normal, expected state (a provider may
    simply not be configured yet) and surfaces as `None`, not an exception.
    """

    def __init__(
        self,
        parameter_name: str,
        aws_profile: str,
        aws_region: str,
        logger: logging.Logger,
        refresh_seconds: float = REFRESH_SECONDS,
    ) -> None:
        self._parameter_name = parameter_name
        self._aws_profile = aws_profile
        self._aws_region = aws_region
        self._logger = logger
        self._refresh_seconds = refresh_seconds
        self._value: Optional[str] = None
        self._next_refresh = 0.0
        self._warned_unavailable = False

    def get(self, force: bool = False) -> Optional[str]:
        now = time.monotonic()
        if not force and now < self._next_refresh:
            return self._value
        self._next_refresh = now + self._refresh_seconds
        command = [
            "/usr/bin/aws",
            "ssm",
            "get-parameter",
            "--name",
            self._parameter_name,
            "--with-decryption",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--profile",
            self._aws_profile,
            "--region",
            self._aws_region,
        ]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self._note_unavailable()
            return None
        candidate = result.stdout.strip() if result.returncode == 0 else ""
        if candidate and candidate != "None":
            if self._value is None:
                self._logger.info("parameter_available name=%s", self._parameter_name)
            self._value = candidate
            self._warned_unavailable = False
        else:
            self._value = None
            self._note_unavailable()
        return self._value

    def _note_unavailable(self) -> None:
        if not self._warned_unavailable:
            self._logger.warning("parameter_unavailable name=%s", self._parameter_name)
            self._warned_unavailable = True


class ParameterRegistry:
    """Holds one SsmSecureStringCache per provider, keyed by provider name."""

    def __init__(
        self,
        parameter_names: Dict[str, str],
        aws_profile: str,
        aws_region: str,
        logger: logging.Logger,
    ) -> None:
        self._caches = {
            provider: SsmSecureStringCache(name, aws_profile, aws_region, logger)
            for provider, name in parameter_names.items()
            if name
        }

    def get(self, provider: str) -> Optional[str]:
        cache = self._caches.get(provider)
        if cache is None:
            return None
        return cache.get()

    def configured_providers(self) -> List[str]:
        return sorted(self._caches.keys())
