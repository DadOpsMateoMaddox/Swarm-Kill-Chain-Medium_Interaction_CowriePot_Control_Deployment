#!/opt/python/3.8.20/bin/python3.8
"""Independent, non-overlapping, content-addressed S3 Cowrie evidence archive."""

import errno
import base64
import hashlib
import json
import logging
from logging.handlers import WatchedFileHandler
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Dict, Iterator, Optional, Tuple
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - production is Amazon Linux 2
    fcntl = None


LOG_PATH = Path(os.environ.get("COWRIE_JSON_PATH", "/opt/cowrie/var/log/cowrie/cowrie.json"))
STATE_PATH = Path(os.environ.get("ARCHIVE_STATE_PATH", "/var/lib/patriotpot-archive/state.json"))
SPOOL_DIR = Path(os.environ.get("ARCHIVE_SPOOL_DIR", "/var/lib/patriotpot-archive/spool"))
LOCK_PATH = Path(os.environ.get("ARCHIVE_LOCK_PATH", "/var/lib/patriotpot-archive/archive.lock"))
OPS_LOG = Path(os.environ.get("ARCHIVE_OPS_LOG", "/var/log/patriotpot/archive.log"))
BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
PREFIX = os.environ.get("EVIDENCE_PREFIX", "control/production").strip("/")
AWS_PROFILE = os.environ.get("AWS_PROFILE", "patriotpot")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")
MAX_PUT_ATTEMPTS = 4
ANCHOR_BYTES = 64
READ_CHUNK_BYTES = 1024 * 1024
S3_CLIENT: Optional[Any] = None
TRANSIENT_PUT_EXCEPTIONS = (
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)


class S3AccessError(RuntimeError):
    pass


class S3TransientError(RuntimeError):
    pass


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("patriotpot-archive")
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
    try:
        descriptor = os.open(str(LOG_PATH), os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT):
            return
        raise
    else:
        os.close(descriptor)
        raise RuntimeError("Cowrie JSON source is writable by the archive service")


def default_state() -> Dict[str, object]:
    return {
        "version": 3,
        "current": None,
        "lineages": {},
        "rotated": {},
        "uploaded_objects": 0,
        "updated_at": None,
    }


def load_state() -> Dict[str, object]:
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_state()
    if not isinstance(state, dict) or state.get("version") not in (1, 2, 3):
        raise ValueError("unsupported archive state")
    if not isinstance(state.get("rotated", {}), dict):
        raise ValueError("invalid rotated state")
    if state.get("version") == 1:
        current = state.get("current")
        lineages: Dict[str, object] = {}
        if isinstance(current, dict):
            base = f"{int(current['device'])}:{int(current['inode'])}"
            lineages[base] = {
                "generation": 0,
                "offset": int(current.get("offset", 0)),
                "anchor": None,
            }
        state["version"] = 2
        state["lineages"] = lineages
    if not isinstance(state.get("lineages"), dict):
        raise ValueError("invalid lineage state")
    if state.get("version") == 2:
        # Version 2 stored only a digest string. Keep it as a valid legacy
        # witness when it matches the descriptor, rather than replaying a
        # source that was already durably advanced.
        for lineage in state["lineages"].values():
            if not isinstance(lineage, dict):
                raise ValueError("invalid lineage entry")
            anchor = lineage.get("anchor")
            if isinstance(anchor, str):
                offset = int(lineage.get("offset", 0))
                lineage["anchor"] = {
                    "schema": "patriotpot-archive-anchor/v1",
                    "offset": offset,
                    "window_start": max(0, offset - ANCHOR_BYTES),
                    "sha256": anchor,
                }
            elif anchor is not None and not isinstance(anchor, dict):
                raise ValueError("invalid lineage anchor")
        state["version"] = 3
    return state


def save_state(state: Dict[str, object]) -> None:
    STATE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
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
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(candidate), str(STATE_PATH))
    except Exception:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
        raise


def instance_id() -> str:
    token_request = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        data=b"",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    with urllib.request.urlopen(token_request, timeout=2) as response:
        token = response.read().decode("ascii")
    identity_request = urllib.request.Request(
        "http://169.254.169.254/latest/meta-data/instance-id",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with urllib.request.urlopen(identity_request, timeout=2) as response:
        value = response.read().decode("ascii").strip()
    if not re.fullmatch(r"i-[0-9a-f]+", value):
        raise RuntimeError("invalid instance identity")
    return value


def s3_client():
    global S3_CLIENT
    if S3_CLIENT is None:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        S3_CLIENT = session.client(
            "s3",
            config=Config(
                connect_timeout=10,
                read_timeout=120,
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )
    return S3_CLIENT


def classify_client_error(error: ClientError) -> str:
    response = error.response if isinstance(error.response, dict) else {}
    metadata = response.get("ResponseMetadata", {})
    error_data = response.get("Error", {})
    status = metadata.get("HTTPStatusCode")
    code = str(error_data.get("Code", ""))
    if status == 412 or code in ("PreconditionFailed", "412"):
        return "precondition"
    if status == 409 or code in ("ConditionalRequestConflict", "409"):
        return "conflict"
    if status == 403 or code in (
        "AccessDenied",
        "Forbidden",
        "InvalidAccessKeyId",
    ):
        return "access"
    if isinstance(status, int) and status >= 500:
        return "transient"
    if code in (
        "InternalError",
        "RequestTimeout",
        "ServiceUnavailable",
        "SlowDown",
    ):
        return "transient"
    return "other"


def checksum_b64(digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid SHA-256 digest")
    return base64.b64encode(bytes.fromhex(digest)).decode("ascii")


def content_address_matches(key: str, digest: str) -> bool:
    filename = key.rsplit("/", 1)[-1]
    return bool(re.search(rf"(?:^|-){re.escape(digest)}\.json$", filename))


def verify_object(
    key: str,
    digest: str,
    version_id: Optional[str],
    require_content_address: bool = True,
) -> Dict[str, object]:
    """GET and hash the stored body; object metadata is never an integrity input."""
    if require_content_address and not content_address_matches(key, digest):
        raise RuntimeError(f"object key is not content-addressed by expected digest: {key}")
    arguments: Dict[str, object] = {
        "Bucket": BUCKET,
        "Key": key,
        "ChecksumMode": "ENABLED",
    }
    if version_id is not None:
        if not isinstance(version_id, str) or not version_id:
            raise RuntimeError(f"missing required S3 version for key {key}")
        arguments["VersionId"] = version_id
    try:
        response = s3_client().get_object(**arguments)
    except ClientError as error:
        category = classify_client_error(error)
        if category == "access":
            raise S3AccessError(f"S3 GET denied for key {key}") from error
        if category == "transient":
            raise S3TransientError(f"S3 GET transient failure for key {key}") from error
        raise RuntimeError(f"S3 GET failed for key {key}") from error
    except TRANSIENT_PUT_EXCEPTIONS as error:
        raise S3TransientError(f"S3 GET transient failure for key {key}") from error

    stored_version = response.get("VersionId")
    if not isinstance(stored_version, str) or not stored_version:
        raise RuntimeError(f"S3 GET omitted required version for key {key}")
    if version_id is not None and stored_version != version_id:
        raise RuntimeError(f"S3 GET returned the wrong version for key {key}")
    expected_checksum = checksum_b64(digest)
    stored_checksum = response.get("ChecksumSHA256")
    if stored_checksum is not None and stored_checksum != expected_checksum:
        raise RuntimeError(f"S3 checksum mismatch for key {key}")

    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise RuntimeError(f"S3 GET returned a malformed body for key {key}")
    hasher = hashlib.sha256()
    try:
        while True:
            chunk = body.read(READ_CHUNK_BYTES)
            if chunk == b"":
                break
            if not isinstance(chunk, bytes):
                raise RuntimeError(f"S3 GET returned a malformed body for key {key}")
            hasher.update(chunk)
    except TRANSIENT_PUT_EXCEPTIONS as error:
        raise S3TransientError(f"S3 GET body read failed for key {key}") from error
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if hasher.hexdigest() != digest:
        raise RuntimeError(f"S3 body digest mismatch for key {key}")
    return {
        "VersionId": stored_version,
        "ETag": response.get("ETag"),
        "ChecksumSHA256": stored_checksum,
    }


def put_once(path: Path, key: str, digest: str, content_type: str) -> Dict[str, object]:
    """Conditionally create once, then verify the exact stored bytes by GET."""
    if not content_address_matches(key, digest) and not key.endswith(".manifest.json"):
        raise RuntimeError(f"object key is not content-addressed by expected digest: {key}")
    arguments: Dict[str, object] = {
        "Bucket": BUCKET,
        "Key": key,
        "ContentType": content_type,
        "Metadata": {"sha256": digest},
        "ServerSideEncryption": "AES256",
        "IfNoneMatch": "*",
        "ChecksumSHA256": checksum_b64(digest),
    }
    for attempt in range(1, MAX_PUT_ATTEMPTS + 1):
        try:
            with path.open("rb") as body:
                response = s3_client().put_object(Body=body, **arguments)
        except ClientError as error:
            category = classify_client_error(error)
            if category == "precondition":
                verified = verify_object(
                    key,
                    digest,
                    None,
                    require_content_address=not key.endswith(".manifest.json"),
                )
                verified["Existing"] = True
                return verified
            if category == "access":
                raise S3AccessError(f"S3 conditional PUT denied for key {key}") from error
            if category not in ("conflict", "transient"):
                raise RuntimeError(f"S3 conditional PUT failed for key {key}") from error
            if attempt == MAX_PUT_ATTEMPTS:
                raise S3TransientError(
                    f"S3 conditional PUT retries exhausted for key {key}"
                ) from error
        except TRANSIENT_PUT_EXCEPTIONS as error:
            if attempt == MAX_PUT_ATTEMPTS:
                raise S3TransientError(
                    f"S3 conditional PUT retries exhausted for key {key}"
                ) from error
        else:
            if not isinstance(response, dict):
                raise RuntimeError(f"S3 conditional PUT returned malformed data for key {key}")
            version_id = response.get("VersionId")
            if not isinstance(version_id, str) or not version_id:
                raise RuntimeError(f"S3 conditional PUT omitted required version for key {key}")
            returned_checksum = response.get("ChecksumSHA256")
            if returned_checksum is not None and returned_checksum != checksum_b64(digest):
                raise RuntimeError(f"S3 conditional PUT checksum mismatch for key {key}")
            verified = verify_object(
                key,
                digest,
                version_id,
                require_content_address=not key.endswith(".manifest.json"),
            )
            verified["Existing"] = False
            return verified
        time.sleep(min(8, 2 ** (attempt - 1)))
    raise AssertionError("unreachable")


def write_bytes(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def upload_with_manifest(
    source: Path,
    data_path: Path,
    key: str,
    digest: str,
    size: int,
    source_identity: Dict[str, object],
) -> Dict[str, object]:
    response = put_once(data_path, key, digest, "application/x-ndjson")
    manifest = {
        "schema": "patriotpot-evidence-manifest/v3",
        "source_name": source.name,
        "source_identity": source_identity,
        "sha256": digest,
        "size": size,
        "object_key": key,
        "object_version_id": response.get("VersionId"),
        "logical_contract": "non-overlapping-byte-ranges-per-inode-generation",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_path = SPOOL_DIR / (
        f"manifest-{os.getpid()}-{os.urandom(12).hex()}-{digest}.json"
    )
    write_bytes(manifest_path, manifest_bytes)
    try:
        put_once(
            manifest_path,
            key + ".manifest.json",
            hashlib.sha256(manifest_bytes).hexdigest(),
            "application/json",
        )
    finally:
        manifest_path.unlink(missing_ok=True)
    LOGGER.info(
        "archive_verified key=%s sha256=%s size=%s version_id=%s existing=%s",
        key,
        digest,
        size,
        response.get("VersionId") or "none",
        response.get("Existing"),
    )
    return response


def clean_name(name: str) -> str:
    return SAFE_COMPONENT.sub("_", name)


def descriptor_identity(status: os.stat_result) -> Dict[str, int]:
    """Return the immutable identity fields obtained from one open descriptor."""
    return {
        "device": int(status.st_dev),
        "inode": int(status.st_ino),
    }


def same_descriptor(
    before: os.stat_result, after: os.stat_result
) -> bool:
    return (
        stat.S_ISREG(before.st_mode)
        and stat.S_ISREG(after.st_mode)
        and descriptor_identity(before) == descriptor_identity(after)
    )


def open_source(path: Path) -> Optional[int]:
    """Open an archive source once; all identity and content checks use its fd."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        return os.open(str(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        # A rotation can remove a path between globbing and open. A symlink or
        # non-directory component is never an archive source.
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return None
        if exc.errno == errno.ELOOP:
            LOGGER.warning("source_rejected_symlink path=%s", path.name)
            return None
        raise


def read_at(handle, start: int, length: int) -> bytes:
    """Read a bounded range from the descriptor-backed binary handle."""
    if start < 0 or length < 0:
        raise ValueError("negative archive read range")
    handle.seek(start)
    remaining = length
    chunks = []
    while remaining:
        chunk = handle.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def anchor_from_window(
    status: os.stat_result, end: int, window: bytes
) -> Optional[Dict[str, object]]:
    """Describe the final bytes at an offset using descriptor-derived identity."""
    if end <= 0:
        return None
    window_start = max(0, end - ANCHOR_BYTES)
    if len(window) != end - window_start:
        return None
    anchor: Dict[str, object] = {
        "schema": "patriotpot-archive-anchor/v1",
        "offset": end,
        "window_start": window_start,
        "sha256": hashlib.sha256(window).hexdigest(),
    }
    anchor.update(descriptor_identity(status))
    return anchor


def descriptor_anchor(
    handle, status: os.stat_result, end: int
) -> Optional[Dict[str, object]]:
    """Read anchor bytes from the same descriptor that supplied source content."""
    if end < 0 or int(status.st_size) < end:
        return None
    start = max(0, end - ANCHOR_BYTES)
    return anchor_from_window(status, end, read_at(handle, start, end - start))


def snapshot_anchor(
    status: os.stat_result, snapshot_start: int, snapshot: bytes, end: int
) -> Optional[Dict[str, object]]:
    """Build an anchor only from bytes captured by the source descriptor read."""
    window_start = max(0, end - ANCHOR_BYTES)
    first = window_start - snapshot_start
    last = end - snapshot_start
    if first < 0 or last > len(snapshot):
        return None
    return anchor_from_window(status, end, snapshot[first:last])


def anchor_digest(anchor: object) -> Optional[str]:
    if isinstance(anchor, str):
        return anchor
    if isinstance(anchor, dict):
        value = anchor.get("sha256")
        if isinstance(value, str):
            return value
    return None


def anchors_match(expected: object, actual: object) -> bool:
    """Accept legacy digest-only anchors while enforcing new descriptor metadata."""
    expected_digest = anchor_digest(expected)
    actual_digest = anchor_digest(actual)
    if expected_digest is None or actual_digest is None:
        return False
    if expected_digest != actual_digest:
        return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for field in ("offset", "window_start", "device", "inode"):
            if field in expected and expected[field] != actual.get(field):
                return False
    return True


def reset_generation(lineage: Dict[str, object], path: Path, reason: str) -> None:
    lineage["generation"] = int(lineage.get("generation", 0)) + 1
    lineage["offset"] = 0
    lineage["anchor"] = None
    LOGGER.warning(
        "source_generation_reset path=%s generation=%s reason=%s",
        path.name,
        lineage["generation"],
        reason,
    )


def lineage_for(
    state: Dict[str, object], path: Path, status: os.stat_result, handle
) -> Tuple[str, Dict[str, object]]:
    base = f"{status.st_dev}:{status.st_ino}"
    lineages = state["lineages"]
    lineage = lineages.get(base)
    if not isinstance(lineage, dict):
        lineage = {
            "generation": 0,
            "offset": 0,
            "anchor": None,
            "descriptor": descriptor_identity(status),
        }
        lineages[base] = lineage
        return base, lineage
    offset = int(lineage.get("offset", 0))
    expected_anchor = lineage.get("anchor")
    if offset < 0:
        reset_generation(lineage, path, "negative_offset")
    elif int(status.st_size) < offset:
        reset_generation(lineage, path, "size_regressed")
    elif offset > 0 and not anchors_match(
        expected_anchor, descriptor_anchor(handle, status, offset)
    ):
        # Reuse of a pathname, copytruncate, or in-place replacement must not
        # continue an old byte range under the same generation.
        reset_generation(lineage, path, "anchor_mismatch")
    lineage["descriptor"] = descriptor_identity(status)
    return base, lineage


def legacy_rotated_marker_matches(
    handle, fd: int, status: os.stat_result, marker: object
) -> bool:
    """Preserve v1 rotated-file idempotence using the same opened descriptor."""
    if not isinstance(marker, str):
        return False
    size = int(status.st_size)
    prefix = f"{status.st_dev}:{status.st_ino}:{size}:"
    if not marker.startswith(prefix):
        return False
    data = read_at(handle, 0, size)
    after = os.fstat(fd)
    return (
        len(data) == size
        and same_descriptor(status, after)
        and int(after.st_size) == size
        and marker == prefix + hashlib.sha256(data).hexdigest()
    )


def complete_records(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Yield only LF-terminated Cowrie JSON records and their relative ends."""
    cursor = 0
    while True:
        newline = data.find(b"\n", cursor)
        if newline < 0:
            return
        end = newline + 1
        yield end, data[cursor:end]
        cursor = end


def archive_path(
    state: Dict[str, object],
    sensor_id: str,
    path: Path,
    kind: str,
    legacy_rotated_marker: object = None,
) -> None:
    fd = open_source(path)
    if fd is None:
        return
    try:
        handle = os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise
    with handle as handle:
        # Never use pathname metadata after this point. fstat, reads, and the
        # persisted anchor all refer to this one descriptor.
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            LOGGER.warning("source_rejected_non_regular path=%s", path.name)
            return
        if legacy_rotated_marker_matches(
            handle, fd, status, legacy_rotated_marker
        ):
            return

        _, lineage = lineage_for(state, path, status, handle)
        start = int(lineage.get("offset", 0))
        snapshot_end = int(status.st_size)
        if snapshot_end <= start:
            return

        # Capture enough prefix context to calculate every saved record anchor
        # from the exact bytes read by this descriptor, not from a later path
        # reopen. The two pre/post anchors accept normal appends but reject a
        # reset or overwrite of the bounded snapshot.
        snapshot_start = max(0, start - ANCHOR_BYTES)
        start_anchor = (
            descriptor_anchor(handle, status, start) if start > 0 else None
        )
        end_anchor = descriptor_anchor(handle, status, snapshot_end)
        snapshot = read_at(handle, snapshot_start, snapshot_end - snapshot_start)
        after = os.fstat(fd)
        captured_end_anchor = snapshot_anchor(
            status, snapshot_start, snapshot, snapshot_end
        )
        stable = (
            len(snapshot) == snapshot_end - snapshot_start
            and same_descriptor(status, after)
            and int(after.st_size) >= snapshot_end
            and anchors_match(end_anchor, captured_end_anchor)
            and anchors_match(
                captured_end_anchor,
                descriptor_anchor(handle, after, snapshot_end),
            )
        )
        if start_anchor is not None:
            stable = stable and anchors_match(
                start_anchor, descriptor_anchor(handle, after, start)
            )
        if not stable:
            reset_generation(lineage, path, "changed_during_descriptor_read")
            return

        initial_start = start
        data = snapshot[start - snapshot_start :]
        generation = int(lineage.get("generation", 0))
        # A complete LF-terminated JSON record is the authoritative segment.
        # A crash after PUT but before state persistence retries its exact key.
        for relative_end, segment in complete_records(data):
            end = initial_start + relative_end
            segment_anchor = snapshot_anchor(
                status, snapshot_start, snapshot, end
            )
            if segment_anchor is None:
                raise RuntimeError("archive segment anchor is unavailable")
            digest = hashlib.sha256(segment).hexdigest()
            segment_path = SPOOL_DIR / (
                f"segment-{os.getpid()}-{os.urandom(12).hex()}-{digest}.json"
            )
            write_bytes(segment_path, segment)
            key = (
                f"{PREFIX}/instances/{sensor_id}/segments/"
                f"{status.st_dev}-{status.st_ino}-g{generation:06d}/"
                f"{start:020d}-{end:020d}-{digest}.json"
            )
            source_identity: Dict[str, object] = descriptor_identity(status)
            source_identity.update(
                {
                    "generation": generation,
                    "kind": kind,
                    "snapshot_size": snapshot_end,
                    "start_offset": start,
                    "end_offset": end,
                    "anchor": segment_anchor,
                    "dedupe_key": (
                        f"{status.st_dev}:{status.st_ino}:{generation}:{start}:{end}"
                    ),
                }
            )
            try:
                upload_with_manifest(
                    path,
                    segment_path,
                    key,
                    digest,
                    len(segment),
                    source_identity,
                )
            finally:
                segment_path.unlink(missing_ok=True)
            lineage["offset"] = end
            lineage["anchor"] = segment_anchor
            lineage["descriptor"] = descriptor_identity(status)
            state["current"] = {
                "device": status.st_dev,
                "inode": status.st_ino,
                "generation": generation,
                "offset": end,
                "anchor": segment_anchor,
            }
            state["uploaded_objects"] = int(state.get("uploaded_objects", 0)) + 1
            save_state(state)
            start = end


def archive_rotated(state: Dict[str, object], sensor_id: str) -> None:
    for path in sorted(LOG_PATH.parent.glob(LOG_PATH.name + "*")):
        if path == LOG_PATH:
            continue
        # Preserve the v1 idempotence marker during migration. It is checked
        # only after archive_path has opened and fstat'ed this exact descriptor.
        legacy = state.get("rotated", {}).get(path.name)
        archive_path(
            state,
            sensor_id,
            path,
            "rotated-continuation",
            legacy,
        )


def archive_current(state: Dict[str, object], sensor_id: str) -> None:
    archive_path(state, sensor_id, LOG_PATH, "current")


def locked_run() -> None:
    LOCK_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(LOCK_PATH), flags, 0o600)
    with os.fdopen(fd, "r+"):
        if fcntl is None:
            raise RuntimeError("POSIX process locking is unavailable")
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = load_state()
        sensor_id = instance_id()
        archive_rotated(state, sensor_id)
        archive_current(state, sensor_id)
        save_state(state)


def self_test() -> None:
    sample = b'{"eventid":"cowrie.session.connect"}\n'
    digest = hashlib.sha256(sample).hexdigest()
    assert len(digest) == 64
    assert checksum_b64(digest)
    assert content_address_matches(f"0-1-{digest}.json", digest)
    assert clean_name("../../cowrie.json") == ".._.._cowrie.json"
    assert PREFIX
    print("s3-archive self-test: PASS")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return
    require_read_only_source()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", BUCKET):
        raise SystemExit("invalid or missing evidence bucket")
    SPOOL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    locked_run()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        LOGGER.exception("archive_failed reason=%s", type(error).__name__)
        raise
