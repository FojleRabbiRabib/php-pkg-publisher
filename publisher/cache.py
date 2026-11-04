# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Download release assets into a private, content-addressed cache.

The cache stores bytes only; it does not decide whether they are trustworthy. Every stored
file has been checked against the size and sha256 digest that GitHub lists for the asset, and
is named by that digest, never by release data. Rules:
  * a release asset URL answers with exactly one redirect, to a fixed CDN host; anything else
    is refused, and no credential is ever sent;
  * the download is cut off at the listed size and at a deadline, and an asset without a
    digest is refused;
  * a file is written to a temporary name, flushed, then renamed into place, so a reader sees
    a whole file or none;
  * the cache directory must be private to the current user (POSIX systems only).
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import os
import re
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Generator, Mapping
from pathlib import Path
from typing import Final

from publisher import net
from publisher.feed import Asset

ORIGIN_HOSTS: Final = frozenset({"github.com"})
ASSET_HOSTS: Final = frozenset({"release-assets.githubusercontent.com"})
USER_AGENT: Final = "php-pkg-publisher"
MAX_ASSET_BYTES: Final = 512 * 1024 * 1024
MAX_LOCATION_LENGTH: Final = 4096
TIMEOUT_SECONDS: Final = 30.0
DOWNLOAD_DEADLINE_SECONDS: Final = 900.0
READ_CHUNK_BYTES: Final = 64 * 1024
SINGLE_HEADERS: Final = frozenset({"content-encoding", "content-length", "location"})

DIGEST: Final = re.compile(r"sha256:([0-9a-f]{64})")
CONTENT_LENGTH: Final = re.compile(r"[0-9]{1,12}")
PRINTABLE_ASCII: Final = re.compile(r"[\x21-\x7e]+")

Chunks = Generator[bytes, None, None]
Fetch = Callable[[str, int], Chunks]


class CacheError(Exception):
    """Base of the cache errors; catch a subclass to tell one bad asset from a bad cache."""


class CacheDirectoryError(CacheError):
    """The cache directory or its files cannot be used; the whole run must stop."""


class DownloadError(CacheError):
    """One asset could not be fetched or does not match what GitHub lists for it."""


class HttpsFetcher:
    """Fetch one release asset: one redirect to the CDN allow-list, no token, no proxy."""

    _SCHEMES: tuple[str, ...] = ("https://",)

    def __init__(
        self,
        *,
        origins: frozenset[str] = ORIGIN_HOSTS,
        hosts: frozenset[str] = ASSET_HOSTS,
    ) -> None:
        self._origins = origins
        self._hosts = hosts
        self._opener = urllib.request.OpenerDirector()
        for handler in self._handlers():
            self._opener.add_handler(handler)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            net.NoRedirect(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
            urllib.request.UnknownHandler(),
        ]

    def __call__(self, url: str, size: int) -> Chunks:
        location = self._redirect(url)
        with self._get(location) as (status, headers, reply):
            if status != 200:
                raise DownloadError(f"asset server answered {status}")
            if headers.get("content-encoding", "identity") != "identity":
                raise DownloadError("asset server compressed the file")
            length = headers.get("content-length")
            if length is not None and (not CONTENT_LENGTH.fullmatch(length) or int(length) != size):
                raise DownloadError("asset length does not match the listed size")
            try:
                while chunk := reply.read1(READ_CHUNK_BYTES):
                    yield chunk
            except (http.client.HTTPException, OSError) as error:
                raise DownloadError(f"download failed: {type(error).__name__}") from error

    def _redirect(self, url: str) -> str:
        if (
            not url.startswith(self._SCHEMES)
            or urllib.parse.urlsplit(url).netloc not in self._origins
        ):
            raise DownloadError("asset URL is not on an allowed origin")
        with self._get(url) as (status, headers, _reply):
            if status != 302:
                raise DownloadError(f"asset origin answered {status}, expected one redirect")
            location = headers.get("location")
        if (
            location is None
            or len(location) > MAX_LOCATION_LENGTH
            or not PRINTABLE_ASCII.fullmatch(location)
            or not location.startswith(self._SCHEMES)
        ):
            raise DownloadError("redirect target is not allowed")
        parts = urllib.parse.urlsplit(location)
        if parts.fragment:
            raise DownloadError("redirect target is not allowed")
        if parts.netloc not in self._hosts:
            raise DownloadError(f"redirect target host {net.safe(parts.netloc)} is not allowed")
        return location

    @contextlib.contextmanager
    def _get(
        self, url: str
    ) -> Generator[
        tuple[int, Mapping[str, str], http.client.HTTPResponse | urllib.error.HTTPError],
        None,
        None,
    ]:
        request = urllib.request.Request(  # noqa: S310
            url,
            headers={"Accept": "application/octet-stream", "User-Agent": USER_AGENT},
            method="GET",
        )
        reply: http.client.HTTPResponse | urllib.error.HTTPError
        try:
            reply = self._opener.open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            reply = error
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise DownloadError(f"request failed: {type(error).__name__}") from error
        with reply:
            try:
                headers = net.headers(reply.headers.items(), SINGLE_HEADERS)
            except ValueError as error:
                raise DownloadError(str(error)) from error
            status = reply.getcode()
            if status is None:
                raise DownloadError("response has no status")
            yield status, headers, reply


def _require_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise CacheDirectoryError(f"{path}: cannot inspect: {error.strerror or error}") from error
    if not stat.S_ISDIR(info.st_mode):
        raise CacheDirectoryError(f"{path}: not a directory")
    if info.st_uid != os.geteuid():
        raise CacheDirectoryError(f"{path}: must be owned by the current user")
    if info.st_mode & 0o077:
        raise CacheDirectoryError(f"{path}: must not be accessible by group or others")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Cache:
    """Content-addressed store of verified-size, verified-digest asset files."""

    def __init__(self, root: Path, fetch: Fetch) -> None:
        if os.name != "posix":
            raise CacheDirectoryError("the cache needs a POSIX system")
        if not root.is_absolute():
            raise CacheDirectoryError(f"{root}: cache root must be an absolute path")
        self._objects = root / "objects"
        self._temporary = root / "tmp"
        self._fetch = fetch
        _require_private_directory(root)
        for directory in (self._objects, self._temporary):
            try:
                directory.mkdir(mode=0o700, exist_ok=True)
            except OSError as error:
                raise CacheDirectoryError(
                    f"{directory}: cannot create: {error.strerror or error}"
                ) from error
            _require_private_directory(directory)
        self._sweep_temporary()

    def _sweep_temporary(self) -> None:
        """Remove download leftovers that no live download can still be writing."""
        oldest = time.time() - (DOWNLOAD_DEADLINE_SECONDS + TIMEOUT_SECONDS)
        try:
            for entry in self._temporary.iterdir():
                if entry.name.startswith("dl-") and entry.lstat().st_mtime < oldest:
                    entry.unlink(missing_ok=True)
        except OSError as error:
            raise CacheDirectoryError(
                f"{self._temporary}: cannot clean up: {error.strerror or error}"
            ) from error

    def obtain(self, asset: Asset) -> Path:
        """Return the cached file for `asset`, downloading and checking it when absent."""
        match = DIGEST.fullmatch(asset.digest or "")
        if match is None:
            raise DownloadError(f"asset {net.safe(asset.name)} has no usable digest")
        if asset.size > MAX_ASSET_BYTES:
            raise DownloadError(f"asset {net.safe(asset.name)} is larger than the allowed size")
        expected = match.group(1)
        target = self._objects / expected
        try:
            intact = self._is_intact(target, asset.size, expected)
        except OSError as error:
            raise CacheDirectoryError(
                f"cannot check {target.name}: {error.strerror or error}"
            ) from error
        if intact:
            return target
        self._download(asset, expected, target)
        return target

    @staticmethod
    def _is_intact(path: Path, size: int, expected: str) -> bool:
        """Check a stored file again; drop it when it is not what its name says."""
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            return False
        except OSError:
            path.unlink(missing_ok=True)
            return False
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                intact = False
            else:
                digest = hashlib.sha256()
                total = 0
                while chunk := handle.read(READ_CHUNK_BYTES):
                    total += len(chunk)
                    digest.update(chunk)
                intact = total == size and digest.hexdigest() == expected
        if not intact:
            path.unlink(missing_ok=True)
        return intact

    def _download(self, asset: Asset, expected: str, target: Path) -> None:
        descriptor, name = tempfile.mkstemp(dir=self._temporary, prefix="dl-")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as out:
                digest = hashlib.sha256()
                total = 0
                deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
                with contextlib.closing(self._fetch(asset.url, asset.size)) as chunks:
                    for chunk in chunks:
                        total += len(chunk)
                        if total > asset.size:
                            raise DownloadError(
                                f"asset {net.safe(asset.name)} is larger than listed"
                            )
                        if time.monotonic() > deadline:
                            raise DownloadError(f"asset {net.safe(asset.name)} took too long")
                        out.write(chunk)
                        digest.update(chunk)
                if total != asset.size:
                    raise DownloadError(f"asset {net.safe(asset.name)} is smaller than listed")
                if digest.hexdigest() != expected:
                    raise DownloadError(f"asset {net.safe(asset.name)} does not match its digest")
                out.flush()
                os.fsync(out.fileno())
            temporary.replace(target)
            _sync_directory(self._objects)
        except OSError as error:
            raise CacheDirectoryError(
                f"cannot store {net.safe(asset.name)}: {error.strerror or error}"
            ) from error
        finally:
            temporary.unlink(missing_ok=True)
