# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""List a product's GitHub releases and their assets.

The client only lists; downloading, verification and state belong to later stages. It returns
plain data and never writes. Every response is untrusted:
  * only https://api.github.com is ever contacted, the `Link` header may not point anywhere
    else, redirects are refused and the token is never sent to a second host;
  * JSON with a repeated key, a wrong type or a missing field fails the whole listing;
  * a release whose own content breaks a rule (asset name, upload state, download URL) is
    reported as rejected and does not stop the other releases;
  * a tag outside the supported shapes is ignored and reported, and never reaches a URL.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from publisher import config

GITHUB_OWNER: Final = "FojleRabbiRabib"
API_HOST: Final = "api.github.com"
API_BASE: Final = f"https://{API_HOST}"
API_VERSION: Final = "2026-03-10"
USER_AGENT: Final = "php-pkg-publisher"
PER_PAGE: Final = 30
MAX_PAGES: Final = 50
MAX_BODY_BYTES: Final = 32 * 1024 * 1024
MAX_TAG_LENGTH: Final = 64
TIMEOUT_SECONDS: Final = 30.0
REQUEST_DEADLINE_SECONDS: Final = 60.0
TOTAL_DEADLINE_SECONDS: Final = 600.0
READ_CHUNK_BYTES: Final = 64 * 1024
SINGLE_HEADERS: Final = frozenset(
    {"content-type", "etag", "link", "retry-after", "x-ratelimit-remaining"}
)

ASSET_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
ETAG: Final = re.compile(r'(?:W/)?"[\x21\x23-\x7e]*"')
PRINTABLE_ASCII: Final = re.compile(r"[\x21-\x7e]+")
QUERY_NUMBER: Final = re.compile(r"[0-9]{1,6}")
RETRY_AFTER: Final = re.compile(r"[0-9]{1,9}")
TOKEN: Final = re.compile(r"[A-Za-z0-9_-]{1,512}")
_LINK_ITEM_SOURCE = r'<[\x21-\x3b=\x3f-\x7e]+>\s*;\s*rel="[A-Za-z ]{1,64}"'
LINK_HEADER: Final = re.compile(rf"\s*{_LINK_ITEM_SOURCE}(?:\s*,\s*{_LINK_ITEM_SOURCE})*\s*")
LINK_ITEM: Final = re.compile(r'<([^<>]+)>\s*;\s*rel="([A-Za-z ]+)"')
MAX_TOKEN_FILE_BYTES: Final = 4096


class FeedError(Exception):
    """The release listing could not be read or is not trustworthy."""


class AuthError(FeedError):
    """GitHub rejected the token (HTTP 401)."""


class NotFound(FeedError):
    """The repository or its releases do not exist (HTTP 404)."""


class RateLimited(FeedError):
    """GitHub is rate limiting this client."""

    def __init__(self, message: str, retry_after: int | None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True, kw_only=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def __call__(self, url: str, headers: Mapping[str, str]) -> Response: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Asset:
    name: str
    size: int
    digest: str | None
    url: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Release:
    tag: str
    kind: Literal["final", "prerelease"]
    immutable: bool
    assets: tuple[Asset, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Rejection:
    tag: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Listing:
    etag: str | None
    releases: tuple[Release, ...]
    rejected: tuple[Rejection, ...]
    ignored: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Unchanged:
    """The first page still matches the etag.

    The etag covers page one only, so a change deeper in the list is not seen. That is safe
    because releases must be immutable to be admitted, and the daily reconcile must also list
    without an etag now and then.
    """

    etag: str


class _Reject(Exception):
    """One release breaks a content rule; the rest of the listing is still valid."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _safe(text: str) -> str:
    return ascii(text)[:80]


def _headers(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in pairs:
        name = key.lower()
        if name in result and name in SINGLE_HEADERS:
            raise FeedError(f"response repeats the {name} header")
        result[name] = value
    return result


class HttpsTransport:
    """GET over https with a timeout, body cap and deadline; no redirects, proxies or http.

    The deadline covers reading the body and is checked after every network read. Waiting for
    the response headers is bounded only by the per-operation timeout, so the service unit must
    also limit the total run time.
    """

    _SCHEMES: tuple[str, ...] = ("https://",)

    def __init__(self, token: str | None = None) -> None:
        self._token = token
        self._opener = urllib.request.OpenerDirector()
        for handler in self._handlers():
            self._opener.add_handler(handler)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
            urllib.request.UnknownHandler(),
        ]

    def __call__(self, url: str, headers: Mapping[str, str]) -> Response:
        if not url.startswith(self._SCHEMES):
            raise FeedError("only https URLs are allowed")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
        if self._token is not None:
            request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as reply:
                return self._read(reply.status, reply.headers.items(), reply)
        except urllib.error.HTTPError as error:
            with error:
                return self._read(error.code, error.headers.items(), error)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise FeedError(f"request failed: {type(error).__name__}") from error

    @staticmethod
    def _read(
        status: int,
        pairs: Iterable[tuple[str, str]],
        reply: http.client.HTTPResponse | urllib.error.HTTPError,
    ) -> Response:
        headers = _headers(pairs)
        deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
        chunks: list[bytes] = []
        total = 0
        while chunk := reply.read1(READ_CHUNK_BYTES):
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise FeedError("response is larger than the allowed size")
            if time.monotonic() > deadline:
                raise FeedError("response took too long")
            chunks.append(chunk)
        return Response(status=status, headers=headers, body=b"".join(chunks))


def read_token(path: Path) -> str:
    """Read the GitHub token from a file only its owner can access."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise FeedError(f"{path}: token file is not a regular file")
            if info.st_mode & 0o077:
                raise FeedError(f"{path}: token file must not be accessible by group or others")
            if info.st_uid != os.geteuid():
                raise FeedError(f"{path}: token file must be owned by the current user")
            raw = handle.read(MAX_TOKEN_FILE_BYTES + 1)
    except OSError as error:
        raise FeedError(f"{path}: cannot read token file: {error.strerror or error}") from error
    if len(raw) > MAX_TOKEN_FILE_BYTES:
        raise FeedError(f"{path}: token file is too large")
    token = raw.decode("ascii", errors="replace").removesuffix("\n")
    if not TOKEN.fullmatch(token):
        raise FeedError(f"{path}: token file does not hold a single token")
    return token


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FeedError(f"response repeats the key {_safe(key)}")
        result[key] = value
    return result


def _check_api_url(url: str) -> str:
    """Accept only a releases page on the GitHub API and return its path."""
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise FeedError("page link is malformed") from error
    if (
        not PRINTABLE_ASCII.fullmatch(url)
        or parts.scheme != "https"
        or parts.hostname != API_HOST
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.fragment
        or not parts.path.startswith(("/repos/", "/repositories/"))
        or not parts.path.endswith("/releases")
        or "%" in parts.path
        or ".." in parts.path.split("/")
        or any(
            key not in ("page", "per_page") or not QUERY_NUMBER.fullmatch(value)
            for key, value in query
        )
    ):
        raise FeedError("page link does not point to the GitHub API")
    return parts.path


def _next_link(header: str | None) -> str | None:
    if header is None:
        return None
    if not LINK_HEADER.fullmatch(header):
        raise FeedError("page link header is not understood")
    targets = [
        url for url, relation in LINK_ITEM.findall(header) if "next" in relation.lower().split()
    ]
    if len(targets) > 1:
        raise FeedError("response has more than one next page link")
    return targets[0] if targets else None


def _fail_status(response: Response) -> FeedError:
    status = response.status
    if status == 401:
        return AuthError("GitHub rejected the token (401)")
    if status == 404:
        return NotFound("repository or releases not found (404)")
    if status in (403, 429):
        retry = response.headers.get("retry-after")
        exhausted = response.headers.get("x-ratelimit-remaining") == "0"
        if retry is not None or exhausted or status == 429:
            seconds = int(retry) if retry is not None and RETRY_AFTER.fullmatch(retry) else None
            return RateLimited(f"GitHub rate limit reached ({status})", seconds)
        return FeedError("GitHub refused the request (403)")
    if status in (301, 302, 303, 307, 308):
        return FeedError(f"redirect refused ({status})")
    return FeedError(f"unexpected response status {status}")


def _mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FeedError(f"{what} is not an object")
    return value


def _typed(item: dict[str, Any], key: str, kind: type) -> Any:
    if key not in item:
        raise FeedError(f"response lacks {key!r}")
    value = item[key]
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise FeedError(f"{key!r} has the wrong type")
    return value


def _asset(repo: str, tag: str, raw: Any) -> Asset:
    item = _mapping(raw, "asset")
    name: str = _typed(item, "name", str)
    state: str = _typed(item, "state", str)
    size: int = _typed(item, "size", int)
    url: str = _typed(item, "browser_download_url", str)
    digest = item.get("digest")
    if digest is not None and not isinstance(digest, str):
        raise FeedError("'digest' has the wrong type")
    if not ASSET_NAME.fullmatch(name) or ".." in name:
        raise _Reject(f"asset name {_safe(name)} is not allowed")
    if state != "uploaded":
        raise _Reject(f"asset {name} is not fully uploaded")
    if size < 0:
        raise _Reject(f"asset {name} has a negative size")
    if digest is not None and not DIGEST.fullmatch(digest):
        raise _Reject(f"asset {name} has a malformed digest")
    expected = f"https://github.com/{GITHUB_OWNER}/{repo}/releases/download/{tag}/{name}"
    if url != expected:
        raise _Reject(f"asset {name} has an unexpected download URL")
    return Asset(name=name, size=size, digest=digest, url=url)


def _release(
    repo: str, tag: str, kind: Literal["final", "prerelease"], item: dict[str, Any]
) -> Release:
    immutable = item.get("immutable", False)
    if not isinstance(immutable, bool):
        raise FeedError("'immutable' has the wrong type")
    raw_assets = _typed(item, "assets", list)
    assets = tuple(_asset(repo, tag, raw) for raw in raw_assets)
    names = [asset.name for asset in assets]
    if len(set(names)) != len(names):
        raise _Reject("two assets share a name")
    return Release(tag=tag, kind=kind, immutable=immutable, assets=assets)


def _parse_page(
    repo: str,
    body: bytes,
    releases: dict[str, Release],
    rejected: dict[str, Rejection],
    ignored: list[str],
    seen: set[str],
) -> None:
    try:
        document = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError) as error:
        raise FeedError("response is not valid JSON") from error
    if not isinstance(document, list):
        raise FeedError("response is not a list of releases")
    for raw in document:
        item = _mapping(raw, "release")
        if _typed(item, "draft", bool):
            continue
        tag: str = _typed(item, "tag_name", str)
        short = len(tag) <= MAX_TAG_LENGTH
        if short and config.FINAL_TAG.fullmatch(tag):
            kind: Literal["final", "prerelease"] = "final"
        elif short and config.RELEASE_TAG.fullmatch(tag):
            kind = "prerelease"
        else:
            ignored.append(_safe(tag))
            continue
        if tag in seen:
            raise FeedError(f"tag {tag} is listed twice")
        seen.add(tag)
        try:
            releases[tag] = _release(repo, tag, kind, item)
        except _Reject as reason:
            rejected[tag] = Rejection(tag=tag, reason=str(reason))


def list_releases(
    repo: str, transport: Transport, *, etag: str | None = None
) -> Listing | Unchanged:
    """Return every release of `repo`, or Unchanged when `etag` still matches page one."""
    if not config.REPO_NAME.fullmatch(repo) or ".." in repo:
        raise FeedError(f"invalid repo name {_safe(repo)}")
    if etag is not None and not ETAG.fullmatch(etag):
        raise FeedError("etag is malformed")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    url: str | None = f"{API_BASE}/repos/{GITHUB_OWNER}/{repo}/releases?per_page={PER_PAGE}"
    releases: dict[str, Release] = {}
    rejected: dict[str, Rejection] = {}
    ignored: list[str] = []
    seen: set[str] = set()
    visited: set[str] = set()
    first_etag: str | None = None
    later_path: str | None = None
    started = time.monotonic()
    page = 0
    while url is not None:
        page += 1
        if page > MAX_PAGES:
            raise FeedError("too many pages; refusing a truncated listing")
        if time.monotonic() - started > TOTAL_DEADLINE_SECONDS:
            raise FeedError("listing took too long")
        if url in visited:
            raise FeedError("page links form a loop")
        visited.add(url)
        path = _check_api_url(url)
        if page > 1 and later_path not in (None, path):
            raise FeedError("page links change repository")
        if page > 1:
            later_path = path
        request_headers = dict(headers)
        if page == 1 and etag is not None:
            request_headers["If-None-Match"] = etag
        response = transport(url, request_headers)
        if page == 1 and etag is not None and response.status == 304:
            return Unchanged(etag=etag)
        if response.status != 200:
            raise _fail_status(response)
        if not response.headers.get("content-type", "").startswith("application/json"):
            raise FeedError("response is not JSON")
        if page == 1:
            candidate = response.headers.get("etag")
            first_etag = candidate if candidate is not None and ETAG.fullmatch(candidate) else None
        _parse_page(repo, response.body, releases, rejected, ignored, seen)
        url = _next_link(response.headers.get("link"))
    return Listing(
        etag=first_etag,
        releases=tuple(releases.values()),
        rejected=tuple(rejected.values()),
        ignored=tuple(ignored),
    )
