# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import hashlib
import os
import stat
import time
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest
from servers import local_server, reply

from publisher import cache
from publisher.cache import (
    Cache,
    CacheDirectoryError,
    CacheError,
    Chunks,
    DownloadError,
    HttpsFetcher,
)
from publisher.feed import Asset

PAYLOAD = b"package bytes " * 100
HEX = hashlib.sha256(PAYLOAD).hexdigest()
URL = "https://github.com/FojleRabbiRabib/p-php/releases/download/v1.0.0/a.deb"


def _asset(
    data: bytes = PAYLOAD, *, digest: str | None = "", size: int | None = None, url: str = URL
) -> Asset:
    if digest == "":
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return Asset(name="a.deb", size=len(data) if size is None else size, digest=digest, url=url)


class Source:
    """A fetch that serves fixed bytes in small chunks and records its use."""

    def __init__(self, data: bytes = PAYLOAD, *, chunk: int = 64) -> None:
        self.data = data
        self.chunk = chunk
        self.calls: list[tuple[str, int]] = []
        self.closed = 0

    def __call__(self, url: str, size: int) -> Chunks:
        self.calls.append((url, size))
        try:
            for start in range(0, len(self.data), self.chunk):
                yield self.data[start : start + self.chunk]
        finally:
            self.closed += 1


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "cache"
    path.mkdir()
    path.chmod(0o700)
    return path


def _leftovers(root: Path) -> list[Path]:
    return sorted((root / "tmp").iterdir())


# ---- cache --------------------------------------------------------------------------------


def test_obtain_stores_the_file_under_its_digest_with_private_mode(root: Path) -> None:
    path = Cache(root, Source()).obtain(_asset())
    assert path == root / "objects" / HEX
    assert path.read_bytes() == PAYLOAD
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _leftovers(root) == []


def test_obtain_reuses_an_intact_file_without_downloading(root: Path) -> None:
    source = Source()
    store = Cache(root, source)
    first = store.obtain(_asset())
    assert store.obtain(_asset()) == first
    assert len(source.calls) == 1


def test_obtain_passes_the_listed_url_and_size_to_the_fetch(root: Path) -> None:
    source = Source()
    Cache(root, source).obtain(_asset())
    assert source.calls == [(URL, len(PAYLOAD))]


def test_obtain_replaces_a_corrupt_stored_file(root: Path) -> None:
    source = Source()
    store = Cache(root, source)
    path = store.obtain(_asset())
    path.write_bytes(b"x" * len(PAYLOAD))
    assert store.obtain(_asset()).read_bytes() == PAYLOAD
    assert len(source.calls) == 2


def test_obtain_replaces_a_stored_symlink_and_leaves_its_target_alone(
    root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(PAYLOAD)
    store = Cache(root, Source())
    (root / "objects" / HEX).symlink_to(outside)
    path = store.obtain(_asset())
    assert not path.is_symlink()
    assert path.read_bytes() == PAYLOAD
    assert outside.read_bytes() == PAYLOAD


def test_obtain_reports_a_directory_where_a_file_belongs(root: Path) -> None:
    store = Cache(root, Source())
    (root / "objects" / HEX).mkdir()
    with pytest.raises(CacheDirectoryError):
        store.obtain(_asset())


@pytest.mark.parametrize(
    "digest", [None, "sha256:", "sha256:ABC", "md5:" + "a" * 32, "sha256:" + "A" * 64]
)
def test_obtain_refuses_an_asset_without_a_usable_digest(root: Path, digest: str | None) -> None:
    source = Source()
    with pytest.raises(DownloadError, match="no usable digest"):
        Cache(root, source).obtain(_asset(digest=digest))
    assert source.calls == []


def test_obtain_refuses_an_oversized_asset_before_downloading(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cache, "MAX_ASSET_BYTES", 5)
    source = Source()
    with pytest.raises(DownloadError, match="larger than the allowed size"):
        Cache(root, source).obtain(_asset())
    assert source.calls == []


@pytest.mark.parametrize(
    ("data", "size", "message"),
    [
        (PAYLOAD + b"x", len(PAYLOAD), "larger than listed"),
        (PAYLOAD[:-1], len(PAYLOAD), "smaller than listed"),
        (b"y" * len(PAYLOAD), len(PAYLOAD), "does not match its digest"),
    ],
    ids=["too-long", "too-short", "wrong-bytes"],
)
def test_obtain_rejects_a_bad_download_and_leaves_nothing(
    root: Path, data: bytes, size: int, message: str
) -> None:
    source = Source(data)
    with pytest.raises(DownloadError, match=message):
        Cache(root, source).obtain(_asset(digest="sha256:" + HEX, size=size))
    assert list((root / "objects").iterdir()) == []
    assert _leftovers(root) == []
    assert source.closed == 1


def test_obtain_stops_a_download_that_runs_past_the_deadline(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cache, "DOWNLOAD_DEADLINE_SECONDS", -1.0)
    with pytest.raises(DownloadError, match="took too long"):
        Cache(root, Source()).obtain(_asset())
    assert _leftovers(root) == []


def test_obtain_cleans_up_when_the_fetch_fails_midway(root: Path) -> None:
    def broken(url: str, size: int) -> Chunks:
        yield PAYLOAD[:10]
        raise DownloadError("download failed: ConnectionResetError")

    with pytest.raises(DownloadError, match="download failed"):
        Cache(root, broken).obtain(_asset())
    assert list((root / "objects").iterdir()) == []
    assert _leftovers(root) == []


def test_error_messages_bound_the_asset_name(root: Path) -> None:
    asset = Asset(name="a\x1b[31m" + "b" * 500, size=1, digest=None, url=URL)
    with pytest.raises(DownloadError) as caught:
        Cache(root, Source()).obtain(asset)
    assert "\x1b" not in str(caught.value)
    assert len(str(caught.value)) < 200


def test_one_bad_asset_and_a_bad_cache_are_different_errors() -> None:
    assert issubclass(DownloadError, CacheError)
    assert issubclass(CacheDirectoryError, CacheError)
    assert not issubclass(DownloadError, CacheDirectoryError)
    assert not issubclass(CacheDirectoryError, DownloadError)


# ---- cache directory ----------------------------------------------------------------------


def test_root_must_be_absolute() -> None:
    with pytest.raises(CacheDirectoryError, match="absolute"):
        Cache(Path("cache"), Source())


def test_root_must_exist(tmp_path: Path) -> None:
    with pytest.raises(CacheDirectoryError, match="cannot inspect"):
        Cache(tmp_path / "missing", Source())


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o707, 0o770])
def test_root_must_not_be_open_to_group_or_others(root: Path, mode: int) -> None:
    root.chmod(mode)
    with pytest.raises(CacheDirectoryError, match="must not be accessible"):
        Cache(root, Source())


def test_root_must_be_a_directory_not_a_symlink_or_file(root: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(root)
    with pytest.raises(CacheDirectoryError, match="not a directory"):
        Cache(link, Source())
    file = tmp_path / "file"
    file.write_bytes(b"")
    with pytest.raises(CacheDirectoryError, match="not a directory"):
        Cache(file, Source())


def test_open_subdirectories_are_refused(root: Path) -> None:
    (root / "objects").mkdir()
    (root / "objects").chmod(0o755)
    with pytest.raises(CacheDirectoryError, match="must not be accessible"):
        Cache(root, Source())


def test_root_must_belong_to_the_current_user(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    other_user = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: other_user)
    with pytest.raises(CacheDirectoryError, match="owned by the current user"):
        Cache(root, Source())


def test_subdirectories_are_created_private(root: Path) -> None:
    Cache(root, Source())
    for name in ("objects", "tmp"):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o700


@pytest.mark.parametrize("name", ["objects", "tmp"])
def test_a_file_where_a_subdirectory_belongs_is_a_cache_error(root: Path, name: str) -> None:
    (root / name).write_bytes(b"")
    with pytest.raises(CacheDirectoryError, match="cannot create"):
        Cache(root, Source())


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_an_unwritable_root_is_a_cache_error(root: Path) -> None:
    root.chmod(0o500)
    try:
        with pytest.raises(CacheDirectoryError, match="cannot create"):
            Cache(root, Source())
    finally:
        root.chmod(0o700)


def test_startup_removes_only_old_download_leftovers(root: Path) -> None:
    (root / "tmp").mkdir(mode=0o700)
    old = root / "tmp" / "dl-old"
    fresh = root / "tmp" / "dl-fresh"
    other = root / "tmp" / "keep-me"
    for path in (old, fresh, other):
        path.write_bytes(b"x")
    stale = time.time() - cache.DOWNLOAD_DEADLINE_SECONDS - cache.TIMEOUT_SECONDS - 60
    os.utime(old, (stale, stale))
    os.utime(other, (stale, stale))
    Cache(root, Source())
    assert not old.exists()
    assert fresh.exists()
    assert other.exists()


# ---- real fetcher against local servers ----------------------------------------------------


class _Local(HttpsFetcher):
    """The production fetcher, pointed at plain-http loopback servers for the tests."""

    _SCHEMES = ("http://",)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [*super()._handlers(), urllib.request.HTTPHandler()]


def _host(base: str) -> frozenset[str]:
    return frozenset({base.removeprefix("http://")})


def _fetch(origin: str, cdn: str, size: int = len(PAYLOAD)) -> bytes:
    fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
    return b"".join(fetcher(origin + "/asset", size))


def _redirect(target: str) -> Callable[[BaseHTTPRequestHandler], None]:
    return reply(302, b"", Location=target)


def test_fetcher_follows_one_redirect_and_sends_no_credentials() -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, cdn_seen),
        local_server(_redirect(cdn + "/blob")) as (origin, origin_seen),
    ):
        assert _fetch(origin, cdn) == PAYLOAD
    for seen in (origin_seen, cdn_seen):
        assert len(seen) == 1
        assert "authorization" not in seen[0]
        assert "cookie" not in seen[0]
        assert seen[0]["user-agent"] == "php-pkg-publisher"


def test_fetcher_refuses_a_redirect_to_another_host() -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (evil, evil_seen),
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(_redirect(evil + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match=r"host .* is not allowed"),
    ):
        _fetch(origin, cdn)
    assert evil_seen == []


def test_fetcher_refuses_a_second_redirect() -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (far, far_seen),
        local_server(_redirect(far + "/again")) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match="answered 302"),
    ):
        _fetch(origin, cdn)
    assert far_seen == []


@pytest.mark.parametrize(
    ("location", "message"),
    [
        ("{cdn_user}", "host .* is not allowed"),
        ("{cdn}/blob#frag", "redirect target is not allowed"),
        ("{cdn}/bl ob", "redirect target is not allowed"),
        ("{cdn}/" + "a" * 5000, "redirect target is not allowed"),
        ("ftp://127.0.0.1/x", "redirect target is not allowed"),
        ("/relative", "redirect target is not allowed"),
    ],
    ids=["userinfo", "fragment", "space", "too-long", "other-scheme", "relative"],
)
def test_fetcher_refuses_a_malformed_redirect_target(location: str, message: str) -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        pytest.raises(DownloadError, match=message),
    ):
        text = location.format(cdn=cdn, cdn_user=cdn.replace("http://", "http://user:pw@") + "/b")
        with local_server(_redirect(text)) as (origin, _):
            _fetch(origin, cdn)


@pytest.mark.parametrize("status", [200, 301, 307, 404])
def test_fetcher_wants_exactly_one_302_from_the_origin(status: int) -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(reply(status, PAYLOAD, Location=cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match=f"origin answered {status}"),
    ):
        _fetch(origin, cdn)


def test_fetcher_refuses_a_redirect_without_a_location() -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(reply(302)) as (origin, _),
        pytest.raises(DownloadError, match="redirect target is not allowed"),
    ):
        _fetch(origin, cdn)


def test_fetcher_refuses_repeated_location_headers() -> None:
    def two(request: BaseHTTPRequestHandler) -> None:
        request.send_response(302)
        request.send_header("Location", "http://127.0.0.1:1/a")
        request.send_header("Location", "http://127.0.0.1:1/b")
        request.send_header("Content-Length", "0")
        request.end_headers()

    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(two) as (origin, _),
        pytest.raises(DownloadError, match="repeats the location header"),
    ):
        _fetch(origin, cdn)


@pytest.mark.parametrize("status", [206, 301, 404, 500])
def test_fetcher_refuses_a_cdn_answer_that_is_not_200(status: int) -> None:
    with (
        local_server(reply(status, PAYLOAD)) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match=f"answered {status}"),
    ):
        _fetch(origin, cdn)


def test_fetcher_refuses_a_length_that_differs_from_the_listed_size() -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match="does not match the listed size"),
    ):
        _fetch(origin, cdn, size=len(PAYLOAD) + 1)


def test_fetcher_refuses_a_compressed_body() -> None:
    with (
        local_server(reply(200, PAYLOAD, Content_Encoding="gzip")) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match="compressed"),
    ):
        _fetch(origin, cdn)


def test_fetcher_refuses_repeated_length_headers() -> None:
    def two(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Content-Length", str(len(PAYLOAD)))
        request.send_header("Content-Length", "1")
        request.end_headers()

    with (
        local_server(two) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match="repeats the content-length header"),
    ):
        _fetch(origin, cdn)


def test_default_hosts_are_the_measured_github_hosts() -> None:
    assert {"github.com"} == cache.ORIGIN_HOSTS
    assert {"release-assets.githubusercontent.com"} == cache.ASSET_HOSTS


def test_production_fetcher_refuses_a_plain_http_redirect_to_the_allowed_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def answer(self: HttpsFetcher, url: str) -> Iterator[tuple[int, dict[str, str], None]]:
        yield 302, {"location": "http://release-assets.githubusercontent.com/x"}, None

    monkeypatch.setattr(HttpsFetcher, "_get", answer)
    with pytest.raises(DownloadError, match="redirect target is not allowed"):
        next(HttpsFetcher()("https://github.com/FojleRabbiRabib/p-php/x", 1))


@pytest.mark.parametrize(
    ("body", "message"),
    [(PAYLOAD + b"x", "larger than listed"), (PAYLOAD[:-1], "smaller than listed")],
    ids=["too-long", "too-short"],
)
def test_a_body_without_a_length_is_held_to_the_listed_size(
    root: Path, body: bytes, message: str
) -> None:
    def unframed(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.end_headers()
        request.wfile.write(body)
        request.close_connection = True

    with (
        local_server(unframed) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match=message),
    ):
        fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
        Cache(root, fetcher).obtain(_asset(url=origin + "/asset"))
    assert list((root / "objects").iterdir()) == []


def test_a_body_without_a_length_of_the_exact_size_is_stored(root: Path) -> None:
    def unframed(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.end_headers()
        request.wfile.write(PAYLOAD)
        request.close_connection = True

    with (
        local_server(unframed) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
    ):
        fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
        assert Cache(root, fetcher).obtain(_asset(url=origin + "/asset")).read_bytes() == PAYLOAD


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x",
        "file:///etc/hostname",
        "https://evil.example/x",
        "https://github.com.evil.example/x",
        "https://user@github.com/x",
        "https://github.com:8443/x",
    ],
)
def test_production_fetcher_only_starts_at_the_https_origin(url: str) -> None:
    with pytest.raises(DownloadError, match="not on an allowed origin"):
        next(HttpsFetcher()(url, 1))


def test_production_fetcher_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
    ):
        assert _fetch(origin, cdn) == PAYLOAD


def test_fetcher_reports_a_connection_failure_as_a_download_error() -> None:
    with local_server(reply(200)) as (dead, _):
        pass
    with pytest.raises(DownloadError, match="request failed"):
        _fetch(dead, dead)


def test_cache_and_fetcher_store_a_real_download(root: Path) -> None:
    with (
        local_server(reply(200, PAYLOAD)) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
    ):
        fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
        path = Cache(root, fetcher).obtain(_asset(url=origin + "/asset"))
    assert path.read_bytes() == PAYLOAD


def test_cache_and_fetcher_reject_a_truncated_download(root: Path) -> None:
    def short(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Content-Length", str(len(PAYLOAD)))
        request.end_headers()
        request.wfile.write(PAYLOAD[:10])
        request.wfile.flush()
        request.close_connection = True

    with (
        local_server(short) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError),
    ):
        fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
        Cache(root, fetcher).obtain(_asset(url=origin + "/asset"))
    assert list((root / "objects").iterdir()) == []
    assert _leftovers(root) == []


def test_cache_stops_a_slow_drip_download(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache, "TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(cache, "DOWNLOAD_DEADLINE_SECONDS", 0.5)

    def drip(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Content-Length", str(len(PAYLOAD)))
        request.end_headers()
        try:
            for byte in PAYLOAD:
                request.wfile.write(bytes([byte]))
                request.wfile.flush()
                time.sleep(0.1)
        except OSError:
            return

    started = time.monotonic()
    with (
        local_server(drip) as (cdn, _),
        local_server(_redirect(cdn + "/blob")) as (origin, _),
        pytest.raises(DownloadError, match="took too long"),
    ):
        fetcher = _Local(origins=_host(origin), hosts=_host(cdn))
        Cache(root, fetcher).obtain(_asset(url=origin + "/asset"))
    assert time.monotonic() - started < 5.0
    assert _leftovers(root) == []


def test_posix_is_required(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(CacheDirectoryError, match="POSIX"):
        Cache(root, Source())
