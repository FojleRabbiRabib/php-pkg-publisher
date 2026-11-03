# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from publisher import feed
from publisher.feed import (
    Asset,
    AuthError,
    FeedError,
    HttpsTransport,
    Listing,
    NotFound,
    RateLimited,
    Rejection,
    Release,
    Response,
    Unchanged,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "resvg-releases.json"
JSON_TYPE = "application/json; charset=utf-8"
ETAG = 'W/"ca0274d1acb166252c757d4cc01d530ad499a4c8bdedce26691ea58d1336a840"'
LIVE_LINK = (
    '<https://api.github.com/repositories/1389021080/releases?per_page=1&page=2>; rel="next", '
    '<https://api.github.com/repositories/1389021080/releases?per_page=1&page=4>; rel="last"'
)
FIRST_URL = "https://api.github.com/repos/FojleRabbiRabib/p-php/releases?per_page=30"
NEXT_URL = "https://api.github.com/repositories/1/releases?per_page=30&page=2"
DIGEST = "sha256:" + "a" * 64


class Fake:
    """Replays queued responses and records the requests."""

    def __init__(self, *responses: Response) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: Mapping[str, str]) -> Response:
        self.calls.append((url, dict(headers)))
        return self.responses.pop(0)


def _asset(name: str = "a.deb", tag: str = "v1.0.0", **override: Any) -> dict[str, Any]:
    asset: dict[str, Any] = {
        "name": name,
        "state": "uploaded",
        "size": 10,
        "digest": DIGEST,
        "browser_download_url": f"https://github.com/FojleRabbiRabib/p-php/releases/download/{tag}/{name}",
    }
    asset.update(override)
    return asset


def _release(tag: str = "v1.0.0", **override: Any) -> dict[str, Any]:
    release: dict[str, Any] = {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": [_asset(tag=tag)],
    }
    release.update(override)
    return release


def _page(body: Any, status: int = 200, **headers: str) -> Response:
    merged = {"content-type": JSON_TYPE, **headers}
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return Response(status=status, headers=merged, body=raw)


def _list(*pages: Response, etag: str | None = None) -> tuple[Listing | Unchanged, Fake]:
    fake = Fake(*pages)
    return feed.list_releases("p-php", fake, etag=etag), fake


def _listing(*pages: Response) -> Listing:
    result, _ = _list(*pages)
    assert isinstance(result, Listing)
    return result


def _error(*pages: Response, etag: str | None = None) -> FeedError:
    with pytest.raises(FeedError) as caught:
        _list(*pages, etag=etag)
    return caught.value


def test_real_resvg_listing_is_parsed() -> None:
    page = _page(json.loads(FIXTURE.read_text(encoding="utf-8")), etag=ETAG)
    result = feed.list_releases("resvg-php", Fake(page))
    assert isinstance(result, Listing)
    assert result.etag == ETAG
    assert [release.tag for release in result.releases] == ["v0.3.0", "v0.2.0"]
    assert result.ignored == ("'v0.1.1+resvg.0.48.1'", "'v0.1.0+resvg.0.48.1'")
    assert result.rejected == ()
    first = result.releases[0]
    assert (first.kind, first.immutable, len(first.assets)) == ("final", False, 3)
    assert first.assets[0] == Asset(
        name="php-pecl-resvg-0.3.0-1.el8.aarch64.rpm",
        size=1325844,
        digest="sha256:f1705dc20487f5960a94add0cd9015a963921204826c66bce979db3f26ec30da",
        url="https://github.com/FojleRabbiRabib/resvg-php/releases/download/v0.3.0/"
        "php-pecl-resvg-0.3.0-1.el8.aarch64.rpm",
    )


def test_request_shape_and_conditional_header() -> None:
    _, fake = _list(_page([]))
    assert fake.calls == [
        (
            FIRST_URL,
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "php-pkg-publisher",
            },
        )
    ]
    _, fake = _list(_page([]), etag=ETAG)
    assert fake.calls[0][1]["If-None-Match"] == ETAG


def test_not_modified_returns_unchanged() -> None:
    result, fake = _list(Response(status=304, headers={}, body=b""), etag=ETAG)
    assert result == Unchanged(etag=ETAG)
    assert len(fake.calls) == 1


def test_not_modified_without_a_conditional_request_is_an_error() -> None:
    assert "unexpected response status 304" in str(
        _error(Response(status=304, headers={}, body=b""))
    )


def test_pages_are_followed_and_only_the_first_is_conditional() -> None:
    first = _page([_release("v1.0.0")], link=f'<{NEXT_URL}>; rel="next"', etag=ETAG)
    second = _page([_release("v1.1.0")])
    result, fake = _list(first, second, etag='"old"')
    assert isinstance(result, Listing)
    assert [release.tag for release in result.releases] == ["v1.0.0", "v1.1.0"]
    assert result.etag == ETAG
    assert [url for url, _ in fake.calls] == [FIRST_URL, NEXT_URL]
    assert "If-None-Match" in fake.calls[0][1]
    assert "If-None-Match" not in fake.calls[1][1]


def test_live_link_header_shape_is_followed() -> None:
    first = _page([], link=LIVE_LINK)
    _, fake = _list(first, _page([]))
    assert (
        fake.calls[1][0]
        == "https://api.github.com/repositories/1389021080/releases?per_page=1&page=2"
    )


@pytest.mark.parametrize(
    "target",
    [
        "http://api.github.com/repos/x/y/releases",
        "https://evil.example/repos/x/y/releases",
        "https://api.github.com.evil.example/repos/x/y/releases",
        "https://user@api.github.com/repos/x/y/releases",
        "https://user:pw@api.github.com/repos/x/y/releases",
        "https://api.github.com:444/repos/x/y/releases",
        "https://api.github.com:99999/repos/x/y/releases",
        "https://api.github.com/users/x",
        "https://api.github.com/repos/x/y/releases#frag",
        "//api.github.com/repos/x/y/releases",
        "/repos/x/y/releases",
        "https://api.github.com/repos/x/y/releases/1",
        "https://api.github.com/repos/../releases",
        "https://api.github.com/repos/x/%2e%2e/releases",
        "https://api.github.com/repos/x/y/releases?evil=1",
        "https://api.github.com/repos/x/y/releases?page=a",
    ],
)
def test_next_link_must_stay_on_the_github_api(target: str) -> None:
    fake = Fake(_page([], link=f'<{target}>; rel="next"'), _page([]))
    with pytest.raises(FeedError, match=r"does not point to the GitHub API|page link is malformed"):
        feed.list_releases("p-php", fake)
    assert len(fake.calls) == 1


def test_too_many_pages_is_an_error_not_a_truncated_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(feed, "MAX_PAGES", 2)
    pages = [
        _page([], link=f'<https://api.github.com/repositories/1/releases?page={n}>; rel="next"')
        for n in (2, 3, 4)
    ]
    assert "too many pages" in str(_error(*pages))


def test_repeated_page_url_is_a_loop() -> None:
    link = f'<{FIRST_URL}>; rel="next"'
    assert "loop" in str(_error(_page([], link=link), _page([], link=link)))


def test_two_next_links_are_an_error() -> None:
    link = f'<{NEXT_URL}>; rel="next", <{NEXT_URL}2>; rel="next"'
    assert "more than one next" in str(_error(_page([], link=link)))


@pytest.mark.parametrize("relation", ["next", "NEXT", "Next"])
def test_link_relation_is_case_insensitive(relation: str) -> None:
    _, fake = _list(_page([], link=f'<{NEXT_URL}>; rel="{relation}"'), _page([]))
    assert [url for url, _ in fake.calls] == [FIRST_URL, NEXT_URL]


@pytest.mark.parametrize(
    "link",
    [
        f"<{NEXT_URL}>; rel=next",
        f"<{NEXT_URL}>; rel='next'",
        f'<{NEXT_URL}>; type="x"; rel="next"',
        f'<{NEXT_URL}>; rel="next" garbage',
        f'<{NEXT_URL}>; rel="next",',
        f'<{NEXT_URL}\x00>; rel="next"',
        f'<{NEXT_URL}é>; rel="next"',
        "garbage",
    ],
)
def test_unparsable_link_header_is_never_taken_for_the_last_page(link: str) -> None:
    fake = Fake(_page([], link=link), _page([]))
    with pytest.raises(FeedError, match="page link header is not understood"):
        feed.list_releases("p-php", fake)
    assert len(fake.calls) == 1


def test_later_pages_must_stay_on_one_repository() -> None:
    first = _page([], link='<https://api.github.com/repositories/1/releases?page=2>; rel="next"')
    second = _page([], link='<https://api.github.com/repositories/2/releases?page=3>; rel="next"')
    assert "page links change repository" in str(_error(first, second, _page([])))


def test_listing_enforces_a_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feed, "TOTAL_DEADLINE_SECONDS", -1.0)
    fake = Fake(_page([]))
    with pytest.raises(FeedError, match="took too long"):
        feed.list_releases("p-php", fake)
    assert fake.calls == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (Response(status=401, headers={}, body=b""), AuthError),
        (Response(status=404, headers={}, body=b""), NotFound),
        (Response(status=403, headers={"x-ratelimit-remaining": "0"}, body=b""), RateLimited),
        (Response(status=403, headers={"retry-after": "5"}, body=b""), RateLimited),
        (Response(status=429, headers={}, body=b""), RateLimited),
    ],
)
def test_status_errors_have_their_own_types(response: Response, expected: type[FeedError]) -> None:
    assert type(_error(response)) is expected


def test_rate_limit_carries_retry_after() -> None:
    error = _error(Response(status=429, headers={"retry-after": "60"}, body=b""))
    assert isinstance(error, RateLimited)
    assert error.retry_after == 60
    unknown = _error(Response(status=429, headers={}, body=b""))
    assert isinstance(unknown, RateLimited)
    assert unknown.retry_after is None


@pytest.mark.parametrize("value", ["²", "٣", "9" * 5000, "-1", "1.5", ""])
def test_hostile_retry_after_is_not_parsed(value: str) -> None:
    error = _error(Response(status=429, headers={"retry-after": value}, body=b""))
    assert isinstance(error, RateLimited)
    assert error.retry_after is None


@pytest.mark.parametrize(
    ("status", "fragment"),
    [
        (403, "refused the request"),
        (302, "redirect refused"),
        (500, "unexpected response status 500"),
    ],
)
def test_other_statuses_fail_closed(status: int, fragment: str) -> None:
    error = _error(Response(status=status, headers={}, body=b""))
    assert fragment in str(error)
    assert not isinstance(error, (AuthError, NotFound, RateLimited))


@pytest.mark.parametrize(
    ("response", "fragment"),
    [
        (Response(status=200, headers={"content-type": "text/html"}, body=b"[]"), "not JSON"),
        (_page(b"{not json"), "not valid JSON"),
        (_page(b"\xff\xfe"), "not valid JSON"),
        (_page(b"[" * 100000), "not valid JSON"),
        (_page({"releases": []}), "not a list"),
        (_page(b'[{"draft": false, "draft": true}]'), "repeats the key 'draft'"),
        (_page(["a string"]), "release is not an object"),
        (_page([{"draft": False}]), "lacks 'tag_name'"),
        (_page([_release(draft="no")]), "'draft' has the wrong type"),
        (_page([_release(assets="none")]), "'assets' has the wrong type"),
        (_page([_release(assets=["x"])]), "asset is not an object"),
        (_page([_release(immutable="yes")]), "'immutable' has the wrong type"),
        (_page([_release(assets=[_asset(size=True)])]), "'size' has the wrong type"),
        (_page([_release(assets=[{**_asset(), "name": 5}])]), "'name' has the wrong type"),
        (_page([_release(assets=[_asset(digest=5)])]), "'digest' has the wrong type"),
        (_page([_release(assets=[{"name": "a"}])]), "lacks 'state'"),
    ],
)
def test_malformed_responses_fail_the_whole_listing(response: Response, fragment: str) -> None:
    assert fragment in str(_error(response))


def test_huge_number_in_json_fails_closed() -> None:
    assert "not valid JSON" in str(_error(_page(b'[{"size": ' + b"9" * 5000 + b"}]")))


def test_drafts_are_skipped() -> None:
    result = _listing(_page([_release("v1.0.0", draft=True), _release("v1.1.0")]))
    assert [release.tag for release in result.releases] == ["v1.1.0"]


@pytest.mark.parametrize(
    ("tag", "kind"),
    [("v1.2.3", "final"), ("v10.20.30", "final"), ("v1.2.3-rc1", "prerelease")],
)
def test_supported_tag_shapes_are_classified(tag: str, kind: str) -> None:
    result = _listing(_page([_release(tag)]))
    assert [(release.tag, release.kind) for release in result.releases] == [(tag, kind)]


@pytest.mark.parametrize(
    "tag",
    [
        "v0.1.1+resvg.0.48.1",
        "latest",
        "1.2.3",
        "v1.2",
        "v1.2.3\n",
        "v1.2.3-RC1",
        "v1.2.3-1",
        "../x",
    ],
)
def test_other_tags_are_ignored_and_never_reach_a_url(tag: str) -> None:
    result = _listing(_page([_release(tag, assets=[_asset(tag="v9.9.9")]), _release("v1.0.0")]))
    assert [release.tag for release in result.releases] == ["v1.0.0"]
    assert result.ignored == (ascii(tag),)
    assert result.rejected == ()


def test_ignored_tag_text_is_escaped_and_bounded() -> None:
    result = _listing(_page([_release("x\x1b[31m" + "y" * 200)]))
    assert len(result.ignored[0]) == 80
    assert "\x1b" not in result.ignored[0]


def test_attacker_text_in_messages_is_bounded() -> None:
    body = b'[{"' + b"k" * 500 + b'": 1, "' + b"k" * 500 + b'": 2}]'
    assert len(str(_error(_page(body)))) < 200
    long_tag = "v1.2.3" + "0" * 100
    result = _listing(_page([_release(long_tag)]))
    assert result.releases == ()
    assert result.ignored == (ascii(long_tag)[:80],)
    for name in ("a" * 129, "a" * 200000):
        result = _listing(_page([_release("v1.0.0", assets=[_asset(name=name)])]))
        assert [rejection.tag for rejection in result.rejected] == ["v1.0.0"]
        assert len(result.rejected[0].reason) < 120


@pytest.mark.parametrize(
    ("asset", "reason"),
    [
        (_asset(name="../x"), "asset name '../x' is not allowed"),
        (_asset(name=".hidden"), "asset name '.hidden' is not allowed"),
        (_asset(name="a b"), "asset name 'a b' is not allowed"),
        (_asset(name="a/b"), "asset name 'a/b' is not allowed"),
        (_asset(name="é.deb"), "asset name '\\xe9.deb' is not allowed"),
        (_asset(name="a..b"), "asset name 'a..b' is not allowed"),
        (_asset(name="a.deb", state="starter"), "asset a.deb is not fully uploaded"),
        (_asset(name="a.deb", size=-1), "asset a.deb has a negative size"),
        (_asset(name="a.deb", digest="sha1:abc"), "asset a.deb has a malformed digest"),
        (_asset(name="a.deb", digest="sha256:" + "A" * 64), "asset a.deb has a malformed digest"),
        (
            _asset(
                browser_download_url="https://github.com/FojleRabbiRabib/other/releases/download/v1.0.0/a.deb"
            ),
            "asset a.deb has an unexpected download URL",
        ),
        (
            _asset(
                browser_download_url="https://github.com/FojleRabbiRabib/p-php/releases/download/v2.0.0/a.deb"
            ),
            "asset a.deb has an unexpected download URL",
        ),
        (
            _asset(
                browser_download_url="https://github.com/Someone/p-php/releases/download/v1.0.0/a.deb"
            ),
            "asset a.deb has an unexpected download URL",
        ),
        (
            _asset(
                browser_download_url="http://github.com/FojleRabbiRabib/p-php/releases/download/v1.0.0/a.deb"
            ),
            "asset a.deb has an unexpected download URL",
        ),
    ],
)
def test_a_bad_asset_rejects_only_its_release(asset: dict[str, Any], reason: str) -> None:
    result = _listing(_page([_release("v1.0.0", assets=[asset]), _release("v1.1.0")]))
    assert result.rejected == (Rejection(tag="v1.0.0", reason=reason),)
    assert [release.tag for release in result.releases] == ["v1.1.0"]


def test_duplicate_asset_names_reject_the_release() -> None:
    result = _listing(_page([_release(assets=[_asset("a.deb"), _asset("a.deb")])]))
    assert result.rejected == (Rejection(tag="v1.0.0", reason="two assets share a name"),)


def test_a_tag_listed_twice_fails_the_listing() -> None:
    first = _page([_release("v1.0.0")], link=f'<{NEXT_URL}>; rel="next"')
    assert "tag v1.0.0 is listed twice" in str(_error(first, _page([_release("v1.0.0")])))


def test_immutable_is_surfaced_and_defaults_to_false() -> None:
    absent = _release("v1.1.0")
    del absent["immutable"]
    result = _listing(_page([_release("v1.0.0"), absent, _release("v1.2.0", immutable=False)]))
    assert [(r.tag, r.immutable) for r in result.releases] == [
        ("v1.0.0", True),
        ("v1.1.0", False),
        ("v1.2.0", False),
    ]


def test_missing_digest_is_allowed() -> None:
    result = _listing(_page([_release(assets=[_asset(digest=None)])]))
    assert result.releases[0].assets[0].digest is None


def test_listing_without_an_etag_header() -> None:
    assert _listing(_page([])).etag is None
    assert _listing(_page([], etag="not an etag")).etag is None


@pytest.mark.parametrize("repo", ["", "A-php", "a/b", "..", "a..b", "-x", "a b"])
def test_invalid_repo_never_reaches_the_network(repo: str) -> None:
    fake = Fake()
    with pytest.raises(FeedError, match="invalid repo name"):
        feed.list_releases(repo, fake)
    assert fake.calls == []


@pytest.mark.parametrize("etag", ["abc", '"a"\r\nX: y', 'W/"a" extra', ""])
def test_malformed_etag_is_refused(etag: str) -> None:
    fake = Fake()
    with pytest.raises(FeedError, match="etag is malformed"):
        feed.list_releases("p-php", fake, etag=etag)
    assert fake.calls == []


def test_release_record_is_complete() -> None:
    result = _listing(_page([_release("v1.0.0", assets=[_asset("a.deb")])]))
    assert result.releases == (
        Release(
            tag="v1.0.0",
            kind="final",
            immutable=True,
            assets=(
                Asset(
                    name="a.deb",
                    size=10,
                    digest=DIGEST,
                    url="https://github.com/FojleRabbiRabib/p-php/releases/download/v1.0.0/a.deb",
                ),
            ),
        ),
    )


# ---- token file ----------------------------------------------------------------------------


def _token_file(tmp_path: Path, content: bytes, mode: int = 0o600) -> Path:
    path = tmp_path / "token"
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_token_is_read_and_one_newline_removed(tmp_path: Path) -> None:
    assert feed.read_token(_token_file(tmp_path, b"tok_AbC-123_x\n")) == "tok_AbC-123_x"
    assert feed.read_token(_token_file(tmp_path, b"tok_pat_x")) == "tok_pat_x"


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666])
def test_token_file_must_be_private(tmp_path: Path, mode: int) -> None:
    with pytest.raises(FeedError, match="must not be accessible"):
        feed.read_token(_token_file(tmp_path, b"tok_x", mode))


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\n",
        b"a b",
        b"a\nb",
        b"tok\r\n",
        b"tok\n\n",
        b"tok\x00",
        "tök".encode(),
        b" tok",
        b"a" * 513,
    ],
)
def test_token_content_cannot_inject_headers(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(FeedError, match="does not hold a single token"):
        feed.read_token(_token_file(tmp_path, content))


def test_oversized_and_unreadable_token_files_fail(tmp_path: Path) -> None:
    with pytest.raises(FeedError, match="too large"):
        feed.read_token(_token_file(tmp_path, b"a" * 5000))
    with pytest.raises(FeedError, match="cannot read token file"):
        feed.read_token(tmp_path / "missing")
    with pytest.raises(FeedError, match="cannot read token file"):
        feed.read_token(tmp_path)


def test_token_fifo_cannot_hang_the_reader(tmp_path: Path) -> None:
    fifo = tmp_path / "token"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(FeedError, match="not a regular file"):
        feed.read_token(fifo)


# ---- real transport against local servers ---------------------------------------------------


class _Local(HttpsTransport):
    """The production transport, pointed at plain-http loopback servers for the tests."""

    _SCHEMES = ("http://",)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [*super()._handlers(), urllib.request.HTTPHandler()]


@contextmanager
def _raw_server(payload: bytes) -> Iterator[str]:
    """Answer one connection with raw bytes, to produce malformed HTTP."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.recv(65536)
            connection.sendall(payload)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        listener.close()
        thread.join()


@contextmanager
def _server(
    handler: Callable[[BaseHTTPRequestHandler], None],
) -> Iterator[tuple[str, list[dict[str, str]]]]:
    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append({key.lower(): value for key, value in self.headers.items()})
            handler(self)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _reply(
    status: int, body: bytes = b"", **headers: str
) -> Callable[[BaseHTTPRequestHandler], None]:
    def respond(request: BaseHTTPRequestHandler) -> None:
        request.send_response(status)
        for key, value in headers.items():
            request.send_header(key.replace("_", "-"), value)
        request.send_header("Content-Length", str(len(body)))
        request.end_headers()
        request.wfile.write(body)

    return respond


def test_transport_returns_status_lowercase_headers_and_body() -> None:
    with _server(_reply(200, b"[]", Content_Type="application/json", ETag='"e"')) as (base, seen):
        response = _Local("tok")(base + "/x", {"Accept": "a", "User-Agent": "ua"})
    assert response.status == 200
    assert response.body == b"[]"
    assert response.headers["etag"] == '"e"'
    assert response.headers["content-type"] == "application/json"
    assert seen[0]["authorization"] == "Bearer tok"
    assert seen[0]["accept"] == "a"
    assert seen[0]["user-agent"] == "ua"


def test_transport_without_a_token_sends_no_authorization() -> None:
    with _server(_reply(200)) as (base, seen):
        _Local()(base + "/x", {})
    assert "authorization" not in seen[0]


def test_transport_reports_304_and_error_statuses_without_raising() -> None:
    with _server(_reply(304)) as (base, _):
        assert _Local("tok")(base + "/x", {}).status == 304
    with _server(_reply(404, b"nope")) as (base, _):
        response = _Local("tok")(base + "/x", {})
    assert (response.status, response.body) == (404, b"nope")


def test_transport_never_follows_a_redirect_or_forwards_the_token() -> None:
    with (
        _server(_reply(200, b"stolen")) as (target, target_seen),
        _server(_reply(302, Location=target + "/steal")) as (base, seen),
    ):
        response = _Local("tok")(base + "/x", {})
    assert response.status == 302
    assert seen[0]["authorization"] == "Bearer tok"
    assert target_seen == []


def test_transport_enforces_the_body_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feed, "MAX_BODY_BYTES", 10)
    with _server(_reply(200, b"x" * 10)) as (base, _):
        assert _Local()(base + "/x", {}).body == b"x" * 10
    with _server(_reply(200, b"x" * 11)) as (base, _), pytest.raises(FeedError, match="larger"):
        _Local()(base + "/x", {})


def test_transport_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feed, "TIMEOUT_SECONDS", 0.2)

    def slow(request: BaseHTTPRequestHandler) -> None:
        time.sleep(1.0)
        _reply(200)(request)

    with _server(slow) as (base, _), pytest.raises(FeedError, match="request failed"):
        _Local()(base + "/x", {})


def test_transport_stops_a_slow_drip_at_the_request_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(feed, "TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(feed, "REQUEST_DEADLINE_SECONDS", 0.5)

    def drip(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Content-Length", "1000")
        request.end_headers()
        try:
            for _ in range(1000):
                request.wfile.write(b"x")
                request.wfile.flush()
                time.sleep(0.1)
        except OSError:
            return

    started = time.monotonic()
    with _server(drip) as (base, _), pytest.raises(FeedError, match="took too long"):
        _Local()(base + "/x", {})
    assert time.monotonic() - started < 5.0


def test_transport_failures_never_leak_the_token() -> None:
    with _server(_reply(200)) as (base, _):
        pass
    with pytest.raises(FeedError) as caught:
        _Local("secrettoken")(base + "/x", {})
    assert "secrettoken" not in str(caught.value)
    assert "request failed" in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        b"garbage\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
    ],
    ids=["bad-status-line", "truncated-chunked-body"],
)
def test_malformed_http_is_reported_as_a_feed_error(payload: bytes) -> None:
    with _raw_server(payload) as base, pytest.raises(FeedError, match="request failed"):
        _Local("secrettoken")(base + "/x", {})


def test_control_character_in_a_url_is_a_feed_error() -> None:
    with pytest.raises(FeedError, match="request failed"):
        _Local()("http://127.0.0.1:1/x\x00y", {})


def test_repeated_security_headers_are_refused() -> None:
    def two_links(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Link", f'<{NEXT_URL}>; rel="next"')
        request.send_header("Link", f'<{NEXT_URL}>; rel="prev"')
        request.send_header("Content-Length", "0")
        request.end_headers()

    with _server(two_links) as (base, _), pytest.raises(FeedError, match="repeats the link header"):
        _Local()(base + "/x", {})


@pytest.mark.parametrize(
    "url",
    ["file:///etc/hostname", "ftp://127.0.0.1/x", "data:text/plain,x", "http://127.0.0.1:1/x"],
)
def test_production_transport_speaks_only_https_and_never_sends_the_token_in_clear(
    url: str,
) -> None:
    with pytest.raises(FeedError, match="only https URLs are allowed"):
        HttpsTransport("tok")(url, {})


def test_transport_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    with _server(_reply(200, b"ok")) as (base, _):
        assert _Local()(base + "/x", {}).body == b"ok"
