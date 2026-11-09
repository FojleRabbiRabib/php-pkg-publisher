# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The webhook receiver, run through a PHP harness: one fixed status per rule, nothing else."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "php" / "harness.php"
SECRET = "a-shared-secret-of-enough-length"  # noqa: S105
GUID = "11111111-2222-3333-4444-555555555555"
NOW = 1_800_000_000
BODY = json.dumps({"action": "published", "release": {"tag_name": "v1.0.0"}})

pytestmark = pytest.mark.skipif(shutil.which("php") is None, reason="needs the php command")


def _sign(body: str, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


class World:
    def __init__(self, root: Path) -> None:
        self.nudge_dir = root / "nudge"
        self.secret_file = root / "secret"
        self.secret_file.write_text(SECRET + "\n", encoding="utf-8")
        self.nudge_dir.mkdir()

    @property
    def nudge(self) -> Path:
        return self.nudge_dir / "sync"

    def post(self, **changes: Any) -> int:
        body = changes.get("body", BODY)
        case: dict[str, Any] = {
            "nudge_dir": str(self.nudge_dir),
            "secret_file": str(self.secret_file),
            "method": "POST",
            "address": "198.51.100.9",
            "content_length": str(len(body.encode())),
            "signature": _sign(body),
            "event": "release",
            "delivery": GUID,
            "body": body,
            "now": NOW,
        }
        case.update(changes)
        out = subprocess.run(  # noqa: S603
            [str(shutil.which("php")), str(HARNESS)],
            input=json.dumps(case),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env={"PATH": os.environ["PATH"]},
        )
        assert out.stderr == ""
        return int(out.stdout)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_a_signed_published_release_touches_the_nudge(world: World) -> None:
    assert world.post() == 202
    assert world.nudge.is_file()


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "HEAD", "", "post"])
def test_only_post_is_accepted(world: World, method: str) -> None:
    assert world.post(method=method) == 405
    assert not world.nudge.exists()


@pytest.mark.parametrize(
    "signature",
    [
        None,
        "",
        "sha256=",
        "sha1=" + "0" * 40,
        "sha256=" + "0" * 64,
        "sha256=" + "A" * 64,
        _sign(BODY).upper(),
        _sign(BODY) + "0",
        _sign(BODY, "another-secret-of-enough-length"),
        _sign(BODY + " "),
    ],
)
def test_a_bad_signature_is_401_and_changes_nothing(world: World, signature: str | None) -> None:
    assert world.post(signature=signature) == 401
    assert not world.nudge.exists()
    assert not (world.nudge_dir / "guid").exists() or not list((world.nudge_dir / "guid").iterdir())


def test_authentication_comes_before_the_event(world: World) -> None:
    assert world.post(event="ping", signature=None) == 401


@pytest.mark.parametrize("event", ["ping", "push", "issues", "Release", None, ""])
def test_other_events_are_answered_and_ignored(world: World, event: str | None) -> None:
    assert world.post(event=event) == 200
    assert not world.nudge.exists()


@pytest.mark.parametrize("action", ["created", "edited", "prereleased", "released", "", None])
def test_only_the_published_action_nudges(world: World, action: str | None) -> None:
    body = json.dumps({"action": action})
    assert world.post(body=body, signature=_sign(body)) == 200
    assert not world.nudge.exists()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("not json", 400),
        ("", 400),
        ("[]", 200),
        ('"published"', 400),
        ("123", 400),
        ("[" * 40, 400),
    ],
)
def test_a_signed_body_that_is_not_a_payload_gets_its_exact_status(
    world: World, body: str, expected: int
) -> None:
    assert world.post(body=body, signature=_sign(body)) == expected
    assert not world.nudge.exists()


def test_unparseable_signed_json_is_400(world: World) -> None:
    assert world.post(body="{oops", signature=_sign("{oops")) == 400


@pytest.mark.parametrize("length", [None, "", "abc", "-1", "1.5", "1048577", "99999999999", " 5"])
def test_content_length_must_be_present_and_within_the_cap(
    world: World, length: str | None
) -> None:
    assert world.post(content_length=length) == 413
    assert not world.nudge.exists()


def test_a_body_over_the_cap_is_413_even_with_a_small_declared_length(world: World) -> None:
    body = "x" * (1048576 + 10)
    assert world.post(body=body, signature=_sign(body), content_length="10") == 413


def test_a_body_exactly_at_the_cap_is_read(world: World) -> None:
    padding = "x" * (1048576 - len(BODY) - 20)
    body = json.dumps({"action": "published", "pad": padding})
    body = body + " " * (1048576 - len(body))
    assert len(body) == 1048576
    assert world.post(body=body, signature=_sign(body), content_length="1048576") == 202


@pytest.mark.parametrize("delivery", [None, "", "short", "g" * 36, GUID + "0", "../" + GUID[3:]])
def test_a_published_release_needs_a_guid_shaped_delivery_id(
    world: World, delivery: str | None
) -> None:
    assert world.post(delivery=delivery) == 400
    assert not world.nudge.exists()


def test_a_repeated_delivery_is_answered_200_and_nudges_only_once(world: World) -> None:
    assert world.post() == 202
    world.nudge.unlink()
    assert world.post(now=NOW + 30) == 200
    assert world.post(delivery=GUID.upper(), now=NOW + 60) == 200
    assert not world.nudge.exists()


def test_a_redelivery_after_the_window_nudges_again(world: World) -> None:
    assert world.post() == 202
    world.nudge.unlink()
    assert world.post(now=NOW + 121) == 202
    assert world.nudge.is_file()


def test_a_new_delivery_is_not_a_duplicate(world: World) -> None:
    assert world.post() == 202
    assert world.post(delivery=GUID[:-1] + "6", now=NOW + 1) == 202


def test_an_existing_nudge_is_success(world: World) -> None:
    world.nudge.write_text("", encoding="utf-8")
    assert world.post() == 202


def test_a_failed_nudge_is_not_remembered_so_the_redelivery_works(world: World) -> None:
    world.nudge.mkdir()  # cannot be opened as a file
    assert world.post() == 500
    world.nudge.rmdir()
    assert world.post(now=NOW + 5) == 202


@pytest.mark.parametrize("content", [None, "", "short\n", "x" * 15])
def test_a_missing_or_weak_secret_is_a_500(world: World, content: str | None) -> None:
    if content is None:
        world.secret_file.unlink()
    else:
        world.secret_file.write_text(content, encoding="utf-8")
    assert world.post() == 500
    assert not world.nudge.exists()


def test_a_secret_without_a_trailing_newline_works(world: World) -> None:
    world.secret_file.write_text(SECRET, encoding="utf-8")
    assert world.post() == 202


def test_an_address_over_the_limit_is_429_before_anything_else(world: World) -> None:
    for i in range(20):
        assert world.post(signature=None, now=NOW + i) == 401
    assert world.post(signature=None, now=NOW + 21) == 429
    assert world.post(now=NOW + 22) == 429  # even a good request
    assert not world.nudge.exists()
    assert world.post(address="203.0.113.5", now=NOW + 22) == 202  # another address


def test_the_limit_resets_after_the_window(world: World) -> None:
    for _ in range(21):
        world.post(signature=None)
    assert world.post(signature=None, now=NOW + 59) == 429
    assert world.post(signature=None, now=NOW + 60) == 401


def test_a_get_is_not_counted(world: World) -> None:
    for _ in range(25):
        assert world.post(method="GET") == 405
    assert world.post() == 202


def test_a_full_throttle_table_stops_recording_but_still_authenticates(world: World) -> None:
    thr = world.nudge_dir / "thr"
    thr.mkdir()
    for i in range(1001):
        (thr / f"{i:064x}").write_text("0 1", encoding="utf-8")
    now = max(p.stat().st_mtime for p in thr.iterdir())
    for _ in range(25):
        assert world.post(signature=None, now=int(now)) == 401
    assert len(list(thr.iterdir())) == 1001
    assert world.post(now=int(now)) == 202


def test_a_full_guid_table_answers_429_without_writing(world: World) -> None:
    guid = world.nudge_dir / "guid"
    guid.mkdir()
    for i in range(1001):
        (guid / f"{i:064x}").write_text("", encoding="utf-8")
    now = int(max(p.stat().st_mtime for p in guid.iterdir()))
    assert world.post(now=now) == 429
    assert not world.nudge.exists()
    assert len(list(guid.iterdir())) == 1001


def test_old_entries_are_removed_twenty_at_a_time(world: World) -> None:
    for name, window in (("thr", 60), ("guid", 120)):
        directory = world.nudge_dir / name
        directory.mkdir()
        for i in range(30):
            entry = directory / f"{i:064x}"
            entry.write_text("", encoding="utf-8")
            os.utime(entry, (NOW - window - 1, NOW - window - 1))
    world.post(method="GET")
    assert world.post(signature=None) == 401
    for name in ("thr", "guid"):
        left = [p for p in (world.nudge_dir / name).iterdir() if p.stat().st_mtime < NOW - 59]
        assert len(left) == 10


def test_a_missing_nudge_directory_is_a_500_and_is_not_created(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.nudge_dir.rmdir()
    assert world.post() == 500
    assert not world.nudge_dir.exists()


def test_an_existing_nudge_that_cannot_be_opened_is_still_success(world: World) -> None:
    world.nudge.write_text("", encoding="utf-8")
    world.nudge.chmod(0)  # the publisher may have re-created it as its own, mode 0600
    try:
        assert world.post() == 202
    finally:
        world.nudge.chmod(0o600)


def test_a_nudge_that_is_a_link_is_not_success(world: World) -> None:
    world.nudge.symlink_to(world.nudge_dir / "elsewhere")
    assert world.post() == 500
    assert not (world.nudge_dir / "elsewhere").exists()  # nothing was created through the link


# --- the real file behind the PHP built-in server ----------------------------------------------


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, World]]:
    world = World(tmp_path)
    source = (ROOT / "web" / "hooks" / "sync.php").read_text(encoding="utf-8")
    patched = source.replace("/var/lib/php-pkg-publisher/nudge", str(world.nudge_dir)).replace(
        "/etc/php-pkg-publisher-webhook/secret", str(world.secret_file)
    )
    assert patched != source
    docroot = tmp_path / "docroot"
    docroot.mkdir()
    (docroot / "sync.php").write_text(patched, encoding="utf-8")
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603
        [str(shutil.which("php")), "-S", f"127.0.0.1:{port}", "-t", str(docroot)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.environ["PATH"]},
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        yield f"http://127.0.0.1:{port}/sync.php", world
    finally:
        process.terminate()
        process.wait(timeout=10)


def _send(
    url: str, body: str = BODY, *, method: str = "POST", **headers: str
) -> tuple[int, dict[str, str], bytes]:
    base = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(body),
        "X-GitHub-Event": "release",
        "X-GitHub-Delivery": GUID,
    }
    base.update({key.replace("_", "-"): value for key, value in headers.items()})
    request = urllib.request.Request(  # noqa: S310
        url, data=body.encode() if method == "POST" else None, headers=base, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:  # noqa: S310
            return reply.status, dict(reply.headers), reply.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, dict(error.headers), error.read()


def test_a_real_delivery_is_202_with_an_empty_body_and_no_php_banner(
    server: tuple[str, World],
) -> None:
    url, world = server
    status, headers, body = _send(url)
    assert (status, body) == (202, b"")
    assert world.nudge.is_file()
    assert "X-Powered-By" not in headers
    assert headers["Cache-Control"] == "no-store"


def test_a_real_get_is_405_and_names_post(server: tuple[str, World]) -> None:
    url, _ = server
    status, headers, body = _send(url, method="GET")
    assert (status, headers["Allow"], body) == (405, "POST", b"")


def test_a_real_bad_signature_is_401(server: tuple[str, World]) -> None:
    url, world = server
    status, _, body = _send(url, X_Hub_Signature_256="sha256=" + "0" * 64)
    assert (status, body) == (401, b"")
    assert not world.nudge.exists()


def test_the_throttle_reads_cf_connecting_ip(server: tuple[str, World]) -> None:
    url, _ = server
    for _ in range(20):
        assert _send(url, X_Hub_Signature_256="bad", CF_Connecting_IP="198.51.100.1")[0] == 401
    assert _send(url, CF_Connecting_IP="198.51.100.1")[0] == 429
    assert _send(url, CF_Connecting_IP="198.51.100.2")[0] == 202


def test_a_garbage_cf_connecting_ip_falls_back_to_the_peer(server: tuple[str, World]) -> None:
    url, _ = server
    for _ in range(20):
        assert _send(url, X_Hub_Signature_256="bad", CF_Connecting_IP="not an ip")[0] == 401
    assert _send(url, CF_Connecting_IP="also not an ip")[0] == 429


def test_a_real_oversized_body_is_413(server: tuple[str, World]) -> None:
    url, world = server
    body = "x" * (1048576 + 1)
    status, _, reply_body = _send(url, body, X_Hub_Signature_256=_sign(body))
    assert (status, reply_body) == (413, b"")
    assert not world.nudge.exists()


def test_ipv6_spellings_and_a_whole_64_share_one_throttle(world: World) -> None:
    spellings = [
        "2001:db8::1",
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "2001:db8::0001",
        "2001:db8:0:0:ffff::2",
    ]
    for i in range(20):
        assert world.post(signature=None, address=spellings[i % 5]) == 401
    assert world.post(signature=None, address="2001:db8::9") == 429
    assert world.post(signature=None, address="2001:db8:0:1::1") == 401  # another /64


def test_ipv4_is_throttled_per_address(world: World) -> None:
    for _ in range(20):
        world.post(signature=None, address="198.51.100.7")
    assert world.post(signature=None, address="198.51.100.7") == 429
    assert world.post(signature=None, address="198.51.100.8") == 401


def test_the_real_server_reads_only_the_declared_length(
    server: tuple[str, World],
) -> None:
    url, world = server
    host, port = url.removeprefix("http://").split("/")[0].split(":")
    body = b"x" * (2 * 1048576)
    head = (
        f"POST /sync.php HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\n"
        f"X-Hub-Signature-256: {_sign('x' * 10)}\r\nX-GitHub-Event: release\r\n"
        f"X-GitHub-Delivery: {GUID}\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, int(port)), timeout=10) as connection:
        connection.sendall(head + body[:10])
        reply = connection.recv(4096)
    # the 10 bytes read match the signature and are not JSON: a signed bad payload, not a 413
    assert reply.startswith(b"HTTP/1.1 400")
    assert not world.nudge.exists()
