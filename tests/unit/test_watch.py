# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import datetime
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from servers import local_server, raw_server, reply

from publisher import alert, watch
from publisher.alert import Alert
from publisher.watch import (
    Public,
    WatchError,
    certificate_alerts,
    certificate_expiry,
    release_dates,
    served_alerts,
    token_alerts,
)

NOW = 1_800_000_000.0
DAY = 86400.0
FORMAT = watch.RELEASE_DATE_FORMAT


def _stamp(seconds: float) -> str:
    moment = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return moment.strftime(FORMAT)


def _release(issued: float, until: float, *, extra: str = "") -> bytes:
    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        f"Origin: x\nDate: {_stamp(issued)}\nValid-Until: {_stamp(until)}\n{extra}"
        "SHA256:\n abc 1 main/Packages\n"
        "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n"
    ).encode("ascii")


def _kinds(alerts: list[Alert]) -> list[str]:
    return [a.kind for a in alerts]


class _Local(Public):
    _SCHEMES = ("http://",)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [*super()._handlers(), urllib.request.HTTPHandler()]


# --- the token -------------------------------------------------------------------------------


def _date_after(days: float) -> datetime.date:
    return datetime.datetime.fromtimestamp(NOW + days * DAY, tz=datetime.timezone.utc).date()


def test_a_token_with_plenty_of_time_is_quiet() -> None:
    assert token_alerts(_date_after(90), NOW) == []


def test_a_token_expiring_soon_alerts_once_a_day_and_urgently() -> None:
    (item,) = token_alerts(_date_after(10), NOW)
    assert item.kind == "token-expiring"
    assert item.urgent
    assert item.key == "token-expiring"
    assert "expires in" in item.text


def test_the_token_is_valid_through_the_end_of_its_date() -> None:
    today = datetime.datetime.fromtimestamp(NOW, tz=datetime.timezone.utc).date()
    (item,) = token_alerts(today, NOW)
    assert "expires in" in item.text  # still valid today
    (gone,) = token_alerts(today - datetime.timedelta(days=1), NOW)
    assert "has expired" in gone.text


def test_the_token_warning_starts_at_thirty_days() -> None:
    end = datetime.datetime.combine(
        _date_after(30) + datetime.timedelta(days=1),
        datetime.time(),
        tzinfo=datetime.timezone.utc,
    ).timestamp()
    assert token_alerts(_date_after(30), end - 30 * DAY + 1)
    assert token_alerts(_date_after(30), end - 30 * DAY) == []


# --- the served InRelease --------------------------------------------------------------------


def test_the_dates_of_a_signed_release_are_read() -> None:
    assert release_dates(_release(NOW, NOW + 14 * DAY)) == (NOW, NOW + 14 * DAY)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<html>blocked</html>",
        b"-----BEGIN PGP SIGNED MESSAGE-----\nDate: Mon, 01 Jan 2024 00:00:00 UTC\n",
        _release(NOW, NOW).replace(b"Date:", b"Data:"),
        _release(NOW, NOW).replace(b"Valid-Until:", b"Valid-Til:"),
        _release(NOW, NOW).replace(_stamp(NOW).encode(), b"yesterday", 1),
        _release(NOW, NOW, extra=f"Date: {_stamp(NOW)}\n"),
        _release(NOW, NOW).replace(b"Origin: x", "Origin: \xe9".encode("latin-1")),
    ],
)
def test_an_unreadable_release_is_refused(body: bytes) -> None:
    with pytest.raises(WatchError):
        release_dates(body)


def test_a_date_inside_the_hash_lists_is_not_a_header() -> None:
    body = _release(NOW, NOW + 14 * DAY).replace(b" abc 1 main", b" Date: whatever\n abc 1 main")
    assert release_dates(body) == (NOW, NOW + 14 * DAY)


def test_a_fresh_release_is_quiet() -> None:
    assert served_alerts(lambda: _release(NOW - DAY, NOW + 13 * DAY), NOW) == []


def test_the_served_date_alerts_after_three_days() -> None:
    assert served_alerts(lambda: _release(NOW - 3 * DAY + 60, NOW + 13 * DAY), NOW) == []
    (item,) = served_alerts(lambda: _release(NOW - 3 * DAY - 60, NOW + 13 * DAY), NOW)
    assert (item.kind, item.urgent, item.key) == ("served-stale", True, "served-date")


def test_a_date_in_the_future_alerts() -> None:
    assert served_alerts(lambda: _release(NOW + 1800, NOW + 14 * DAY), NOW) == []
    (item,) = served_alerts(lambda: _release(NOW + 7200, NOW + 14 * DAY), NOW)
    assert item.kind == "served-date-future"


def test_valid_until_alerts_under_seven_days() -> None:
    assert served_alerts(lambda: _release(NOW, NOW + 7 * DAY), NOW) == []
    (item,) = served_alerts(lambda: _release(NOW, NOW + 7 * DAY - 60), NOW)
    assert (item.kind, item.key) == ("valid-until-low", "valid-until")


def test_an_expired_valid_until_and_a_stale_date_both_alert() -> None:
    items = served_alerts(lambda: _release(NOW - 20 * DAY, NOW - 6 * DAY), NOW)
    assert _kinds(items) == ["served-stale", "valid-until-low"]
    assert "0.0 days" in items[1].text


def test_an_unreadable_or_unreachable_release_alerts_instead_of_raising() -> None:
    def broken() -> bytes:
        raise WatchError("the public site answered 403")

    (item,) = served_alerts(broken, NOW)
    assert (item.kind, item.urgent, item.key) == ("served-unreadable", True, "served")
    assert "403" in item.text


# --- fetching --------------------------------------------------------------------------------


def test_the_release_is_fetched_with_a_plain_get() -> None:
    body = _release(NOW, NOW + 14 * DAY)
    with local_server(reply(200, body)) as (base, seen):
        assert _Local(base).get("/apt/dists/stable/InRelease") == body
    assert len(seen) == 1
    assert seen[0]["user-agent"] == "php-pkg-publisher"


@pytest.mark.parametrize("status", [403, 404, 500, 503])
def test_an_error_status_is_a_watch_error(status: int) -> None:
    with (
        local_server(reply(status, b"nope")) as (base, _),
        pytest.raises(WatchError, match=str(status)),
    ):
        _Local(base).get("/x")


def test_a_redirect_is_not_followed() -> None:
    with (
        local_server(reply(302, b"", Location="http://127.0.0.1:1/x")) as (base, _),
        pytest.raises(WatchError, match="302"),
    ):
        _Local(base).get("/x")


def test_an_oversized_file_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(watch, "MAX_RELEASE_BYTES", 100)
    with (
        local_server(reply(200, b"x" * 200)) as (base, _),
        pytest.raises(WatchError, match="larger"),
    ):
        _Local(base).get("/x")


def test_garbled_http_and_a_refused_connection_are_watch_errors() -> None:
    with (
        raw_server(b"not http at all\r\n\r\n") as base,
        pytest.raises(WatchError, match="cannot reach"),
    ):
        _Local(base).get("/x")
    with pytest.raises(WatchError, match="cannot reach"):
        _Local("http://127.0.0.1:1").get("/x")


def test_the_real_fetcher_only_speaks_https() -> None:
    with pytest.raises(WatchError, match="only https"):
        Public("http://127.0.0.1:1").get("/x")


# --- the origin certificate ------------------------------------------------------------------


def test_a_certificate_far_from_expiry_is_quiet() -> None:
    assert certificate_alerts(lambda: NOW + 60 * DAY, NOW) == []


def test_a_certificate_alerts_under_twenty_one_days() -> None:
    assert certificate_alerts(lambda: NOW + 21 * DAY, NOW) == []
    (item,) = certificate_alerts(lambda: NOW + 21 * DAY - 60, NOW)
    assert (item.kind, item.urgent, item.key) == ("origin-certificate", True, "origin-cert")
    (gone,) = certificate_alerts(lambda: NOW - DAY, NOW)
    assert "has expired" in gone.text


def test_an_unreachable_origin_alerts_instead_of_raising() -> None:
    def broken() -> float:
        raise WatchError("cannot reach the origin (TimeoutError)")

    (item,) = certificate_alerts(broken, NOW)
    assert "cannot reach" in item.text


@contextmanager
def _tls_server(tmp_path: Path, host: str, days: int) -> Iterator[tuple[int, ssl.SSLContext]]:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(  # noqa: S603
        [
            str(shutil.which("openssl")),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            str(days),
            "-subj",
            f"/CN={host}",
            "-addext",
            f"subjectAltName=DNS:{host}",
        ],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(5)

    def serve() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                with server_context.wrap_socket(connection, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], client_context
    finally:
        listener.close()
        thread.join()


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl tool")
def test_the_expiry_of_a_verified_origin_certificate_is_read(tmp_path: Path) -> None:
    with _tls_server(tmp_path, "pkg.example.org", 40) as (port, context):
        expiry = certificate_expiry("pkg.example.org", "127.0.0.1", port=port, context=context)
    left = (expiry - datetime.datetime.now(tz=datetime.timezone.utc).timestamp()) / DAY
    assert 39 < left < 41


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl tool")
def test_a_certificate_for_another_name_is_a_watch_error(tmp_path: Path) -> None:
    with (
        _tls_server(tmp_path, "other.example.org", 40) as (port, context),
        pytest.raises(WatchError, match=r"does not verify: .*Hostname mismatch"),
    ):
        certificate_expiry("pkg.example.org", "127.0.0.1", port=port, context=context)


def test_a_refused_origin_connection_is_a_watch_error() -> None:
    with pytest.raises(WatchError, match="cannot reach the origin"):
        certificate_expiry("pkg.example.org", "127.0.0.1", port=1)


# --- the command -----------------------------------------------------------------------------


def _settings_file(tmp_path: Path, expires: str) -> Path:
    text = (
        f"products: {tmp_path}/products.yml\nexclude: {tmp_path}/exclude.yml\n"
        + "".join(f"{n}: {tmp_path}/{n}\n" for n in ("site", "state", "cache", "trust", "work"))
        + f"lock: {tmp_path}/lock\nnudge: {tmp_path}/nudge/sync\nrpm_key: {tmp_path}/k.asc\n"
        f'token: {{file: {tmp_path}/t, expires: "{expires}"}}\n'
        f"alert: {{file: {tmp_path}/a}}\n"
        "watch: {host: pkg.example.org, origin: 93.184.216.34}\n"
        f"signing: {{home: {tmp_path}/g, fingerprint: {'A' * 40}, "
        f"certificate: {tmp_path}/c, primary: {'B' * 40}}}\n"
    )
    path = tmp_path / "publisher.yml"
    path.write_text(text, encoding="utf-8")
    return path


class _Sent:
    def __init__(self) -> None:
        self.texts: list[str] = []

    def send(self, text: str, *, silent: bool) -> None:
        self.texts.append(text)


def _patch_world(
    monkeypatch: pytest.MonkeyPatch, sent: _Sent, *, cert_days: float, release: bytes
) -> None:
    monkeypatch.setattr(watch, "certificate_expiry", lambda *a, **k: time_now() + cert_days * DAY)
    monkeypatch.setattr(Public, "get", lambda self, path: release)
    monkeypatch.setattr(alert, "read_credentials", lambda path: object())
    monkeypatch.setattr(alert, "Telegram", lambda credentials: sent)


def time_now() -> float:
    return time.time()


def test_a_healthy_pass_sends_nothing_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _Sent()
    now = time_now()
    _patch_world(monkeypatch, sent, cert_days=60, release=_release(now, now + 14 * DAY))
    config = _settings_file(tmp_path, "2099-01-01")
    (tmp_path / "state").mkdir()
    assert watch.main(["--config", str(config)]) == 0
    assert sent.texts == []
    assert capsys.readouterr().err == ""


def test_a_failing_check_is_logged_sent_once_and_remembered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _Sent()
    now = time_now()
    _patch_world(monkeypatch, sent, cert_days=5, release=_release(now - 5 * DAY, now + 2 * DAY))
    config = _settings_file(tmp_path, "2000-01-01")
    (tmp_path / "state").mkdir()
    assert watch.main(["--config", str(config)]) == 0
    assert len(sent.texts) == 1
    for word in ("token", "certificate", "Date", "Valid-Until"):
        assert word in sent.texts[0]
    assert "alert origin-certificate" in capsys.readouterr().err
    memory = json.loads((tmp_path / "state" / "watch-alerts.json").read_text())
    assert set(memory) == {"token-expiring", "origin-cert", "served-date", "valid-until"}
    assert watch.main(["--config", str(config)]) == 0
    assert len(sent.texts) == 1  # the same alerts are not repeated within a day


def test_a_broken_settings_file_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "publisher.yml").write_text("site: /x\n", encoding="utf-8")
    assert watch.main(["--config", str(tmp_path / "publisher.yml")]) == 1
    assert "failed:" in capsys.readouterr().err


def test_unusable_credentials_exit_one_even_when_all_is_well(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    now = time_now()
    monkeypatch.setattr(watch, "certificate_expiry", lambda *a, **k: now + 60 * DAY)
    monkeypatch.setattr(Public, "get", lambda self, path: _release(now, now + 14 * DAY))
    config = _settings_file(tmp_path, "2099-01-01")
    (tmp_path / "state").mkdir()
    assert watch.main(["--config", str(config)]) == 1
    assert "failed:" in capsys.readouterr().err


def test_the_watch_imports_no_publish_module() -> None:
    code = (
        "import sys, publisher.watch;"
        "bad = [m for m in sys.modules if m.startswith('publisher.') and m not in "
        "('publisher.watch','publisher.alert','publisher.files','publisher.net',"
        "'publisher.config','publisher.settings')];"
        "print(bad)"
    )
    root = Path(__file__).resolve().parents[2]
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    assert out.stdout.strip() == "[]"
