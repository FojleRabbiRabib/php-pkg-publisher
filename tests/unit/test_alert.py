# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest
from servers import local_server, raw_server, reply

from publisher import alert, notifier
from publisher.alert import (
    Alert,
    Credentials,
    CredentialsError,
    DeliveryError,
    Dispatcher,
    Telegram,
    compose,
    read_credentials,
)

TOKEN = "123456789:AAFakeTokenFakeTokenFakeTokenFake_x-y"  # noqa: S105
CREDS = Credentials(chat_id=-1001234, token=TOKEN)


def _file(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "telegram.conf"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


GOOD = f"chat_id=-1001234\ntoken={TOKEN}\n"


class _Local(Telegram):
    _SCHEMES = ("http://",)

    def _handlers(self) -> list[urllib.request.BaseHandler]:
        return [*super()._handlers(), urllib.request.HTTPHandler()]


# --- credentials -----------------------------------------------------------------------------


def test_good_credentials_load(tmp_path: Path) -> None:
    creds = read_credentials(_file(tmp_path, GOOD))
    assert creds == Credentials(chat_id=-1001234, token=TOKEN)
    assert TOKEN not in repr(creds)


def test_order_and_missing_final_newline_are_accepted(tmp_path: Path) -> None:
    assert read_credentials(_file(tmp_path, f"token={TOKEN}\nchat_id=7")).chat_id == 7


@pytest.mark.parametrize(
    "text",
    [
        f"chat_id=1\ntoken={TOKEN}\nchat_id=2\n",
        f"chat_id=1\ntoken={TOKEN}\nextra=1\n",
        f"chat_id=1\n\ntoken={TOKEN}\n",
        f"# note\nchat_id=1\ntoken={TOKEN}\n",
        f"chat_id=1\ntoken={TOKEN}\n\n",
        f"chat_id=@channel\ntoken={TOKEN}\n",
        "chat_id=1\ntoken=nocolon\n",
        "chat_id=1\n",
        f"chat_id = 1\ntoken={TOKEN}\n",
        "",
    ],
)
def test_malformed_credentials_are_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(CredentialsError):
        read_credentials(_file(tmp_path, text))


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_credentials_must_be_private(tmp_path: Path, mode: int) -> None:
    with pytest.raises(CredentialsError, match="private"):
        read_credentials(_file(tmp_path, GOOD, mode))


def test_credentials_must_not_be_a_link_or_missing_or_huge(tmp_path: Path) -> None:
    real = _file(tmp_path, GOOD)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(CredentialsError):
        read_credentials(link)
    with pytest.raises(CredentialsError):
        read_credentials(tmp_path / "nothing")
    with pytest.raises(CredentialsError, match="too large"):
        read_credentials(_file(tmp_path, "x" * 600))


def test_credentials_must_be_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bin"
    path.write_bytes(b"\xff\xfe")
    path.chmod(0o600)
    with pytest.raises(CredentialsError, match="UTF-8"):
        read_credentials(path)


# --- the sender ------------------------------------------------------------------------------


def test_a_message_is_posted_as_plain_json() -> None:
    with local_server(reply(200, b'{"ok": true, "result": {}}')) as (base, seen):
        _Local(CREDS, base=base).send("hello", silent=True)
    request = seen[0]
    assert request[":path"] == f"/bot{TOKEN}/sendMessage"
    assert request["content-type"] == "application/json"
    assert json.loads(request[":body"]) == {
        "chat_id": -1001234,
        "text": "hello",
        "disable_notification": True,
    }


def test_the_text_is_cut_to_the_service_limit() -> None:
    with local_server(reply(200, b'{"ok": true}')) as (base, seen):
        _Local(CREDS, base=base).send("x" * 6000, silent=False)
    assert len(json.loads(seen[0][":body"])["text"]) == alert.MESSAGE_LIMIT


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (
            401,
            b'{"ok": false, "error_code": 401, "description": "Unauthorized"}',
            "401: 'Unauthorized'",
        ),
        (
            429,
            b'{"ok": false, "parameters": {"retry_after": 7}, "description": "Too Many"}',
            "retry after 7 s",
        ),
        (500, b"<html>", "answered 500"),
        (200, b'{"ok": false}', "answered 200"),
        (200, b"not json", "answered 200"),
        (200, b'{"ok": "true"}', "answered 200"),
        (200, b'{"ok": true, "ok": true}', "answered 200"),
    ],
)
def test_anything_but_an_accepted_message_is_a_delivery_error(
    status: int, body: bytes, expected: str
) -> None:
    with local_server(reply(status, body)) as (base, _), pytest.raises(DeliveryError) as caught:
        _Local(CREDS, base=base).send("x", silent=True)
    assert expected in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_a_description_that_echoes_the_token_is_scrubbed() -> None:
    body = json.dumps({"ok": False, "description": f"bad bot{TOKEN}"}).encode()
    with local_server(reply(404, body)) as (base, _), pytest.raises(DeliveryError) as caught:
        _Local(CREDS, base=base).send("x", silent=True)
    assert TOKEN not in str(caught.value)
    assert "<token>" in str(caught.value)


def test_a_refused_connection_and_a_garbled_reply_leak_no_token() -> None:
    with pytest.raises(DeliveryError) as refused:
        _Local(CREDS, base="http://127.0.0.1:1").send("x", silent=True)
    assert TOKEN not in str(refused.value)
    assert refused.value.__cause__ is None
    assert refused.value.__suppress_context__
    with raw_server(b"garbage\r\n\r\n") as base, pytest.raises(DeliveryError) as garbled:
        _Local(CREDS, base=base).send("x", silent=True)
    assert TOKEN not in str(garbled.value)


def test_a_redirect_is_not_followed() -> None:
    redirect = reply(302, b"", Location="http://127.0.0.1:1/x")
    with local_server(redirect) as (base, seen), pytest.raises(DeliveryError, match="302"):
        _Local(CREDS, base=base).send("x", silent=True)
    assert len(seen) == 1


def test_a_reply_that_is_too_large_is_refused() -> None:
    big = reply(200, b" " * (alert.MAX_REPLY_BYTES + 10))
    with local_server(big) as (base, _), pytest.raises(DeliveryError, match="larger"):
        _Local(CREDS, base=base).send("x", silent=True)


def test_the_real_sender_only_speaks_https() -> None:
    with pytest.raises(DeliveryError, match="https"):
        Telegram(CREDS, base="http://example.org").send("x", silent=True)


# --- composing one message -------------------------------------------------------------------


def test_urgent_alerts_come_first_and_make_the_message_loud() -> None:
    [(text, silent, carried)] = compose(
        [Alert(kind="published", text="g1"), Alert(kind="stopped", text="bad", urgent=True)]
    )
    assert text.splitlines() == ["!! [stopped] bad", "[published] g1"]
    assert not silent
    assert [a.kind for a in carried] == ["stopped", "published"]


def test_a_message_without_urgent_alerts_is_silent() -> None:
    [(text, silent, _)] = compose([Alert(kind="published", text="g1")])
    assert (text, silent) == ("[published] g1", True)


def test_nothing_composes_to_no_messages() -> None:
    assert compose([]) == []


def test_a_long_set_becomes_several_messages_and_nothing_is_cut() -> None:
    alerts = [Alert(kind="admit-failed", text=f"{i:03d}" + "x" * 250) for i in range(40)]
    messages = compose(alerts)
    assert len(messages) > 1
    assert all(len(text) <= alert.MESSAGE_LIMIT for text, _, _ in messages)
    assert [a for _, _, carried in messages for a in carried] == alerts


def test_a_line_that_exactly_fills_the_message_is_kept() -> None:
    first = Alert(kind="k", text="a" * (alert.MESSAGE_LIMIT - len("[k] ") - 1))
    second = Alert(kind="k", text="b")
    messages = compose([first, second])
    assert [len(carried) for _, _, carried in messages] == [1, 1]


# --- the dispatcher and its memory -----------------------------------------------------------


class _Sender:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[tuple[str, bool]] = []

    def send(self, text: str, *, silent: bool) -> None:
        if self.fail:
            raise DeliveryError("down")
        self.sent.append((text, silent))


def _dispatcher(
    tmp_path: Path, sender: _Sender
) -> tuple[Callable[[list[Alert], float], bool], list[str], Path]:
    logs: list[str] = []
    path = tmp_path / "alerts.json"
    dispatcher = Dispatcher(lambda: sender, path, log=logs.append)
    return (lambda alerts, now: dispatcher(alerts, now)), logs, path


REPEAT = Alert(kind="changed", text="p v1 differs", key="changed:p v1")
PLAIN = Alert(kind="published", text="g1")


def test_unkeyed_alerts_are_always_sent(tmp_path: Path) -> None:
    sender = _Sender()
    send, _, _ = _dispatcher(tmp_path, sender)
    assert send([PLAIN], 10.0)
    assert send([PLAIN], 11.0)
    assert len(sender.sent) == 2


def test_a_repeating_event_is_said_once_a_day(tmp_path: Path) -> None:
    sender = _Sender()
    send, _, _ = _dispatcher(tmp_path, sender)
    send([REPEAT], 0.0)
    send([REPEAT], 3600.0)
    assert len(sender.sent) == 1
    send([REPEAT], alert.REPEAT_SECONDS + 1)
    assert len(sender.sent) == 2


def test_a_key_that_did_not_occur_is_forgotten_so_a_recurrence_alerts(tmp_path: Path) -> None:
    sender = _Sender()
    send, _, _ = _dispatcher(tmp_path, sender)
    send([REPEAT], 0.0)
    send([], 100.0)
    send([REPEAT], 200.0)
    assert len(sender.sent) == 2


def test_a_failed_delivery_logs_everything_and_is_retried_next_run(tmp_path: Path) -> None:
    down = _Sender(fail=True)
    send, logs, path = _dispatcher(tmp_path, down)
    assert not send([REPEAT, PLAIN], 0.0)
    assert any("[changed] p v1 differs" in line for line in logs)
    assert any("[published] g1" in line for line in logs)
    assert json.loads(path.read_text(encoding="utf-8")) == {}
    up = _Sender()
    send2, _, _ = _dispatcher(tmp_path, up)
    assert send2([REPEAT], 10.0)
    assert len(up.sent) == 1


def test_one_message_carries_the_whole_pass(tmp_path: Path) -> None:
    sender = _Sender()
    send, _, _ = _dispatcher(tmp_path, sender)
    send([PLAIN, REPEAT], 0.0)
    assert len(sender.sent) == 1


@pytest.mark.parametrize(
    "garbage",
    [b"not json", b'{"a": 1, "a": 2}', b"[1]", b'{"k": true}', b'{"k": NaN}', b'{"k": "x"}'],
)
def test_a_damaged_memory_is_logged_and_replaced_not_fatal(tmp_path: Path, garbage: bytes) -> None:
    sender = _Sender()
    send, logs, path = _dispatcher(tmp_path, sender)
    path.write_bytes(garbage)
    assert send([REPEAT], 0.0)
    assert len(sender.sent) == 1
    assert any("memory unusable" in line for line in logs)
    assert json.loads(path.read_text(encoding="utf-8")) == {"changed:p v1": 0.0}


def test_bad_credentials_raise_instead_of_hiding(tmp_path: Path) -> None:
    def build() -> alert.Sender:
        return Telegram(read_credentials(tmp_path / "missing"))

    dispatcher = Dispatcher(build, tmp_path / "alerts.json", log=lambda _: None)
    with pytest.raises(CredentialsError):
        dispatcher([PLAIN], 0.0)


# --- the failure notifier --------------------------------------------------------------------


def _run_notifier(monkeypatch: pytest.MonkeyPatch, base: str, args: list[str]) -> int:
    monkeypatch.setattr(
        alert,
        "Telegram",
        lambda creds: _Local(creds, base=base),
    )
    return notifier.main(args)


def test_the_notifier_sends_fixed_text_and_needs_no_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = _file(tmp_path, GOOD)
    with local_server(reply(200, b'{"ok": true}')) as (base, seen):
        code = _run_notifier(
            monkeypatch, base, ["--alert-file", str(file), "--unit", "php-pkg-publisher.service"]
        )
    assert code == 0
    body = json.loads(seen[0][":body"])
    assert body["text"] == "!! [unit-failed] php-pkg-publisher.service failed, see journal"
    assert body["disable_notification"] is False


def test_the_notifier_fails_when_the_message_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    file = _file(tmp_path, GOOD)
    with local_server(reply(401, b'{"ok": false, "description": "Unauthorized"}')) as (base, _):
        code = _run_notifier(monkeypatch, base, ["--alert-file", str(file), "--unit", "a.service"])
    assert code == 1
    assert TOKEN not in capsys.readouterr().err


@pytest.mark.parametrize("unit", ["a b", "a\nb", "", "x" * 81, "a;b", "$(x)"])
def test_the_notifier_refuses_an_odd_unit_name_without_sending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unit: str
) -> None:
    file = _file(tmp_path, GOOD)
    with local_server(reply(200, b'{"ok": true}')) as (base, seen):
        code = _run_notifier(monkeypatch, base, ["--alert-file", str(file), "--unit", unit])
    assert code == 1
    assert seen == []


def test_the_notifier_imports_no_publish_module() -> None:
    code = (
        "import sys, publisher.notifier;"
        "bad = [m for m in sys.modules if m.startswith('publisher.') and m not in "
        "('publisher.notifier','publisher.alert','publisher.files','publisher.net')];"
        "print(bad)"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
    )
    assert out.stdout.strip() == "[]"


def test_a_body_that_fails_on_an_error_status_is_a_delivery_error() -> None:
    class Resetting(_Local):
        @staticmethod
        def _read(reply: object) -> bytes:
            raise ConnectionResetError(TOKEN)

    with local_server(reply(500, b"x")) as (base, _), pytest.raises(DeliveryError) as caught:
        Resetting(CREDS, base=base).send("x", silent=True)
    assert TOKEN not in str(caught.value)
    assert "ConnectionResetError" in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_an_oversized_body_on_an_error_status_drops_the_context_too() -> None:
    big = reply(500, b" " * (alert.MAX_REPLY_BYTES + 10))
    with local_server(big) as (base, _), pytest.raises(DeliveryError) as caught:
        _Local(CREDS, base=base).send("x", silent=True)
    assert "larger" in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_the_credentials_are_checked_on_a_quiet_pass_too(tmp_path: Path) -> None:
    def build() -> alert.Sender:
        return Telegram(read_credentials(tmp_path / "missing"))

    dispatcher = Dispatcher(build, tmp_path / "alerts.json", log=lambda _: None)
    with pytest.raises(CredentialsError):
        dispatcher([], 0.0)


def test_a_set_that_needs_several_messages_pauses_between_them(tmp_path: Path) -> None:
    sender = _Sender()
    pauses: list[float] = []
    dispatcher = Dispatcher(
        lambda: sender, tmp_path / "a.json", log=lambda _: None, pause=pauses.append
    )
    alerts = [Alert(kind="k", text="x" * 280) for _ in range(30)]
    assert dispatcher(alerts, 0.0)
    assert len(sender.sent) == len(pauses) + 1 >= 2
    assert set(pauses) == {alert.PAUSE_SECONDS}


def test_only_alerts_in_accepted_messages_are_remembered(tmp_path: Path) -> None:
    class Flaky(_Sender):
        def send(self, text: str, *, silent: bool) -> None:
            if self.sent:
                raise DeliveryError("down")
            super().send(text, silent=silent)

    path = tmp_path / "a.json"
    logs: list[str] = []
    dispatcher = Dispatcher(lambda: Flaky(), path, log=logs.append, pause=lambda _: None)
    first = Alert(kind="stopped", text="x" * 280, urgent=True, key="k1")
    late = [Alert(kind="changed", text="y" * 280, key=f"k{i}") for i in range(2, 30)]
    assert not dispatcher([first, *late], 5.0)
    remembered = json.loads(path.read_text(encoding="utf-8"))
    assert "k1" in remembered
    assert "k29" not in remembered
    assert any("[changed]" in line and "undelivered" in line for line in logs)


def test_keys_absent_from_a_failed_pass_are_still_forgotten(tmp_path: Path) -> None:
    path = tmp_path / "a.json"
    ok = Dispatcher(lambda: _Sender(), path, log=lambda _: None)
    ok([REPEAT], 0.0)
    down = Dispatcher(lambda: _Sender(fail=True), path, log=lambda _: None)
    assert not down([PLAIN], 100.0)
    assert json.loads(path.read_text(encoding="utf-8")) == {}


def test_too_many_messages_in_one_pass_are_logged_not_dropped_silently(tmp_path: Path) -> None:
    sender = _Sender()
    logs: list[str] = []
    dispatcher = Dispatcher(
        lambda: sender, tmp_path / "a.json", log=logs.append, pause=lambda _: None
    )
    alerts = [Alert(kind="k", text="z" * 290, key=f"key{i}") for i in range(200)]
    assert not dispatcher(alerts, 0.0)
    assert len(sender.sent) == alert.MAX_MESSAGES
    assert any("too many messages" in line for line in logs)
    assert sum("undelivered alert" in line for line in logs) > 0


def test_a_retry_after_reaches_the_journal_line(tmp_path: Path) -> None:
    body = b'{"ok": false, "parameters": {"retry_after": 7}, "description": "Too Many Requests"}'
    logs: list[str] = []
    with local_server(reply(429, body)) as (base, _):
        dispatcher = Dispatcher(
            lambda: _Local(CREDS, base=base), tmp_path / "a.json", log=logs.append
        )
        assert not dispatcher([PLAIN], 0.0)
    assert any("retry after 7 s" in line for line in logs)
    assert not any(TOKEN in line for line in logs)


def test_deeply_nested_memory_is_replaced_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "a.json"
    path.write_text("[" * 100000, encoding="utf-8")
    sender = _Sender()
    dispatcher = Dispatcher(lambda: sender, path, log=lambda _: None)
    assert dispatcher([REPEAT], 0.0)


@pytest.mark.parametrize("content", ["", "chat_id=1\n", f"chat_id=1\ntoken={TOKEN}\n"])
def test_the_notifier_fails_on_unusable_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str
) -> None:
    mode = 0o644 if content.endswith(TOKEN + "\n") else 0o600
    file = _file(tmp_path, content, mode)
    with local_server(reply(200, b'{"ok": true}')) as (base, seen):
        code = _run_notifier(monkeypatch, base, ["--alert-file", str(file), "--unit", "a.service"])
    assert code == 1
    assert seen == []
