# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""What the publisher tells its operator.

An alert goes to an external service, so its text is built here and nowhere else: release and
tool output is cut to a short ASCII literal, and nothing the alert is given may be a token, a
key fingerprint or a path of this host. `key` names an event that repeats on every full
listing; the sender suppresses a repeat of the same key.
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
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

from publisher import files, net

MAX_TEXT: Final = 300
MESSAGE_LIMIT: Final = 4096  # Bot API: sendMessage text is 1-4096 characters
REPEAT_SECONDS: Final = 24 * 3600.0
MAX_CREDENTIAL_BYTES: Final = 512
MAX_REPLY_BYTES: Final = 64 * 1024
TIMEOUT_SECONDS: Final = 15.0
DEADLINE_SECONDS: Final = 30.0
API_BASE: Final = "https://api.telegram.org"
CHAT_ID: Final = re.compile(r"-?[0-9]{1,20}")
BOT_TOKEN: Final = re.compile(r"[0-9]{3,20}:[A-Za-z0-9_-]{20,100}")
MAX_SEEN: Final = 1000
MAX_MESSAGES: Final = 5
PAUSE_SECONDS: Final = 1.1  # the service allows about one message a second per chat
KEY_ID: Final = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
HOST_PATH: Final = re.compile(r"(?<![\w/.])/[^\s'\":,;)(\]\[]+")


@dataclass(frozen=True, slots=True, kw_only=True)
class Alert:
    kind: str
    text: str
    urgent: bool = False
    key: str | None = None


def clean(text: str) -> str:
    """Release or tool text as short ASCII without host paths or key fingerprints."""
    return ascii(KEY_ID.sub("<id>", HOST_PATH.sub("<path>", text)))[:MAX_TEXT]


class AlertError(Exception):
    """Base of the alert faults."""


class CredentialsError(AlertError):
    """The alert credentials file is missing, not private, or malformed."""


class DeliveryError(AlertError):
    """The chat service did not accept the message; the text never holds the bot token."""


@dataclass(frozen=True, slots=True)
class Credentials:
    chat_id: int
    token: str = field(repr=False)


def read_credentials(path: Path) -> Credentials:
    """Read `chat_id=` and `token=` (one line each) from a file only its owner can access."""
    if os.name != "posix":
        raise CredentialsError("credential file checks need a POSIX system")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        with os.fdopen(os.open(path, flags), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise CredentialsError(f"{path}: not a regular file")
            if info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise CredentialsError(f"{path}: must be private to the current user")
            raw = handle.read(MAX_CREDENTIAL_BYTES + 1)
    except OSError as error:
        raise CredentialsError(f"{path}: cannot read: {error.strerror or error}") from None
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise CredentialsError(f"{path}: too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CredentialsError(f"{path}: not valid UTF-8") from None
    fields: dict[str, str] = {}
    for line in text.removesuffix("\n").split("\n"):
        name, separator, value = line.partition("=")
        if not separator or name not in ("chat_id", "token") or name in fields:
            raise CredentialsError(f"{path}: expected exactly one chat_id= and one token= line")
        fields[name] = value
    if set(fields) != {"chat_id", "token"}:
        raise CredentialsError(f"{path}: expected exactly one chat_id= and one token= line")
    if not CHAT_ID.fullmatch(fields["chat_id"]) or not BOT_TOKEN.fullmatch(fields["token"]):
        raise CredentialsError(f"{path}: chat_id or token has the wrong shape")
    return Credentials(chat_id=int(fields["chat_id"]), token=fields["token"])


class Sender(Protocol):
    def send(self, text: str, *, silent: bool) -> None: ...


class Telegram:
    """POST one plain-text message to the Bot API: https only, no proxy, no redirect, no retry.

    The bot token is part of the request URL, so no error text is built from the URL, the
    exceptions of the HTTP library are never chained, and every message is scrubbed of the token.
    """

    _SCHEMES: tuple[str, ...] = ("https://",)

    def __init__(self, credentials: Credentials, *, base: str = API_BASE) -> None:
        self._credentials = credentials
        self._base = base
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

    def _scrub(self, text: str) -> str:
        return clean(text.replace(self._credentials.token, "<token>"))

    def send(self, text: str, *, silent: bool) -> None:
        url = f"{self._base}/bot{self._credentials.token}/sendMessage"
        if not url.startswith(self._SCHEMES):
            raise DeliveryError("only https is allowed")
        body = json.dumps(
            {
                "chat_id": self._credentials.chat_id,
                "text": text[:MESSAGE_LIMIT],
                "disable_notification": silent,
            }
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            try:
                with self._opener.open(request, timeout=TIMEOUT_SECONDS) as reply:
                    status, raw = reply.status, self._read(reply)
            except urllib.error.HTTPError as error:
                with error:
                    status, raw = error.code, self._read(error)
        except DeliveryError as error:
            # raised while an HTTPError (whose url holds the token) is the context: drop it
            raise DeliveryError(str(error)) from None
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise DeliveryError(f"request failed: {type(error).__name__}") from None
        self._check(status, raw)

    @staticmethod
    def _read(reply: Any) -> bytes:
        deadline = time.monotonic() + DEADLINE_SECONDS
        chunks: list[bytes] = []
        total = 0
        while chunk := reply.read1(8192):
            total += len(chunk)
            if total > MAX_REPLY_BYTES:
                raise DeliveryError("reply is larger than the allowed size")
            if time.monotonic() > deadline:
                raise DeliveryError("reply took too long")
            chunks.append(chunk)
        return b"".join(chunks)

    def _check(self, status: int, raw: bytes) -> None:
        try:
            document = json.loads(raw, object_pairs_hook=net.no_duplicate_keys)
        except ValueError:
            document = None
        answer = document if isinstance(document, dict) else {}
        if status == 200 and answer.get("ok") is True:
            return
        detail = answer.get("description")
        parameters = answer.get("parameters")
        retry = parameters.get("retry_after") if isinstance(parameters, dict) else None
        message = f"the chat service answered {status}"
        if isinstance(detail, str):
            message += f": {self._scrub(detail)}"
        if isinstance(retry, int) and not isinstance(retry, bool):
            message += f" (retry after {retry} s)"
        raise DeliveryError(message)


def compose(alerts: Sequence[Alert]) -> list[tuple[str, bool, list[Alert]]]:
    """Messages for a set of alerts, urgent first: (text, silent, the alerts it carries).

    Nothing is cut: a set that does not fit the service's size limit becomes several messages.
    """
    ordered = sorted(alerts, key=lambda a: not a.urgent)
    messages: list[tuple[str, bool, list[Alert]]] = []
    lines: list[str] = []
    carried: list[Alert] = []
    size = 0

    def close() -> None:
        if carried:
            messages.append(("\n".join(lines), not any(a.urgent for a in carried), list(carried)))
        lines.clear()
        carried.clear()

    for item in ordered:
        line = f"{'!! ' if item.urgent else ''}[{item.kind}] {item.text}"[:MESSAGE_LIMIT]
        if carried and size + len(line) + 1 > MESSAGE_LIMIT:
            close()
            size = 0
        lines.append(line)
        carried.append(item)
        size += len(line) + 1
    close()
    return messages


def _load_seen(path: Path) -> dict[str, float]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    document = json.loads(raw, object_pairs_hook=net.no_duplicate_keys)
    if not isinstance(document, dict) or len(document) > MAX_SEEN:
        raise ValueError("not a table of keys")
    seen: dict[str, float] = {}
    for key, when in document.items():
        if (
            not isinstance(key, str)
            or isinstance(when, bool)
            or not isinstance(when, (int, float))
            or when != when  # NaN
            or when in (float("inf"), float("-inf"))
        ):
            raise ValueError("bad entry")
        seen[key] = float(when)
    return seen


class Dispatcher:
    """Send the alerts of a pass, and say repeating events once a day.

    An alert with a `key` is an event that repeats on every full listing. It is recorded only
    after the message that carried it was accepted, so an undelivered one is tried again on the
    next run, and keys that did not occur in a pass are forgotten, so a recurrence alerts again.
    A failed delivery never fails the run: every undelivered alert goes to `log` in full. The
    credentials are checked on every call, also when there is nothing to say, so a broken
    credentials file is found before the day an alert is needed.
    """

    def __init__(
        self,
        sender: Callable[[], Sender],
        seen_path: Path,
        *,
        log: Callable[[str], None],
        pause: Callable[[float], None] = time.sleep,
    ):
        self._sender = sender
        self._path = seen_path
        self._log = log
        self._pause = pause

    def _seen(self) -> dict[str, float]:
        try:
            return _load_seen(self._path)
        except (OSError, ValueError, RecursionError) as error:
            self._log(f"error: alert memory unusable, starting empty: {type(error).__name__}")
            return {}

    def __call__(self, alerts: Sequence[Alert], now: float) -> bool:
        """True when nothing was left undelivered."""
        sender = self._sender()
        seen = self._seen()
        pending = [
            a
            for a in alerts
            if a.key is None or not (0 <= now - seen.get(a.key, -1e18) < REPEAT_SECONDS)
        ]
        delivered: list[Alert] = []
        messages = compose(pending)
        for index, (text, silent, carried) in enumerate(messages):
            if index >= MAX_MESSAGES:
                self._undelivered(messages[index:], "too many messages for one pass")
                break
            if index:
                self._pause(PAUSE_SECONDS)
            try:
                sender.send(text, silent=silent)
            except DeliveryError as error:
                self._undelivered(messages[index:], str(error))
                break
            delivered.extend(carried)
        remembered = {
            a.key: now if a in delivered else seen[a.key]
            for a in alerts
            if a.key is not None and (a in delivered or a.key in seen)
        }
        try:
            files.write_atomic(self._path, json.dumps(remembered, sort_keys=True).encode("utf-8"))
        except (files.FileError, OSError) as error:
            self._log(f"error: cannot save the alert memory: {type(error).__name__}")
        return len(delivered) == len(pending)

    def _undelivered(self, messages: Sequence[tuple[str, bool, list[Alert]]], why: str) -> None:
        self._log(f"error: alerts not delivered: {why}")
        for _, _, carried in messages:
            for item in carried:
                self._log(f"error: undelivered alert [{item.kind}] {item.text}")
