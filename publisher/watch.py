# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The hourly watch: `python -m publisher.watch --config publisher.yml`.

It shares no schedule and no publish module with the daily run (it imports only the settings
reader, the alert sender and the HTTP helpers), so a dead publisher cannot silence it. Every pass
it checks four things and alerts, at most once a day for each, on:

- the GitHub token: fewer than 30 days left (the date comes from `publisher.yml`);
- the origin certificate: fewer than 21 days left, read by connecting to the origin address with
  the public name, so Cloudflare's own certificate is never the one that is checked;
- the served `Date:` of `InRelease`: older than 3 days;
- the served `Valid-Until:` of `InRelease`: fewer than 7 days left.

The served file is read only for these two dates. Its signature is not checked here: the clients
do that, and this is a freshness alarm.
"""

from __future__ import annotations

import argparse
import datetime
import http.client
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

from publisher import alert, config, net
from publisher.alert import Alert
from publisher.settings import Settings, load_settings

DAY: Final = 86400.0
TOKEN_WARNING_DAYS: Final = 30
CERTIFICATE_WARNING_DAYS: Final = 21
DATE_MAX_AGE_DAYS: Final = 3
VALID_UNTIL_WARNING_DAYS: Final = 7
FUTURE_SLACK_SECONDS: Final = 3600.0
RELEASE_PATH: Final = "/apt/dists/stable/InRelease"
RELEASE_DATE_FORMAT: Final = "%a, %d %b %Y %H:%M:%S UTC"
MAX_RELEASE_BYTES: Final = 8 * 1024 * 1024
TIMEOUT_SECONDS: Final = 15.0
DEADLINE_SECONDS: Final = 30.0
USER_AGENT: Final = "php-pkg-publisher"
SIGNATURE_START: Final = b"-----BEGIN PGP SIGNATURE-----"
FIELD: Final = re.compile(r"(Date|Valid-Until): ([ -~]{1,64})")


class WatchError(Exception):
    """A check could not be made; the text is safe to put in an alert."""


def token_alerts(expires: datetime.date, now: float) -> list[Alert]:
    """The token is valid through the end of its date."""
    end = datetime.datetime.combine(
        expires + datetime.timedelta(days=1), datetime.time(), tzinfo=datetime.timezone.utc
    ).timestamp()
    left = (end - now) / DAY
    if left >= TOKEN_WARNING_DAYS:
        return []
    text = (
        "the GitHub token has expired"
        if left <= 0
        else f"the GitHub token expires in {left:.0f} days"
    )
    return [Alert(kind="token-expiring", text=text, urgent=True, key="token-expiring")]


def certificate_expiry(
    host: str,
    origin: str,
    *,
    port: int = 443,
    context: ssl.SSLContext | None = None,
) -> float:
    """The `notAfter` of the certificate the origin presents for `host`, after verifying it."""
    context = context or ssl.create_default_context()
    try:
        with (
            socket.create_connection((origin, port), timeout=TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            found = tls.getpeercert()
    except ssl.SSLCertVerificationError as error:
        why = alert.clean(error.verify_message or "unknown reason")
        raise WatchError(f"the origin certificate does not verify: {why}") from None
    except (OSError, ssl.SSLError, ValueError) as error:
        raise WatchError(f"cannot reach the origin ({type(error).__name__})") from None
    not_after = found.get("notAfter") if found else None
    if not isinstance(not_after, str):
        raise WatchError("the origin presented no certificate expiry")
    try:
        return float(ssl.cert_time_to_seconds(not_after))
    except ValueError:
        raise WatchError("the origin certificate expiry is not readable") from None


def certificate_alerts(expiry: Callable[[], float], now: float) -> list[Alert]:
    try:
        left = (expiry() - now) / DAY
    except WatchError as error:
        return [Alert(kind="origin-certificate", text=str(error), urgent=True, key="origin-cert")]
    if left >= CERTIFICATE_WARNING_DAYS:
        return []
    text = (
        "the origin certificate has expired"
        if left <= 0
        else f"the origin certificate expires in {left:.0f} days"
    )
    return [Alert(kind="origin-certificate", text=text, urgent=True, key="origin-cert")]


class Public:
    """Fetch one public file: https only, no proxy, no redirect, a bounded and timed read."""

    _SCHEMES: tuple[str, ...] = ("https://",)

    def __init__(self, base: str) -> None:
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

    def get(self, path: str) -> bytes:
        url = self._base + path
        if not url.startswith(self._SCHEMES):
            raise WatchError("only https is allowed")
        request = urllib.request.Request(  # noqa: S310
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as reply:
                if reply.status != 200:
                    raise WatchError(f"the public site answered {reply.status}")
                return self._read(reply)
        except urllib.error.HTTPError as error:
            with error:
                raise WatchError(f"the public site answered {error.code}") from None
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise WatchError(f"cannot reach the public site ({type(error).__name__})") from None

    @staticmethod
    def _read(reply: Any) -> bytes:
        deadline = time.monotonic() + DEADLINE_SECONDS
        chunks: list[bytes] = []
        total = 0
        while chunk := reply.read1(65536):
            total += len(chunk)
            if total > MAX_RELEASE_BYTES:
                raise WatchError("the public file is larger than the allowed size")
            if time.monotonic() > deadline:
                raise WatchError("the public file took too long")
            chunks.append(chunk)
        return b"".join(chunks)


def release_dates(body: bytes) -> tuple[float, float]:
    """`Date` and `Valid-Until` of a clear-signed `InRelease`, as seconds since the epoch."""
    if not body.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"):
        raise WatchError("the served InRelease is not a signed message")
    end = body.find(SIGNATURE_START)
    if end < 0:
        raise WatchError("the served InRelease has no signature")
    try:
        text = body[:end].decode("ascii")
    except UnicodeDecodeError:
        raise WatchError("the served InRelease is not ASCII") from None
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = FIELD.fullmatch(line)
        if match is None:
            continue
        if match[1] in found:
            raise WatchError(f"the served InRelease repeats {match[1]}")
        found[match[1]] = match[2]
    try:
        stamps = [
            datetime.datetime.strptime(found[name], RELEASE_DATE_FORMAT)
            .replace(tzinfo=datetime.timezone.utc)
            .timestamp()
            for name in ("Date", "Valid-Until")
        ]
    except KeyError as error:
        raise WatchError(f"the served InRelease has no {error.args[0]}") from None
    except ValueError:
        raise WatchError("the served InRelease dates are not readable") from None
    return stamps[0], stamps[1]


def served_alerts(fetch: Callable[[], bytes], now: float) -> list[Alert]:
    try:
        issued, until = release_dates(fetch())
    except WatchError as error:
        return [Alert(kind="served-unreadable", text=str(error), urgent=True, key="served")]
    alerts: list[Alert] = []
    age = (now - issued) / DAY
    if age < -FUTURE_SLACK_SECONDS / DAY:
        alerts.append(
            Alert(
                kind="served-date-future",
                text="the served Date is in the future",
                urgent=True,
                key="served-date",
            )
        )
    elif age > DATE_MAX_AGE_DAYS:
        alerts.append(
            Alert(
                kind="served-stale",
                text=f"the served Date is {age:.1f} days old",
                urgent=True,
                key="served-date",
            )
        )
    left = (until - now) / DAY
    if left < VALID_UNTIL_WARNING_DAYS:
        alerts.append(
            Alert(
                kind="valid-until-low",
                text=f"the served Valid-Until is {max(left, 0):.1f} days away",
                urgent=True,
                key="valid-until",
            )
        )
    return alerts


def check(settings: Settings, now: float, *, public: Public | None = None) -> list[Alert]:
    """All checks of one pass, each independent of the others."""
    target = settings.watch
    public = public or Public(f"https://{target.host}")
    return [
        *token_alerts(settings.token_expires, now),
        *certificate_alerts(lambda: certificate_expiry(target.host, target.origin), now),
        *served_alerts(lambda: public.get(RELEASE_PATH), now),
    ]


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m publisher.watch")
    parser.add_argument("--config", type=Path, required=True, help="path of publisher.yml")
    arguments = parser.parse_args(argv)
    try:
        settings = load_settings(arguments.config)
        now = time.time()
        alerts = check(settings, now)
        for item in alerts:
            _stderr(f"alert {item.kind}: {item.text}")
        dispatch = alert.Dispatcher(
            lambda: alert.Telegram(alert.read_credentials(settings.alert_file)),
            settings.state / "watch-alerts.json",
            log=_stderr,
        )
        dispatch(alerts, now)
    except (alert.AlertError, config.ConfigError, OSError) as error:
        _stderr(f"failed: {alert.clean(str(error))}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
