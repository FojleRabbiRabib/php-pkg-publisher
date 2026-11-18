# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Load the publisher's own settings (`publisher.yml`): where it works and which keys it uses.

The file holds locations and public pins, never a secret: the GitHub token, the signing key and
the alert credentials stay in their own private files that this file only names. It is parsed
like `products.yml` (repeated and unknown keys are errors, every error carries its line) and
has no defaults: a missing key stops the run before anything is touched.

    products:  /etc/php-pkg-publisher/products.yml
    exclude:   /etc/php-pkg-publisher/exclude.yml
    site:      /srv/pkg/site          # versions/, store/, generations/, current
    state:     /var/lib/php-pkg-publisher/state
    cache:     /var/lib/php-pkg-publisher/cache
    trust:     /var/lib/php-pkg-publisher/trust
    work:      /var/lib/php-pkg-publisher/work
    lock:      /var/lib/php-pkg-publisher/lock
    nudge:     /var/lib/php-pkg-publisher/nudge/sync
    rpm_key:   /etc/php-pkg-publisher/rpm-signing.asc
    token:     {file: /etc/php-pkg-publisher/github.token, expires: "2027-01-31"}
    alert:     {file: /etc/php-pkg-publisher/telegram.conf}
    signing:   {home: ..., fingerprint: ..., certificate: ..., primary: ...}
    watch:     {host: pkg.example.org, origin: <public IPv4 of the origin>}

The six directories must be distinct and none may lie inside another, so a tree that a run
removes or rewrites can never be the one that holds the lock, the state or the keys.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from yaml.nodes import Node

from publisher import config
from publisher.config import ConfigError, Reader

MAX_PATH_BYTES: Final = 200
DATE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
HOST: Final = re.compile(
    r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?"
)
DIRECTORIES: Final = ("site", "state", "cache", "trust", "work", "lock")


@dataclass(frozen=True, slots=True, kw_only=True)
class SigningPins:
    """Where the signing subkey lives and the public pins it is checked against."""

    home: Path
    fingerprint: str
    certificate: Path
    primary: str


@dataclass(frozen=True, slots=True, kw_only=True)
class WatchTarget:
    """The public name the clients use and the address of the origin behind it."""

    host: str
    origin: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    source: Path
    products: Path
    exclude: Path
    site: Path
    state: Path
    cache: Path
    trust: Path
    work: Path
    lock: Path
    nudge: Path
    rpm_key: Path
    token_file: Path
    token_expires: datetime.date
    alert_file: Path
    signing: SigningPins
    watch: WatchTarget


def _path(reader: Reader, node: Node) -> Path:
    text = reader.string(node)
    pure = PurePosixPath(text)
    if (
        not pure.is_absolute()
        or "\0" in text
        or ".." in pure.parts
        or str(pure) != text
        or text.startswith("//")
        or len(text.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise reader.fail(
            node, "expected a normal absolute path (no '..', no '//', no trailing '/')"
        )
    return Path(text)


def _date(reader: Reader, node: Node) -> datetime.date:
    text = reader.string(node, 'expected a quoted date such as "2027-01-31"')
    if not DATE.fullmatch(text):
        raise reader.fail(node, f"invalid date {text!r}")
    try:
        return datetime.date.fromisoformat(text)
    except ValueError as error:
        raise reader.fail(node, f"invalid date {text!r}") from error


def _fingerprint(reader: Reader, node: Node) -> str:
    text = reader.string(node)
    if not config.FINGERPRINT.fullmatch(text):
        raise reader.fail(node, "expected 40 uppercase hexadecimal digits")
    return text


def _host(reader: Reader, node: Node) -> str:
    text = reader.string(node)
    if not HOST.fullmatch(text):
        raise reader.fail(node, "expected a lower-case host name such as pkg.example.org")
    return text


def _address(reader: Reader, node: Node) -> str:
    text = reader.string(node)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise reader.fail(node, f"invalid address {text!r}") from error
    if str(address) != text or not address.is_global:
        raise reader.fail(node, "expected a public IP address in its shortest form")
    return text


def _nested(outer: Path, inner: Path) -> bool:
    return inner == outer or outer in inner.parents


def load_settings(path: Path) -> Settings:
    reader, root, _ = config.open_document(path)
    top = reader.mapping(
        root,
        required=(
            "products",
            "exclude",
            *DIRECTORIES,
            "nudge",
            "rpm_key",
            "token",
            "alert",
            "signing",
            "watch",
        ),
    )
    watch = reader.mapping(top["watch"], required=("host", "origin"))
    token = reader.mapping(top["token"], required=("file", "expires"))
    alert = reader.mapping(top["alert"], required=("file",))
    signing = reader.mapping(
        top["signing"], required=("home", "fingerprint", "certificate", "primary")
    )
    directories = {name: _path(reader, top[name]) for name in DIRECTORIES}
    for i, name in enumerate(DIRECTORIES):
        for other in DIRECTORIES[i + 1 :]:
            if _nested(directories[name], directories[other]) or _nested(
                directories[other], directories[name]
            ):
                raise reader.fail(
                    top[other], f"{other!r} must not be the same as or inside {name!r}"
                )
    nudge = _path(reader, top["nudge"])
    key = SigningPins(
        home=_path(reader, signing["home"]),
        fingerprint=_fingerprint(reader, signing["fingerprint"]),
        certificate=_path(reader, signing["certificate"]),
        primary=_fingerprint(reader, signing["primary"]),
    )
    singles = {
        "products": _path(reader, top["products"]),
        "exclude": _path(reader, top["exclude"]),
        "rpm_key": _path(reader, top["rpm_key"]),
        "token file": _path(reader, token["file"]),
        "alert file": _path(reader, alert["file"]),
        "certificate": key.certificate,
        "nudge": nudge,
    }
    for name, directory in directories.items():
        if _nested(directory, key.home) or _nested(key.home, directory):
            raise reader.fail(signing["home"], f"the signing home must not overlap {name!r}")
        for label, single in singles.items():
            if _nested(directory, single):
                raise reader.fail(top[name], f"{label} must not be inside {name!r}")
    for label, single in singles.items():
        if _nested(key.home, single):
            raise reader.fail(signing["home"], f"{label} must not be inside the signing home")
    return Settings(
        source=path,
        products=singles["products"],
        exclude=singles["exclude"],
        nudge=nudge,
        rpm_key=singles["rpm_key"],
        token_file=singles["token file"],
        alert_file=singles["alert file"],
        token_expires=_date(reader, token["expires"]),
        signing=key,
        watch=WatchTarget(
            host=_host(reader, watch["host"]), origin=_address(reader, watch["origin"])
        ),
        **directories,
    )


__all__ = ["ConfigError", "Settings", "load_settings"]
