# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from publisher.config import ConfigError
from publisher.settings import load_settings

FPR = "A" * 40
PRIMARY = "B" * 40

VALID = {
    "products": "/etc/pp/products.yml",
    "exclude": "/etc/pp/exclude.yml",
    "site": "/srv/pkg/site",
    "state": "/var/lib/pp/state",
    "cache": "/var/lib/pp/cache",
    "trust": "/var/lib/pp/trust",
    "work": "/var/lib/pp/work",
    "lock": "/var/lib/pp/lock",
    "nudge": "/var/lib/pp/nudge/sync",
    "rpm_key": "/etc/pp/rpm.asc",
}


def _text(**changes: str | None) -> str:
    fields = {**VALID, **changes}
    lines = [f"{key}: {value}" for key, value in fields.items() if value is not None]
    lines.append('token: {file: /etc/pp/github.token, expires: "2027-01-31"}')
    lines.append("alert: {file: /etc/pp/telegram.conf}")
    lines.append(
        f"signing: {{home: /var/lib/pp/gpg, fingerprint: {FPR}, "
        f"certificate: /etc/pp/cert.asc, primary: {PRIMARY}}}"
    )
    lines.append("watch: {host: pkg.example.org, origin: 93.184.216.34}")
    return "\n".join(lines) + "\n"


def _load(tmp_path: Path, text: str) -> object:
    path = tmp_path / "publisher.yml"
    path.write_text(text, encoding="utf-8")
    return load_settings(path)


def _fail(tmp_path: Path, text: str) -> str:
    with pytest.raises(ConfigError) as caught:
        _load(tmp_path, text)
    return str(caught.value)


def test_a_valid_file_loads(tmp_path: Path) -> None:
    path = tmp_path / "publisher.yml"
    path.write_text(_text(), encoding="utf-8")
    loaded = load_settings(path)
    assert loaded.site == Path("/srv/pkg/site")
    assert loaded.token_expires == datetime.date(2027, 1, 31)
    assert loaded.signing.fingerprint == FPR
    assert loaded.signing.primary == PRIMARY
    assert loaded.nudge == Path("/var/lib/pp/nudge/sync")
    assert loaded.alert_file == Path("/etc/pp/telegram.conf")
    assert loaded.watch.host == "pkg.example.org"
    assert loaded.watch.origin == "93.184.216.34"


@pytest.mark.parametrize("key", list(VALID))
def test_a_missing_key_is_refused(tmp_path: Path, key: str) -> None:
    assert f"missing required key {key!r}" in _fail(tmp_path, _text(**{key: None}))


def test_an_unknown_key_is_refused(tmp_path: Path) -> None:
    assert "unknown key 'extra'" in _fail(tmp_path, _text() + "extra: /x\n")


def test_a_repeated_key_is_refused(tmp_path: Path) -> None:
    assert "duplicate key" in _fail(tmp_path, _text() + "site: /other\n")


@pytest.mark.parametrize(
    "value", ["relative/path", "/a/../b", "/a//b", "/a/b/", "//a/b", "/a/./b", '"/a/\\0b"']
)
def test_a_path_that_is_not_normal_and_absolute_is_refused(tmp_path: Path, value: str) -> None:
    assert "absolute path" in _fail(tmp_path, _text(site=value))


def test_a_path_that_is_too_long_is_refused(tmp_path: Path) -> None:
    assert "absolute path" in _fail(tmp_path, _text(site="/" + "a" * 250))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"cache": "/srv/pkg/site"}, "same as or inside"),
        ({"cache": "/srv/pkg/site/cache"}, "same as or inside"),
        ({"site": "/var/lib/pp/cache/site"}, "same as or inside"),
        ({"nudge": "/srv/pkg/site/nudge"}, "must not be inside 'site'"),
        ({"nudge": "/var/lib/pp/lock/nudge"}, "must not be inside 'lock'"),
    ],
)
def test_overlapping_locations_are_refused(
    tmp_path: Path, changes: dict[str, str], message: str
) -> None:
    assert message in _fail(tmp_path, _text(**changes))


def test_a_signing_home_inside_a_work_directory_is_refused(tmp_path: Path) -> None:
    text = _text().replace("/var/lib/pp/gpg", "/var/lib/pp/work/gpg")
    assert "signing home" in _fail(tmp_path, text)


@pytest.mark.parametrize("value", ["2027-02-30", "27-01-31", "tomorrow", "2027-1-31"])
def test_a_bad_expiry_date_is_refused(tmp_path: Path, value: str) -> None:
    text = _text().replace('"2027-01-31"', f'"{value}"')
    assert "invalid date" in _fail(tmp_path, text)


def test_an_unquoted_expiry_date_is_refused(tmp_path: Path) -> None:
    text = _text().replace('"2027-01-31"', "2027-01-31")
    assert "quoted date" in _fail(tmp_path, text)


@pytest.mark.parametrize("fingerprint", ["a" * 40, "A" * 39, "G" * 40])
def test_a_bad_fingerprint_is_refused(tmp_path: Path, fingerprint: str) -> None:
    text = _text().replace(FPR, fingerprint, 1)
    assert "40 uppercase" in _fail(tmp_path, text)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            "rpm_key: /etc/pp/rpm.asc",
            "rpm_key: /var/lib/pp/work/rpm.asc",
            "rpm_key must not be inside 'work'",
        ),
        (
            "products: /etc/pp/products.yml",
            "products: /srv/pkg/site/p.yml",
            "products must not be inside 'site'",
        ),
        (
            "exclude: /etc/pp/exclude.yml",
            "exclude: /var/lib/pp/state/e.yml",
            "exclude must not be inside 'state'",
        ),
        ("/etc/pp/github.token", "/var/lib/pp/cache/t", "token file must not be inside 'cache'"),
        ("/etc/pp/cert.asc", "/var/lib/pp/trust/c", "certificate must not be inside 'trust'"),
        ("/etc/pp/telegram.conf", "/var/lib/pp/state/t", "alert file must not be inside 'state'"),
        (
            "nudge: /var/lib/pp/nudge/sync",
            "nudge: /var/lib/pp/gpg/sync",
            "nudge must not be inside the signing home",
        ),
    ],
)
def test_a_file_inside_a_working_directory_is_refused(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    assert message in _fail(tmp_path, _text().replace(old, new))


def test_a_missing_watch_section_is_refused(tmp_path: Path) -> None:
    text = _text().replace("watch: {host: pkg.example.org, origin: 93.184.216.34}\n", "")
    assert "missing required key 'watch'" in _fail(tmp_path, text)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "PKG.example.org",
        "pkg..example.org",
        "-a.example.org",
        "a b.example.org",
        "https://pkg.example.org",
        "pkg.example.org/",
        "pkg.example.org:443",
        "1.2.3.4",
    ],
)
def test_a_bad_watch_host_is_refused(tmp_path: Path, host: str) -> None:
    text = _text().replace("host: pkg.example.org", f'host: "{host}"')
    assert "host name" in _fail(tmp_path, text)


@pytest.mark.parametrize(
    "origin",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",  # noqa: S104
        "::1",
        "203.000.113.7",
        "pkg.example.org",
        "203.0.113",
        "2001:DB8::1",
    ],
)
def test_a_bad_watch_origin_is_refused(tmp_path: Path, origin: str) -> None:
    text = _text().replace("origin: 93.184.216.34", f'origin: "{origin}"')
    assert "address" in _fail(tmp_path, text)
