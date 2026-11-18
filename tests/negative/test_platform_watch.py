# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The weekly outside watch against a real published tree served over HTTP.

The tree comes from a whole publisher pass, the keyring package from `tools/build_keyring.py`,
and every check has a case that fails it. The expected redirect is the shipped rewrite rule's own
output (`Mirror.redirects`), not the watch's.
"""

from __future__ import annotations

import gzip
import hashlib
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import platform_watch
import pytest
from clients import publish
from mirror import Mirror
from platform_watch import Site, check, read_pin, rpm_redirect, served_key, trees, verify
from rig import Rig, product
from setupkit import served

from publisher import alert
from publisher.watch import WatchError

DAY = 86400.0
TAG = "v1.0.0"
ROOT = Path(__file__).resolve().parents[2]
ASC = "rpm/8.3/x86_64/repodata/repomd.xml.asc"
PRODUCTS = frozenset({"a-php"})
GITHUB_FIRST = "https://github.com/FojleRabbiRabib/a-php/releases/download/v1.0.0/"


class Local(Site):
    """The watch's client, allowed to speak plain http to the test server."""

    _SCHEMES = ("http://",)


@pytest.fixture
def published(
    make_rig: Callable[..., Rig], packages: Path
) -> Iterator[tuple[Rig, Mirror, Local, str, float]]:
    who = product("a-php", "a")
    rig = make_rig(who, rpm_key="keyring")
    now = time.time()
    publish(rig, who, TAG, now)
    with Mirror(rig, served(packages)) as mirror:
        yield rig, mirror, Local(mirror.base), rig.kit.master.primary_fingerprint.upper(), now


def _run(
    published: tuple[Rig, Mirror, Local, str, float],
    *,
    now: float | None = None,
    pin: str | None = None,
    modified: dict[str, float] | None = None,
) -> list[str]:
    _, mirror, site, fingerprint, made = published
    when = made if now is None else now
    # the signature files are re-signed with the run, so their time follows the clock too
    for tree in trees():
        mirror.modified[f"{tree}/repodata/repomd.xml.asc"] = when
    mirror.modified.update(modified or {})
    return check(site, pin or fingerprint, when, products=PRODUCTS, github=mirror.base + "/")


def test_a_fresh_signed_tree_with_the_pinned_key_passes(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    assert _run(published) == []
    # the two redirects the check followed are the shipped rule's, to the exact release asset
    assert [r.removeprefix(GITHUB_FIRST) for r in published[1].redirects] == [
        "php8.3-a_1.0.0-1_amd64.deb",
        "php-a-1.0.0-1.php83.x86_64.rpm",
    ]
    assert all(r.startswith(GITHUB_FIRST) for r in published[1].redirects)


def test_a_date_older_than_four_days_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    failures = _run(published, now=published[4] + 5 * DAY)
    assert [f for f in failures if "InRelease" in f] == [
        "the served InRelease Date is 5.0 days old"
    ]


def test_an_old_signature_replayed_with_a_fresh_last_modified_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    # every file says it was served now, but the signatures were made 5 days before
    failures = _run(published, now=published[4] + 5 * DAY)
    assert f"{ASC} was signed 5.0 days ago" in failures
    assert not [f for f in failures if f.endswith("days old") and "repomd" in f]


def test_a_date_of_three_and_a_half_days_passes(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    assert _run(published, now=published[4] + 3.5 * DAY) == []


def test_a_valid_until_fewer_than_seven_days_away_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    # the file says 14 days; at 8 days old a client has 6 left, and the Date is stale too
    failures = _run(published, now=published[4] + 8 * DAY)
    assert "the served InRelease Valid-Until is 6.0 days away" in failures
    assert _run(published, now=published[4] + 3.5 * DAY) == []


def test_a_signature_file_older_than_four_days_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    assert _run(published, modified={ASC: published[4] - 5 * DAY}) == [f"{ASC} is 5.0 days old"]


def test_a_signature_file_with_no_time_or_a_wrong_time_fails() -> None:
    now = time.time()
    name = "t/repodata/repomd.xml.asc"
    assert platform_watch._age(name, None, now) == [f"{name} has no Last-Modified"]
    assert platform_watch._age(name, "yesterday", now) == [
        f"{name} has an unreadable Last-Modified"
    ]
    assert platform_watch._age(name, "Mon, 01 Jan 2035 00:00:00 GMT", now) == [
        f"{name} Last-Modified is in the future"
    ]
    # a stamp with no zone would be read in the runner's own time
    assert platform_watch._age(name, "Mon, 01 Jan 2035 00:00:00 -0000", now) == [
        f"{name} has a Last-Modified with no time zone"
    ]


def test_a_keyring_with_another_primary_key_fails_and_stops(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    other = published[0].kit.rpm_keys["other"].primary_fingerprint.upper()
    assert _run(published, pin=other) == [
        "the primary key of the served keyring is not the pinned one"
    ]


def test_a_signature_by_a_key_other_than_the_pinned_one_fails(
    published: tuple[Rig, Mirror, Local, str, float], tmp_path: Path
) -> None:
    rig, site, fingerprint = published[0], published[2], published[3]
    key = served_key(site, fingerprint, tmp_path)
    inrelease = rig.current / "apt/dists/stable/InRelease"
    verify(key, fingerprint, "InRelease", inrelease)
    other = rig.kit.rpm_keys["other"].primary_fingerprint.upper()
    with pytest.raises(WatchError, match="does not verify against the pinned key"):
        verify(key, other, "InRelease", inrelease)


def test_a_tampered_inrelease_fails(published: tuple[Rig, Mirror, Local, str, float]) -> None:
    published[1].tamper.add("apt/dists/stable/InRelease")
    assert _run(published) == ["InRelease does not verify against the pinned key"]


def test_a_tampered_signature_file_fails(published: tuple[Rig, Mirror, Local, str, float]) -> None:
    published[1].tamper.add(ASC)
    assert _run(published) == [f"{ASC} does not verify against the pinned key"]


def test_a_tampered_repomd_fails(published: tuple[Rig, Mirror, Local, str, float]) -> None:
    published[1].tamper.add("rpm/8.3/x86_64/repodata/repomd.xml")
    failures = _run(published)
    assert (
        "rpm/8.3/x86_64/repodata/repomd.xml.asc does not verify against the pinned key" in failures
    )


def test_a_missing_file_fails_and_the_other_checks_still_run(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    published[1].missing.add("apt/dists/stable/InRelease")
    assert _run(published) == ["apt/dists/stable/InRelease answered 404"]


def test_a_redirect_to_another_target_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    _, _, site, fingerprint, now = published
    failures = check(site, fingerprint, now, products=PRODUCTS, github="https://elsewhere.invalid/")
    assert [f.split(" does not")[0] for f in failures] == [
        "apt/pool/a-php/v1.0.0/php8.3-a_1.0.0-1_amd64.deb",
        "pool/a-php/v1.0.0/php-a-1.0.0-1.php83.x86_64.rpm",
    ]


def test_an_empty_package_list_fails(make_rig: Callable[..., Rig], packages: Path) -> None:
    rig = make_rig(product("a-php", "a"), rpm_key="keyring")
    result = rig.run_pass(time.time())
    assert result.failure is None
    now = time.time()
    with Mirror(rig, served(packages)) as mirror:
        for tree in trees():
            mirror.modified[f"{tree}/repodata/repomd.xml.asc"] = now
        failures = check(
            Local(mirror.base),
            rig.kit.master.primary_fingerprint.upper(),
            now,
            products=PRODUCTS,
            github=mirror.base + "/",
        )
    assert failures == ["the apt index lists no package", "no rpm tree lists a package"]


def test_an_index_that_is_not_the_signed_one_fails(
    make_rig: Callable[..., Rig], packages: Path
) -> None:
    who = product("a-php", "a")
    rig = make_rig(who, rpm_key="keyring")
    publish(rig, who, TAG, time.time())
    now = time.time()
    forged = b"Package: x\nFilename: pool/a-php/v1.0.0/x.deb\n"
    with Mirror(
        rig, {**served(packages), "apt/dists/stable/main/binary-amd64/Packages": forged}
    ) as mirror:
        for tree in trees():
            mirror.modified[f"{tree}/repodata/repomd.xml.asc"] = now
        failures = check(
            Local(mirror.base),
            rig.kit.master.primary_fingerprint.upper(),
            now,
            products=PRODUCTS,
            github=mirror.base + "/",
        )
    assert failures == ["the apt package index does not match the signed InRelease"]


def _repomd(packed: bytes) -> bytes:
    digest = hashlib.sha256(packed).hexdigest()
    return (
        '<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">'
        f'<checksum type="sha256">{digest}</checksum><size>{len(packed)}</size>'
        '<location href="repodata/p.xml.gz"/></data></repomd>'
    ).encode()


def _primary(location: str) -> bytes:
    xml = f'<metadata><package type="rpm"><location href="{location}"/></package></metadata>'
    packed = gzip.compress(xml.encode())
    return packed


def test_a_hostile_package_location_is_a_failure_and_not_a_traceback(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    packed = _primary("//[x/pool/a/b/c")
    tree = "rpm/8.3/x86_64"
    with (
        Mirror(published[0], {f"{tree}/repodata/p.xml.gz": packed}) as mirror,
        pytest.raises(WatchError, match="unreadable package location"),
    ):
        rpm_redirect(Local(mirror.base), {tree: _repomd(packed)}, PRODUCTS, mirror.base + "/")


def test_a_package_location_outside_the_pool_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    tree = "rpm/8.3/x86_64"
    packed = _primary("../../../elsewhere/a.rpm")
    with (
        Mirror(published[0], {f"{tree}/repodata/p.xml.gz": packed}) as mirror,
        pytest.raises(WatchError, match="outside /pool/"),
    ):
        rpm_redirect(Local(mirror.base), {tree: _repomd(packed)}, PRODUCTS, mirror.base + "/")


def test_a_primary_index_that_is_not_the_signed_one_fails(
    published: tuple[Rig, Mirror, Local, str, float],
) -> None:
    tree = "rpm/8.3/x86_64"
    signed = _primary("../../../pool/a-php/v1.0.0/a.rpm")
    served_instead = _primary("../../../pool/a-php/v1.0.0/b.rpm")
    with (
        Mirror(published[0], {f"{tree}/repodata/p.xml.gz": served_instead}) as mirror,
        pytest.raises(WatchError, match=r"does not match the signed repomd\.xml"),
    ):
        rpm_redirect(Local(mirror.base), {tree: _repomd(signed)}, PRODUCTS, mirror.base + "/")


@pytest.mark.parametrize(
    ("parts", "why"),
    [
        (("evil-repo", "v1.0.0", "x.rpm"), "an undeclared product"),
        (("a-php", "..", "x.rpm"), "a dot-dot tag"),
        (("a-php", "v1.0.0", "x?y.rpm"), "a query in the name"),
        (("a-php", "v1.0.0", ".hidden"), "a leading dot"),
    ],
)
def test_a_package_of_an_undeclared_product_or_a_hostile_name_is_refused(
    published: tuple[Rig, Mirror, Local, str, float], parts: tuple[str, str, str], why: str
) -> None:
    with pytest.raises(WatchError, match="not one of a declared product"):
        platform_watch._redirect(published[2], "x", parts, PRODUCTS, "https://github.com/")


def test_a_cut_short_or_padded_gzip_and_a_document_type_are_refused() -> None:
    packed = gzip.compress(b"<a/>" * 100)
    assert platform_watch._inflate(packed) == b"<a/>" * 100
    with pytest.raises(WatchError, match="cut short"):
        platform_watch._inflate(packed[:-10])
    with pytest.raises(WatchError, match="cut short"):
        platform_watch._inflate(packed + b"extra")
    with pytest.raises(WatchError, match="document type"):
        platform_watch._xml(b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')


def test_a_keyring_package_whose_key_is_a_link_or_missing_is_refused(tmp_path: Path) -> None:
    for name in ("link", "empty"):
        root = tmp_path / name
        (root / "DEBIAN").mkdir(parents=True)
        (root / "DEBIAN" / "control").write_text(
            "Package: k\nVersion: 1\nArchitecture: all\nMaintainer: t <t@example.invalid>\n"
            "Description: t\n",
            encoding="utf-8",
        )
        (root / "usr" / "share" / "keyrings").mkdir(parents=True)
        if name == "link":
            (root / "usr" / "share" / "keyrings" / "rabib-archive-keyring.gpg").symlink_to(
                "/etc/passwd"
            )
        package = tmp_path / f"{name}.deb"
        subprocess.run(  # noqa: S603
            ["dpkg-deb", "--build", str(root), str(package)],  # noqa: S607
            check=True,
            capture_output=True,
        )
        with pytest.raises(WatchError, match="does not hold the key file"):
            platform_watch.keyring_file(package)


def test_an_unreachable_site_fails_without_a_traceback() -> None:
    failures = check(Local("http://127.0.0.1:1"), "A" * 40, time.time(), products=PRODUCTS)
    assert failures == ["cannot reach keyring/rabib-archive-keyring.deb (URLError)"]


def test_the_workflow_runs_this_script_with_the_committed_pin_and_the_chat_secrets() -> None:
    text = (ROOT / ".github" / "workflows" / "platform-watch.yml").read_text(encoding="utf-8")
    assert "python tools/platform_watch.py --site https://pkg.rabib.me" in text
    assert "--pin-file deploy/primary-fingerprint.txt --products products.yml --notify" in text
    assert (ROOT / "deploy" / "primary-fingerprint.txt").is_file()
    assert "PYTHONPATH: ." in text
    for name in ("TELEGRAM_CHAT_ID", "TELEGRAM_BOT_TOKEN"):
        assert f"{name}: ${{{{ secrets.{name} }}}}" in text
    # started by hand until the site is live: a schedule would be red every week
    assert "workflow_dispatch:" in text
    assert "schedule:" not in text
    assert "permissions:\n  contents: read\n" in text


def test_the_committed_pin_is_a_placeholder_and_a_placeholder_is_refused() -> None:
    with pytest.raises(WatchError, match="does not hold a primary key fingerprint"):
        read_pin(ROOT / "deploy" / "primary-fingerprint.txt")


def test_a_real_fingerprint_is_the_pin(tmp_path: Path) -> None:
    path = tmp_path / "pin"
    path.write_text("A" * 40 + "\n", encoding="utf-8")
    assert read_pin(path) == "A" * 40
    path.write_text("a" * 40 + "\n", encoding="utf-8")
    with pytest.raises(WatchError):
        read_pin(path)


def test_main_exits_one_and_prints_each_failure_and_zero_with_the_completion_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = tmp_path / "pin"
    pin.write_text("A" * 40 + "\n", encoding="utf-8")
    arguments = ["--site", "https://pkg.example.org", "--products", str(ROOT / "products.yml")]
    monkeypatch.setattr(platform_watch, "check", lambda *_args, **_kw: ["one", "two"])
    assert platform_watch.main([*arguments, "--pin-file", str(pin)]) == 1
    assert capsys.readouterr().out == "FAIL: 'one'\nFAIL: 'two'\n"
    monkeypatch.setattr(platform_watch, "check", lambda *_args, **_kw: [])
    assert platform_watch.main([*arguments, "--pin-file", str(pin)]) == 0
    assert capsys.readouterr().out == "PLATFORM WATCH PASSED\n"
    assert platform_watch.main([*arguments, "--pin-file", "/no/such"]) == 1
    # a crash inside a check is still a failure line, never a traceback
    monkeypatch.setattr(platform_watch, "check", lambda *_args, **_kw: 1 / 0)
    assert platform_watch.main([*arguments, "--pin-file", str(pin)]) == 1
    assert capsys.readouterr().out.endswith("FAIL: 'a check failed (ZeroDivisionError)'\n")


def test_a_failure_reaches_the_chat_only_when_asked_and_never_leaks_the_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[tuple[str, int]] = []

    class Chat:
        def __init__(self, credentials: alert.Credentials) -> None:
            self.credentials = credentials

        def send(self, text: str, *, silent: bool) -> None:
            sent.append((text, self.credentials.chat_id))
            assert silent is False

    token = "123456:" + "A" * 30
    pin = tmp_path / "pin"
    pin.write_text("A" * 40 + "\n", encoding="utf-8")
    monkeypatch.setattr(platform_watch, "check", lambda *_args, **_kw: ["one"])
    monkeypatch.setattr(alert, "Telegram", Chat)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", token)
    arguments = [
        *("--site", "https://pkg.example.org", "--pin-file", str(pin)),
        *("--products", str(ROOT / "products.yml")),
    ]
    assert platform_watch.main(arguments) == 1
    assert sent == []
    assert platform_watch.main([*arguments, "--notify"]) == 1
    assert sent == [("platform watch failed:\n'one'", -100123)]
    assert token not in capsys.readouterr().out
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "not a token")
    assert platform_watch.main([*arguments, "--notify"]) == 1
    assert len(sent) == 1
    assert "wrong shape" in capsys.readouterr().err
