# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The read-only status view: what it shows, that it changes nothing, and that it trusts nothing
it reads from the web server's side."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import pytest

from publisher import admit, status
from publisher import lock as locking
from publisher.__main__ import main
from publisher.settings import Settings, load_settings

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_800_000_000  # 2027-01-15T08:00:00Z


def _settings(tmp_path: Path) -> Settings:
    for name in ("site", "state", "cache", "trust", "work", "lock", "nudge"):
        (tmp_path / name).mkdir(mode=0o700)
    (tmp_path / "site").chmod(0o755)
    (tmp_path / "products.yml").write_text(
        "products:\n"
        "  - repo: usearch-php\n    extension: usearch\n"
        '    php: ["8.3"]\n    arch: [amd64]\n    ts: [nts]\n',
        encoding="utf-8",
    )
    (tmp_path / "exclude.yml").write_text("exclude: []\n", encoding="utf-8")
    text = (
        f"products: {tmp_path}/products.yml\nexclude: {tmp_path}/exclude.yml\n"
        + "".join(f"{n}: {tmp_path}/{n}\n" for n in ("site", "state", "cache", "trust", "work"))
        + f"lock: {tmp_path}/lock\nnudge: {tmp_path}/nudge/sync\nrpm_key: {tmp_path}/k.asc\n"
        f'token: {{file: {tmp_path}/t, expires: "2027-01-31"}}\n'
        f"alert: {{file: {tmp_path}/a}}\n"
        "watch: {host: pkg.example.org, origin: 93.184.216.34}\n"
        f"signing: {{home: {tmp_path}/g, fingerprint: {'A' * 40}, "
        f"certificate: {tmp_path}/c, primary: {'B' * 40}}}\n"
    )
    (tmp_path / "publisher.yml").write_text(text, encoding="utf-8")
    return load_settings(tmp_path / "publisher.yml")


def _admitted(at: float) -> admit.AdmittedTag:
    package = admit.AdmittedPackage(
        name="php8.3-usearch_1.0.0_amd64.deb",
        kind="deb",
        layout="deb",
        php="8.3",
        arch="amd64",
        sha256="a" * 64,
        size=10,
    )
    return admit.AdmittedTag(admitted_at=at, packages=(package,))


def _failure(
    attempts: int, retry: float, *, quarantined: bool = False, reason: str = "r"
) -> admit.Failure:
    return admit.Failure(
        reason=reason,
        attempts=attempts,
        first_failed=1.0,
        next_retry=retry,
        quarantined=quarantined,
        last_alert=None,
    )


def _save(settings: Settings, repo: str, state: admit.ProductState) -> None:
    with locking.RunLock(settings.lock) as lock:
        admit.StateStore(settings.state, lock).save(repo, state)


def _populate(settings: Settings) -> None:
    _save(
        settings,
        "usearch-php",
        admit.ProductState(
            admitted={f"v1.{i}.0": _admitted(1_799_000_000 + i * 100_000) for i in range(7)},
            failed={
                "v1.7.0": _failure(2, 1_800_003_600, reason="download failed"),
                "v1.8.0": _failure(5, 9e9, quarantined=True, reason="bad bundle"),
                "v1.9.0": _failure(1, 1_799_990_000, reason="late"),
            },
        ),
    )
    _save(
        settings,
        "resvg-php",
        admit.ProductState(admitted={"v0.1.0": _admitted(1_799_900_000)}),
    )
    (settings.nudge.parent / "duplicates").write_text("3 1799990000", encoding="utf-8")


def _text(settings: Settings) -> str:
    return status.render_text(status.gather(settings, NOW))


def test_the_view_lists_what_was_accepted_what_failed_and_what_repeated(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _populate(settings)
    assert _text(settings) == "\n".join(
        [
            "status as of 2027-01-15T08:00:00Z",
            "publisher: idle",
            "run requested: no",
            "products: 2",
            "",
            "resvg-php",
            "  accepted (1):",
            "    v0.1.0  2027-01-14T04:13:20Z",
            "  failed: none",
            "",
            "usearch-php",
            "  accepted (newest 5 of 7):",
            "    v1.6.0  2027-01-10T16:53:20Z",
            "    v1.5.0  2027-01-09T13:06:40Z",
            "    v1.4.0  2027-01-08T09:20:00Z",
            "    v1.3.0  2027-01-07T05:33:20Z",
            "    v1.2.0  2027-01-06T01:46:40Z",
            "  failed:",
            "    v1.9.0  attempt 1, retry due, 'late'",
            "    v1.8.0  quarantined after 5 attempts, needs requeue or exclude, 'bad bundle'",
            "    v1.7.0  attempt 2, retry 2027-01-15T09:00:00Z, 'download failed'",
            "",
            "repeated deliveries (again within 120 s): 3, last 2027-01-15T05:13:20Z",
        ]
    )


def test_the_json_view_holds_the_same_facts(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _populate(settings)
    document = json.loads(status.render_json(status.gather(settings, NOW)))
    assert document["as_of"] == "2027-01-15T08:00:00Z"
    assert document["publisher"] == "idle"
    assert document["run_requested"] is False
    assert document["repeated_deliveries"] == {
        "count": 3,
        "last": "2027-01-15T05:13:20Z",
        "window_seconds": 120,
    }
    resvg, usearch = document["products"]
    assert resvg == {
        "repo": "resvg-php",
        "readable": True,
        "accepted_total": 1,
        "accepted": [{"tag": "v0.1.0", "at": "2027-01-14T04:13:20Z"}],
        "failed": [],
    }
    assert [item["tag"] for item in usearch["accepted"]] == [f"v1.{i}.0" for i in (6, 5, 4, 3, 2)]
    assert usearch["accepted_total"] == 7
    assert usearch["failed"] == [
        {
            "tag": "v1.9.0",
            "attempts": 1,
            "quarantined": False,
            "due": True,
            "retry": None,
            "reason": "'late'",
        },
        {
            "tag": "v1.8.0",
            "attempts": 5,
            "quarantined": True,
            "due": False,
            "retry": None,
            "reason": "'bad bundle'",
        },
        {
            "tag": "v1.7.0",
            "attempts": 2,
            "quarantined": False,
            "due": False,
            "retry": "2027-01-15T09:00:00Z",
            "reason": "'download failed'",
        },
    ]


def test_the_newest_accepted_come_first_by_time_then_by_version_not_by_text(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    _save(
        settings,
        "usearch-php",
        admit.ProductState(
            admitted={
                "v1.9.0": _admitted(1_799_000_000),
                "v1.10.0": _admitted(1_799_000_000),
                "v1.2.0": _admitted(1_799_500_000),
            }
        ),
    )
    (product,) = status.gather(settings, NOW).products or ()
    assert [item.tag for item in product.accepted] == ["v1.2.0", "v1.10.0", "v1.9.0"]


def test_a_retry_date_too_far_away_is_shown_as_due_because_the_next_run_tries_it(
    tmp_path: Path,
) -> None:
    """A date more than a day ahead came from a clock step or damage; the run ignores it."""
    settings = _settings(tmp_path)
    _save(
        settings,
        "usearch-php",
        admit.ProductState(failed={"v1.0.0": _failure(2, NOW + 10 * 86400)}),
    )
    assert "    v1.0.0  attempt 2, retry due, 'r'\n" in _text(settings) + "\n"


def test_a_working_run_and_a_waiting_nudge_are_shown(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.nudge.write_bytes(b"")
    with locking.RunLock(settings.lock):
        started = time.monotonic()
        text = _text(settings)
        assert time.monotonic() - started < 1  # the view never waits for the run
    assert "publisher: working" in text
    assert "run requested: yes" in text
    assert "publisher: idle" in _text(settings)


def test_with_nothing_recorded_the_view_says_so_and_creates_nothing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    def tree() -> list[str]:
        return sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))

    before = tree()
    assert _text(settings) == "\n".join(
        [
            "status as of 2027-01-15T08:00:00Z",
            "publisher: idle",
            "run requested: no",
            "products: 0",
            "",
            "repeated deliveries (again within 120 s): none counted",
        ]
    )
    assert tree() == before  # no lock file, no products directory, no counter


def test_the_view_leaves_a_runs_temporary_state_file_alone(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _populate(settings)
    temporary = settings.state / "products" / ".state-in-flight"
    temporary.write_bytes(b"half written")
    _text(settings)
    assert temporary.read_bytes() == b"half written"
    assert status.gather(settings, NOW).products is not None


def test_a_state_file_that_cannot_be_trusted_is_shown_as_unreadable_and_the_rest_still_is(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    _populate(settings)
    admit.state_file(settings.state, "usearch-php").chmod(0o644)
    text = _text(settings)
    assert "usearch-php\n  state: unreadable\n" in text
    assert "resvg-php\n  accepted (1):" in text
    assert "products: 2" in text


def test_an_unreadable_state_directory_is_shown_as_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)

    def refuse(directory: Path) -> list[str]:
        raise PermissionError(13, "Permission denied", str(directory))

    monkeypatch.setattr(admit, "recorded_products", refuse)
    text = _text(settings)
    assert "products: unreadable" in text
    assert str(tmp_path) not in text


def test_text_from_a_state_file_is_shown_as_short_ascii_without_paths(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    hostile = "x\x1b[31m\nfailed to open /var/lib/pp/state/p.json " + "z" * 500
    _save(
        settings,
        "usearch-php",
        admit.ProductState(failed={"v1.0.0": _failure(1, 9e9, reason=hostile)}),
    )
    text = _text(settings)
    assert "\x1b" not in text
    assert "/var/lib" not in text
    assert str(tmp_path) not in text
    assert all(line.isascii() for line in text.splitlines())
    assert max(len(line) for line in text.splitlines()) < 400


def test_a_state_file_name_that_is_not_a_repository_name_is_shown_cleaned(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    _populate(settings)
    (settings.state / "products" / "bad\x1b[31m.json").write_bytes(b"{}")
    text = _text(settings)
    assert "\x1b" not in text
    assert "state: unreadable" in text


@pytest.mark.parametrize(
    ("content", "count", "last"),
    [
        (b"3 1800000000", 3, 1_800_000_000.0),
        (b"3 1800000000\n", 3, 1_800_000_000.0),
        (b"999999999 1800000000", 999_999_999, 1_800_000_000.0),
    ],
)
def test_the_receivers_count_is_read_when_it_has_exactly_the_expected_shape(
    tmp_path: Path, content: bytes, count: int, last: float
) -> None:
    settings = _settings(tmp_path)
    (settings.nudge.parent / "duplicates").write_bytes(content)
    assert status.gather(settings, NOW).repeats == status.Repeats(count=count, last=last)


def test_an_empty_count_file_is_the_instant_before_the_first_count_not_a_fault(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.nudge.parent / "duplicates").write_bytes(b"")
    assert status.gather(settings, NOW).repeats == status.Repeats(count=0, last=None)


@pytest.mark.parametrize(
    "content",
    [
        b"x",
        b"3",
        b"3 4 5",
        b"-1 5",
        b" 3 4",
        b"1234567890 5",
        b"3 1234567890123",
        b"3 4\n\n",
        b"\xff\xfe",
        b"1" * 200,
    ],
)
def test_a_count_file_of_any_other_shape_is_unreadable_not_a_crash(
    tmp_path: Path, content: bytes
) -> None:
    settings = _settings(tmp_path)
    (settings.nudge.parent / "duplicates").write_bytes(content)
    assert status.gather(settings, NOW).repeats is None
    assert "repeated deliveries (again within 120 s): unreadable" in _text(settings)


@pytest.mark.timeout(10)
def test_a_count_file_that_is_a_link_a_directory_or_a_pipe_is_unreadable(tmp_path: Path) -> None:
    """The web server's group may create any entry here; a pipe must not hang the view."""
    settings = _settings(tmp_path)
    counter = settings.nudge.parent / "duplicates"
    target = tmp_path / "elsewhere"
    target.write_text("3 1800000000", encoding="utf-8")
    counter.symlink_to(target)
    assert status.gather(settings, NOW).repeats is None
    counter.unlink()
    counter.mkdir()
    assert status.gather(settings, NOW).repeats is None
    counter.rmdir()
    os.mkfifo(counter)
    assert status.gather(settings, NOW).repeats is None


def test_times_are_utc_and_an_impossible_one_is_not_a_crash() -> None:
    assert status.when(0) == "1970-01-01T00:00:00Z"
    assert status.when(NOW) == "2027-01-15T08:00:00Z"
    assert status.when(1e300) == "unknown time"


def test_the_constants_the_view_shares_with_the_receiver_are_the_receivers() -> None:
    receiver = (ROOT / "web" / "sync.php").read_text(encoding="utf-8")
    (window,) = re.findall(r"const GUID_WINDOW = (\d+);", receiver)
    assert int(window) == status.REPEAT_WINDOW_SECONDS
    (name,) = re.findall(r"const DUPLICATES_FILE = '([^']+)';", receiver)
    assert name == status.DUPLICATES_FILE
    (cap,) = re.findall(r"const MAX_DUPLICATES = (\d+);", receiver)
    assert len(cap) <= 9  # the view reads at most nine digits
    assert status.DUPLICATES.fullmatch(f"{cap} {NOW}")
    # the receiver writes nine digits, a space and twelve; the view takes one to nine and one to
    # twelve, so every line the receiver writes is one the view reads
    assert "sprintf('%09d %012d'," in receiver
    assert status.DUPLICATES.fullmatch("000000001 001800000030")


def test_the_status_command_prints_the_text_view_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _populate(_settings(tmp_path))
    assert main(["--config", str(tmp_path / "publisher.yml"), "status"]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    assert out.out.startswith("status as of ")
    assert "usearch-php\n  accepted (newest 5 of 7):\n    v1.6.0  " in out.out
    assert str(tmp_path) not in out.out


def test_the_status_command_prints_json_with_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _populate(_settings(tmp_path))
    assert main(["--config", str(tmp_path / "publisher.yml"), "status", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [product["repo"] for product in document["products"]] == ["resvg-php", "usearch-php"]
    assert document["publisher"] == "idle"


def test_the_status_command_refuses_a_settings_file_it_cannot_load(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(tmp_path / "missing.yml"), "status"]) == 1
    assert capsys.readouterr().out == ""
