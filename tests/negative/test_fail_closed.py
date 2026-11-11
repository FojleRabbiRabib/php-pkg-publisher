# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The negative layer: whole passes that must fail closed, judged by what a client would see.

Every case runs the real pass (see `rig.py`) and then reads the published tree with `gpgv` and
the standard library (see `oracle.py`). Each case asserts what is served against an expectation
built from the release files themselves; the failure cases also check the state files, and most
check that the tree is still signed and that the signed files match the indexes they cover.

Where a case is already proven closer to its code, this file does not repeat it:
  - the cosign identity, changed bytes and changed bundle against a real Sigstore bundle:
    `tests/unit/test_verify.py` (the rpm key-id check is also isolated there; here the real
    `rpmkeys` refuses a foreign key too, and the stored failure reason tells the two apart);
  - the webhook (method, size, signature, replay, throttle, table caps): `test_receiver.py`;
  - direct `.php` access: `test_htaccess.py`;
  - the retry schedule and quarantine: `test_admit.py`.
The 20-day case steps the pass clock but not the signing clock (`Date` always comes from the
system clock), so it shows that every daily pass re-signs, not that 20 real days have passed.
"""

from __future__ import annotations

import gzip
import time
from collections.abc import Callable
from typing import Any, Literal

import pytest
from conftest import A, B, client
from rig import DAY, SUMS, Rig, package_names

from publisher.config import Exclusion
from publisher.lock import LockBusy, RunLock

FIRST = "v1.0.0"
SECOND = "v1.1.0"
THIRD = "v1.2.0"
HOUR = 3600.0


def _add(rig: Rig, who: Any, tag: str, **options: Any) -> frozenset[str]:
    """Build a release of `who`, put it in the feed, and return its package file names."""
    immutable = options.pop("immutable", True)
    files = rig.kit.release(who, tag, **options)
    rig.feed.add(who.repo, tag, files, immutable=immutable)
    return package_names(files)


def _served(rig: Rig) -> frozenset[str]:
    return client(rig).served_files()


def _assert_signed(rig: Rig) -> None:
    seen = client(rig)
    assert seen.in_release_verifies()
    assert seen.release_gpg_verifies()
    assert seen.repomd_verifies()
    assert seen.index_hashes_match()
    assert seen.package_bytes_in_tree() == []


def _versions(tag: str, names: frozenset[str]) -> dict[str, str]:
    """The version each package file name must carry, from the tag (debs add the `-1`)."""
    number = tag.removeprefix("v")
    return {name: f"{number}-1" if name.endswith(".deb") else number for name in names}


def _kinds(rig_result: Any) -> list[str]:
    return [item.kind for item in rig_result.alerts]


# ---- a good release is the baseline the failing cases are measured against ----------------------


def test_good_releases_of_two_products_are_served_signed_and_never_as_package_bytes(
    rig: Rig,
) -> None:
    first = _add(rig, A, FIRST)
    second = _add(rig, B, FIRST)
    result = rig.run_pass(time.time())
    assert result.failure is None
    assert _kinds(result) == ["published"]
    assert client(rig).served_versions() == {**_versions(FIRST, first), **_versions(FIRST, second)}
    _assert_signed(rig)
    assert set(rig.state(A.repo)["admitted"]) == {FIRST}


# ---- one bad release: it is left out, the run goes on, what was served stays -------------------


def _tampered(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    files = rig.kit.release(A, tag)
    deb = next(name for name in files if name.endswith(".deb"))
    files[deb] += b"\0"
    return files, True


def _signed_by_another_repo(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag, signed_for=("other-php", tag)), True


def _signed_for_another_tag(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag, signed_for=(A.repo, "v9.9.9")), True


def _without_a_bundle(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    files = rig.kit.release(A, tag)
    del files[next(name for name in files if name.endswith(".deb.bundle"))]
    return files, True


def _without_a_package(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    files = rig.kit.release(A, tag)
    del files[next(name for name in files if name.endswith(".deb"))]
    return files, True


def _with_wrong_sums(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    files = rig.kit.release(A, tag)
    files[SUMS] = "".join(f"{'0' * 64}  ./{n}\n" for n in package_names(files)).encode()
    return files, True


def _with_an_unknown_file_in_the_sums(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    files = rig.kit.release(A, tag)
    files[SUMS] += f"{'0' * 64}  ./ghost.deb\n".encode()
    return files, True


def _with_an_unsigned_rpm(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag, rpm_key=None), True


def _with_an_rpm_signed_by_another_key(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag, rpm_key="other"), True


def _with_a_deb_of_another_version(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag, deb_version="9.9.9-1"), True


def _mutable(rig: Rig, tag: str) -> tuple[dict[str, bytes], bool]:
    return rig.kit.release(A, tag), False


SIGNED = "is not signed by the release workflow of this tag"
METADATA = "does not declare the expected package metadata"

# case -> (builder, the part of the stored failure reason that names the check that refused it)
BAD_RELEASES: dict[str, tuple[Callable[[Rig, str], tuple[dict[str, bytes], bool]], str]] = {
    "a package changed after it was signed": (_tampered, SIGNED),
    "bundles of another repo's workflow": (_signed_by_another_repo, SIGNED),
    "bundles of another tag": (_signed_for_another_tag, SIGNED),
    "a package without its bundle": (_without_a_bundle, "release lacks"),
    "a declared package missing": (_without_a_package, "release lacks"),
    "a SHA256SUMS that disagrees": (_with_wrong_sums, "disagrees with the release"),
    "a SHA256SUMS that lists a file the release lacks": (
        _with_an_unknown_file_in_the_sums,
        "lists ghost.deb",
    ),
    "an unsigned rpm": (_with_an_unsigned_rpm, "is not signed by the pinned rpm key"),
    "an rpm signed by another key": (
        _with_an_rpm_signed_by_another_key,
        "is not signed by the pinned rpm key",
    ),
    "a deb that declares another version": (_with_a_deb_of_another_version, METADATA),
    "a release that is not immutable": (_mutable, "the release is not immutable"),
}


@pytest.mark.parametrize("name", list(BAD_RELEASES))
def test_a_bad_release_is_not_served_and_the_good_one_before_it_stays(
    make_rig: Callable[..., Rig], name: str
) -> None:
    build, reason = BAD_RELEASES[name]
    rig = make_rig(A)
    good = _add(rig, A, FIRST)
    files, immutable = build(rig, SECOND)
    rig.feed.add(A.repo, SECOND, files, immutable=immutable)
    result = rig.run_pass(time.time())
    assert result.failure is None
    assert "admit-failed" in _kinds(result)
    assert client(rig).served_versions() == _versions(FIRST, good)
    _assert_signed(rig)
    state = rig.state(A.repo)
    assert set(state["admitted"]) == {FIRST}
    assert set(state["failed"]) == {SECOND}
    assert reason in state["failed"][SECOND]["reason"]


def test_a_repository_whose_only_release_is_bad_serves_no_package_but_is_signed(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    files, _ = _tampered(rig, FIRST)
    rig.feed.add(A.repo, FIRST, files)
    result = rig.run_pass(time.time())
    assert result.failure is None
    assert _served(rig) == frozenset()
    _assert_signed(rig)


@pytest.mark.parametrize("flag", ["prerelease", "final"])
def test_an_rc_tag_is_ignored_whether_or_not_the_release_carries_the_prerelease_flag(
    make_rig: Callable[..., Rig], flag: Literal["final", "prerelease"]
) -> None:
    rig = make_rig(A)
    good = _add(rig, A, FIRST)
    files = rig.kit.release(A, "v1.1.0-rc1")
    rig.feed.add(A.repo, "v1.1.0-rc1", files, kind=flag)
    rig.run_pass(time.time())
    assert _served(rig) == good
    _assert_signed(rig)
    assert set(rig.state(A.repo)["admitted"]) == {FIRST}


def test_the_oracle_refuses_an_index_that_no_longer_matches_what_was_signed(rig: Rig) -> None:
    _add(rig, A, FIRST)
    rig.run_pass(time.time())
    seen = client(rig)
    assert seen.index_hashes_match()
    packages = rig.current / "apt/dists/stable/main/binary-amd64/Packages"
    original = packages.read_bytes()
    packages.write_bytes(original + b"\n")
    assert not seen.index_hashes_match()
    packages.write_bytes(original)
    assert seen.index_hashes_match()
    primary = next(rig.current.glob("rpm/*/*/repodata/*primary.xml.gz"))
    raw = primary.read_bytes()
    primary.write_bytes(gzip.compress(gzip.decompress(raw) + b" "))
    assert not seen.index_hashes_match()


# ---- failure isolation -------------------------------------------------------------------------


def test_a_tampered_product_does_not_hold_back_another_product(rig: Rig) -> None:
    a_first = _add(rig, A, FIRST)
    b_first = _add(rig, B, FIRST)
    files, _ = _tampered(rig, SECOND)
    rig.feed.add(A.repo, SECOND, files)
    b_second = _add(rig, B, SECOND)
    result = rig.run_pass(time.time())
    assert result.failure is None
    assert _served(rig) == a_first | b_first | b_second
    _assert_signed(rig)
    assert set(rig.state(A.repo)["failed"]) == {SECOND}


def test_a_failing_tag_does_not_hold_back_the_next_tag(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig(A)
    first = _add(rig, A, FIRST)
    files, _ = _tampered(rig, SECOND)
    rig.feed.add(A.repo, SECOND, files)
    third = _add(rig, A, THIRD)
    rig.run_pass(time.time())
    assert _served(rig) == first | third
    _assert_signed(rig)


# ---- transient faults ---------------------------------------------------------------------------


def test_a_download_that_fails_once_is_published_by_the_next_pass_with_no_new_release(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    now = time.time()
    first = _add(rig, A, FIRST)
    rig.run_pass(now)
    second = _add(rig, A, SECOND)
    rig.feed.fail_once.add(next(name for name in second if name.endswith(".rpm")))
    rig.run_pass(now + HOUR)
    assert _served(rig) == first
    assert set(rig.state(A.repo)["failed"]) == {SECOND}
    fetched = len(rig.feed.fetched)
    rig.run_pass(now + HOUR + 30 * 60)  # inside the one-hour backoff: not tried again
    assert len(rig.feed.fetched) == fetched
    assert _served(rig) == first
    result = rig.run_pass(now + 2 * HOUR + 60)
    assert _served(rig) == first | second
    assert rig.state(A.repo)["failed"] == {}
    assert "published" in _kinds(result)
    _assert_signed(rig)


def test_an_unreachable_sigstore_admits_nothing_but_the_daily_re_sign_still_runs(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    now = time.time()
    first = _add(rig, A, FIRST)
    rig.run_pass(now)
    before = rig.current_id()
    issued_before, _ = client(rig).release_dates()
    _add(rig, A, SECOND)
    time.sleep(1.1)  # a new Date needs a new second
    result = rig.run_pass(now + DAY + 60, sigstore_up=False)
    assert result.failure is not None
    assert result.failure.startswith("admit stopped")
    assert "stopped" in _kinds(result)
    assert rig.current_id() != before
    assert _served(rig) == first
    assert client(rig).release_dates()[0] > issued_before
    _assert_signed(rig)


def test_an_admit_stage_that_fails_for_twenty_days_is_re_signed_every_day(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    now = time.time()
    first = _add(rig, A, FIRST)
    rig.run_pass(now)
    seen = {rig.current_id()}
    for day in range(1, 21):
        result = rig.run_pass(now + day * DAY + 60, sigstore_up=False)
        assert result.failure is not None
        assert "published" in _kinds(result), f"day {day} was not re-signed"
        seen.add(rig.current_id())
    assert len(seen) == 21
    assert _served(rig) == first
    _assert_signed(rig)
    _, until = client(rig).release_dates()
    assert until.timestamp() - time.time() > 13 * DAY


# ---- withdrawing and rolling back --------------------------------------------------------------


def test_an_excluded_release_leaves_the_repository_but_stays_admitted(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    now = time.time()
    first = _add(rig, A, FIRST)
    second = _add(rig, A, SECOND)
    rig.run_pass(now)
    assert _served(rig) == first | second
    rig.excluded.append(Exclusion(product=A.repo, tag=SECOND))
    rig.run_pass(now + 60)
    assert _served(rig) == first
    assert set(rig.state(A.repo)["admitted"]) == {FIRST, SECOND}
    _assert_signed(rig)


def test_a_rollback_serves_the_older_set_signed_and_holds_new_releases(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    now = time.time()
    first = _add(rig, A, FIRST)
    rig.run_pass(now)
    old = rig.current_id()
    second = _add(rig, A, SECOND)
    rig.run_pass(now + 60)
    assert _served(rig) == first | second
    rig.rollback(old, now + 120)
    assert _served(rig) == first
    _assert_signed(rig)
    _add(rig, A, THIRD)
    result = rig.run_pass(now + 180)
    assert result.failure is None
    assert _served(rig) == first
    assert "publish skipped: nothing changed" in rig.log
    assert _kinds(result) == []
    # the held release is admitted, and only waits for the pin to be cleared
    assert set(rig.state(A.repo)["admitted"]) == {FIRST, SECOND, THIRD}


# ---- concurrency --------------------------------------------------------------------------------


def test_a_second_run_cannot_enter_while_a_pass_is_running(make_rig: Callable[..., Rig]) -> None:
    rig = make_rig(A)
    first = _add(rig, A, FIRST)
    refused: list[bool] = []

    def try_to_enter() -> None:
        other = RunLock(rig.settings.lock, wait_seconds=0.2, poll_seconds=0.05)
        with pytest.raises(LockBusy):
            other.acquire()
        refused.append(True)

    rig.feed.during_fetch = try_to_enter
    rig.run_pass(time.time())
    assert refused == [True]
    assert _served(rig) == first
    _assert_signed(rig)


def test_a_nudge_that_arrives_during_a_run_earns_another_pass(
    make_rig: Callable[..., Rig],
) -> None:
    rig = make_rig(A)
    first = _add(rig, A, FIRST)
    rig.nudge.touch()
    second: list[frozenset[str]] = []

    def release_arrives() -> None:
        second.append(_add(rig, A, SECOND))
        rig.nudge.touch()

    rig.feed.during_fetch = release_arrives
    results = rig.run_nudged(time.time())
    assert len(results) == 2
    assert _served(rig) == first | second[0]
    assert not rig.nudge.exists()
    _assert_signed(rig)
