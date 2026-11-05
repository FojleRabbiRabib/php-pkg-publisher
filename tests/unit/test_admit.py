# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import hashlib
import json
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any

import pytest

from publisher import admit, config, feed, files
from publisher.admit import (
    ALERT_INTERVAL_SECONDS,
    ALL_KINDS,
    BACKOFF_SECONDS,
    DAY,
    FULL_LISTING_SECONDS,
    HOUR,
    QUARANTINE_AGE_SECONDS,
    Admitter,
    Failure,
    ProductState,
    Report,
    StateError,
    StateStore,
    requeue,
)
from publisher.cache import Cache, CacheDirectoryError, DownloadError
from publisher.feed import Asset, Listing, Rejection, Release, Unchanged
from publisher.lock import RunLock
from publisher.tools import ToolError
from publisher.verify import (
    Rejected,
    Unsupported,
    Verified,
    VerifiedPackage,
    Verifier,
    expected_packages,
)

NOW = 1_800_000_000.0
ETAG = '"listing-1"'
A = config.Product(
    repo="a-php", extension="a", php=("8.3",), arch=("amd64",), ts=("nts",), exclude=()
)
B = config.Product(
    repo="b-php", extension="b", php=("8.3",), arch=("amd64",), ts=("nts",), exclude=()
)


def _release(product: config.Product, tag: str, *, immutable: bool = True) -> Release:
    assets = tuple(
        Asset(
            name=package.name,
            size=10,
            digest="sha256:" + hashlib.sha256(package.name.encode()).hexdigest(),
            url=f"https://github.com/{feed.GITHUB_OWNER}/{product.repo}/releases/download/{tag}/{package.name}",
        )
        for package in expected_packages(product, tag)
    )
    kind: admit.Kind = "final" if config.FINAL_TAG.fullmatch(tag) else "prerelease"
    return Release(tag=tag, kind=kind, immutable=immutable, assets=assets)


def _no_download(url: str, size: int) -> Generator[bytes, None, None]:
    raise AssertionError("the admit tests never download")
    yield b""


def _listing(*releases: Release, rejected: tuple[Rejection, ...] = (), etag: str = ETAG) -> Listing:
    return Listing(etag=etag, releases=releases, rejected=rejected, ignored=())


class World:
    """A state store, a scripted release feed and a scripted verifier."""

    def __init__(self, tmp_path: Path) -> None:
        self.state_dir = tmp_path / "state"
        self.state_dir.mkdir(mode=0o700)
        cache_root = tmp_path / "cache"
        cache_root.mkdir(mode=0o700)
        self.lock = RunLock(self.state_dir)
        self.lock.acquire()
        self.store = StateStore(self.state_dir, self.lock)
        self.cache = Cache(cache_root, _no_download)
        self.feeds: dict[str, Listing | Exception] = {}
        self.verdicts: dict[tuple[str, str], Exception] = {}
        self.list_calls: list[tuple[str, str | None]] = []
        self.verify_calls: list[tuple[str, str]] = []

    def lister(self, repo: str, *, etag: str | None) -> Listing | Unchanged:
        self.list_calls.append((repo, etag))
        outcome = self.feeds[repo]
        if isinstance(outcome, Exception):
            raise outcome
        if etag is not None and etag == outcome.etag:
            return Unchanged(etag=etag)
        return outcome

    def verify(self, product: config.Product, release: Release, cache: Cache) -> Verified:
        assert cache is self.cache
        self.verify_calls.append((product.repo, release.tag))
        verdict = self.verdicts.get((product.repo, release.tag))
        if verdict is not None:
            raise verdict
        packages = tuple(
            VerifiedPackage(package=package, path=Path("/unused"))
            for package in expected_packages(product, release.tag)
        )
        return Verified(tag=release.tag, packages=packages)

    def run(
        self,
        *products: config.Product,
        now: float = NOW,
        exclusions: tuple[config.Exclusion, ...] = (),
        kinds: frozenset[admit.Kind] = admit.FINAL_ONLY,
    ) -> Report:
        listed = config.ProductList(source=Path("products.yml"), sha256="", products=products)
        excluded = config.ExclusionList(
            source=Path("exclude.yml"), sha256="", exclusions=exclusions
        )
        admitter = Admitter(
            listed,
            excluded,
            store=self.store,
            lister=self.lister,
            verifier=self,
            cache=self.cache,
            kinds=kinds,
        )
        return admitter.run(now)

    def state(self, repo: str) -> ProductState:
        return self.store.load(repo)


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setattr(admit, "MIN_FREE_BYTES", 0)
    made = World(tmp_path)
    yield made
    made.lock.release()


def _kinds(report: Report) -> list[tuple[str, str | None, str]]:
    return [(event.product, event.tag, event.kind) for event in report.events]


def test_a_new_valid_release_is_admitted_with_its_package_record(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    report = world.run(A)
    assert report.stopped is None
    assert _kinds(report) == [("a-php", "v1.0.0", "admitted")]
    state = world.state(A.repo)
    stored = state.admitted["v1.0.0"]
    assert stored.admitted_at == NOW
    expected = expected_packages(A, "v1.0.0")
    assert [(p.name, p.kind, p.layout, p.php, p.arch) for p in stored.packages] == [
        (p.name, p.kind, p.layout, p.php, p.arch) for p in expected
    ]
    assert [p.sha256 for p in stored.packages] == [
        hashlib.sha256(p.name.encode()).hexdigest() for p in expected
    ]
    assert all(p.size == 10 for p in stored.packages)
    assert state.etag == ETAG
    assert state.listed == ("v1.0.0",)
    assert state.listed_at == NOW


def test_an_admitted_tag_is_not_verified_again(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    world.list_calls.clear()
    world.verify_calls.clear()
    world.run(A, now=NOW + 1)
    assert world.verify_calls == []


def test_a_failing_tag_does_not_block_a_later_tag(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.1.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("tampered")
    report = world.run(A)
    assert ("a-php", "v1.1.0", "admitted") in _kinds(report)
    assert ("a-php", "v1.0.0", "failed") in _kinds(report)
    state = world.state(A.repo)
    assert list(state.admitted) == ["v1.1.0"]
    assert state.failed["v1.0.0"].attempts == 1


def test_a_transient_download_failure_is_admitted_by_the_next_run_without_a_new_release(
    world: World,
) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = DownloadError("connection reset")
    world.run(A)
    del world.verdicts[(A.repo, "v1.0.0")]
    world.list_calls.clear()
    report = world.run(A, now=NOW + HOUR)
    assert world.list_calls == [("a-php", None)]
    assert _kinds(report) == [("a-php", "v1.0.0", "admitted")]
    assert world.state(A.repo).failed == {}


def test_a_tampered_product_does_not_block_another_and_keeps_what_it_had(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.feeds[B.repo] = _listing()
    world.run(A, B)
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.0.1"), etag='"a-2"')
    world.feeds[B.repo] = _listing(_release(B, "v2.0.0"), etag='"b-2"')
    world.verdicts[(A.repo, "v1.0.1")] = Rejected("bad cosign identity")
    report = world.run(A, B, now=NOW + 60)
    assert ("b-php", "v2.0.0", "admitted") in _kinds(report)
    assert list(world.state(A.repo).admitted) == ["v1.0.0"]
    assert "v1.0.1" in world.state(A.repo).failed
    assert list(world.state(B.repo).admitted) == ["v2.0.0"]


def test_a_mutable_release_is_rejected_without_any_fetch(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0", immutable=False))
    report = world.run(A)
    assert world.verify_calls == []
    assert _kinds(report) == [("a-php", "v1.0.0", "failed")]
    assert "not immutable" in world.state(A.repo).failed["v1.0.0"].reason


def test_a_release_rejected_by_the_feed_is_a_failure_without_verification(world: World) -> None:
    rejection = Rejection(tag="v1.0.0", reason="asset name 'x' is not allowed")
    world.feeds[A.repo] = _listing(rejected=(rejection,))
    world.run(A)
    assert world.verify_calls == []
    assert world.state(A.repo).failed["v1.0.0"].reason == rejection.reason


def test_prereleases_are_ignored_unless_asked_for(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.1.0-rc1"))
    world.run(A)
    assert list(world.state(A.repo).admitted) == ["v1.0.0"]
    world.run(A, now=NOW + 1, kinds=ALL_KINDS)
    assert sorted(world.state(A.repo).admitted) == ["v1.0.0", "v1.1.0-rc1"]


@pytest.mark.parametrize("where", ["products", "exclude-file"])
def test_an_excluded_tag_is_not_admitted_and_its_failure_is_cleared(
    world: World, where: str
) -> None:
    product = config.Product(
        repo=A.repo,
        extension=A.extension,
        php=A.php,
        arch=A.arch,
        ts=A.ts,
        exclude=("v1.0.0",) if where == "products" else (),
    )
    exclusions = () if where == "products" else (config.Exclusion(product=A.repo, tag="v1.0.0"),)
    world.store.save(
        A.repo,
        ProductState(
            failed={
                "v1.0.0": Failure(
                    reason="x",
                    attempts=2,
                    first_failed=NOW - DAY,
                    next_retry=NOW - 1,
                    quarantined=False,
                    last_alert=None,
                )
            }
        ),
    )
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(product, exclusions=exclusions)
    assert world.verify_calls == []
    assert world.state(A.repo).failed == {}
    assert world.state(A.repo).admitted == {}


def test_an_excluded_tag_that_was_admitted_stays_admitted(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    world.run(A, now=NOW + 1, exclusions=(config.Exclusion(product=A.repo, tag="v1.0.0"),))
    assert list(world.state(A.repo).admitted) == ["v1.0.0"]


def test_an_admitted_tag_that_vanishes_is_kept_and_reported(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    world.feeds[A.repo] = _listing(etag='"empty"')
    report = world.run(A, now=NOW + 1)
    assert ("a-php", "v1.0.0", "vanished") in _kinds(report)
    assert list(world.state(A.repo).admitted) == ["v1.0.0"]


def test_an_admitted_tag_whose_digest_changed_is_kept_and_reported(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    changed = _release(A, "v1.0.0")
    first = changed.assets[0]
    swapped = Asset(name=first.name, size=first.size, digest="sha256:" + "0" * 64, url=first.url)
    world.feeds[A.repo] = Listing(
        etag='"listing-2"',
        releases=(
            Release(
                tag="v1.0.0", kind="final", immutable=True, assets=(swapped, *changed.assets[1:])
            ),
        ),
        rejected=(),
        ignored=(),
    )
    report = world.run(A, now=NOW + 1)
    assert ("a-php", "v1.0.0", "changed") in _kinds(report)
    assert world.state(A.repo).admitted["v1.0.0"].packages[0].sha256 != "0" * 64


def test_a_failed_tag_that_is_no_longer_listed_is_forgotten(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("x")
    world.run(A)
    world.feeds[A.repo] = _listing()
    world.run(A, now=NOW + 1)
    assert world.state(A.repo).failed == {}


def test_backoff_grows_then_stays_daily_and_a_retry_waits_for_it(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("x")
    now = NOW
    for attempt, delay in enumerate((HOUR, 6 * HOUR, DAY, DAY, DAY), start=1):
        world.run(A, now=now)
        failure = world.state(A.repo).failed["v1.0.0"]
        assert failure.attempts == attempt
        assert failure.next_retry == now + delay
        calls = len(world.verify_calls)
        world.run(A, now=failure.next_retry - 1)
        assert len(world.verify_calls) == calls
        now = failure.next_retry
    assert BACKOFF_SECONDS == (HOUR, 6 * HOUR, DAY)


def _seed_failure(world: World, *, attempts: int, first_failed: float) -> None:
    world.store.save(
        A.repo,
        ProductState(
            failed={
                "v1.0.0": Failure(
                    reason="earlier",
                    attempts=attempts,
                    first_failed=first_failed,
                    next_retry=NOW,
                    quarantined=False,
                    last_alert=None,
                )
            }
        ),
    )
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("still bad")


def test_five_attempts_after_exactly_three_days_quarantine_the_tag(world: World) -> None:
    _seed_failure(world, attempts=4, first_failed=NOW - QUARANTINE_AGE_SECONDS)
    report = world.run(A)
    assert ("a-php", "v1.0.0", "quarantined") in _kinds(report)
    failure = world.state(A.repo).failed["v1.0.0"]
    assert failure.quarantined
    assert failure.attempts == 5
    assert failure.last_alert == NOW


def test_five_attempts_one_second_short_of_three_days_do_not_quarantine(world: World) -> None:
    _seed_failure(world, attempts=4, first_failed=NOW - QUARANTINE_AGE_SECONDS + 1)
    report = world.run(A)
    assert "quarantined" not in [kind for _, _, kind in _kinds(report)]
    assert not world.state(A.repo).failed["v1.0.0"].quarantined


def test_four_attempts_after_a_long_time_do_not_quarantine(world: World) -> None:
    _seed_failure(world, attempts=3, first_failed=NOW - 10 * DAY)
    world.run(A)
    failure = world.state(A.repo).failed["v1.0.0"]
    assert failure.attempts == 4
    assert not failure.quarantined


def test_the_retry_schedule_quarantines_on_the_sixth_attempt(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("x")
    now = NOW
    for hours in (0, 1, 7, 31, 55, 79):
        world.run(A, now=NOW + hours * HOUR)
    failure = world.state(A.repo).failed["v1.0.0"]
    assert failure.attempts == 6
    assert failure.quarantined
    assert now == NOW


def _quarantine(world: World, last_alert: float | None) -> None:
    world.store.save(
        A.repo,
        ProductState(
            etag=ETAG,
            listed=("v1.0.0",),
            listed_at=NOW - 1,
            failed={
                "v1.0.0": Failure(
                    reason="bad",
                    attempts=6,
                    first_failed=NOW - 5 * DAY,
                    next_retry=NOW - DAY,
                    quarantined=True,
                    last_alert=last_alert,
                )
            },
        ),
    )
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))


def test_a_quarantined_tag_is_not_tried_again(world: World) -> None:
    _quarantine(world, last_alert=NOW)
    world.run(A)
    assert world.verify_calls == []


def test_a_quarantined_tag_raises_one_alert_a_day(world: World) -> None:
    _quarantine(world, last_alert=NOW - ALERT_INTERVAL_SECONDS + 1)
    assert world.run(A).events == ()
    _quarantine(world, last_alert=NOW - ALERT_INTERVAL_SECONDS)
    report = world.run(A)
    assert _kinds(report) == [("a-php", "v1.0.0", "quarantine-alert")]
    assert world.state(A.repo).failed["v1.0.0"].last_alert == NOW


def test_the_alert_is_raised_even_when_the_listing_is_unchanged(world: World) -> None:
    _quarantine(world, last_alert=None)
    world.run(A)
    assert world.list_calls == [("a-php", ETAG)]
    assert world.run(A, now=NOW + ALERT_INTERVAL_SECONDS).events[0].kind == "quarantine-alert"


def test_requeue_lifts_a_quarantine_and_the_tag_is_tried_again(world: World) -> None:
    _quarantine(world, last_alert=NOW)
    requeue(world.store, A.repo, "v1.0.0")
    report = world.run(A)
    assert _kinds(report) == [("a-php", "v1.0.0", "admitted")]


def test_requeue_of_an_unknown_failure_is_an_error(world: World) -> None:
    with pytest.raises(StateError, match="no recorded failure"):
        requeue(world.store, A.repo, "v1.0.0")


def test_the_etag_is_sent_only_when_everything_listed_is_admitted(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    world.run(A, now=NOW + 1)
    assert world.list_calls == [("a-php", None), ("a-php", ETAG)]


def test_an_unchanged_listing_changes_nothing_and_verifies_nothing(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    before = world.store.path(A.repo).read_bytes()
    world.verify_calls.clear()
    report = world.run(A, now=NOW + 1)
    assert report.events == ()
    assert world.verify_calls == []
    assert world.store.path(A.repo).read_bytes() == before


def test_the_etag_is_dropped_once_the_last_full_listing_is_a_week_old(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    world.run(A, now=NOW + FULL_LISTING_SECONDS - 1)
    world.run(A, now=NOW + FULL_LISTING_SECONDS)
    assert [etag for _, etag in world.list_calls] == [None, ETAG, None]


def test_the_etag_is_not_sent_while_a_failure_waits_for_a_retry(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Rejected("x")
    world.run(A)
    world.run(A, now=NOW + 1)
    assert [etag for _, etag in world.list_calls] == [None, None]


def test_a_listed_tag_that_is_not_admitted_prevents_the_etag(world: World) -> None:
    world.store.save(A.repo, ProductState(etag=ETAG, listed=("v1.0.0",), listed_at=NOW - 1))
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    assert world.list_calls == [("a-php", None)]


def test_a_product_that_cannot_be_listed_is_skipped_and_the_others_continue(world: World) -> None:
    world.feeds[A.repo] = feed.NotFound("repository or releases not found (404)")
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    report = world.run(A, B)
    assert report.stopped is None
    assert ("a-php", None, "product-error") in _kinds(report)
    assert ("b-php", "v1.0.0", "admitted") in _kinds(report)
    assert world.state(A.repo) == ProductState()


def test_a_product_that_declares_something_unsupported_is_skipped(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    world.verdicts[(A.repo, "v1.0.0")] = Unsupported("declares zts")
    report = world.run(A, B)
    assert ("a-php", None, "product-error") in _kinds(report)
    assert ("b-php", "v1.0.0", "admitted") in _kinds(report)
    assert world.state(A.repo).failed == {}


@pytest.mark.parametrize(
    "fault",
    [
        ToolError("rpm is not installed"),
        CacheDirectoryError("cannot store x: No space left on device"),
    ],
)
def test_a_fault_of_this_host_stops_the_stage_and_counts_against_no_tag(
    world: World, fault: Exception
) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.1.0"))
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    world.verdicts[(A.repo, "v1.1.0")] = fault
    report = world.run(A, B)
    assert report.stopped is not None
    assert "a-php v1.1.0" in report.stopped
    assert [call for call in world.list_calls if call[0] == "b-php"] == []
    assert world.state(A.repo).failed == {}


@pytest.mark.parametrize(
    "fault", [feed.AuthError("GitHub rejected the token (401)"), feed.RateLimited("limit", 60)]
)
def test_a_rejected_token_or_a_rate_limit_stops_the_stage(world: World, fault: Exception) -> None:
    world.feeds[A.repo] = fault
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    report = world.run(A, B)
    assert report.stopped is not None
    assert world.verify_calls == []
    assert [call for call in world.list_calls if call[0] == "b-php"] == []


def test_low_disk_space_stops_the_stage_before_any_request(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admit, "MIN_FREE_BYTES", 2**62)
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    report = world.run(A)
    assert report.stopped is not None
    assert "bytes free" in report.stopped
    assert world.list_calls == []


def test_a_corrupt_state_file_stops_the_stage_and_is_left_untouched(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    path = world.store.path(A.repo)
    path.write_bytes(b"{not json")
    path.chmod(0o600)
    report = world.run(A, B)
    assert report.stopped is not None
    assert path.read_bytes() == b"{not json"
    assert world.list_calls == []


def test_a_stop_keeps_what_earlier_products_already_admitted(world: World) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.feeds[B.repo] = feed.AuthError("GitHub rejected the token (401)")
    report = world.run(A, B)
    assert report.stopped is not None
    assert list(world.state(A.repo).admitted) == ["v1.0.0"]


def _document(world: World) -> dict[str, Any]:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.verdicts[(B.repo, "v1.0.0")] = Rejected("x")
    world.feeds[B.repo] = _listing(_release(B, "v1.0.0"))
    world.run(A, B)
    return json.loads(world.store.path(A.repo).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _write(world: World, repo: str, document: object) -> None:
    path = world.store.path(repo)
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)


def test_state_round_trips(world: World) -> None:
    document = _document(world)
    before = world.state(A.repo)
    world.store.save(A.repo, before)
    assert world.state(A.repo) == before
    assert document["version"] == 1


def test_the_state_file_is_private(world: World) -> None:
    _document(world)
    assert world.store.path(A.repo).stat().st_mode & 0o777 == 0o600


def _mutations() -> list[tuple[str, Any]]:
    def drop(key: str) -> Any:
        return lambda d: d.pop(key)

    def put(key: str, value: object) -> Any:
        return lambda d: d.__setitem__(key, value)

    def package(key: str, value: object) -> Any:
        return lambda d: d["admitted"]["v1.0.0"]["packages"][0].__setitem__(key, value)

    return [
        ("missing key", drop("etag")),
        ("unknown key", put("extra", 1)),
        ("wrong version", put("version", 2)),
        ("boolean version", put("version", True)),
        ("etag type", put("etag", 5)),
        ("etag shape", put("etag", "unquoted")),
        ("listed type", put("listed", "v1.0.0")),
        ("listed tag", put("listed", ["main"])),
        ("listed duplicate", put("listed", ["v1.0.0", "v1.0.0"])),
        ("listed_at negative", put("listed_at", -1)),
        ("listed_at text", put("listed_at", "now")),
        ("admitted type", put("admitted", [])),
        ("admitted tag", lambda d: d["admitted"].__setitem__("../x", d["admitted"]["v1.0.0"])),
        ("no packages", lambda d: d["admitted"]["v1.0.0"].__setitem__("packages", [])),
        ("package sha", package("sha256", "abc")),
        ("package kind", package("kind", "tar")),
        ("package layout", package("layout", "other")),
        ("package php", package("php", "7.4")),
        ("package arch", package("arch", "mips")),
        ("package size", package("size", -1)),
        ("package name", package("name", "../x")),
        ("package extra", package("extra", 1)),
        ("failed type", put("failed", [])),
        (
            "both admitted and failed",
            lambda d: d["failed"].__setitem__(
                "v1.0.0",
                {
                    "reason": "x",
                    "attempts": 1,
                    "first_failed": 1,
                    "next_retry": 1,
                    "quarantined": False,
                    "last_alert": None,
                },
            ),
        ),
    ]


@pytest.mark.parametrize(("name", "mutate"), _mutations(), ids=[m[0] for m in _mutations()])
def test_a_malformed_state_is_refused_not_read_as_empty(
    world: World, name: str, mutate: Any
) -> None:
    document = _document(world)
    mutate(document)
    _write(world, A.repo, document)
    with pytest.raises(StateError):
        world.store.load(A.repo)


@pytest.mark.parametrize(
    "bad",
    [
        {"attempts": -1},
        {"attempts": True},
        {"quarantined": "no"},
        {"first_failed": float("nan")},
        {"next_retry": "soon"},
        {"last_alert": "x"},
        {"reason": 5},
        {"extra": 1},
    ],
)
def test_a_malformed_failure_is_refused(world: World, bad: dict[str, Any]) -> None:
    document = _document(world)
    failure: dict[str, Any] = {
        "reason": "x",
        "attempts": 1,
        "first_failed": 1,
        "next_retry": 1,
        "quarantined": False,
        "last_alert": None,
    }
    failure.update(bad)
    document["failed"] = {"v1.1.0": failure}
    path = world.store.path(A.repo)
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StateError):
        world.store.load(A.repo)


def test_a_repeated_key_in_the_state_is_refused(world: World) -> None:
    _document(world)
    path = world.store.path(A.repo)
    path.write_text('{"version": 1, "version": 1}', encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StateError, match="repeats the key"):
        world.store.load(A.repo)


def test_a_state_file_that_is_too_large_is_refused(world: World) -> None:
    path = world.store.path(A.repo)
    path.write_bytes(b" " * (admit.MAX_STATE_BYTES + 1))
    path.chmod(0o600)
    with pytest.raises(StateError, match="too large"):
        world.store.load(A.repo)


def test_a_state_file_open_to_others_is_refused(world: World) -> None:
    _document(world)
    world.store.path(A.repo).chmod(0o644)
    with pytest.raises(StateError, match="private to the current user"):
        world.store.load(A.repo)


def test_a_state_file_that_is_a_symlink_is_refused(world: World, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    world.store.path(A.repo).symlink_to(target)
    with pytest.raises(StateError, match="cannot open"):
        world.store.load(A.repo)


def test_a_repo_name_that_could_escape_is_refused(world: World) -> None:
    with pytest.raises(StateError, match="invalid repo name"):
        world.store.path("../etc")


def test_the_store_needs_the_lock_and_a_private_directory(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    from publisher.lock import LockError

    with pytest.raises(LockError, match="not held"):
        StateStore(directory, RunLock(directory))
    open_directory = tmp_path / "open"
    open_directory.mkdir()
    open_directory.chmod(0o755)
    other = RunLock(directory)
    with other, pytest.raises(StateError, match="unusable"):
        StateStore(open_directory, other)


def test_leftover_temporary_state_files_are_removed_at_start(world: World, tmp_path: Path) -> None:
    leftover = world.state_dir / "products" / ".state-leftover"
    leftover.write_bytes(b"x")
    StateStore(world.state_dir, world.lock)
    assert not leftover.exists()


def test_a_failed_write_keeps_the_old_state_and_stops_the_stage(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"))
    world.run(A)
    before = world.store.path(A.repo).read_bytes()

    def failing(path: Path, data: bytes, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "write_atomic", failing)
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.1.0"), etag='"two"')
    report = world.run(A, now=NOW + 1)
    assert report.stopped is not None
    assert "No space left" in report.stopped
    assert world.store.path(A.repo).read_bytes() == before


def test_a_repo_whose_name_looks_like_a_temporary_file_keeps_its_state(world: World) -> None:
    odd = config.Product(
        repo="state-x", extension="x", php=("8.3",), arch=("amd64",), ts=("nts",), exclude=()
    )
    world.feeds[odd.repo] = _listing(_release(odd, "v1.0.0"))
    world.run(odd)
    StateStore(world.state_dir, world.lock)
    assert list(world.state(odd.repo).admitted) == ["v1.0.0"]


def test_an_os_error_during_verification_stops_the_stage_and_keeps_the_report(
    world: World,
) -> None:
    world.feeds[A.repo] = _listing(_release(A, "v1.0.0"), _release(A, "v1.1.0"))
    world.verdicts[(A.repo, "v1.0.0")] = OSError(5, "Input/output error")
    report = world.run(A)
    assert report.stopped is not None
    assert ("a-php", "v1.1.0", "admitted") in _kinds(report)
    assert world.state(A.repo).failed == {}


def test_a_listing_date_in_the_future_does_not_hide_the_weekly_full_listing(world: World) -> None:
    world.store.save(
        A.repo,
        ProductState(etag=ETAG, listed=(), listed_at=NOW + 10 * DAY),
    )
    world.feeds[A.repo] = _listing()
    world.run(A)
    assert world.list_calls == [("a-php", None)]


def test_an_alert_date_in_the_future_does_not_silence_a_quarantine(world: World) -> None:
    _quarantine(world, last_alert=NOW + 10 * DAY)
    assert _kinds(world.run(A)) == [("a-php", "v1.0.0", "quarantine-alert")]


def test_a_retry_date_far_in_the_future_does_not_block_the_retry_for_ever(world: World) -> None:
    _seed_failure(world, attempts=1, first_failed=NOW - DAY)
    failure = world.state(A.repo).failed["v1.0.0"]
    world.store.save(
        A.repo,
        ProductState(
            failed={
                "v1.0.0": Failure(
                    reason=failure.reason,
                    attempts=1,
                    first_failed=NOW - DAY,
                    next_retry=NOW + 400 * DAY,
                    quarantined=False,
                    last_alert=None,
                )
            }
        ),
    )
    world.run(A)
    assert world.verify_calls == [("a-php", "v1.0.0")]


def test_the_real_verifier_and_feed_fit_the_admit_interfaces() -> None:
    """The annotations are the test: mypy fails when a signature drifts from the Protocols."""

    def as_verifier(value: Verifier) -> admit.ReleaseVerifier:
        return value

    def as_lister(transport: feed.Transport) -> admit.Lister:
        def call(repo: str, *, etag: str | None) -> Listing | Unchanged:
            return feed.list_releases(repo, transport, etag=etag)

        return call

    assert callable(as_verifier)
    assert callable(as_lister)


def test_a_skipped_product_still_raises_its_quarantine_alerts(world: World) -> None:
    _quarantine(world, last_alert=None)
    world.feeds[A.repo] = feed.NotFound("repository or releases not found (404)")
    kinds = [kind for _, _, kind in _kinds(world.run(A))]
    assert sorted(kinds) == ["product-error", "quarantine-alert"]
