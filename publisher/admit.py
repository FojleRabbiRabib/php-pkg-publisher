# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The admit stage: decide, tag by tag, which releases of each product may be served.

Per product the stage keeps a state file: the tags admitted so far with the packages that were
verified, the tags that failed (attempts, backoff, quarantine) and the last listing (its etag
and tag set). Admission is per tag, so one bad tag never blocks a later tag or another
product, and a tag that was admitted is never dropped because a later check fails.

Three tiers of error:
  * per tag: the release breaks a rule or its download fails (Rejected, DownloadError, not
    immutable). It is recorded as a failure with backoff; five attempts over three days
    quarantine the tag until an operator excludes or requeues it.
  * per product: GitHub cannot list the product, or it declares something unsupported. The
    product is skipped and its state is left as it was.
  * whole stage: a fault of this host (missing tool, unusable cache or state, low disk space,
    rejected token, rate limit). The stage stops, no counter changes, and the report says why,
    so publishing can still run from what is already admitted.

The caller holds the run lock (lock.py); `now` is passed in so every rule is testable.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from publisher import config, feed, files, net
from publisher.cache import MAX_ASSET_BYTES, Cache, CacheDirectoryError, DownloadError
from publisher.feed import Listing, Release, Unchanged
from publisher.lock import RunLock
from publisher.tools import ToolError
from publisher.verify import Rejected, Unsupported, Verified

STATE_VERSION: Final = 1
STATE_TEMPORARY: Final = ".state-"  # a repo name cannot start with a dot, so no clash
PRODUCTS_DIRECTORY: Final = "products"
MAX_STATE_BYTES: Final = 8 * 1024 * 1024
MAX_REASON_LENGTH: Final = 300
MIN_FREE_BYTES: Final = 2 * MAX_ASSET_BYTES

HOUR: Final = 3600.0
DAY: Final = 24 * HOUR
BACKOFF_SECONDS: Final = (HOUR, 6 * HOUR, DAY)
QUARANTINE_ATTEMPTS: Final = 5
QUARANTINE_AGE_SECONDS: Final = 3 * DAY
ALERT_INTERVAL_SECONDS: Final = DAY
FULL_LISTING_SECONDS: Final = 7 * DAY

Kind = Literal["final", "prerelease"]
FINAL_ONLY: Final[frozenset[Kind]] = frozenset({"final"})
ALL_KINDS: Final[frozenset[Kind]] = frozenset({"final", "prerelease"})

SHA256: Final = re.compile(r"[0-9a-f]{64}")
DIGEST_PREFIX: Final = "sha256:"
PACKAGE_KINDS: Final = frozenset({"deb", "rpm"})
PACKAGE_LAYOUTS: Final = frozenset({"deb", "base", "versioned"})


class StateError(Exception):
    """A state file is unreadable, malformed or cannot be written; it is never read as empty."""


class _Stop(Exception):
    """A fault of this host: stop the whole stage."""


class _SkipProduct(Exception):
    """Nothing more can be done for this product in this run."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmittedPackage:
    name: str
    kind: str
    layout: str
    php: str
    arch: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmittedTag:
    admitted_at: float
    packages: tuple[AdmittedPackage, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Failure:
    reason: str
    attempts: int
    first_failed: float
    next_retry: float
    quarantined: bool
    last_alert: float | None


@dataclass(slots=True, kw_only=True)
class ProductState:
    etag: str | None = None
    listed: tuple[str, ...] = ()
    listed_at: float | None = None
    admitted: dict[str, AdmittedTag] = field(default_factory=dict)
    failed: dict[str, Failure] = field(default_factory=dict)


EventKind = Literal[
    "admitted", "failed", "quarantined", "quarantine-alert", "changed", "vanished", "product-error"
]


@dataclass(frozen=True, slots=True, kw_only=True)
class Event:
    product: str
    tag: str | None
    kind: EventKind
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Report:
    events: tuple[Event, ...]
    stopped: str | None


class Lister(Protocol):
    def __call__(self, repo: str, *, etag: str | None) -> Listing | Unchanged: ...


class ReleaseVerifier(Protocol):
    def verify(self, product: config.Product, release: Release, cache: Cache) -> Verified: ...


def _bad(path: Path, message: str) -> StateError:
    return StateError(f"{path}: {message}")


def _exact(path: Path, value: Any, keys: frozenset[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _bad(path, f"{what} must be an object with exactly the keys {sorted(keys)}")
    return value


def _number(path: Path, value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _bad(path, f"{what} must be a number")
    if not math.isfinite(value) or value < 0:
        raise _bad(path, f"{what} must be a finite, non-negative number")
    return float(value)


def _count(path: Path, value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _bad(path, f"{what} must be a non-negative integer")
    return value


def _text(path: Path, value: Any, what: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or (pattern is not None and not pattern.fullmatch(value)):
        raise _bad(path, f"{what} is not valid")
    return value


def _tag(path: Path, value: Any, what: str) -> str:
    return _text(path, value, what, config.RELEASE_TAG)


def _package(path: Path, raw: Any) -> AdmittedPackage:
    keys = frozenset({"name", "kind", "layout", "php", "arch", "sha256", "size"})
    item = _exact(path, raw, keys, "a package")
    package = AdmittedPackage(
        name=_text(path, item["name"], "package name", feed.ASSET_NAME),
        kind=_text(path, item["kind"], "package kind"),
        layout=_text(path, item["layout"], "package layout"),
        php=_text(path, item["php"], "package php"),
        arch=_text(path, item["arch"], "package arch"),
        sha256=_text(path, item["sha256"], "package sha256", SHA256),
        size=_count(path, item["size"], "package size"),
    )
    if (
        package.kind not in PACKAGE_KINDS
        or package.layout not in PACKAGE_LAYOUTS
        or package.php not in config.PHP_VERSIONS
        or package.arch not in config.ARCHITECTURES
    ):
        raise _bad(path, "a package declares an unknown kind, layout, php or arch")
    return package


def _admitted(path: Path, raw: Any) -> dict[str, AdmittedTag]:
    if not isinstance(raw, dict):
        raise _bad(path, "admitted must be an object")
    result: dict[str, AdmittedTag] = {}
    for tag, value in raw.items():
        item = _exact(path, value, frozenset({"admitted_at", "packages"}), "an admitted tag")
        packages = item["packages"]
        if not isinstance(packages, list) or not packages:
            raise _bad(path, "an admitted tag needs a non-empty package list")
        result[_tag(path, tag, "admitted tag")] = AdmittedTag(
            admitted_at=_number(path, item["admitted_at"], "admitted_at"),
            packages=tuple(_package(path, package) for package in packages),
        )
    return result


def _failed(path: Path, raw: Any) -> dict[str, Failure]:
    if not isinstance(raw, dict):
        raise _bad(path, "failed must be an object")
    keys = frozenset(
        {"reason", "attempts", "first_failed", "next_retry", "quarantined", "last_alert"}
    )
    result: dict[str, Failure] = {}
    for tag, value in raw.items():
        item = _exact(path, value, keys, "a failure")
        quarantined = item["quarantined"]
        last_alert = item["last_alert"]
        if not isinstance(quarantined, bool):
            raise _bad(path, "quarantined must be true or false")
        result[_tag(path, tag, "failed tag")] = Failure(
            reason=_text(path, item["reason"], "failure reason"),
            attempts=_count(path, item["attempts"], "attempts"),
            first_failed=_number(path, item["first_failed"], "first_failed"),
            next_retry=_number(path, item["next_retry"], "next_retry"),
            quarantined=quarantined,
            last_alert=None if last_alert is None else _number(path, last_alert, "last_alert"),
        )
    return result


def _parse(path: Path, raw: bytes) -> ProductState:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=net.no_duplicate_keys)
    except (ValueError, RecursionError) as error:
        raise _bad(path, f"not valid JSON: {error}") from error
    keys = frozenset({"version", "etag", "listed", "listed_at", "admitted", "failed"})
    item = _exact(path, document, keys, "the state")
    if item["version"] != STATE_VERSION or isinstance(item["version"], bool):
        raise _bad(path, f"unsupported state version {net.safe(str(item['version']))}")
    etag = item["etag"]
    if etag is not None and (not isinstance(etag, str) or not feed.ETAG.fullmatch(etag)):
        raise _bad(path, "etag is not valid")
    listed = item["listed"]
    if not isinstance(listed, list):
        raise _bad(path, "listed must be a list")
    tags = tuple(_tag(path, tag, "listed tag") for tag in listed)
    if len(set(tags)) != len(tags):
        raise _bad(path, "listed repeats a tag")
    listed_at = item["listed_at"]
    state = ProductState(
        etag=etag,
        listed=tags,
        listed_at=None if listed_at is None else _number(path, listed_at, "listed_at"),
        admitted=_admitted(path, item["admitted"]),
        failed=_failed(path, item["failed"]),
    )
    if state.admitted.keys() & state.failed.keys():
        raise _bad(path, "a tag is both admitted and failed")
    return state


def _serialise(state: ProductState) -> bytes:
    document = {
        "version": STATE_VERSION,
        "etag": state.etag,
        "listed": list(state.listed),
        "listed_at": state.listed_at,
        "admitted": {
            tag: {
                "admitted_at": item.admitted_at,
                "packages": [
                    {
                        "name": p.name,
                        "kind": p.kind,
                        "layout": p.layout,
                        "php": p.php,
                        "arch": p.arch,
                        "sha256": p.sha256,
                        "size": p.size,
                    }
                    for p in item.packages
                ],
            }
            for tag, item in sorted(state.admitted.items())
        },
        "failed": {
            tag: {
                "reason": f.reason,
                "attempts": f.attempts,
                "first_failed": f.first_failed,
                "next_retry": f.next_retry,
                "quarantined": f.quarantined,
                "last_alert": f.last_alert,
            }
            for tag, f in sorted(state.failed.items())
        },
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


class StateStore:
    """One JSON file per product in a private directory; written atomically, read strictly."""

    def __init__(self, directory: Path, lock: RunLock) -> None:
        lock.require_held()
        try:
            files.require_private_directory(directory)
            self._directory = directory / PRODUCTS_DIRECTORY
            self._directory.mkdir(mode=0o700, exist_ok=True)
            files.require_private_directory(self._directory)
            files.sweep_temporary(self._directory, STATE_TEMPORARY, older_than=math.inf)
        except (files.FileError, OSError) as error:
            raise StateError(f"{directory}: state directory unusable: {error}") from error

    def path(self, repo: str) -> Path:
        if not config.REPO_NAME.fullmatch(repo) or ".." in repo:
            raise StateError(f"invalid repo name {net.safe(repo)}")
        return self._directory / f"{repo}.json"

    def load(self, repo: str) -> ProductState:
        path = self.path(repo)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            return ProductState()
        except OSError as error:
            raise _bad(path, f"cannot open: {error.strerror or error}") from error
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise _bad(path, "must be a regular file private to the current user")
            raw = handle.read(MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise _bad(path, "is too large")
        return _parse(path, raw)

    def save(self, repo: str, state: ProductState) -> None:
        path = self.path(repo)
        try:
            files.write_atomic(path, _serialise(state), prefix=STATE_TEMPORARY)
            path.chmod(0o600)
        except OSError as error:
            raise _bad(path, f"cannot write: {error.strerror or error}") from error


def requeue(store: StateStore, repo: str, tag: str) -> None:
    """Lift a failure or a quarantine so the next run tries the tag again."""
    state = store.load(repo)
    if tag not in state.failed:
        raise StateError(f"{repo} {net.safe(tag)} has no recorded failure")
    del state.failed[tag]
    store.save(repo, state)


def _kind(tag: str) -> Kind:
    return "final" if config.FINAL_TAG.fullmatch(tag) else "prerelease"


def _order(tag: str) -> tuple[int, ...]:
    return tuple(int(number) for number in re.findall(r"[0-9]+", tag))


def _reason(error: Exception) -> str:
    return net.safe(str(error))[:MAX_REASON_LENGTH] if str(error) else type(error).__name__


class Admitter:
    """Runs the admit stage for every product; build one per run, call `run` once."""

    def __init__(
        self,
        products: config.ProductList,
        exclusions: config.ExclusionList,
        *,
        store: StateStore,
        lister: Lister,
        verifier: ReleaseVerifier,
        cache: Cache,
        kinds: frozenset[Kind] = FINAL_ONLY,
    ) -> None:
        self._products = products.products
        self._exclusions = exclusions.exclusions
        self._store = store
        self._lister = lister
        self._verifier = verifier
        self._cache = cache
        self._kinds = kinds
        self._events: list[Event] = []

    def run(self, now: float) -> Report:
        """Admit what can be admitted; returns what happened and why it stopped, if it did."""
        self._events = []
        stopped: str | None = None
        try:
            try:
                files.require_free_space(self._cache.root, MIN_FREE_BYTES)
            except files.FileError as error:
                raise _Stop(str(error)) from error
            for product in self._products:
                try:
                    self._product(product, now)
                except _SkipProduct as skip:
                    self._event(product.repo, None, "product-error", str(skip))
        except _Stop as stop:
            stopped = str(stop)
        return Report(events=tuple(self._events), stopped=stopped)

    def _event(self, product: str, tag: str | None, kind: EventKind, detail: str) -> None:
        self._events.append(Event(product=product, tag=tag, kind=kind, detail=detail))

    def _excluded(self, product: config.Product) -> frozenset[str]:
        listed = {e.tag for e in self._exclusions if e.product == product.repo}
        return frozenset(listed | set(product.exclude))

    def _wanted(self, tag: str, excluded: frozenset[str]) -> bool:
        return tag not in excluded and _kind(tag) in self._kinds

    def _load(self, repo: str) -> ProductState:
        try:
            return self._store.load(repo)
        except StateError as error:
            raise _Stop(str(error)) from error

    def _save(self, repo: str, state: ProductState) -> None:
        try:
            self._store.save(repo, state)
        except StateError as error:
            raise _Stop(str(error)) from error

    def _product(self, product: config.Product, now: float) -> None:
        repo = product.repo
        state = self._load(repo)
        excluded = self._excluded(product)
        cleared = [tag for tag in state.failed if tag in excluded]
        for tag in cleared:
            del state.failed[tag]
        if cleared:
            self._save(repo, state)
        try:
            self._list_and_apply(product, state, excluded, now)
        except _SkipProduct:
            self._remind(repo, state, now)
            raise
        self._remind(repo, state, now)

    def _list_and_apply(
        self, product: config.Product, state: ProductState, excluded: frozenset[str], now: float
    ) -> None:
        repo = product.repo
        try:
            listing = self._lister(repo, etag=self._etag_to_send(state, excluded, now))
        except (feed.AuthError, feed.RateLimited) as error:
            raise _Stop(f"{repo}: {_reason(error)}") from error
        except feed.FeedError as error:
            raise _SkipProduct(f"cannot list releases: {_reason(error)}") from error
        if isinstance(listing, Listing):
            self._apply(product, state, listing, excluded, now)

    def _etag_to_send(
        self, state: ProductState, excluded: frozenset[str], now: float
    ) -> str | None:
        """Use the etag only when nothing is waiting to be admitted or retried."""
        if state.etag is None or state.listed_at is None:
            return None
        if not 0 <= now - state.listed_at < FULL_LISTING_SECONDS:
            return None
        if any(not failure.quarantined for failure in state.failed.values()):
            return None
        quarantined = {tag for tag, failure in state.failed.items() if failure.quarantined}
        waiting = {
            tag
            for tag in state.listed
            if self._wanted(tag, excluded) and tag not in state.admitted and tag not in quarantined
        }
        return None if waiting else state.etag

    def _apply(
        self,
        product: config.Product,
        state: ProductState,
        listing: Listing,
        excluded: frozenset[str],
        now: float,
    ) -> None:
        repo = product.repo
        rejected = {item.tag: item.reason for item in listing.rejected}
        present = {release.tag for release in listing.releases} | rejected.keys()
        state.etag = listing.etag
        state.listed_at = now
        state.listed = tuple(sorted(present, key=_order))
        for tag in sorted(state.admitted.keys() - present, key=_order):
            self._event(repo, tag, "vanished", "an admitted tag is no longer listed")
        for tag in [tag for tag in state.failed if tag not in present]:
            del state.failed[tag]
        self._save(repo, state)
        for tag in sorted(rejected, key=_order, reverse=True):
            if (
                self._wanted(tag, excluded)
                and tag not in state.admitted
                and self._due(state, tag, now)
            ):
                self._fail(repo, state, tag, rejected[tag], now)
        for release in sorted(listing.releases, key=lambda r: _order(r.tag), reverse=True):
            if not self._wanted(release.tag, excluded):
                continue
            if release.tag in state.admitted:
                self._check_unchanged(repo, state.admitted[release.tag], release)
            elif self._due(state, release.tag, now):
                self._attempt(product, state, release, now)

    @staticmethod
    def _due(state: ProductState, tag: str, now: float) -> bool:
        failure = state.failed.get(tag)
        if failure is None:
            return True
        # A retry date further away than the longest backoff came from a clock step or damage.
        too_far = failure.next_retry > now + BACKOFF_SECONDS[-1]
        return not failure.quarantined and (now >= failure.next_retry or too_far)

    def _check_unchanged(self, repo: str, admitted: AdmittedTag, release: Release) -> None:
        assets = {asset.name: asset for asset in release.assets}
        for package in admitted.packages:
            asset = assets.get(package.name)
            if asset is None or asset.digest != f"{DIGEST_PREFIX}{package.sha256}":
                self._event(repo, release.tag, "changed", f"{package.name} differs from admission")

    def _attempt(
        self, product: config.Product, state: ProductState, release: Release, now: float
    ) -> None:
        repo = product.repo
        try:
            if not release.immutable:
                raise Rejected("the release is not immutable")
            verified = self._verifier.verify(product, release, self._cache)
        except (Rejected, DownloadError) as error:
            self._fail(repo, state, release.tag, _reason(error), now)
        except Unsupported as error:
            raise _SkipProduct(_reason(error)) from error
        except (ToolError, CacheDirectoryError, OSError) as error:
            raise _Stop(f"{repo} {release.tag}: {_reason(error)}") from error
        else:
            self._admit(repo, state, release, verified, now)

    def _admit(
        self, repo: str, state: ProductState, release: Release, verified: Verified, now: float
    ) -> None:
        assets = {asset.name: asset for asset in release.assets}
        packages: list[AdmittedPackage] = []
        for item in verified.packages:
            package = item.package
            asset = assets[package.name]
            digest = asset.digest or ""
            if not digest.startswith(DIGEST_PREFIX):
                raise _Stop(f"{repo} {release.tag}: {package.name} has no usable digest")
            packages.append(
                AdmittedPackage(
                    name=package.name,
                    kind=package.kind,
                    layout=package.layout,
                    php=package.php,
                    arch=package.arch,
                    sha256=digest[len(DIGEST_PREFIX) :],
                    size=asset.size,
                )
            )
        state.admitted[release.tag] = AdmittedTag(admitted_at=now, packages=tuple(packages))
        state.failed.pop(release.tag, None)
        self._save(repo, state)
        self._event(repo, release.tag, "admitted", f"{len(packages)} packages verified")

    def _fail(self, repo: str, state: ProductState, tag: str, reason: str, now: float) -> None:
        old = state.failed.get(tag)
        attempts = (old.attempts if old else 0) + 1
        first = old.first_failed if old else now
        delay = BACKOFF_SECONDS[min(attempts, len(BACKOFF_SECONDS)) - 1]
        quarantined = attempts >= QUARANTINE_ATTEMPTS and now - first >= QUARANTINE_AGE_SECONDS
        state.failed[tag] = Failure(
            reason=reason,
            attempts=attempts,
            first_failed=first,
            next_retry=now + delay,
            quarantined=quarantined,
            last_alert=now if quarantined else None,
        )
        self._save(repo, state)
        self._event(repo, tag, "failed", f"attempt {attempts}: {reason}")
        if quarantined:
            self._event(repo, tag, "quarantined", f"after {attempts} attempts: {reason}")

    def _remind(self, repo: str, state: ProductState, now: float) -> None:
        """Raise the daily alert for each quarantined tag until an operator deals with it."""
        changed = False
        for tag, failure in sorted(state.failed.items()):
            due = failure.last_alert is None or not (
                0 <= now - failure.last_alert < ALERT_INTERVAL_SECONDS
            )
            if failure.quarantined and due:
                state.failed[tag] = Failure(
                    reason=failure.reason,
                    attempts=failure.attempts,
                    first_failed=failure.first_failed,
                    next_retry=failure.next_retry,
                    quarantined=True,
                    last_alert=now,
                )
                self._event(repo, tag, "quarantine-alert", failure.reason)
                changed = True
        if changed:
            self._save(repo, state)
