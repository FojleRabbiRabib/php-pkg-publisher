# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""One publisher run: admit what can be admitted, then publish what is admitted.

The pass is written against `Stages`, so every rule here (what alerts, what fails the run, that
publishing still happens when admitting stopped) is tested without the network or the tools.
`LiveStages` is the real thing and is only assembled by `open_live`.

Exit contract, used by the service unit's `OnFailure=`: a run fails (exit 1) when the admit stage
stopped, when publishing failed, or when anything raised. A tag that failed admission, a
quarantine, a pin dropped by an exclusion and a clean-up failure after the flip are reported as
alerts and do not fail the run, because the repository is still correct and still served.
"""

from __future__ import annotations

import contextlib
import functools
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from publisher import admit, config, feed, generation, metadata, verify
from publisher import lock as locking
from publisher.alert import Alert, clean
from publisher.cache import Cache, HttpsFetcher
from publisher.lock import RunLock
from publisher.settings import Settings
from publisher.tools import ToolError, Tools

STAGE_ALERTS: Final[Mapping[str, tuple[str, bool]]] = {
    "failed": ("admit-failed", False),
    "quarantined": ("quarantined", False),
    "quarantine-alert": ("quarantined", False),
    "product-error": ("product-error", False),
    "changed": ("changed", False),
    "vanished": ("vanished", False),
}
SETUP_FAULTS: Final = (ToolError, feed.FeedError, verify.VerifyError, OSError)
REPEATING: Final = frozenset({"changed", "vanished"})


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    """What the pass did: the alerts to send and, when it failed, the reason."""

    alerts: tuple[Alert, ...]
    failure: str | None


class Stages(Protocol):
    """The parts of a pass that touch the network, the tools and the site."""

    def trusted_root(self, now: float) -> verify.TrustedRoot: ...

    def admit(self, now: float) -> admit.Report: ...

    def publish(
        self, products: config.ProductList, exclusions: config.ExclusionList, now: float
    ) -> generation.Published: ...


def excluded_pairs(
    products: config.ProductList, exclusions: config.ExclusionList
) -> frozenset[tuple[str, str]]:
    """Every (product, tag) that is excluded, whether in products.yml or exclude.yml."""
    pairs = {(item.product, item.tag) for item in exclusions.exclusions}
    pairs |= {(product.repo, tag) for product in products.products for tag in product.exclude}
    return frozenset(pairs)


def _event_alert(event: admit.Event) -> Alert:
    kind, urgent = STAGE_ALERTS[event.kind]
    where = event.product if event.tag is None else f"{event.product} {event.tag}"
    key = f"{event.kind}:{where}" if event.kind in REPEATING else None
    return Alert(kind=kind, text=clean(f"{where}: {event.detail}"), urgent=urgent, key=key)


def run_pass(
    stages: Stages,
    products: config.ProductList,
    exclusions: config.ExclusionList,
    *,
    now: float,
    log: Callable[[str], None],
) -> Result:
    """Admit, then publish from what is admitted, even when admitting stopped."""
    alerts: list[Alert] = []
    failure: str | None = None
    log(f"products {products.sha256} exclusions {exclusions.sha256}")
    try:
        trusted = stages.trusted_root(now)
        if not trusted.refreshed:
            days = trusted.age_seconds / 86400
            alerts.append(
                Alert(
                    kind="stale-trust-root", text=f"trusted root not refreshed, {days:.1f} days old"
                )
            )
        report = stages.admit(now)
    except SETUP_FAULTS as error:
        # Nothing could be verified, so nothing is admitted; publishing still re-signs what was
        # admitted earlier, otherwise Valid-Until would run out for every client.
        report = admit.Report(events=(), stopped=str(error))
    for event in report.events:
        log(f"{event.kind} {clean(event.product)} {clean(event.tag or '-')}: {clean(event.detail)}")
        if event.kind in STAGE_ALERTS:
            alerts.append(_event_alert(event))
    if report.stopped is not None:
        failure = f"admit stopped: {clean(report.stopped)}"
        alerts.append(Alert(kind="stopped", text=failure, urgent=True))
    published = stages.publish(products, exclusions, now)
    if published.skipped:
        log("publish skipped: nothing changed")
    else:
        log(f"published {published.generation}")
        held = "; pinned, new releases held" if published.pinned else ""
        alerts.append(Alert(kind="published", text=f"published {published.generation}{held}"))
    if published.pin_dropped:
        alerts.append(
            Alert(
                kind="pin-dropped", text="a rollback pin was dropped by an exclusion", urgent=True
            )
        )
    if published.retire_error is not None:
        alerts.append(
            Alert(kind="cleanup-failed", text=clean(f"clean-up failed: {published.retire_error}"))
        )
    return Result(alerts=tuple(alerts), failure=failure)


class LiveStages:
    """The real stages for one run; holds the lock, the cache and the tools."""

    def __init__(
        self,
        settings: Settings,
        products: config.ProductList,
        exclusions: config.ExclusionList,
        *,
        lock: RunLock,
        tools: Tools,
        cache: Cache,
    ) -> None:
        self._settings = settings
        self._products = products
        self._exclusions = exclusions
        self._tools = tools
        self._cache = cache
        self._store = admit.StateStore(settings.state, lock)
        self._trusted: verify.TrustedRoot | None = None

    def trusted_root(self, now: float) -> verify.TrustedRoot:
        self._trusted = verify.obtain_trusted_root(self._tools, self._settings.trust, now=now)
        return self._trusted

    def admit(self, now: float) -> admit.Report:
        if self._trusted is None:
            raise verify.VerifyError("the trusted root must be obtained before admitting")
        token = feed.read_token(self._settings.token_file)
        transport = feed.HttpsTransport(token)
        lister = functools.partial(feed.list_releases, transport=transport)
        with verify.Verifier(
            self._tools,
            rpm_key=self._settings.rpm_key,
            trusted_root=self._trusted.path,
            work=self._settings.work,
        ) as verifier:
            stage = admit.Admitter(
                self._products,
                self._exclusions,
                store=self._store,
                lister=lister,
                verifier=verifier,
                cache=self._cache,
            )
            return stage.run(now)

    def publish(
        self, products: config.ProductList, exclusions: config.ExclusionList, now: float
    ) -> generation.Published:
        states = {product.repo: self._store.load(product.repo) for product in products.products}
        entries = metadata.select(products, exclusions, states)
        return generation.publish(
            generation.open_site(self._settings.site),
            entries,
            cache=self._cache,
            tools=self._tools,
            key=self._settings.signing,
            excluded=excluded_pairs(products, exclusions),
            now=now,
        )


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@contextlib.contextmanager
def _held(settings: Settings) -> Iterator[RunLock]:
    with RunLock(settings.lock) as lock:
        yield lock


def _load(settings: Settings) -> tuple[config.ProductList, config.ExclusionList]:
    products = config.load_products(settings.products)
    return products, config.load_exclusions(settings.exclude, products)


def run_once(
    settings: Settings,
    *,
    emit: Callable[[Result], None],
    now: float | None = None,
    log: Callable[[str], None] = _log,
) -> list[Result]:
    """The `run` command: take the lock and make passes while nudges keep arriving.

    `emit` receives each pass's result as soon as the pass ends, so the alerts of a pass that
    completed are not lost when a later pass raises.
    """
    with _held(settings) as lock:

        def one_pass() -> Result:
            products, exclusions = _load(settings)
            stages = LiveStages(
                settings,
                products,
                exclusions,
                lock=lock,
                tools=Tools.locate(),
                cache=Cache(settings.cache, HttpsFetcher()),
            )
            result = run_pass(
                stages, products, exclusions, now=time.time() if now is None else now, log=log
            )
            emit(result)
            return result

        return locking.run_passes(lock, settings.nudge, one_pass)


def rollback(
    settings: Settings, identifier: str, *, now: float | None = None
) -> generation.Published:
    """The `rollback` command: re-sign an older content set as a new generation and pin it."""
    with _held(settings):
        products, exclusions = _load(settings)
        return generation.rollback(
            generation.open_site(settings.site),
            identifier,
            excluded=excluded_pairs(products, exclusions),
            cache=Cache(settings.cache, HttpsFetcher()),
            tools=Tools.locate(),
            key=settings.signing,
            now=time.time() if now is None else now,
        )


def clear_pin(settings: Settings) -> None:
    """The `clear-pin` command: let the next run publish the admitted state again."""
    with _held(settings):
        generation.clear_pin(generation.open_site(settings.site))
