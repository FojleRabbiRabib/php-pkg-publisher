# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The `status` command: a read-only view of what the publisher is doing and has done.

It shows whether a run is working, the tags each product accepted last, the tags that failed
with their next retry or wait in quarantine, and how many repeated webhook deliveries the
receiver counted. It takes no lock, creates nothing and removes nothing, so it can run while a
run is working. A part that cannot be read is shown as unreadable and the rest is still shown;
no path, fingerprint or secret is printed. Run it as the publisher user: the state is private.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from publisher import admit, config, lock
from publisher.alert import clean
from publisher.settings import Settings

NEWEST: Final = 5
DUPLICATES_FILE: Final = "duplicates"
# the window in which the receiver treats a delivery id that comes again as a repeat
REPEAT_WINDOW_SECONDS: Final = 120
MAX_DUPLICATES_BYTES: Final = 64
DUPLICATES: Final = re.compile(r"([0-9]{1,9}) ([0-9]{1,12})\n?")


@dataclass(frozen=True, slots=True, kw_only=True)
class Accepted:
    tag: str
    at: float


@dataclass(frozen=True, slots=True, kw_only=True)
class Failing:
    tag: str
    attempts: int
    quarantined: bool
    due: bool
    retry: float | None
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Product:
    repo: str
    readable: bool
    accepted_total: int
    accepted: tuple[Accepted, ...]
    failing: tuple[Failing, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Repeats:
    count: int
    last: float | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Status:
    now: float
    working: bool | None
    requested: bool | None
    products: tuple[Product, ...] | None
    repeats: Repeats | None


def when(timestamp: float) -> str:
    """A UTC time stamp such as `2026-01-31T09:05:00Z`."""
    try:
        moment = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "unknown time"
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_repeats(path: Path) -> Repeats | None:
    """The receiver's count of repeated deliveries; none recorded yet is a count of zero.

    The file belongs to the web server's user, so it is read as untrusted: a regular file, a
    few bytes, exactly `<count> <time>`. A file that is still empty is the instant between the
    receiver creating it and writing the first count, so it is a count of zero too.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return Repeats(count=0, last=None)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None
            raw = handle.read(MAX_DUPLICATES_BYTES + 1)
    except OSError:
        return None
    if not raw:
        return Repeats(count=0, last=None)
    found = DUPLICATES.fullmatch(raw.decode("ascii", errors="replace"))
    if found is None:
        return None
    return Repeats(count=int(found[1]), last=float(found[2]))


def _failing(tag: str, item: admit.Failure, now: float) -> Failing:
    # the admit stage decides what is due, so the view says what the next run will do
    due = admit.retry_due(item, now)
    return Failing(
        tag=tag,
        attempts=item.attempts,
        quarantined=item.quarantined,
        due=due,
        retry=None if item.quarantined or due else item.next_retry,
        reason=clean(item.reason),
    )


def _product(directory: Path, repo: str, now: float) -> Product:
    name = repo if config.REPO_NAME.fullmatch(repo) else clean(repo)
    try:
        state = admit.read_state(admit.state_file(directory, repo))
    except (admit.StateError, OSError):
        return Product(repo=name, readable=False, accepted_total=0, accepted=(), failing=())
    newest = sorted(
        state.admitted.items(),
        key=lambda item: (item[1].admitted_at, admit.tag_order(item[0])),
        reverse=True,
    )
    failing = sorted(state.failed.items(), key=lambda item: admit.tag_order(item[0]), reverse=True)
    return Product(
        repo=name,
        readable=True,
        accepted_total=len(newest),
        accepted=tuple(Accepted(tag=tag, at=item.admitted_at) for tag, item in newest[:NEWEST]),
        failing=tuple(_failing(tag, item, now) for tag, item in failing),
    )


def gather(settings: Settings, now: float) -> Status:
    """Read everything the view shows; nothing is locked, created or changed."""
    try:
        repos = admit.recorded_products(settings.state)
    except OSError:
        products = None
    else:
        products = tuple(_product(settings.state, repo, now) for repo in repos)
    try:
        requested: bool | None = lock.pending(settings.nudge)
    except lock.LockError:
        requested = None
    return Status(
        now=now,
        working=lock.busy(settings.lock),
        requested=requested,
        products=products,
        repeats=read_repeats(settings.nudge.with_name(DUPLICATES_FILE)),
    )


def _publisher(working: bool | None) -> str:
    return "unknown" if working is None else "working" if working else "idle"


def _yes(value: bool | None) -> str:
    return "unknown" if value is None else "yes" if value else "no"


def _failing_line(item: Failing) -> str:
    if item.quarantined:
        state = f"quarantined after {item.attempts} attempts, needs requeue or exclude"
    elif item.due or item.retry is None:
        state = f"attempt {item.attempts}, retry due"
    else:
        state = f"attempt {item.attempts}, retry {when(item.retry)}"
    return f"    {item.tag}  {state}, {item.reason}"


def render_text(status: Status) -> str:
    lines = [
        f"status as of {when(status.now)}",
        f"publisher: {_publisher(status.working)}",
        f"run requested: {_yes(status.requested)}",
    ]
    if status.products is None:
        lines.append("products: unreadable")
    else:
        lines.append(f"products: {len(status.products)}")
    for product in status.products or ():
        lines += ["", product.repo]
        if not product.readable:
            lines.append("  state: unreadable")
            continue
        if not product.accepted:
            lines.append("  accepted: none")
        else:
            shown = len(product.accepted)
            of = "" if shown == product.accepted_total else f"newest {shown} of "
            lines.append(f"  accepted ({of}{product.accepted_total}):")
            lines += [f"    {item.tag}  {when(item.at)}" for item in product.accepted]
        if not product.failing:
            lines.append("  failed: none")
        else:
            lines.append("  failed:")
            lines += [_failing_line(item) for item in product.failing]
    lines.append("")
    label = f"repeated deliveries (again within {REPEAT_WINDOW_SECONDS} s)"
    if status.repeats is None:
        lines.append(f"{label}: unreadable")
    elif status.repeats.last is None:
        lines.append(f"{label}: none counted")
    else:
        lines.append(f"{label}: {status.repeats.count}, last {when(status.repeats.last)}")
    return "\n".join(lines)


def render_json(status: Status) -> str:
    products = (
        None
        if status.products is None
        else [
            {
                "repo": product.repo,
                "readable": product.readable,
                "accepted_total": product.accepted_total,
                "accepted": [{"tag": item.tag, "at": when(item.at)} for item in product.accepted],
                "failed": [
                    {
                        "tag": item.tag,
                        "attempts": item.attempts,
                        "quarantined": item.quarantined,
                        "due": item.due,
                        "retry": None if item.retry is None else when(item.retry),
                        "reason": item.reason,
                    }
                    for item in product.failing
                ],
            }
            for product in status.products
        ]
    )
    repeats = (
        None
        if status.repeats is None
        else {
            "count": status.repeats.count,
            "last": None if status.repeats.last is None else when(status.repeats.last),
            "window_seconds": REPEAT_WINDOW_SECONDS,
        }
    )
    document = {
        "as_of": when(status.now),
        "publisher": _publisher(status.working),
        "run_requested": status.requested,
        "products": products,
        "repeated_deliveries": repeats,
    }
    return json.dumps(document, indent=2)
