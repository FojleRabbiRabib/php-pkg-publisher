# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Command line: `python -m publisher --config publisher.yml COMMAND`.

Commands: `run`, `rollback ID`, `clear-pin`, `requeue REPO TAG`.
"""

from __future__ import annotations

import argparse
import contextlib
import signal
import sys
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import FrameType

from publisher import (
    admit,
    alert,
    cache,
    config,
    feed,
    files,
    generation,
    lock,
    metadata,
    run,
    signer,
    tools,
    verify,
)
from publisher.alert import clean
from publisher.settings import Settings, load_settings

FAULTS = (
    admit.StateError,
    alert.AlertError,
    cache.CacheError,
    config.ConfigError,
    feed.FeedError,
    files.FileError,
    generation.GenerationError,
    lock.LockError,
    metadata.MetadataError,
    signer.SigningError,
    tools.ToolError,
    verify.VerifyError,
    OSError,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m publisher")
    parser.add_argument("--config", type=Path, required=True, help="path of publisher.yml")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="admit new releases, then publish")
    back = commands.add_parser("rollback", help="re-sign an older generation's content and pin it")
    back.add_argument("generation")
    commands.add_parser("clear-pin", help="end a rollback; the next run publishes normally")
    again = commands.add_parser(
        "requeue", help="lift a failure or quarantine so the next run tries the tag again"
    )
    again.add_argument("repo")
    again.add_argument("tag")
    return parser


def _print_alerts(result: run.Result) -> None:
    for item in result.alerts:
        print(f"alert {item.kind}: {item.text}", file=sys.stderr)


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class _Emitter:
    """Log each pass's alerts to the journal, then send them (the sender is built on first use).

    A fault of the alert setup (an unusable credentials file) is logged and remembered in
    `failed`, not raised: a raise would put the run's nudge back and the service would start
    again until its start limit, while the alerts that could not be sent are already in the
    journal. The run then ends with exit 1.
    """

    def __init__(self, settings: Settings) -> None:
        self.failed = False
        self._dispatch = alert.Dispatcher(
            lambda: alert.Telegram(alert.read_credentials(settings.alert_file)),
            settings.state / "alerts.json",
            log=_stderr,
        )

    def __call__(self, result: run.Result) -> None:
        _print_alerts(result)
        try:
            self._dispatch(result.alerts, time.time())
        except alert.AlertError as error:
            self.failed = True
            _stderr(f"failed: alerts not sent: {clean(str(error))}")


@contextlib.contextmanager
def _stop_as_exit() -> Iterator[None]:
    """Turn SIGTERM (a stop, a reboot, the unit's timeout) into `SystemExit`, so the run's own
    clean-up runs and the nudge it consumed is put back. The exit status is 128 + 15."""

    def stop(signal_number: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signal_number)

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        settings = load_settings(arguments.config)
        if arguments.command == "run":
            emitter = _Emitter(settings)
            with _stop_as_exit():
                results = run.run_once(settings, emit=emitter)
            failures = [r.failure for r in results if r.failure is not None]
            for failure in failures:
                print(f"failed: {failure}", file=sys.stderr)
            return 1 if failures or emitter.failed else 0
        if arguments.command == "rollback":
            done = run.rollback(settings, arguments.generation)
            print(f"rolled back: new generation {done.generation}, pinned until clear-pin")
            if done.repaired:
                print(f"store repaired: {len(done.repaired)} hash-named files restored")
            if done.lost:
                print(f"store lost: {len(done.lost)} hash-named files have no copy")
            return 0
        if arguments.command == "requeue":
            run.requeue(settings, arguments.repo, arguments.tag)
            print(f"requeued: {clean(arguments.repo)} {clean(arguments.tag)}")
            return 0
        run.clear_pin(settings)
        print("pin cleared")
        return 0
    except FAULTS as error:
        print(f"failed: {clean(str(error))}", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"failed: unexpected {type(error).__name__}: {clean(str(error))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
