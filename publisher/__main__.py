# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Command line: `python -m publisher --config publisher.yml run | rollback ID | clear-pin`."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

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
    return parser


def _print_alerts(result: run.Result) -> None:
    for item in result.alerts:
        print(f"alert {item.kind}: {item.text}", file=sys.stderr)


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _emitter(settings: Settings) -> Callable[[run.Result], None]:
    """Log each pass's alerts to the journal, then send them (the sender is built on first use)."""
    dispatch = alert.Dispatcher(
        lambda: alert.Telegram(alert.read_credentials(settings.alert_file)),
        settings.state / "alerts.json",
        log=_stderr,
    )

    def emit(result: run.Result) -> None:
        _print_alerts(result)
        dispatch(result.alerts, time.time())

    return emit


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        settings = load_settings(arguments.config)
        if arguments.command == "run":
            results = run.run_once(settings, emit=_emitter(settings))
            failures = [r.failure for r in results if r.failure is not None]
            for failure in failures:
                print(f"failed: {failure}", file=sys.stderr)
            return 1 if failures else 0
        if arguments.command == "rollback":
            done = run.rollback(settings, arguments.generation)
            print(f"rolled back: new generation {done.generation}, pinned until clear-pin")
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
