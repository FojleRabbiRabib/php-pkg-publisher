# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Tell the operator that a unit failed: the `OnFailure=` entry point.

It imports only the alert sender, takes the credentials path as its own argument and sends fixed
text, so a broken `publisher.yml`, a broken publish module or a hostile journal cannot silence
it. Exit 0 when the message was accepted, 1 when it was not (the reason goes to the journal).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from publisher import alert

UNIT_NAME: Final = re.compile(r"[A-Za-z0-9_.@:-]{1,80}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m publisher.notifier")
    parser.add_argument("--alert-file", type=Path, required=True)
    parser.add_argument("--unit", required=True)
    arguments = parser.parse_args(argv)
    if not UNIT_NAME.fullmatch(arguments.unit):
        print("failed: the unit name is not valid", file=sys.stderr)
        return 1
    message = alert.Alert(
        kind="unit-failed", text=f"{arguments.unit} failed, see journal", urgent=True
    )
    try:
        ((text, silent, _),) = alert.compose([message])
        alert.Telegram(alert.read_credentials(arguments.alert_file)).send(text, silent=silent)
    except alert.AlertError as error:
        print(f"failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
