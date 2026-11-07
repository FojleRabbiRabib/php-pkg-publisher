# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""What the publisher tells its operator.

An alert goes to an external service, so its text is built here and nowhere else: release and
tool output is cut to a short ASCII literal, and nothing the alert is given may be a token, a
key fingerprint or a path of this host. `key` names an event that repeats on every full
listing; the sender suppresses a repeat of the same key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

MAX_TEXT: Final = 300
KEY_ID: Final = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
HOST_PATH: Final = re.compile(r"(?<![\w/.])/[^\s'\":,;)(\]\[]+")


@dataclass(frozen=True, slots=True, kw_only=True)
class Alert:
    kind: str
    text: str
    urgent: bool = False
    key: str | None = None


def clean(text: str) -> str:
    """Release or tool text as short ASCII without host paths or key fingerprints."""
    return ascii(KEY_ID.sub("<id>", HOST_PATH.sub("<path>", text)))[:MAX_TEXT]
