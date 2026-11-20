# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Pieces shared by the HTTPS clients: no redirects, bounded error text, strict headers."""

from __future__ import annotations

import re
import urllib.request
from collections.abc import Iterable
from typing import Any, Final

KEY_ID: Final = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
HOST_PATH: Final = re.compile(r"(?<![\w/.])/[^\s'\":,;)(\]\[]+")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand every 3xx back to the caller instead of following it."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def redact(text: str) -> str:
    """Replace host paths and key fingerprints; do it before any cut, which could split one."""
    return KEY_ID.sub("<id>", HOST_PATH.sub("<path>", text))


def safe(text: str) -> str:
    """Return untrusted text as a short ASCII literal that is safe to put in a message."""
    return ascii(redact(text))[:80]


class DuplicateKey(ValueError):
    """A JSON object repeats a key."""


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """`object_pairs_hook` for json.loads that refuses a repeated key."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"repeats the key {safe(key)}")
        result[key] = value
    return result


def headers(pairs: Iterable[tuple[str, str]], single: frozenset[str]) -> dict[str, str]:
    """Lowercase header names; raise ValueError when a header in `single` is repeated."""
    result: dict[str, str] = {}
    for key, value in pairs:
        name = key.lower()
        if name in result and name in single:
            raise ValueError(f"response repeats the {name} header")
        result[name] = value
    return result
