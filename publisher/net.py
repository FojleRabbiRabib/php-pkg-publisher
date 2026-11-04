# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Pieces shared by the HTTPS clients: no redirects, bounded error text, strict headers."""

from __future__ import annotations

import urllib.request
from collections.abc import Iterable
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand every 3xx back to the caller instead of following it."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def safe(text: str) -> str:
    """Return untrusted text as a short ASCII literal that is safe to put in a message."""
    return ascii(text)[:80]


def headers(pairs: Iterable[tuple[str, str]], single: frozenset[str]) -> dict[str, str]:
    """Lowercase header names; raise ValueError when a header in `single` is repeated."""
    result: dict[str, str] = {}
    for key, value in pairs:
        name = key.lower()
        if name in result and name in single:
            raise ValueError(f"response repeats the {name} header")
        result[name] = value
    return result
