# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import pytest

from publisher import net
from publisher.alert import MAX_TEXT, clean

LEAK = 8  # a run of this many characters of a redacted value is a leak


def test_redact_replaces_a_host_path_and_a_fingerprint() -> None:
    text = f"cannot read /var/lib/x/y and {'A' * 40} here"
    assert net.redact(text) == "cannot read <path> and <id> here"


def test_redact_leaves_a_digest_and_a_relative_path_alone() -> None:
    text = f"{'c' * 64} release/notes a/b.txt"
    assert net.redact(text) == text


# The text is quoted, so the cut shows 80 - 1 - cut characters of a fingerprint that starts after
# `cut` characters; each value leaves at least LEAK of them when the cut comes before the redaction.
@pytest.mark.parametrize("cut", [40, 60, 80 - 1 - LEAK])
def test_safe_redacts_a_fingerprint_before_it_cuts(cut: int) -> None:
    shown = net.safe("x" * cut + "A" * 40)
    assert "A" * LEAK not in shown


def test_safe_redacts_a_host_path() -> None:
    shown = net.safe("cannot read /home/someone/private/file")
    assert "/home" not in shown
    assert "<path>" in shown


def test_safe_is_still_short_ascii() -> None:
    shown = net.safe("é" * 500)
    assert len(shown) == 80
    assert shown.isascii()


# The fingerprint must run past the cut (cut + 1 + 40 > MAX_TEXT) and show LEAK characters of it.
@pytest.mark.parametrize("cut", [MAX_TEXT - 40, MAX_TEXT - 20, MAX_TEXT - 1 - LEAK])
def test_clean_redacts_a_fingerprint_before_it_cuts(cut: int) -> None:
    shown = clean("x" * cut + "B" * 40)
    assert "B" * LEAK not in shown


def test_clean_redacts_a_host_path() -> None:
    shown = clean("cannot read /home/someone/private/file")
    assert "/home" not in shown
    assert "<path>" in shown
