# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The container layer's free-disk guard: a named error instead of a refused release."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from box import FREE_DISK_NEEDED, require_free_disk

from publisher.admit import MIN_FREE_BYTES


def test_the_guard_needs_headroom_above_the_admit_floor() -> None:
    assert FREE_DISK_NEEDED > MIN_FREE_BYTES


def test_a_disk_with_less_free_space_than_needed_stops_with_a_named_error(tmp_path: Path) -> None:
    free = shutil.disk_usage(tmp_path).free
    with pytest.raises(OSError, match=r"the container layer needs .* MiB free for .*only .* MiB"):
        require_free_disk(tmp_path, free + (1 << 30))


def test_a_disk_with_enough_free_space_passes(tmp_path: Path) -> None:
    require_free_disk(tmp_path, 1)
