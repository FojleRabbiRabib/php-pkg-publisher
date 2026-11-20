# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
HANG = "import time\n\n\ndef test_hangs() -> None:\n    time.sleep(120)\n"


def test_the_suite_gives_every_test_a_time_limit(pytestconfig: pytest.Config) -> None:
    assert 0 < float(pytestconfig.getini("timeout")) <= 120


RECORDER = """
def pytest_collection_finish(session):
    for item in session.items:
        marker = item.get_closest_marker("timeout")
        print("TIMEOUT", marker.args[0] if marker else None)
"""


def test_every_container_test_gets_a_limit_below_the_ci_job_limit(tmp_path: Path) -> None:
    (tmp_path / "recorder.py").write_text(RECORDER, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    command = [sys.executable, "-m", "pytest", "-m", "container", "--collect-only", "-q", "-s"]
    done = subprocess.run(  # noqa: S603
        [*command, "-p", "recorder", "-p", "no:cacheprovider"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0
    limits = {line.split()[1] for line in done.stdout.splitlines() if line.startswith("TIMEOUT")}
    assert len(limits) == 1
    (limit,) = limits
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job_seconds = workflow["jobs"]["container-image"]["timeout-minutes"] * 60
    assert limit.isdigit()
    assert int(limit) < job_seconds  # else the job limit stops a hung test first, without a stack


def test_a_hung_test_is_stopped_and_reported_as_a_failure(tmp_path: Path) -> None:
    (tmp_path / "test_hang.py").write_text(HANG, encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--timeout=2", "test_hang.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 1
    assert "Timeout (>2.0s) from pytest-timeout" in done.stdout
