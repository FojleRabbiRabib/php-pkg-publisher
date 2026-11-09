# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The systemd units in deploy/systemd: what they start, how they fail, how they are fenced."""

from __future__ import annotations

import configparser
import shlex
from pathlib import Path

import pytest

from publisher import notifier

DIRECTORY = Path(__file__).resolve().parents[2] / "deploy" / "systemd"
SERVICES = ["php-pkg-publisher.service", "php-pkg-publisher-watch.service"]
NOTIFY = "php-pkg-publisher-notify@.service"
ALL = sorted(path.name for path in DIRECTORY.iterdir())


def _unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read(DIRECTORY / name, encoding="utf-8")
    return parser


def _exec(name: str) -> list[str]:
    return shlex.split(_unit(name)["Service"]["ExecStart"])


def test_the_expected_units_exist() -> None:
    assert (
        sorted(
            [
                NOTIFY,
                "php-pkg-publisher.path",
                "php-pkg-publisher.service",
                "php-pkg-publisher.timer",
                "php-pkg-publisher-watch.service",
                "php-pkg-publisher-watch.timer",
            ]
        )
        == ALL
    )


@pytest.mark.parametrize("name", ALL)
def test_every_unit_carries_the_licence_header(name: str) -> None:
    head = (DIRECTORY / name).read_text(encoding="utf-8").splitlines()[:2]
    assert head[0] == "# SPDX-License-Identifier: Apache-2.0"
    assert head[1].startswith("# Copyright 2026 ")


@pytest.mark.parametrize("name", [*SERVICES, NOTIFY])
def test_services_run_one_python_module_without_a_shell(name: str) -> None:
    command = _exec(name)
    assert command[:3] == ["/usr/bin/python3", "-s", "-m"]
    assert command[3].startswith("publisher")
    text = (DIRECTORY / name).read_text(encoding="utf-8")
    assert "/bin/sh" not in text
    assert "bash" not in text
    unit = _unit(name)["Service"]
    assert unit["Type"] == "oneshot"
    assert unit["User"] == "php-pkg-publisher"
    assert not any(line.startswith(("ExecStartPre", "ExecStartPost")) for line in text.splitlines())


@pytest.mark.parametrize("name", [*SERVICES, NOTIFY])
def test_every_service_has_a_start_timeout(name: str) -> None:
    # a hung resolver in the notifier would otherwise hang the alarm itself
    assert _unit(name)["Service"]["TimeoutStartSec"]


@pytest.mark.parametrize("name", [*SERVICES, "php-pkg-publisher.path"])
def test_failures_go_to_the_notifier_by_unit_name(name: str) -> None:
    assert _unit(name)["Unit"]["OnFailure"] == "php-pkg-publisher-notify@%n.service"


def test_the_notifier_does_not_notify_about_itself() -> None:
    assert "OnFailure" not in _unit(NOTIFY)["Unit"]


def test_the_notifier_gets_the_instance_text_not_the_unescaped_path() -> None:
    command = _exec(NOTIFY)
    assert command[command.index("--unit") + 1] == "%i"  # %I would turn dashes into slashes
    assert "%I" not in " ".join(command)
    for service in [*SERVICES, "php-pkg-publisher.path"]:
        assert notifier.UNIT_NAME.fullmatch(service)


def test_the_notifier_is_independent_of_the_settings_file() -> None:
    text = (DIRECTORY / NOTIFY).read_text(encoding="utf-8")
    assert "publisher.yml" not in text
    assert "--alert-file" in text


def test_the_path_unit_starts_the_publisher_on_the_nudge() -> None:
    path = _unit("php-pkg-publisher.path")["Path"]
    assert path["PathExists"].endswith("/nudge/sync")
    assert path["Unit"] == "php-pkg-publisher.service"


def test_a_restored_nudge_cannot_restart_the_publisher_for_ever() -> None:
    unit = _unit("php-pkg-publisher.service")["Unit"]
    assert int(unit["StartLimitBurst"]) <= 5
    assert int(unit["StartLimitIntervalSec"]) >= 60


def test_the_timers_start_their_services_and_survive_downtime() -> None:
    for timer in ("php-pkg-publisher.timer", "php-pkg-publisher-watch.timer"):
        parser = _unit(timer)
        assert parser["Timer"]["Persistent"] == "true"
        assert parser["Timer"]["RandomizedDelaySec"]
        assert parser["Install"]["WantedBy"] == "timers.target"
    assert _unit("php-pkg-publisher-watch.timer")["Timer"]["OnCalendar"] == "hourly"
    assert "03:17" in _unit("php-pkg-publisher.timer")["Timer"]["OnCalendar"]


@pytest.mark.parametrize("name", [*SERVICES, NOTIFY])
def test_services_are_fenced(name: str) -> None:
    service = _unit(name)["Service"]
    for key, value in {
        "NoNewPrivileges": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "true",
        "PrivateTmp": "true",
        "UMask": "0077",
        "RestrictSUIDSGID": "true",
    }.items():
        assert service[key] == value
    assert service["CapabilityBoundingSet"] == ""
    assert service["ReadOnlyPaths"] == "/etc/php-pkg-publisher"


def test_only_the_publisher_may_write_the_site() -> None:
    assert "/srv/pkg/site" in _unit("php-pkg-publisher.service")["Service"]["ReadWritePaths"]
    assert _unit("php-pkg-publisher-watch.service")["Service"]["ReadWritePaths"] == (
        "/var/lib/php-pkg-publisher/state"
    )
    assert "ReadWritePaths" not in _unit(NOTIFY)["Service"]


def test_the_publisher_and_the_watch_read_the_same_settings_file() -> None:
    for name in SERVICES:
        command = _exec(name)
        assert command[command.index("--config") + 1] == "/etc/php-pkg-publisher/publisher.yml"
