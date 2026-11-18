# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import keyrings
import pytest
import setupkit
from box import FREE_DISK_NEEDED, require_free_disk
from oracle import Client
from rig import Kit, Rig, make_kit, product

from publisher.config import Product

A = product("a-php", "a")
B = product("b-php", "b")

# The default `timeout` of pyproject.toml suits a unit test; a container test builds images and runs
# distro installs, and its session fixtures count against the first test that uses them.
CONTAINER_TIMEOUT = 1200


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("container") and not item.get_closest_marker("timeout"):
            item.add_marker(pytest.mark.timeout(CONTAINER_TIMEOUT))


@pytest.fixture(scope="session", autouse=True)
def _free_disk(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> None:
    """A container run stops at the start, with a clear error, when the disk is nearly full."""
    if any(item.get_closest_marker("container") for item in request.session.items):
        try:
            require_free_disk(tmp_path_factory.getbasetemp(), FREE_DISK_NEEDED)
        except OSError as error:
            pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="session")
def kit(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Kit]:
    yield from make_kit(tmp_path_factory.mktemp("kit"))


@pytest.fixture(scope="session")
def packages(kit: Kit, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """The built keyring packages the container tests install, see `keyrings.build`."""
    yield from keyrings.build(kit, tmp_path_factory.mktemp("keyring"))


@pytest.fixture(scope="session")
def php_rpms(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Fake PHP rpms for the `setup.sh` container tests, see `setupkit.build_php_rpms`."""
    return setupkit.build_php_rpms(tmp_path_factory.mktemp("fakephp"))


@pytest.fixture
def make_rig(kit: Kit, tmp_path_factory: pytest.TempPathFactory) -> Callable[..., Rig]:
    def build(*products: Product, rpm_key: str = "good") -> Rig:
        return Rig(tmp_path_factory.mktemp("rig"), kit, products or (A, B), rpm_key=rpm_key)

    return build


@pytest.fixture
def rig(make_rig: Callable[..., Rig]) -> Rig:
    return make_rig()


def client(rig: Rig) -> Client:
    return Client(rig.current, rig.kit.master.public, rig.root / "client")
