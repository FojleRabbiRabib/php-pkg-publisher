# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from oracle import Client
from rig import Kit, Rig, make_kit, product

from publisher.config import Product

A = product("a-php", "a")
B = product("b-php", "b")


@pytest.fixture(scope="session")
def kit(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Kit]:
    yield from make_kit(tmp_path_factory.mktemp("kit"))


@pytest.fixture
def make_rig(kit: Kit, tmp_path_factory: pytest.TempPathFactory) -> Callable[..., Rig]:
    def build(*products: Product) -> Rig:
        return Rig(tmp_path_factory.mktemp("rig"), kit, products or (A, B))

    return build


@pytest.fixture
def rig(make_rig: Callable[..., Rig]) -> Rig:
    return make_rig()


def client(rig: Rig) -> Client:
    return Client(rig.current, rig.kit.master.public, rig.root / "client")
