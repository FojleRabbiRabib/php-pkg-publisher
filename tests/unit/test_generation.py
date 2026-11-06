# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from pkgkit import build_deb, build_rpm, make_key, stop_agent, subkeys_only

from publisher import feed, files, generation, metadata, signer
from publisher.admit import AdmittedPackage
from publisher.cache import Cache, Chunks
from publisher.generation import GenerationError, Site
from publisher.metadata import Entry
from publisher.signer import SigningKey
from publisher.tools import Tools

DAY = 24 * 3600
REPO = "p-php"


@pytest.fixture(scope="module")
def tools() -> Tools:
    return Tools.locate(os.environ["PATH"])


@dataclass
class Blobs:
    data: dict[str, bytes]

    def __call__(self, url: str, size: int) -> Chunks:
        yield self.data[url]


@dataclass(frozen=True)
class World:
    key: SigningKey
    blobs: Blobs
    entries_a: list[Entry]
    entries_b: list[Entry]
    tree_a: Path
    tree_b: Path


def _entry(tools: Tools, root: Path, tag: str, kind: str, blobs: dict[str, bytes]) -> Entry:
    version = tag.removeprefix("v")
    if kind == "deb":
        name = f"php8.3-p_{version}_amd64.deb"
        data = build_deb(tools, root, package="php8.3-p", version=version, architecture="amd64")
    else:
        name = f"php8.3-p-{version}-1.x86_64.rpm"
        data = build_rpm(root, name="php8.3-p", version=version, release="1", arch="x86_64")
    package = AdmittedPackage(
        name=name,
        kind=kind,
        layout="deb" if kind == "deb" else "versioned",
        php="8.3",
        arch="amd64",
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )
    blobs[feed.download_url(REPO, tag, name)] = data
    return Entry(repo=REPO, tag=tag, package=package)


def _signed_tree(
    tools: Tools, base: Path, name: str, entries: list[Entry], blobs: Blobs, key: SigningKey
) -> Path:
    root = base / name
    for sub, mode in (("cache", 0o700), ("tree", 0o755), ("work", 0o700)):
        (root / sub).mkdir(parents=True, mode=mode)
    built = metadata.build(
        entries,
        cache=Cache(root / "cache", blobs),
        tools=tools,
        target=root / "tree",
        work=root / "work",
    )
    signer.sign(root / "tree", built, key, tools=tools, work=root / "work")
    return root / "tree"


@pytest.fixture(scope="module")
def world(tools: Tools, tmp_path_factory: pytest.TempPathFactory) -> Iterator[World]:
    base = tmp_path_factory.mktemp("gen")
    keys = tmp_path_factory.mktemp("k")
    master = make_key(tools, keys, "repo")
    vps = subkeys_only(tools, master, keys, "vps")
    key = SigningKey(
        home=vps.home,
        fingerprint=master.subkey_fingerprint,
        certificate=master.public,
        primary=master.primary_fingerprint,
    )
    data: dict[str, bytes] = {}
    packages = tmp_path_factory.mktemp("pk")
    old = [_entry(tools, packages / f"o{k}", "v1.0.0", k, data) for k in ("deb", "rpm")]
    new = [_entry(tools, packages / f"n{k}", "v1.1.0", k, data) for k in ("deb", "rpm")]
    blobs = Blobs(data)
    entries_b = [*old, *new]
    yield World(
        key=key,
        blobs=blobs,
        entries_a=old,
        entries_b=entries_b,
        tree_a=_signed_tree(tools, base, "a", old, blobs, key),
        tree_b=_signed_tree(tools, base, "b", entries_b, blobs, key),
    )
    stop_agent(master)
    stop_agent(vps)


@pytest.fixture
def site(tmp_path: Path) -> Site:
    root = tmp_path / "site"
    root.mkdir(mode=0o755)
    return generation.open_site(root)


_counter = itertools.count()


def _install(site: Site, tree: Path, entries: list[Entry], now: float) -> str:
    copy = site.root.parent / f"copy-{next(_counter)}"
    shutil.copytree(tree, copy, symlinks=True)
    return generation.install(site, copy, entries, now=now).generation


def _clients_fetch(root: Path) -> set[str]:
    """Hash-named paths a client holding this tree's Release or repomd.xml asks for."""
    wanted: set[str] = set()
    release = (root / "apt/dists/stable/Release").read_text(encoding="utf-8")
    for algorithm in ("SHA256", "SHA512"):
        section = re.search(rf"^{algorithm}:\n((?: .*\n)+)", release, re.MULTILINE)
        assert section is not None
        for line in section.group(1).splitlines():
            digest, _, name = line.split()
            parent = name.rsplit("/", 1)[0]
            wanted.add(f"apt/dists/stable/{parent}/by-hash/{algorithm}/{digest}")
    for repomd in root.glob("rpm/*/*/repodata/repomd.xml"):
        text = repomd.read_text(encoding="utf-8")
        for name in re.findall(r'<location href="repodata/([^"]+)"', text):
            wanted.add(repomd.parent.relative_to(root).as_posix() + f"/{name}")
    return wanted


def _stored(site: Site) -> set[str]:
    return {p.relative_to(site.store).as_posix() for p in site.store.rglob("*") if p.is_file()}


def _current_id(site: Site) -> str:
    return site.current.readlink().name


# --- the first publication ------------------------------------------------------------------


def test_the_first_generation_is_served_through_current(site: Site, world: World) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    assert re.fullmatch(r"00000001-\d{8}T\d{6}Z", identifier)
    assert site.current.is_symlink()
    assert str(site.current.readlink()) == f"versions/{identifier}"
    root = site.current
    assert (root / "apt/dists/stable/InRelease").is_file()
    assert (root / "apt/dists/stable/Release.gpg").is_file()
    assert (root / "rpm/8.3/x86_64/repodata/repomd.xml.asc").is_file()
    assert not (root / "dists").exists()


def test_the_published_tree_is_readable_by_the_web_server(site: Site, world: World) -> None:
    _install(site, world.tree_a, world.entries_a, time.time())
    for path in [site.current.resolve(), *site.current.resolve().rglob("*")]:
        expected = 0o755 if path.is_dir() else 0o644
        assert stat.S_IMODE(path.stat().st_mode) == expected, path
    for directory in (site.store, site.manifests, site.staging):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_hash_named_files_are_hard_links_into_the_store(site: Site, world: World) -> None:
    _install(site, world.tree_a, world.entries_a, time.time())
    root = site.current.resolve()
    wanted = _clients_fetch(root)
    assert wanted
    assert _stored(site) == wanted
    for relative in wanted:
        assert (root / relative).stat().st_ino == (site.store / relative).stat().st_ino


def test_the_manifest_records_the_content_set(site: Site, world: World) -> None:
    now = time.time()
    identifier = _install(site, world.tree_b, world.entries_b, now)
    created, entries = generation.read_manifest(site, identifier)
    assert created == now
    assert sorted(entries, key=generation._order) == sorted(world.entries_b, key=generation._order)
    assert stat.S_IMODE((site.manifests / f"{identifier}.json").stat().st_mode) == 0o600


def test_nothing_is_left_in_staging_or_as_a_temporary_link(site: Site, world: World) -> None:
    _install(site, world.tree_a, world.entries_a, time.time())
    assert list(site.staging.iterdir()) == []
    assert [p.name for p in site.root.iterdir() if p.name.startswith("current-")] == []
    assert [p.name for p in site.versions.iterdir() if p.name.endswith(".new")] == []


# --- clients holding an older index ---------------------------------------------------------


def test_an_index_fetched_before_a_publish_is_still_served_after_it(
    site: Site, world: World
) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    old_root = site.versions / first
    old_paths = _clients_fetch(old_root)
    old_bytes = {p: (old_root / p).read_bytes() for p in old_paths}
    _install(site, world.tree_b, world.entries_b, now + 60)
    new_root = site.current.resolve()
    assert new_root != old_root
    for relative, content in old_bytes.items():
        assert (new_root / relative).read_bytes() == content, relative
    assert _clients_fetch(new_root) <= {
        p.relative_to(new_root).as_posix() for p in new_root.rglob("*")
    }


def test_both_by_hash_algorithms_are_carried(site: Site, world: World) -> None:
    now = time.time()
    _install(site, world.tree_a, world.entries_a, now)
    _install(site, world.tree_b, world.entries_b, now + 60)
    paths = {
        p.relative_to(site.current.resolve()).as_posix() for p in site.current.resolve().rglob("*")
    }
    for algorithm in ("SHA256", "SHA512"):
        assert any(f"/by-hash/{algorithm}/" in p for p in paths)


def test_a_file_is_dropped_once_no_recent_generation_lists_it_and_it_is_old(
    site: Site, world: World
) -> None:
    start = time.time()
    first = _install(site, world.tree_a, world.entries_a, start)
    a_paths = _clients_fetch(site.versions / first)
    steps = [start + 3 * DAY * n for n in range(1, 5)]
    for index, now in enumerate(steps):
        _install(site, world.tree_b, world.entries_b, now)
        stored = _stored(site)
        b_paths = _clients_fetch(site.current.resolve())
        unique_to_a = a_paths - b_paths
        assert unique_to_a
        if index < 2:  # the oldest of the last three generations still lists A, or under 7 days
            assert unique_to_a <= stored
        else:
            assert not (unique_to_a & stored), index
            for relative in unique_to_a:
                assert not (site.current.resolve() / relative).exists()


def test_files_listed_by_a_recent_generation_are_kept_even_when_old(
    site: Site, world: World
) -> None:
    start = time.time()
    _install(site, world.tree_b, world.entries_b, start)
    _install(site, world.tree_a, world.entries_a, start + 30 * DAY)
    live = _clients_fetch(site.current.resolve())
    assert live <= _stored(site)


def test_old_files_still_listed_by_a_recent_generation_survive_a_content_change(
    site: Site, world: World
) -> None:
    """Age alone must not decide: B is ten days old but the last generations still list it."""
    start = time.time()
    _install(site, world.tree_b, world.entries_b, start)
    _install(site, world.tree_b, world.entries_b, start + 10 * DAY)
    held = _clients_fetch(site.current.resolve())
    assert any("/by-hash/SHA512/" in p for p in held)
    _install(site, world.tree_a, world.entries_a, start + 10 * DAY + 60)
    root = site.current.resolve()
    for relative in held:
        assert (root / relative).is_file(), relative


def test_a_recent_file_nobody_lists_any_more_is_kept_for_seven_days(
    site: Site, world: World
) -> None:
    """Liveness and age are separate rules: A's files are unlisted after three B generations."""
    start = time.time()
    first = _install(site, world.tree_a, world.entries_a, start)
    a_only = _clients_fetch(site.versions / first)
    for n in range(1, 4):
        _install(site, world.tree_b, world.entries_b, start + n * 60)
    a_only -= _clients_fetch(site.current.resolve())
    assert a_only
    assert a_only <= _stored(site)
    assert all((site.current.resolve() / p).is_file() for p in a_only)


def test_a_clock_that_steps_back_does_not_age_files_out_early(site: Site, world: World) -> None:
    start = time.time()
    first = _install(site, world.tree_a, world.entries_a, start)
    a_only = _clients_fetch(site.versions / first)
    for n in range(1, 4):
        _install(site, world.tree_b, world.entries_b, start - n * 60)
    a_only -= _clients_fetch(site.current.resolve())
    assert a_only
    assert a_only <= _stored(site)


# --- retention ------------------------------------------------------------------------------


def test_only_the_newest_three_trees_are_kept_but_manifests_stay(site: Site, world: World) -> None:
    start = time.time()
    ids = [_install(site, world.tree_a, world.entries_a, start + n * 60) for n in range(5)]
    assert generation.generations(site) == ids[-3:]
    assert generation._manifest_ids(site) == ids
    assert _current_id(site) == ids[-1]


def test_old_manifests_are_pruned_beyond_the_limit(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(generation, "KEEP_MANIFESTS", 2)
    start = time.time()
    ids = [_install(site, world.tree_a, world.entries_a, start + n) for n in range(4)]
    assert generation._manifest_ids(site) == ids[-2:]


def test_generations_follow_the_sequence_not_the_clock(site: Site, world: World) -> None:
    start = time.time()
    first = _install(site, world.tree_a, world.entries_a, start)
    second = _install(site, world.tree_a, world.entries_a, start - 10 * DAY)
    third = _install(site, world.tree_a, world.entries_a, start + 10 * DAY)
    assert [generation._sequence(i) for i in (first, second, third)] == [1, 2, 3]
    assert generation.generations(site) == [first, second, third]
    assert _current_id(site) == third


# --- the flip and its failure points --------------------------------------------------------


def test_current_is_wrong_when_it_is_not_a_link_to_a_generation(site: Site, world: World) -> None:
    site.current.mkdir()
    with pytest.raises(GenerationError, match="must be a symbolic link"):
        _install(site, world.tree_a, world.entries_a, time.time())


def test_current_pointing_elsewhere_is_refused(site: Site, world: World, tmp_path: Path) -> None:
    site.current.symlink_to(tmp_path)
    with pytest.raises(GenerationError, match="not a generation"):
        _install(site, world.tree_a, world.entries_a, time.time())
    assert tmp_path.exists()


def test_a_failed_flip_keeps_the_old_tree_served_and_the_next_run_cleans_up(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    real = Path.replace

    def failing(self: Path, target: str | os.PathLike[str]) -> Path:
        if Path(target).name == "current":
            raise OSError(5, "Input/output error")
        return real(self, target)

    monkeypatch.setattr(Path, "replace", failing)
    with pytest.raises(GenerationError, match="cannot flip current"):
        _install(site, world.tree_b, world.entries_b, now + 60)
    monkeypatch.undo()
    assert _current_id(site) == first
    assert (site.current / "apt/dists/stable/InRelease").is_file()
    assert [p.name for p in site.root.iterdir() if p.name.startswith("current-")] == []
    second = _install(site, world.tree_b, world.entries_b, now + 120)
    assert _current_id(site) == second
    assert generation.generations(site)[-1] == second
    assert generation._sequence(second) > generation._sequence(first)


def test_a_failed_manifest_write_keeps_the_old_tree_and_leaves_no_new_tree_behind(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)

    def failing(path: Path, data: bytes, **_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "write_atomic", failing)
    with pytest.raises(GenerationError, match="cannot write the generation"):
        _install(site, world.tree_b, world.entries_b, now + 60)
    monkeypatch.undo()
    assert _current_id(site) == first
    _install(site, world.tree_b, world.entries_b, now + 120)
    assert [p.name for p in site.versions.iterdir() if p.name.endswith(".new")] == []
    assert len(generation.generations(site)) == 2


def test_a_failed_store_link_stops_before_anything_is_visible(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)

    def failing(src: object, dst: object, **_: object) -> None:
        raise OSError(31, "Too many links")

    monkeypatch.setattr(os, "link", failing)
    with pytest.raises(GenerationError, match="cannot link"):
        _install(site, world.tree_b, world.entries_b, now + 60)
    monkeypatch.undo()
    assert _current_id(site) == first
    _install(site, world.tree_b, world.entries_b, now + 120)
    assert [p.name for p in site.versions.iterdir() if p.name.endswith(".new")] == []


def test_a_manifest_of_a_generation_that_never_went_live_is_removed(
    site: Site, world: World
) -> None:
    now = time.time()
    _install(site, world.tree_a, world.entries_a, now)
    orphan = site.manifests / "00000099-20261106T000000Z.json"
    orphan.write_text("{}", encoding="utf-8")
    _install(site, world.tree_a, world.entries_a, now + 60)
    assert not orphan.exists()


def test_a_tree_that_would_hide_an_older_hash_is_refused_before_the_flip(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    monkeypatch.setattr(
        generation, "_plan_store", lambda *a, **k: generation._Plan(carry=set(), drop=set())
    )
    with pytest.raises(GenerationError, match="would disappear"):
        _install(site, world.tree_b, world.entries_b, now + 60)
    assert _current_id(site) == first


def test_a_stored_file_that_does_not_match_its_name_is_refused(site: Site, world: World) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    victim = sorted(p for p in site.store.rglob("*") if p.is_file() and "primary" in p.name)[0]
    victim.unlink()
    victim.write_bytes(b"not the index")
    shutil.rmtree(site.versions / first / "rpm")
    with pytest.raises(GenerationError, match=r"exists with other content|does not match its name"):
        _install(site, world.tree_b, world.entries_b, now + 60)


def test_a_tree_without_signatures_is_refused(site: Site, world: World, tmp_path: Path) -> None:
    copy = tmp_path / "unsigned"
    shutil.copytree(world.tree_a, copy, symlinks=True)
    (copy / "dists/stable/InRelease").unlink()
    with pytest.raises(GenerationError, match="missing from the tree"):
        generation.install(site, copy, world.entries_a, now=time.time())
    assert not site.current.exists()


def test_a_tree_with_a_stray_top_level_entry_is_refused(
    site: Site, world: World, tmp_path: Path
) -> None:
    copy = tmp_path / "stray"
    shutil.copytree(world.tree_a, copy, symlinks=True)
    (copy / "extra").mkdir()
    with pytest.raises(GenerationError, match="exactly dists and rpm"):
        generation.install(site, copy, world.entries_a, now=time.time())


# --- the site directory ---------------------------------------------------------------------


def test_the_site_root_must_be_absolute(tmp_path: Path) -> None:
    with pytest.raises(GenerationError, match="absolute"):
        generation.open_site(Path("site"))


def test_a_site_root_writable_by_others_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "open"
    root.mkdir(mode=0o777)
    root.chmod(0o777)
    with pytest.raises(GenerationError, match="not writable by others"):
        generation.open_site(root)


def test_a_missing_site_root_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GenerationError, match="cannot prepare"):
        generation.open_site(tmp_path / "none")


def test_open_site_creates_the_directories_with_their_modes(site: Site) -> None:
    modes = {
        d.name: stat.S_IMODE(d.stat().st_mode)
        for d in (site.versions, site.store, site.manifests, site.staging)
    }
    assert modes == {"versions": 0o755, "store": 0o700, "generations": 0o700, "staging": 0o700}


def test_a_store_that_is_open_to_others_is_refused(site: Site) -> None:
    site.store.chmod(0o755)
    with pytest.raises(GenerationError, match="group or others"):
        generation.open_site(site.root)


# --- manifests ------------------------------------------------------------------------------


def test_a_manifest_with_an_unexpected_key_is_refused(site: Site, world: World) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    path = site.manifests / f"{identifier}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["extra"] = 1
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(GenerationError, match="expected keys"):
        generation.read_manifest(site, identifier)


def test_a_manifest_with_a_repeated_key_is_refused(site: Site, world: World) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    path = site.manifests / f"{identifier}.json"
    text = path.read_text(encoding="utf-8")
    forged = text.replace('"created": ', '"id": "x", "created": ', 1)
    assert forged != text
    path.write_text(forged, encoding="utf-8")
    with pytest.raises(GenerationError, match="not valid"):
        generation.read_manifest(site, identifier)


def test_a_manifest_entry_with_a_wrong_type_is_refused(site: Site, world: World) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    path = site.manifests / f"{identifier}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"][0]["size"] = "12"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(GenerationError, match="wrong type"):
        generation.read_manifest(site, identifier)


def test_a_manifest_of_another_generation_is_refused(site: Site, world: World) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    second = _install(site, world.tree_a, world.entries_a, now + 1)
    shutil.copy(site.manifests / f"{first}.json", site.manifests / f"{second}.json")
    with pytest.raises(GenerationError, match="another generation"):
        generation.read_manifest(site, second)


def test_a_bad_generation_id_is_refused(site: Site) -> None:
    with pytest.raises(GenerationError, match="not a generation id"):
        generation.read_manifest(site, "../../etc/passwd")


# --- the whole pipeline: build, sign, publish -----------------------------------------------


@dataclass
class Pipeline:
    site: Site
    cache: Cache
    tools: Tools
    key: SigningKey

    def publish(
        self, entries: list[Entry], now: float, excluded: set[tuple[str, str]] | None = None
    ) -> generation.Published:
        return generation.publish(
            self.site,
            entries,
            cache=self.cache,
            tools=self.tools,
            key=self.key,
            excluded=excluded or set(),
            now=now,
        )

    def rollback(
        self, identifier: str, now: float, excluded: set[tuple[str, str]] | None = None
    ) -> generation.Published:
        return generation.rollback(
            self.site,
            identifier,
            excluded=excluded or set(),
            cache=self.cache,
            tools=self.tools,
            key=self.key,
            now=now,
        )


@pytest.fixture
def pipeline(site: Site, world: World, tools: Tools, tmp_path: Path) -> Pipeline:
    (tmp_path / "cache").mkdir(mode=0o700)
    return Pipeline(
        site=site, cache=Cache(tmp_path / "cache", world.blobs), tools=tools, key=world.key
    )


def test_publish_builds_signs_and_flips(pipeline: Pipeline, world: World) -> None:
    result = pipeline.publish(world.entries_a, time.time())
    assert result.generation is not None
    assert not result.skipped
    assert not result.pinned
    assert _current_id(pipeline.site) == result.generation
    assert (pipeline.site.current / "apt/dists/stable/InRelease").is_file()


def test_an_unchanged_content_set_is_not_published_again_within_a_day(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now)
    again = pipeline.publish(world.entries_a, now + 3600)
    assert again.skipped
    assert again.generation is None
    assert _current_id(pipeline.site) == first.generation


def test_an_unchanged_content_set_is_re_signed_after_a_day(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now)
    later = pipeline.publish(world.entries_a, now + DAY + 60)
    assert not later.skipped
    assert later.generation != first.generation


def test_a_changed_content_set_is_published_at_once(pipeline: Pipeline, world: World) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now)
    second = pipeline.publish(world.entries_b, now + 60)
    assert second.generation is not None
    assert second.generation != first.generation


def test_staging_is_empty_after_a_failed_build(
    pipeline: Pipeline, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*args: object, **kwargs: object) -> object:
        raise metadata.MetadataError("boom")

    monkeypatch.setattr(metadata, "build", failing)
    with pytest.raises(metadata.MetadataError):
        pipeline.publish(world.entries_a, time.time())
    assert list(pipeline.site.staging.iterdir()) == []
    assert not pipeline.site.current.exists()


# --- rollback -------------------------------------------------------------------------------


def test_rollback_publishes_the_older_content_as_a_new_generation_and_pins_it(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    second = pipeline.publish(world.entries_b, now + 60).generation
    assert first is not None
    assert second is not None
    result = pipeline.rollback(first, now + 120)
    assert result.generation not in (first, second)
    assert result.pinned
    assert generation.pinned(pipeline.site) == first
    current = _current_id(pipeline.site)
    _, entries = generation.read_manifest(pipeline.site, current)
    assert sorted(entries, key=generation._order) == sorted(world.entries_a, key=generation._order)


def test_rollback_publishes_a_rebuilt_generation_with_a_new_id(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    second = pipeline.publish(world.entries_b, now + 60).generation
    assert first is not None
    assert second is not None
    result = pipeline.rollback(first, now + 120)
    assert result.generation not in (first, second)
    assert result.generation == _current_id(pipeline.site)
    assert (pipeline.site.current / "apt/dists/stable/InRelease").is_file()


def test_an_exclusion_beats_the_rollback_pin(pipeline: Pipeline, world: World) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    pipeline.publish(world.entries_b, now + 60)
    assert first is not None
    pipeline.rollback(first, now + 120)
    admitted = [e for e in world.entries_b if e.tag != "v1.0.0"]
    result = pipeline.publish(admitted, now + 180, excluded={(REPO, "v1.0.0")})
    assert result.pin_dropped
    assert not result.pinned
    assert generation.pinned(pipeline.site) is None
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(admitted)


def test_a_pinned_site_keeps_the_rolled_back_content_when_new_releases_arrive(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    pipeline.publish(world.entries_b, now + 60)
    assert first is not None
    pipeline.rollback(first, now + 120)
    held = pipeline.publish(world.entries_b, now + 180)
    assert held.pinned
    assert held.skipped
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(world.entries_a)


def test_a_pinned_site_is_re_signed_after_a_day_with_the_pinned_content(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    pipeline.publish(world.entries_b, now + 60)
    assert first is not None
    pipeline.rollback(first, now + 120)
    held = pipeline.publish(world.entries_b, now + 2 * DAY)
    assert held.pinned
    assert not held.skipped
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(world.entries_a)


def test_clearing_the_pin_lets_the_admitted_state_through_again(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    pipeline.publish(world.entries_b, now + 60)
    assert first is not None
    pipeline.rollback(first, now + 120)
    generation.clear_pin(pipeline.site)
    assert generation.pinned(pipeline.site) is None
    result = pipeline.publish(world.entries_b, now + 180)
    assert not result.pinned
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(world.entries_b)


def test_rollback_to_a_set_with_an_excluded_release_is_refused(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    pipeline.publish(world.entries_b, now + 60)
    assert first is not None
    with pytest.raises(GenerationError, match="excluded release"):
        pipeline.rollback(first, now + 120, excluded={(REPO, "v1.0.0")})
    assert generation.pinned(pipeline.site) is None


def test_rollback_to_the_content_that_is_already_current_is_refused(
    pipeline: Pipeline, world: World
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    assert first is not None
    with pytest.raises(GenerationError, match="already current"):
        pipeline.rollback(first, now + 60)


def test_rollback_to_an_unknown_generation_is_refused(pipeline: Pipeline, world: World) -> None:
    pipeline.publish(world.entries_a, time.time())
    with pytest.raises(GenerationError, match="cannot read"):
        pipeline.rollback("00000042-20261106T000000Z", time.time())


def test_a_failed_rollback_keeps_the_pin_so_the_next_run_retries_it(
    pipeline: Pipeline, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    second = pipeline.publish(world.entries_b, now + 60).generation
    assert first is not None
    monkeypatch.setattr(
        metadata, "build", lambda *a, **k: (_ for _ in ()).throw(metadata.MetadataError("boom"))
    )
    with pytest.raises(metadata.MetadataError):
        pipeline.rollback(first, now + 120)
    monkeypatch.undo()
    assert _current_id(pipeline.site) == second
    assert generation.pinned(pipeline.site) == first
    retried = pipeline.publish(world.entries_b, now + 180)
    assert retried.pinned
    assert retried.generation is not None
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(world.entries_a)


# --- findings of the blind review -----------------------------------------------------------


def test_a_strict_umask_does_not_close_the_tree_to_the_web_server(
    world: World, tmp_path: Path
) -> None:
    root = tmp_path / "strict"
    root.mkdir(mode=0o755)
    previous = os.umask(0o077)
    try:
        site = generation.open_site(root)
        _install(site, world.tree_a, world.entries_a, time.time())
    finally:
        os.umask(previous)
    assert stat.S_IMODE(site.versions.stat().st_mode) == 0o755
    for path in [site.current.resolve(), *site.current.resolve().rglob("*")]:
        assert stat.S_IMODE(path.stat().st_mode) == (0o755 if path.is_dir() else 0o644), path


def test_a_site_root_the_web_server_cannot_enter_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "closed"
    root.mkdir(mode=0o700)
    with pytest.raises(GenerationError, match="web server"):
        generation.open_site(root)


def test_leftovers_of_a_crashed_run_are_all_cleaned_up(site: Site, world: World) -> None:
    now = time.time()
    first = _install(site, world.tree_a, world.entries_a, now)
    leftovers = [
        site.versions / "00000050-20261106T000000Z.new",
        site.versions / "00000099-20261106T000000Z",
        site.staging / "build-abc",
    ]
    for path in leftovers:
        (path / "inner").mkdir(parents=True)
    (site.staging / "stray-file").write_text("x", encoding="utf-8")
    (site.root / "current-deadbeef").symlink_to("versions/x")
    second = _install(site, world.tree_a, world.entries_a, now + 60)
    assert not any(p.exists() for p in leftovers)
    assert list(site.staging.iterdir()) == []
    assert not (site.root / "current-deadbeef").is_symlink()
    assert generation.generations(site) == [first, second]


def test_a_missing_current_with_several_generations_is_not_silently_wiped(
    site: Site, world: World
) -> None:
    now = time.time()
    for n in range(3):
        _install(site, world.tree_a, world.entries_a, now + n)
    site.current.unlink()
    with pytest.raises(GenerationError, match="current is missing"):
        _install(site, world.tree_a, world.entries_a, now + 10)
    assert len(generation.generations(site)) == 3
    assert len(generation._manifest_ids(site)) == 3


def test_a_first_publish_that_died_before_the_flip_is_restarted(site: Site, world: World) -> None:
    _install(site, world.tree_a, world.entries_a, time.time())
    site.current.unlink()
    again = _install(site, world.tree_a, world.entries_a, time.time())
    assert generation._sequence(again) == 1
    assert _current_id(site) == again


def test_the_pinned_manifest_survives_manifest_pruning(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(generation, "KEEP_MANIFESTS", 2)
    start = time.time()
    first = _install(site, world.tree_a, world.entries_a, start)
    files.write_atomic(site.pin, json.dumps({"generation": first, "since": start}).encode("utf-8"))
    for n in range(1, 5):
        _install(site, world.tree_b, world.entries_b, start + n)
    assert (site.manifests / f"{first}.json").exists()


def test_a_hash_named_file_that_does_not_hold_its_name_is_refused(
    site: Site, world: World, tmp_path: Path
) -> None:
    copy = tmp_path / "corrupt"
    shutil.copytree(world.tree_a, copy, symlinks=True)
    victim = next(copy.glob("dists/stable/main/binary-amd64/by-hash/SHA512/*"))
    victim.write_bytes(b"other")
    with pytest.raises(GenerationError, match="promises"):
        generation.install(site, copy, world.entries_a, now=time.time())
    assert not site.current.exists()


def test_the_new_tree_is_flushed_to_disk_before_the_flip(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[int] = []
    real = os.fsync

    def counting(descriptor: int) -> None:
        synced.append(descriptor)
        real(descriptor)

    monkeypatch.setattr(os, "fsync", counting)
    _install(site, world.tree_a, world.entries_a, time.time())
    tree = site.current.resolve()
    entries = len(list(tree.rglob("*")))
    assert len(synced) >= entries


def test_a_second_rollback_replaces_the_pin(pipeline: Pipeline, world: World) -> None:
    now = time.time()
    first = pipeline.publish(world.entries_a, now).generation
    second = pipeline.publish(world.entries_b, now + 60).generation
    assert first is not None
    assert second is not None
    pipeline.rollback(first, now + 120)
    pipeline.rollback(second, now + 180)
    assert generation.pinned(pipeline.site) == second
    _, entries = generation.read_manifest(pipeline.site, _current_id(pipeline.site))
    assert len(entries) == len(world.entries_b)


def test_a_retire_failure_after_the_flip_is_reported_not_raised(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()

    def broken(*args: object, **kwargs: object) -> None:
        raise GenerationError("cannot remove an old tree")

    monkeypatch.setattr(generation, "_retire", broken)
    copy = site.root.parent / f"copy-{next(_counter)}"
    shutil.copytree(world.tree_a, copy, symlinks=True)
    done = generation.install(site, copy, world.entries_a, now=now)
    assert done.retire_error == "cannot remove an old tree"
    assert _current_id(site) == done.generation


def _manifest_path(site: Site, identifier: str) -> Path:
    return site.manifests / f"{identifier}.json"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [("version", True, "another generation"), ("created", float("nan"), "finite")],
)
def test_a_loose_manifest_is_refused(
    site: Site, world: World, field: str, value: object, message: str
) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    path = _manifest_path(site, identifier)
    document = json.loads(path.read_text(encoding="utf-8"))
    document[field] = value
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(GenerationError, match=message):
        generation.read_manifest(site, identifier)


def test_a_manifest_that_is_a_link_is_refused(site: Site, world: World, tmp_path: Path) -> None:
    identifier = _install(site, world.tree_a, world.entries_a, time.time())
    path = _manifest_path(site, identifier)
    other = tmp_path / "other.json"
    other.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(other)
    with pytest.raises(GenerationError, match="link"):
        generation.read_manifest(site, identifier)


def test_a_pin_with_a_text_date_is_refused(site: Site) -> None:
    files.write_atomic(
        site.pin, json.dumps({"generation": "00000001-20260101T000000Z", "since": "now"}).encode()
    )
    with pytest.raises(GenerationError, match="finite"):
        generation.pinned(site)


def test_a_dangling_pin_link_is_refused_not_ignored(site: Site, tmp_path: Path) -> None:
    site.pin.symlink_to(tmp_path / "nowhere")
    with pytest.raises(GenerationError, match="link"):
        generation.pinned(site)


def test_a_failed_directory_sync_after_the_flip_is_reported_as_such(
    site: Site, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = files.sync_directory

    def failing(path: Path) -> None:
        if path == site.root:
            raise OSError("disk gone")
        real(path)

    monkeypatch.setattr(files, "sync_directory", failing)
    copy = site.root.parent / f"copy-{next(_counter)}"
    shutil.copytree(world.tree_a, copy, symlinks=True)
    with pytest.raises(GenerationError, match="may not survive a power loss"):
        generation.install(site, copy, world.entries_a, now=time.time())
    assert _current_id(site).startswith("00000001-")


def test_entries_that_list_an_excluded_release_are_refused(
    pipeline: Pipeline, world: World
) -> None:
    with pytest.raises(GenerationError, match="excluded release"):
        pipeline.publish(world.entries_b, time.time(), excluded={(REPO, "v1.1.0")})
    assert not pipeline.site.current.exists()
