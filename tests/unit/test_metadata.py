# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import dataclasses
import gzip
import hashlib
import lzma
import os
import re
import shutil
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import pytest
from pkgkit import build_deb, build_rpm

from publisher import config, feed, metadata
from publisher.admit import ALL_KINDS, AdmittedPackage, AdmittedTag, ProductState
from publisher.cache import Cache, Chunks
from publisher.metadata import Entry, MetadataError, build, select
from publisher.tools import ToolError, Tools, ToolTimeout

ROOT = "https://packages.example.test/"
REPO = "p-php"
RPM_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
OLD, NEW = "v1.0.0", "v1.1.0"
MATRIX = [
    (OLD, php, arch, kind)
    for php in ("8.3", "8.4")
    for arch in ("amd64", "arm64")
    for kind in ("deb", "rpm")
] + [(NEW, "8.3", "amd64", kind) for kind in ("deb", "rpm")]


@dataclass
class Blobs:
    """A fetch function that serves package bytes by URL and records every request."""

    data: dict[str, bytes] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def __call__(self, url: str, size: int) -> Chunks:
        self.calls.append(url)
        yield self.data.get(url, b"")


@dataclass(frozen=True)
class Fixtures:
    entries: dict[tuple[str, str, str, str], Entry]
    blobs: dict[str, bytes]

    def pick(self, *, tag: str | None = None) -> list[Entry]:
        return [e for key, e in self.entries.items() if tag is None or key[0] == tag]


@pytest.fixture(scope="module")
def tools() -> Tools:
    return Tools.locate(os.environ["PATH"])


@pytest.fixture(scope="module")
def fixtures(tools: Tools, tmp_path_factory: pytest.TempPathFactory) -> Fixtures:
    base = tmp_path_factory.mktemp("packages")
    entries: dict[tuple[str, str, str, str], Entry] = {}
    blobs: dict[str, bytes] = {}
    for tag, php, arch, kind in MATRIX:
        root = base / f"{tag}-{php}-{arch}-{kind}"
        root.mkdir()
        version = tag.removeprefix("v")
        package = f"php{php}-p"
        if kind == "deb":
            name = f"{package}_{version}_{arch}.deb"
            data = build_deb(tools, root, package=package, version=version, architecture=arch)
        else:
            name = f"{package}-{version}-1.{RPM_ARCH[arch]}.rpm"
            data = build_rpm(root, name=package, version=version, release="1", arch=RPM_ARCH[arch])
        admitted = AdmittedPackage(
            name=name,
            kind=kind,
            layout="deb" if kind == "deb" else "versioned",
            php=php,
            arch=arch,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
        )
        entries[(tag, php, arch, kind)] = Entry(repo=REPO, tag=tag, package=admitted)
        blobs[feed.download_url(REPO, tag, name)] = data
    return Fixtures(entries=entries, blobs=blobs)


@dataclass
class Site:
    cache: Cache
    served: Blobs
    target: Path
    work: Path


@pytest.fixture
def site(fixtures: Fixtures, tmp_path: Path) -> Site:
    served = Blobs(dict(fixtures.blobs))
    cache_root = tmp_path / "cache"
    cache_root.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    return Site(cache=Cache(cache_root, served), served=served, target=target, work=work)


@dataclass(frozen=True)
class Built:
    site: Site
    result: metadata.Built
    entries: list[Entry]


@pytest.fixture(scope="module")
def built(tools: Tools, fixtures: Fixtures, tmp_path_factory: pytest.TempPathFactory) -> Built:
    base = tmp_path_factory.mktemp("built")
    served = Blobs(dict(fixtures.blobs))
    (base / "cache").mkdir(mode=0o700)
    (base / "target").mkdir(mode=0o755)
    (base / "work").mkdir(mode=0o700)
    site = Site(Cache(base / "cache", served), served, base / "target", base / "work")
    entries = fixtures.pick()
    result = build(entries, cache=site.cache, tools=tools, target=site.target, work=site.work)
    return Built(site=site, result=result, entries=entries)


def _stanzas(text: str) -> list[dict[str, str]]:
    return [
        dict(line.split(": ", 1) for line in block.split("\n") if line and line[0] != " ")
        for block in text.strip().split("\n\n")
        if block.strip()
    ]


def _primary(tree: Path) -> str:
    (path,) = (tree / "repodata").glob("*-primary.xml.gz")
    return gzip.decompress(path.read_bytes()).decode("utf-8")


# --- the apt tree, checked against the package bytes themselves -----------------------------


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_packages_lists_exactly_the_debs_of_that_architecture(built: Built, arch: str) -> None:
    index = built.site.target / "dists/stable/main" / f"binary-{arch}" / "Packages"
    found = {
        (s["Filename"], s["SHA256"], int(s["Size"]), s["Architecture"])
        for s in _stanzas(index.read_text(encoding="utf-8"))
    }
    expected = {
        (e.pool_path, e.package.sha256, e.package.size, arch)
        for e in built.entries
        if e.package.kind == "deb" and e.package.arch == arch
    }
    assert found == expected
    assert len(expected) == (3 if arch == "amd64" else 2)


def test_packages_filenames_are_the_pool_paths_under_the_tag(built: Built) -> None:
    index = built.site.target / "dists/stable/main/binary-amd64/Packages"
    names = sorted(s["Filename"] for s in _stanzas(index.read_text(encoding="utf-8")))
    assert names == [
        "pool/p-php/v1.0.0/php8.3-p_1.0.0_amd64.deb",
        "pool/p-php/v1.0.0/php8.4-p_1.0.0_amd64.deb",
        "pool/p-php/v1.1.0/php8.3-p_1.1.0_amd64.deb",
    ]


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_compressed_indexes_hold_the_same_text(built: Built, arch: str) -> None:
    directory = built.site.target / "dists/stable/main" / f"binary-{arch}"
    plain = (directory / "Packages").read_bytes()
    assert gzip.decompress((directory / "Packages.gz").read_bytes()) == plain
    assert lzma.decompress((directory / "Packages.xz").read_bytes()) == plain


def test_release_carries_the_declared_identity(built: Built) -> None:
    text = (built.site.target / "dists/stable/Release").read_text(encoding="utf-8")
    fields = dict(
        line.split(": ", 1)
        for line in text.split("\n")
        if line and line[0] not in " \t"
        if ": " in line
    )
    assert fields["Origin"] == "Fojle Rabbi (Rabib)"
    assert fields["Label"] == "Fojle Rabbi PHP extensions"
    assert fields["Description"] == "PHP extensions by Fojle Rabbi (Rabib)"
    assert fields["Suite"] == fields["Codename"] == "stable"
    assert fields["Architectures"] == "amd64 arm64"
    assert fields["Components"] == "main"
    assert fields["Acquire-By-Hash"] == "yes"


def test_release_dates_come_from_the_clock_and_span_fourteen_days(built: Built) -> None:
    text = (built.site.target / "dists/stable/Release").read_text(encoding="utf-8")
    fmt = "%a, %d %b %Y %H:%M:%S UTC"
    date = re.search(r"^Date: (.+)$", text, re.MULTILINE)
    until = re.search(r"^Valid-Until: (.+)$", text, re.MULTILINE)
    assert date is not None
    assert until is not None
    issued = datetime.strptime(date.group(1), fmt).replace(tzinfo=timezone.utc)
    ends = datetime.strptime(until.group(1), fmt).replace(tzinfo=timezone.utc)
    assert (ends - issued).total_seconds() == 14 * 24 * 3600
    assert abs(time.time() - issued.timestamp()) < 3600


def test_release_hashes_every_index_and_has_by_hash_copies(built: Built) -> None:
    dists = built.site.target / "dists/stable"
    text = (dists / "Release").read_text(encoding="utf-8")
    listed = re.findall(r"^ ([0-9a-f]{64}) +([0-9]+) (\S+)$", text, re.MULTILINE)
    names = {name for _, _, name in listed}
    assert names == {
        f"main/binary-{arch}/{index}"
        for arch in ("amd64", "arm64")
        for index in ("Packages", "Packages.gz", "Packages.xz")
    }
    assert "Release" not in names
    for sha, size, name in listed:
        path = dists / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
        assert path.stat().st_size == int(size)
        copy = path.parent / "by-hash/SHA256" / sha
        assert copy.read_bytes() == path.read_bytes()


# --- the rpm trees --------------------------------------------------------------------------


def test_six_rpm_trees_always_exist(built: Built) -> None:
    assert built.result.rpm_trees == tuple(
        f"rpm/{php}/{arch}" for php in ("8.3", "8.4", "8.5") for arch in ("x86_64", "aarch64")
    )
    for tree in built.result.rpm_trees:
        assert (built.site.target / tree / "repodata/repomd.xml").is_file()


@pytest.mark.parametrize(
    ("php", "arch", "count"),
    [
        ("8.3", "x86_64", 2),
        ("8.3", "aarch64", 1),
        ("8.4", "x86_64", 1),
        ("8.4", "aarch64", 1),
        ("8.5", "x86_64", 0),
        ("8.5", "aarch64", 0),
    ],
)
def test_each_rpm_tree_lists_only_its_php_and_architecture(
    built: Built, php: str, arch: str, count: int
) -> None:
    tree = built.site.target / "rpm" / php / arch
    primary = _primary(tree)
    assert f'packages="{count}"' in primary
    hrefs = re.findall(r'<location href="([^"]+)"/>', primary)
    expected = sorted(
        "../../../" + e.pool_path
        for e in built.entries
        if e.package.kind == "rpm" and e.package.php == php and RPM_ARCH[e.package.arch] == arch
    )
    assert sorted(hrefs) == expected


def test_rpm_locations_resolve_to_the_pool_root_from_the_repository_url(built: Built) -> None:
    for php, arch in (("8.3", "x86_64"), ("8.4", "aarch64")):
        base = f"{ROOT}rpm/{php}/{arch}/"
        for href in re.findall(
            r'<location href="([^"]+)"/>', _primary(built.site.target / "rpm" / php / arch)
        ):
            assert urljoin(base, href).startswith(f"{ROOT}pool/{REPO}/v1.")


def test_rpm_checksums_and_sizes_are_those_of_the_package_bytes(built: Built) -> None:
    primary = _primary(built.site.target / "rpm/8.3/x86_64")
    for e in built.entries:
        if e.package.kind == "rpm" and e.package.php == "8.3" and e.package.arch == "amd64":
            assert f">{e.package.sha256}</checksum>" in primary
            assert f'<size package="{e.package.size}"' in primary


# --- the whole tree -------------------------------------------------------------------------


def test_the_tree_holds_metadata_only(built: Built) -> None:
    for path in built.site.target.rglob("*"):
        assert not path.is_symlink()
        assert path.suffix not in (".deb", ".rpm")
        assert not path.is_dir() or "pool" not in path.parts


def test_the_result_counts_what_was_listed(built: Built) -> None:
    assert built.result.entries == 10
    assert built.result.apt_architectures == ("amd64", "arm64")


def test_staging_is_removed_after_a_build(built: Built) -> None:
    assert list(built.site.work.iterdir()) == []


def test_a_second_build_uses_the_cache_and_fetches_nothing(
    tools: Tools, fixtures: Fixtures, site: Site
) -> None:
    entries = fixtures.pick(tag=OLD)
    build(entries, cache=site.cache, tools=tools, target=site.target, work=site.work)
    assert len(site.served.calls) == len(entries)
    again = site.target.parent / "again"
    again.mkdir(mode=0o755)
    build(entries, cache=site.cache, tools=tools, target=again, work=site.work)
    assert len(site.served.calls) == len(entries)


def test_an_empty_repository_still_builds_every_tree(tools: Tools, site: Site) -> None:
    result = build([], cache=site.cache, tools=tools, target=site.target, work=site.work)
    assert result.entries == 0
    assert len(result.rpm_trees) == 6
    index = site.target / "dists/stable/main/binary-amd64/Packages"
    assert index.read_text(encoding="utf-8") == ""
    assert 'packages="0"' in _primary(site.target / "rpm/8.3/x86_64")


# --- selection ------------------------------------------------------------------------------


def _product(**changes: object) -> config.Product:
    base = config.Product(
        repo=REPO,
        extension="p",
        php=("8.3", "8.4"),
        arch=("amd64", "arm64"),
        ts=("nts",),
        exclude=(),
    )
    return dataclasses.replace(base, **changes)  # type: ignore[arg-type]


def _lists(
    product: config.Product, exclusions: tuple[config.Exclusion, ...] = ()
) -> tuple[config.ProductList, config.ExclusionList]:
    return (
        config.ProductList(source=Path("products.yml"), sha256="", products=(product,)),
        config.ExclusionList(source=Path("exclude.yml"), sha256="", exclusions=exclusions),
    )


def _state(fixtures: Fixtures, *tags: str) -> ProductState:
    state = ProductState()
    for tag in tags:
        packages = tuple(e.package for e in fixtures.pick(tag=tag))
        state.admitted[tag] = AdmittedTag(admitted_at=0.0, packages=packages)
    return state


def _selected(entries: tuple[Entry, ...]) -> set[tuple[str, str, str]]:
    return {(e.tag, e.package.php, e.package.arch) for e in entries}


def test_select_lists_every_admitted_package_of_the_declared_product(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product())
    entries = select(listed, excluded, {REPO: _state(fixtures, OLD, NEW)})
    assert len(entries) == 10


def test_select_orders_tags_numerically(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product())
    state = _state(fixtures, NEW, OLD)
    tags = [e.tag for e in select(listed, excluded, {REPO: state})]
    assert tags == sorted(tags, key=lambda t: [int(n) for n in re.findall(r"[0-9]+", t)])


def test_the_declaration_filters_what_is_listed(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product(php=("8.3",), arch=("amd64",)))
    entries = select(listed, excluded, {REPO: _state(fixtures, OLD, NEW)})
    assert _selected(entries) == {(OLD, "8.3", "amd64"), (NEW, "8.3", "amd64")}


def test_a_tag_excluded_in_products_yml_is_not_listed(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product(exclude=(OLD,)))
    entries = select(listed, excluded, {REPO: _state(fixtures, OLD, NEW)})
    assert {e.tag for e in entries} == {NEW}


def test_a_tag_excluded_in_exclude_yml_is_not_listed(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product(), (config.Exclusion(product=REPO, tag=OLD),))
    entries = select(listed, excluded, {REPO: _state(fixtures, OLD, NEW)})
    assert {e.tag for e in entries} == {NEW}


def test_an_exclusion_of_another_product_changes_nothing(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product(), (config.Exclusion(product="other-php", tag=OLD),))
    entries = select(listed, excluded, {REPO: _state(fixtures, OLD)})
    assert {e.tag for e in entries} == {OLD}


def test_prereleases_are_listed_only_when_asked(fixtures: Fixtures) -> None:
    state = _state(fixtures, OLD)
    state.admitted["v1.2.0-rc1"] = state.admitted[OLD]
    listed, excluded = _lists(_product())
    assert {e.tag for e in select(listed, excluded, {REPO: state})} == {OLD}
    every = select(listed, excluded, {REPO: state}, kinds=ALL_KINDS)
    assert {e.tag for e in every} == {OLD, "v1.2.0-rc1"}


def test_a_declared_product_without_a_state_is_an_error(fixtures: Fixtures) -> None:
    listed, excluded = _lists(_product())
    with pytest.raises(MetadataError, match="no state was loaded for p-php"):
        select(listed, excluded, {})


# --- refusals before any work ---------------------------------------------------------------


def test_the_target_must_be_empty(tools: Tools, site: Site) -> None:
    (site.target / "leftover").write_text("x", encoding="utf-8")
    with pytest.raises(MetadataError, match="must be empty"):
        build([], cache=site.cache, tools=tools, target=site.target, work=site.work)


def test_the_target_must_be_absolute(tools: Tools, site: Site) -> None:
    with pytest.raises(MetadataError, match="absolute"):
        build([], cache=site.cache, tools=tools, target=Path("target"), work=site.work)


def test_the_target_must_not_be_a_symlink(tools: Tools, site: Site, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(site.target)
    with pytest.raises(MetadataError, match="directory owned"):
        build([], cache=site.cache, tools=tools, target=link, work=site.work)


def test_the_target_must_exist(tools: Tools, site: Site, tmp_path: Path) -> None:
    with pytest.raises(MetadataError, match="cannot inspect"):
        build([], cache=site.cache, tools=tools, target=tmp_path / "none", work=site.work)


def test_the_work_directory_must_exist(tools: Tools, site: Site, tmp_path: Path) -> None:
    with pytest.raises(MetadataError, match="cannot inspect"):
        build([], cache=site.cache, tools=tools, target=site.target, work=tmp_path / "none")


@pytest.mark.parametrize(
    "change",
    [
        {"name": "../x.deb"},
        {"name": "a..b.deb"},
        {"name": "x.rpm"},
        {"kind": "tar"},
        {"php": "7.4"},
        {"arch": "i386"},
        {"sha256": "ABC"},
        {"size": -1},
    ],
)
def test_an_invalid_record_is_refused(
    tools: Tools, fixtures: Fixtures, site: Site, change: dict[str, object]
) -> None:
    entry = fixtures.entries[(OLD, "8.3", "amd64", "deb")]
    broken = dataclasses.replace(entry, package=dataclasses.replace(entry.package, **change))  # type: ignore[arg-type]
    with pytest.raises(MetadataError, match="is not valid"):
        build([broken], cache=site.cache, tools=tools, target=site.target, work=site.work)
    assert site.served.calls == []


@pytest.mark.parametrize("change", [{"repo": "A/b"}, {"repo": "a..b"}, {"tag": "1.0"}])
def test_an_invalid_repo_or_tag_is_refused(
    tools: Tools, fixtures: Fixtures, site: Site, change: dict[str, object]
) -> None:
    entry = dataclasses.replace(fixtures.entries[(OLD, "8.3", "amd64", "deb")], **change)  # type: ignore[arg-type]
    with pytest.raises(MetadataError, match="is not valid"):
        build([entry], cache=site.cache, tools=tools, target=site.target, work=site.work)


def test_the_same_package_twice_is_refused(tools: Tools, fixtures: Fixtures, site: Site) -> None:
    entry = fixtures.entries[(OLD, "8.3", "amd64", "deb")]
    with pytest.raises(MetadataError, match="listed twice"):
        build([entry, entry], cache=site.cache, tools=tools, target=site.target, work=site.work)


# --- the cache and the fetch ----------------------------------------------------------------


def test_a_package_that_does_not_match_its_digest_stops_the_build(
    tools: Tools, fixtures: Fixtures, site: Site
) -> None:
    entry = fixtures.entries[(OLD, "8.3", "amd64", "deb")]
    url = feed.download_url(REPO, OLD, entry.package.name)
    site.served.data[url] = b"tampered"
    with pytest.raises(MetadataError, match="cannot fetch"):
        build([entry], cache=site.cache, tools=tools, target=site.target, work=site.work)
    assert list(site.work.iterdir()) == []


def test_a_package_that_cannot_be_fetched_stops_the_build(
    tools: Tools, fixtures: Fixtures, site: Site
) -> None:
    entry = fixtures.entries[(OLD, "8.3", "amd64", "deb")]
    site.served.data.clear()
    with pytest.raises(MetadataError, match="cannot fetch"):
        build([entry], cache=site.cache, tools=tools, target=site.target, work=site.work)


# --- a tool that misbehaves fails closed ----------------------------------------------------


def _stand_in(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _wrapper(directory: Path, name: str, real: Path, after: str) -> Path:
    """A program that runs the real tool, then changes its output with a few lines of Python."""
    path = directory / name
    path.write_text(
        f"#!{sys.executable}\nimport subprocess, sys\n"
        f"code = subprocess.run([{str(real)!r}, *sys.argv[1:]]).returncode\n"
        f"{after}\nsys.exit(code)\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _small(fixtures: Fixtures) -> list[Entry]:
    return [fixtures.entries[(OLD, "8.3", "amd64", kind)] for kind in ("deb", "rpm")]


@pytest.mark.parametrize(
    ("program", "message"),
    [("apt_ftparchive", "exactly the three indexes"), ("createrepo_c", "cannot be read")],
)
def test_a_tool_that_writes_nothing_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path, program: str, message: str
) -> None:
    fake = dataclasses.replace(tools, **{program: _stand_in(tmp_path, program, "exit 0")})
    with pytest.raises(MetadataError, match=message):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)
    assert list(site.work.iterdir()) == []


def test_a_primary_count_that_disagrees_with_the_packages_is_refused(
    built: Built, tmp_path: Path
) -> None:
    """Forge the count in primary.xml and keep repomd consistent, so only the count is wrong."""
    repodata = tmp_path / "repodata"
    shutil.copytree(built.site.target / "rpm/8.3/x86_64/repodata", repodata)
    (primary,) = repodata.glob("*-primary.xml.gz")
    text = gzip.decompress(primary.read_bytes()).decode("utf-8")
    forged = text.replace('packages="2"', 'packages="3"')
    assert forged != text
    data = gzip.compress(forged.encode("utf-8"))
    primary.write_bytes(data)
    repomd = repodata / "repomd.xml"
    xml = repomd.read_text(encoding="utf-8")
    old_sum = re.escape(primary.name)
    block = re.search(rf'<data type="primary">.*?{old_sum}.*?</data>', xml, re.DOTALL)
    assert block is not None
    new_block = re.sub(
        r'(<checksum type="sha256">)[0-9a-f]{64}',
        rf"\g<1>{hashlib.sha256(data).hexdigest()}",
        block.group(0),
    )
    new_block = re.sub(
        r'(<open-checksum type="sha256">)[0-9a-f]{64}',
        rf"\g<1>{hashlib.sha256(forged.encode('utf-8')).hexdigest()}",
        new_block,
    )
    repomd.write_text(xml.replace(block.group(0), new_block), encoding="utf-8")
    wanted = [
        e
        for e in built.entries
        if e.package.kind == "rpm" and e.package.php == "8.3" and e.package.arch == "amd64"
    ]
    assert len(wanted) == 2
    with pytest.raises(MetadataError, match=r"primary\.xml does not match"):
        metadata._check_repodata(repodata, wanted)


@pytest.mark.parametrize("program", ["apt_ftparchive", "createrepo_c"])
def test_a_tool_that_fails_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path, program: str
) -> None:
    fake = dataclasses.replace(
        tools, **{program: _stand_in(tmp_path, program, "echo broken >&2; exit 2")}
    )
    with pytest.raises(MetadataError, match="failed: 'broken'"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_an_index_that_drops_a_package_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    drop = (
        "if sys.argv[1] == 'generate':\n"
        "    d = re.search(r'ArchiveDir \"(.*)\"', open(sys.argv[2]).read()).group(1)\n"
        "    open(d + '/dists/stable/main/binary-amd64/Packages', 'w').close()\n"
    )
    wrapper = _wrapper(tmp_path, "apt-ftparchive", tools.apt_ftparchive, "import re\n" + drop)
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match="does not match the admitted packages"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_package_the_tool_adds_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "apt-ftparchive",
        tools.apt_ftparchive,
        "import re\n"
        "if sys.argv[1] == 'generate':\n"
        "    d = re.search(r'ArchiveDir \"(.*)\"', open(sys.argv[2]).read()).group(1)\n"
        "    stanza = 'Filename: pool/x.deb\\nSHA256: ' + '0' * 64 + '\\nSize: 1\\n\\n'\n"
        "    with open(d + '/dists/stable/main/binary-amd64/Packages', 'a') as out:\n"
        "        out.write(stanza)\n",
    )
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match="does not match the admitted packages"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_missing_repodata_file_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "createrepo_c",
        tools.createrepo_c,
        "import glob, os\n"
        "for p in glob.glob(sys.argv[-1] + '/repodata/*-other.xml.gz'):\n"
        "    os.unlink(p)\n",
    )
    fake = dataclasses.replace(tools, createrepo_c=wrapper)
    with pytest.raises(MetadataError, match="cannot be read"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_repodata_file_that_repomd_does_not_list_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "createrepo_c",
        tools.createrepo_c,
        "open(sys.argv[-1] + '/repodata/stray.xml', 'w').write('x')\n",
    )
    fake = dataclasses.replace(tools, createrepo_c=wrapper)
    with pytest.raises(MetadataError, match="does not list"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_wrong_location_prefix_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    """The same tool without `--location-prefix` writes plain locations, which must be refused."""
    plain = _stand_in(
        tmp_path,
        "createrepo_c",
        f'for last; do :; done\nexec {tools.createrepo_c} --quiet --no-database "$last"',
    )
    fake = dataclasses.replace(tools, createrepo_c=plain)
    with pytest.raises(MetadataError, match=r"primary\.xml does not match"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_tool_that_hangs_is_stopped(
    tools: Tools,
    fixtures: Fixtures,
    site: Site,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(metadata, "APT_TIMEOUT_SECONDS", 0.3)
    fake = dataclasses.replace(tools, apt_ftparchive=_stand_in(tmp_path, "apt", "sleep 30"))
    with pytest.raises(ToolTimeout):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)
    assert list(site.work.iterdir()) == []


def test_a_tool_that_floods_its_output_is_stopped(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    flood = _stand_in(tmp_path, "createrepo_c", "head -c 20000000 /dev/zero")
    fake = dataclasses.replace(tools, createrepo_c=flood)
    with pytest.raises(ToolError, match="more output than allowed"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_working_path_the_tool_cannot_take_is_refused(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    odd = tmp_path / 'odd"name'
    odd.mkdir(mode=0o700)
    with pytest.raises(MetadataError, match="characters the tool cannot take"):
        build(_small(fixtures), cache=site.cache, tools=tools, target=site.target, work=odd)


def test_a_planted_link_or_package_in_the_tree_is_found(tmp_path: Path) -> None:
    (tmp_path / "ok").write_text("x", encoding="utf-8")
    metadata._require_no_package_bytes(tmp_path)
    (tmp_path / "a.deb").write_bytes(b"x")
    with pytest.raises(MetadataError, match="no package or link"):
        metadata._require_no_package_bytes(tmp_path)
    (tmp_path / "a.deb").unlink()
    (tmp_path / "link").symlink_to(tmp_path / "ok")
    with pytest.raises(MetadataError, match="no package or link"):
        metadata._require_no_package_bytes(tmp_path)


def test_the_stand_in_helpers_are_executable(tmp_path: Path) -> None:
    path = _stand_in(tmp_path, "x", "exit 0")
    assert stat.S_IMODE(path.stat().st_mode) == 0o755


# --- findings of the blind review -----------------------------------------------------------


def test_a_link_left_in_an_index_directory_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "apt-ftparchive",
        tools.apt_ftparchive,
        "import os, re\n"
        "if sys.argv[1] == 'generate':\n"
        "    d = re.search(r'ArchiveDir \"(.*)\"', open(sys.argv[2]).read()).group(1)\n"
        "    os.symlink('/etc/hostname', d + '/dists/stable/main/binary-amd64/extra')\n",
    )
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match="exactly the three indexes"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_corrupt_compressed_index_is_a_metadata_error(tmp_path: Path) -> None:
    bad = tmp_path / "x.gz"
    good = gzip.compress(bytes(range(256)) * 40 + b"a" * 4000)
    bad.write_bytes(good[:20] + b"\xff" * 200 + good[220:])
    with pytest.raises(MetadataError, match="cannot be read"):
        metadata._digest(bad, "gz")
    with pytest.raises(MetadataError, match="cannot be read"):
        metadata._text(bad, "gz")


def test_two_records_for_one_pool_path_are_refused(
    tools: Tools, fixtures: Fixtures, site: Site
) -> None:
    entry = fixtures.entries[(OLD, "8.3", "amd64", "deb")]
    other = dataclasses.replace(entry, package=dataclasses.replace(entry.package, sha256="1" * 64))
    with pytest.raises(MetadataError, match="listed twice"):
        build([entry, other], cache=site.cache, tools=tools, target=site.target, work=site.work)


def test_a_release_dated_off_the_clock_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    script = tmp_path / "apt-date"
    script.write_text(
        f"#!{sys.executable}\nimport re, subprocess, sys\n"
        f"r = subprocess.run([{str(tools.apt_ftparchive)!r}, *sys.argv[1:]], capture_output=True)\n"
        "out = r.stdout.decode()\n"
        "if 'release' in sys.argv:\n"
        "    out = re.sub(r'(Date: .* )20\\d\\d', lambda m: m.group(1) + '2020', out)\n"
        "    out = re.sub(r'(Valid-Until: .* )20\\d\\d', lambda m: m.group(1) + '2020', out)\n"
        "sys.stdout.write(out)\nsys.stderr.write(r.stderr.decode())\nsys.exit(r.returncode)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    fake = dataclasses.replace(tools, apt_ftparchive=script)
    with pytest.raises(MetadataError, match="not near the clock"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_writable_target_is_refused(tools: Tools, site: Site) -> None:
    site.target.chmod(0o777)
    with pytest.raises(MetadataError, match="writable by others"):
        build([], cache=site.cache, tools=tools, target=site.target, work=site.work)


def _release_rewriter(directory: Path, real: Path, edit: str) -> Path:
    """A program that runs the real tool and rewrites the text of its `release` output."""
    path = directory / "apt-release"
    path.write_text(
        f"#!{sys.executable}\nimport re, subprocess, sys\n"
        f"r = subprocess.run([{str(real)!r}, *sys.argv[1:]], capture_output=True)\n"
        "out = r.stdout.decode()\n"
        f"if 'release' in sys.argv:\n    {edit}\n"
        "sys.stdout.write(out)\nsys.stderr.write(r.stderr.decode())\nsys.exit(r.returncode)\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ("out = out.replace('Origin: Fojle', 'Origin: Other')", "field Origin"),
        ("out = out.replace('Label: Fojle', 'Label: Other')", "field Label"),
        ("out = out.replace('Acquire-By-Hash: yes', 'Acquire-By-Hash: no')", "Acquire-By-Hash"),
        (
            "out = re.sub(r'(Valid-Until: \\w+, )(\\d+)', lambda m: m.group(1) + '28', out)",
            "validity period",
        ),
        (
            "out = re.sub(r'\\n [0-9a-f]{64} +\\d+ main/binary-arm64/Packages.xz', '', out)",
            "exactly the index files",
        ),
        (
            "out = re.sub(r'(\\n [0-9a-f]{63})([0-9a-f])',"
            " lambda m: m.group(1) + ('1' if m.group(2) == '0' else '0'), out, count=1)",
            "does not match",
        ),
        ("out = out.replace('SHA256:', 'SHA256:\\n zz 1 x', 1)", "malformed"),
        (
            "out = re.sub(r'(\\n [0-9a-f]{127})([0-9a-f])',"
            " lambda m: m.group(1) + ('1' if m.group(2) == '0' else '0'), out, count=1)",
            "does not match",
        ),
        (
            "out = re.sub(r'\\n [0-9a-f]{128} +\\d+ main/binary-arm64/Packages.xz', '', out)",
            "exactly the index files",
        ),
        ("out = out.replace('SHA512:', 'SHA512:\\n zz 1 x', 1)", "malformed"),
        ("out = re.sub(r'\\nSHA512:.*', '', out, flags=re.S)", "SHA512"),
    ],
)
def test_a_release_that_breaks_a_rule_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path, edit: str, message: str
) -> None:
    script = _release_rewriter(tmp_path, tools.apt_ftparchive, edit)
    fake = dataclasses.replace(tools, apt_ftparchive=script)
    with pytest.raises(MetadataError, match=message):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_missing_by_hash_copy_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "apt-ftparchive",
        tools.apt_ftparchive,
        "import shutil\n"
        "if 'release' in sys.argv:\n"
        "    shutil.rmtree(sys.argv[-1] + '/main/binary-amd64/by-hash')\n",
    )
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match="by-hash copy"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_a_missing_sha512_by_hash_copy_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path
) -> None:
    """apt requests the by-hash/SHA512 path, so a missing SHA512 copy breaks every client."""
    wrapper = _wrapper(
        tmp_path,
        "apt-ftparchive",
        tools.apt_ftparchive,
        "import shutil\n"
        "if 'release' in sys.argv:\n"
        "    shutil.rmtree(sys.argv[-1] + '/main/binary-amd64/by-hash/SHA512')\n",
    )
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match="by-hash copy"):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (
            "t = re.sub(r'SHA256: [0-9a-f]{64}', 'SHA256: ' + '0' * 64, t, count=1)",
            "does not match",
        ),
        ("t = re.sub(r'Size: \\d+', 'Size: 1', t, count=1)", "does not match"),
        (
            "t = t.replace('Description: test', 'Description: other', 1)",
            "compressed indexes differ",
        ),
    ],
)
def test_a_packages_index_that_changes_a_record_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path, edit: str, message: str
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "apt-ftparchive",
        tools.apt_ftparchive,
        "import re\n"
        "if sys.argv[1] == 'generate':\n"
        "    d = re.search(r'ArchiveDir \"(.*)\"', open(sys.argv[2]).read()).group(1)\n"
        "    f = d + '/dists/stable/main/binary-amd64/Packages'\n"
        "    t = open(f).read()\n"
        f"    {edit}\n"
        "    open(f, 'w').write(t)\n",
    )
    fake = dataclasses.replace(tools, apt_ftparchive=wrapper)
    with pytest.raises(MetadataError, match=message):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (
            "t = re.sub(r'(<checksum type=\"sha256\">)[0-9a-f]', r'\\g<1>0', t, count=1)",
            r"checksum of \w+ does not match",
        ),
        (
            "t = re.sub(r'(<open-checksum type=\"sha256\">)[0-9a-f]', r'\\g<1>0', t, count=1)",
            "open-checksum",
        ),
        (
            "t = re.sub(r'<data type=\"filelists\">.*?</data>', '', t, flags=re.S)",
            "lacks primary, filelists or other",
        ),
        (
            "t = t.replace('<location href=\"repodata/', '<location href=\"x/', 1)",
            "is incomplete",
        ),
    ],
)
def test_a_repomd_that_breaks_a_rule_fails_the_build(
    tools: Tools, fixtures: Fixtures, site: Site, tmp_path: Path, edit: str, message: str
) -> None:
    wrapper = _wrapper(
        tmp_path,
        "createrepo_c",
        tools.createrepo_c,
        "import re\n"
        "f = sys.argv[-1] + '/repodata/repomd.xml'\n"
        "t = open(f).read()\n"
        f"{edit}\n"
        "open(f, 'w').write(t)\n",
    )
    fake = dataclasses.replace(tools, createrepo_c=wrapper)
    with pytest.raises(MetadataError, match=message):
        build(_small(fixtures), cache=site.cache, tools=fake, target=site.target, work=site.work)


def test_the_release_is_readable_by_the_web_server(built: Built) -> None:
    release = built.site.target / "dists/stable/Release"
    assert stat.S_IMODE(release.stat().st_mode) == 0o644


def test_every_file_and_directory_is_readable_whatever_the_umask(
    tools: Tools, fixtures: Fixtures, site: Site
) -> None:
    previous = os.umask(0o077)
    try:
        build(_small(fixtures), cache=site.cache, tools=tools, target=site.target, work=site.work)
    finally:
        os.umask(previous)
    paths = [site.target, *site.target.rglob("*")]
    assert len(paths) > 20
    for path in paths:
        expected = 0o755 if path.is_dir() else 0o644
        assert stat.S_IMODE(path.stat().st_mode) == expected, path
