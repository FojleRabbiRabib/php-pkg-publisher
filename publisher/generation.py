# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Publish a signed metadata tree as a new generation, flip `current` to it, and roll back.

Layout under the site root (outside the web root; the web root holds two static links,
`apt -> <root>/current/apt` and `rpm -> <root>/current/rpm`, made once at bootstrap):

  versions/<id>/apt/dists/...   versions/<id>/rpm/...   one immutable tree per generation
  store/<path>                  every hash-named file kept for clients that fetched an older index
  generations/<id>.json         the content set of each generation, for rollback and skipping
  staging/                      scratch space on the same file system
  current -> versions/<id>      the only thing a flip changes
  pin.json                      present while a rollback is in force

A generation id is `<8-digit sequence>-<UTC time>`; generations are ordered by the sequence, never
by the clock. A client that fetched an old `InRelease` or `repomd.xml` asks for the hash-named
files that file names (`by-hash/SHA256|SHA512/<hash>`, `repodata/<sha256>-*`), so the new tree
carries them forward by hard link from the store: a hash-named file stays while one of the last
three generations lists it or it is less than seven days old. What each generation lists is read
from that generation's own `Release` and `repomd.xml`, not from a separate list. Before the flip
the new tree must resolve every path named by the last three generations. The flip is a
temporary symlink renamed over `current`, never `ln -sfn`. The caller holds the run lock.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import shutil
import stat
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from publisher import config, files, metadata, net, signer
from publisher.admit import AdmittedPackage
from publisher.cache import Cache
from publisher.metadata import Entry
from publisher.signer import SigningKey
from publisher.tools import Tools
from publisher.verify import RPM_ARCHITECTURES

GENERATION_ID: Final = re.compile(r"([0-9]{8})-[0-9]{8}T[0-9]{6}Z")
KEEP_TREES: Final = 3
LIVE_GENERATIONS: Final = 3
KEEP_MANIFESTS: Final = 60
HASHED_MIN_AGE_SECONDS: Final = 7 * 24 * 3600
REFRESH_SECONDS: Final = 24 * 3600
NEW_SUFFIX: Final = ".new"
LINK_PREFIX: Final = "current-"
MANIFEST_VERSION: Final = 1
MAX_MANIFEST_BYTES: Final = 16 * 1024 * 1024
READ_CHUNK_BYTES: Final = 1024 * 1024
APT_ROOT: Final = f"apt/dists/{metadata.SUITE}"
BY_HASH_PATH: Final = re.compile(
    rf"{APT_ROOT}/{metadata.COMPONENT}/binary-[a-z0-9]+/by-hash/(SHA256|SHA512)/([0-9a-f]+)"
)
REPODATA_PATH: Final = re.compile(r"rpm/[0-9.]+/[a-z0-9_]+/repodata/([0-9a-f]{64})-[A-Za-z0-9._-]+")
LOCATION: Final = re.compile(r'<location href="repodata/([^"/]+)"/>')
ENTRY_KEYS: Final = frozenset(
    {"repo", "tag", "name", "kind", "layout", "php", "arch", "sha256", "size"}
)
MANIFEST_KEYS: Final = frozenset({"version", "id", "created", "entries"})
PIN_KEYS: Final = frozenset({"generation", "since"})


class GenerationError(Exception):
    """The site is not in a state that can be published to, or a check before the flip failed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Site:
    root: Path

    @property
    def versions(self) -> Path:
        return self.root / "versions"

    @property
    def store(self) -> Path:
        return self.root / "store"

    @property
    def manifests(self) -> Path:
        return self.root / "generations"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def current(self) -> Path:
        return self.root / "current"

    @property
    def pin(self) -> Path:
        return self.root / "pin.json"


@dataclass(frozen=True, slots=True, kw_only=True)
class Published:
    """What a publish did: the new generation, or None when nothing changed."""

    generation: str | None
    skipped: bool
    pinned: bool
    pin_dropped: bool = False
    retire_error: str | None = None


def _fail(message: str, error: OSError) -> GenerationError:
    return GenerationError(f"{message}: {error.strerror or error}")


def open_site(root: Path) -> Site:
    """Check the site directories (creating the missing ones) and that hard links can work."""
    if not root.is_absolute():
        raise GenerationError(f"{root}: must be an absolute path")
    site = Site(root=root)
    try:
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise GenerationError(
                f"{root}: must be a directory of the current user, not writable by others"
            )
        if not info.st_mode & 0o001:
            raise GenerationError(f"{root}: the web server must be able to enter it (o+x)")
        for directory, mode in (
            (site.versions, 0o755),
            (site.store, 0o700),
            (site.manifests, 0o700),
            (site.staging, 0o700),
        ):
            directory.mkdir(mode=mode, exist_ok=True)
            if mode == 0o755:
                directory.chmod(mode)  # the umask must not close the tree to the web server
            current = directory.lstat()
            if (
                not stat.S_ISDIR(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_mode & 0o022
            ):
                raise GenerationError(f"{directory}: must be a directory of the current user")
            if mode == 0o700:
                files.require_private_directory(directory)
        devices = {path.lstat().st_dev for path in (site.versions, site.store, site.staging)}
    except OSError as error:
        raise _fail(f"{root}: cannot prepare", error) from error
    except files.FileError as error:
        raise GenerationError(str(error)) from error
    if len(devices) != 1:
        raise GenerationError(f"{root}: versions, store and staging must share one file system")
    return site


def _sequence(identifier: str) -> int:
    match = GENERATION_ID.fullmatch(identifier)
    if match is None:
        raise GenerationError(f"{net.safe(identifier)}: not a generation id")
    return int(match.group(1))


def _current(site: Site) -> str | None:
    """The id `current` points to; None when there is none yet. Anything odd is an error."""
    try:
        info = site.current.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _fail(f"{site.current}: cannot inspect", error) from error
    if not stat.S_ISLNK(info.st_mode):
        raise GenerationError(f"{site.current}: must be a symbolic link")
    target = str(site.current.readlink())
    prefix = "versions/"
    if not target.startswith(prefix) or GENERATION_ID.fullmatch(target[len(prefix) :]) is None:
        raise GenerationError(f"{site.current}: points to {net.safe(target)}, not a generation")
    identifier = target[len(prefix) :]
    if not (site.versions / identifier).is_dir():
        raise GenerationError(f"{site.current}: points to a generation that does not exist")
    return identifier


def generations(site: Site) -> list[str]:
    """The ids of the version trees, oldest first."""
    try:
        names = [p.name for p in site.versions.iterdir() if GENERATION_ID.fullmatch(p.name)]
    except OSError as error:
        raise _fail(f"{site.versions}: cannot list", error) from error
    return sorted(names, key=_sequence)


def _manifest_ids(site: Site) -> list[str]:
    try:
        stems = [p.stem for p in site.manifests.iterdir() if p.suffix == ".json"]
    except OSError as error:
        raise _fail(f"{site.manifests}: cannot list", error) from error
    return sorted((s for s in stems if GENERATION_ID.fullmatch(s)), key=_sequence)


def _entry_document(entry: Entry) -> dict[str, Any]:
    package = entry.package
    return {
        "repo": entry.repo,
        "tag": entry.tag,
        "name": package.name,
        "kind": package.kind,
        "layout": package.layout,
        "php": package.php,
        "arch": package.arch,
        "sha256": package.sha256,
        "size": package.size,
    }


def _order(entry: Entry) -> tuple[str, str, str]:
    return (entry.repo, entry.tag, entry.package.name)


def _manifest_bytes(identifier: str, now: float, entries: Sequence[Entry]) -> bytes:
    document = {
        "version": MANIFEST_VERSION,
        "id": identifier,
        "created": now,
        "entries": [_entry_document(e) for e in sorted(entries, key=_order)],
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load_json(path: Path, keys: frozenset[str]) -> dict[str, Any]:
    if path.is_symlink():
        raise GenerationError(f"{path.name}: must not be a link")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise GenerationError(f"{path.name}: larger than allowed")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=net.no_duplicate_keys)
    except OSError as error:
        raise _fail(f"{path.name}: cannot read", error) from error
    except (ValueError, net.DuplicateKey) as error:
        raise GenerationError(f"{path.name}: is not valid: {error}") from error
    if not isinstance(document, dict) or set(document) != keys:
        raise GenerationError(f"{path.name}: does not have exactly the expected keys")
    return document


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise GenerationError("a finite number was expected")
    return float(value)


def read_manifest(site: Site, identifier: str) -> tuple[float, tuple[Entry, ...]]:
    """The creation time and content set of a generation, strictly parsed."""
    _sequence(identifier)
    path = site.manifests / f"{identifier}.json"
    document = _load_json(path, MANIFEST_KEYS)
    version = document["version"]
    if type(version) is not int or version != MANIFEST_VERSION or document["id"] != identifier:
        raise GenerationError(f"{path.name}: is for another generation or version")
    created = _number(document["created"])
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list):
        raise GenerationError(f"{path.name}: entries must be a list")
    entries: list[Entry] = []
    for item in raw_entries:
        if not isinstance(item, dict) or set(item) != ENTRY_KEYS:
            raise GenerationError(f"{path.name}: an entry does not have the expected keys")
        text = {k: v for k, v in item.items() if k != "size"}
        size = item["size"]
        if any(not isinstance(v, str) for v in text.values()) or (
            isinstance(size, bool) or not isinstance(size, int)
        ):
            raise GenerationError(f"{path.name}: an entry has a value of the wrong type")
        package = AdmittedPackage(
            name=text["name"],
            kind=text["kind"],
            layout=text["layout"],
            php=text["php"],
            arch=text["arch"],
            sha256=text["sha256"],
            size=size,
        )
        entries.append(Entry(repo=text["repo"], tag=text["tag"], package=package))
    return created, tuple(sorted(entries, key=_order))


def _file_digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm.lower())
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(READ_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as error:
        raise _fail(f"{path.name}: cannot read", error) from error
    return digest.hexdigest()


def _expected_digest(relative: str) -> tuple[str, str] | None:
    """(algorithm, hex digest) a hash-named path promises, or None when it is not hash-named."""
    by_hash = BY_HASH_PATH.fullmatch(relative)
    if by_hash is not None:
        algorithm, digest = by_hash.group(1), by_hash.group(2)
        length = metadata.BY_HASH_ALGORITHMS[algorithm]
        return (algorithm, digest) if len(digest) == length else None
    repodata = REPODATA_PATH.fullmatch(relative)
    if repodata is not None:
        return "SHA256", repodata.group(1)
    return None


def _hashed_files(root: Path) -> dict[str, Path]:
    """The hash-named files of a tree, each checked to hold the content its name promises."""
    found: dict[str, Path] = {}
    for top in ("apt", "rpm"):
        base = root / top
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_symlink():
                raise GenerationError(f"{path.relative_to(root)}: a link in the tree")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            promised = _expected_digest(relative)
            if promised is None:
                continue
            if _file_digest(path, promised[0]) != promised[1]:
                raise GenerationError(f"{relative}: does not hold the content its name promises")
            found[relative] = path
    return found


def _live_paths(root: Path) -> set[str]:
    """Every hash-named path the metadata of this tree itself names (Release and repomd.xml)."""
    release = root / APT_ROOT / "Release"
    try:
        _, hashes = metadata.parse_release(release.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, metadata.MetadataError) as error:
        raise GenerationError(f"{release}: cannot be read: {error}") from error
    live: set[str] = set()
    for algorithm, listed in hashes.items():
        for name, (digest, _) in listed.items():
            parent = posixpath.dirname(name)
            live.add(f"{APT_ROOT}/{parent}/by-hash/{algorithm}/{digest}")
    for tree in _rpm_trees():
        repomd = root / tree / "repodata" / "repomd.xml"
        try:
            text = repomd.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise GenerationError(f"{repomd}: cannot be read: {error}") from error
        for name in LOCATION.findall(text):
            live.add(f"{tree}/repodata/{name}")
    return live


def _rpm_trees() -> list[str]:
    return [
        f"rpm/{php}/{RPM_ARCHITECTURES[arch]}"
        for php in sorted(config.PHP_VERSIONS)
        for arch in sorted(config.ARCHITECTURES)
    ]


def _check_tree(root: Path) -> None:
    """The tree must be complete and signed, and hold no package and no link."""
    required = [f"{APT_ROOT}/{name}" for name in ("Release", "InRelease", "Release.gpg")]
    for tree in _rpm_trees():
        required += [f"{tree}/repodata/repomd.xml", f"{tree}/repodata/repomd.xml.asc"]
    for relative in required:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise GenerationError(f"{relative}: missing from the tree")
    for path in root.rglob("*"):
        if path.is_symlink() or path.suffix in (".deb", ".rpm"):
            raise GenerationError(f"{path.relative_to(root)}: a package or a link in the tree")


def _read_release_date(release: Path) -> float:
    try:
        fields, _ = metadata.parse_release(release.read_text(encoding="utf-8"))
        issued = datetime.strptime(fields["Date"], metadata.RELEASE_DATE_FORMAT)
    except (OSError, UnicodeDecodeError, KeyError, ValueError, metadata.MetadataError) as error:
        raise GenerationError(f"{release}: has no readable Date: {error}") from error
    return issued.replace(tzinfo=timezone.utc).timestamp()


def _make_dirs(path: Path, stop: Path, mode: int) -> None:
    """Create `path` and its missing parents below `stop`, each with exactly `mode`."""
    missing: list[Path] = []
    current = path
    while current != stop and not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=mode)
        directory.chmod(mode)


def _link(source: Path, destination: Path, stop: Path, mode: int) -> bool:
    """Hard-link `source` at `destination`; True when it is new, False when the same bytes exist."""
    _make_dirs(destination.parent, stop, mode)
    try:
        os.link(source, destination)
    except FileExistsError:
        if _file_digest(source, "SHA256") != _file_digest(destination, "SHA256"):
            raise GenerationError(f"{destination.name}: exists with other content") from None
        return False
    except OSError as error:
        raise _fail(f"cannot link {destination.name}", error) from error
    return True


def _remove_tree(path: Path) -> None:
    """Remove a directory tree; a failure is an error, never silently ignored."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise _fail(f"{path}: cannot remove", error) from error


def _sweep(site: Site) -> None:
    """Remove what a crashed run left: half-built trees, temporary links, staging, orphans.

    Trees and manifests newer than `current` never went live and are removed. Without a
    `current`, only a first publication that died before its flip can have left anything, which
    is sequence 1; anything more means the link was lost, and nothing is deleted.
    """
    current = _current(site)
    newest = _sequence(current) if current else 0
    known = [*generations(site), *_manifest_ids(site)]
    if current is None and any(_sequence(i) > 1 for i in known):
        raise GenerationError(
            f"{site.current}: current is missing but several generations exist; restore the link"
        )
    try:
        for path in site.versions.iterdir():
            if path.name.endswith(NEW_SUFFIX):
                _remove_tree(path)
        for path in site.root.iterdir():
            if path.name.startswith(LINK_PREFIX) and path.is_symlink():
                path.unlink()
        for path in site.staging.iterdir():
            if path.is_dir() and not path.is_symlink():
                _remove_tree(path)
            else:
                path.unlink()
        for identifier in generations(site):
            if _sequence(identifier) > newest:
                _remove_tree(site.versions / identifier)
        for identifier in _manifest_ids(site):
            if _sequence(identifier) > newest:
                (site.manifests / f"{identifier}.json").unlink(missing_ok=True)
    except OSError as error:
        raise _fail(f"{site.root}: cannot clean up", error) from error


def _next_identifier(site: Site, now: float) -> str:
    current = _current(site)
    known = [*generations(site), *_manifest_ids(site)]
    if current:
        known.append(current)
    sequence = max((_sequence(i) for i in known), default=0) + 1
    if sequence > 99_999_999:
        raise GenerationError("the generation sequence is exhausted")
    return f"{sequence:08d}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}"


@dataclass(frozen=True, slots=True, kw_only=True)
class _Plan:
    """What a new tree must carry from the store and what the store may drop afterwards."""

    carry: set[str]
    drop: set[str]


def _plan_store(site: Site, live: set[str], now: float) -> _Plan:
    carry: set[str] = set()
    drop: set[str] = set()
    try:
        stored = [p for p in site.store.rglob("*") if p.is_file()]
    except OSError as error:
        raise _fail(f"{site.store}: cannot list", error) from error
    for path in stored:
        relative = path.relative_to(site.store).as_posix()
        try:
            age = now - path.stat().st_mtime
        except OSError as error:
            raise _fail(f"{relative}: cannot inspect", error) from error
        # A negative age (the clock stepped back) counts as young: never age a file out early.
        if relative in live or age < HASHED_MIN_AGE_SECONDS:
            carry.add(relative)
        else:
            drop.add(relative)
    return _Plan(carry=carry, drop=drop)


def _assemble(
    site: Site, tree: Path, identifier: str, now: float, previous: Sequence[str]
) -> tuple[Path, set[str]]:
    """Build `versions/<id>.new` from a signed tree plus the hash-named files to carry forward.

    Returns the new tree and the store files that may be removed once the flip has happened.
    """
    new = site.versions / f"{identifier}{NEW_SUFFIX}"
    new.mkdir(mode=0o755)
    new.chmod(0o755)
    (new / "apt").mkdir(mode=0o755)
    (new / "apt").chmod(0o755)
    if {p.name for p in tree.iterdir()} != {"dists", "rpm"}:
        raise GenerationError(f"{tree}: must hold exactly dists and rpm")
    (tree / "dists").rename(new / "apt" / "dists")
    (tree / "rpm").rename(new / "rpm")
    _check_tree(new)
    for relative, path in _hashed_files(new).items():
        stored = site.store / relative
        if _link(path, stored, site.store, 0o700):
            os.utime(stored, (now, now))  # the age of a stored file counts from its first storage
    older = {i: _live_paths(site.versions / i) for i in previous[-(LIVE_GENERATIONS - 1) :]}
    plan = _plan_store(site, _live_paths(new).union(*older.values()), now)
    for relative in sorted(plan.carry):
        target = new / relative
        if target.exists():
            continue
        promised = _expected_digest(relative)
        if promised is None or _file_digest(site.store / relative, promised[0]) != promised[1]:
            raise GenerationError(f"{relative}: the stored file does not match its name")
        _link(site.store / relative, target, new, 0o755)
    for live_before in older.values():
        for relative in live_before:
            if not (new / relative).is_file():
                raise GenerationError(f"{relative}: would disappear for clients of an older index")
    return new, plan.drop


def _flip(site: Site, identifier: str) -> None:
    temporary = site.root / f"{LINK_PREFIX}{secrets.token_hex(6)}"
    try:
        temporary.symlink_to(f"versions/{identifier}")
        temporary.replace(site.current)
    except OSError as error:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise _fail("cannot flip current", error) from error
    try:
        files.sync_directory(site.root)
    except OSError as error:
        raise _fail(
            "current was flipped but the change may not survive a power loss", error
        ) from error


def _retire(site: Site, identifier: str, drop: Collection[str]) -> None:
    """After the flip: remove old trees, old manifests and store files nobody needs."""
    try:
        trees = generations(site)
        for old in trees[: max(0, len(trees) - KEEP_TREES)]:
            if old != identifier:
                _remove_tree(site.versions / old)
        manifests = _manifest_ids(site)
        pinned = _read_pin(site)
        for old in manifests[: max(0, len(manifests) - KEEP_MANIFESTS)]:
            if old not in (identifier, pinned):
                (site.manifests / f"{old}.json").unlink(missing_ok=True)
        for relative in drop:
            (site.store / relative).unlink(missing_ok=True)
        for directory in sorted(
            (p for p in site.store.rglob("*") if p.is_dir()), key=lambda p: -len(p.parts)
        ):
            with contextlib.suppress(OSError):
                directory.rmdir()
    except OSError as error:
        raise _fail("cannot retire old generations", error) from error


def _read_pin(site: Site) -> str | None:
    if not os.path.lexists(site.pin):  # a dangling link is not "no pin"
        return None
    document = _load_json(site.pin, PIN_KEYS)
    identifier = document["generation"]
    if not isinstance(identifier, str):
        raise GenerationError("pin.json: generation must be a string")
    _number(document["since"])
    _sequence(identifier)
    return identifier


def pinned(site: Site) -> str | None:
    """The generation a rollback holds the site at, or None."""
    return _read_pin(site)


def clear_pin(site: Site) -> None:
    """End a rollback: the next publish builds from the admitted state again."""
    try:
        site.pin.unlink(missing_ok=True)
        files.sync_directory(site.root)
    except OSError as error:
        raise _fail("cannot clear the pin", error) from error


def _sync_tree(root: Path) -> None:
    """Flush every file and directory of the new tree: the tools that wrote it do not."""
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            files.sync_directory(path)
        else:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


@dataclass(frozen=True, slots=True, kw_only=True)
class Installed:
    """A generation that is live. `retire_error` is set when only the clean-up afterwards failed."""

    generation: str
    retire_error: str | None


def install(
    site: Site, tree: Path, entries: Sequence[Entry], *, now: float, sweep: bool = True
) -> Installed:
    """Turn a signed tree into the newest generation and make `current` point at it."""
    if sweep:
        _sweep(site)
    identifier = _next_identifier(site, now)
    previous = [i for i in generations(site) if i != identifier]
    new, drop = _assemble(site, tree, identifier, now, previous)
    try:
        _sync_tree(new)
        files.write_atomic(
            site.manifests / f"{identifier}.json", _manifest_bytes(identifier, now, entries)
        )
        new.rename(site.versions / identifier)
        files.sync_directory(site.versions)
    except OSError as error:
        raise _fail("cannot write the generation", error) from error
    _flip(site, identifier)
    try:
        _retire(site, identifier, drop)
    except GenerationError as error:
        return Installed(generation=identifier, retire_error=str(error))
    return Installed(generation=identifier, retire_error=None)


def _same_content(left: Sequence[Entry], right: Sequence[Entry]) -> bool:
    return sorted(left, key=_order) == sorted(right, key=_order)


def _build_and_install(
    site: Site,
    entries: Sequence[Entry],
    *,
    cache: Cache,
    tools: Tools,
    key: SigningKey,
    now: float,
) -> Installed:
    stage = site.staging / f"build-{secrets.token_hex(6)}"
    try:
        stage.mkdir(mode=0o700)
        (stage / "tree").mkdir(mode=0o755)
        (stage / "tree").chmod(0o755)
        (stage / "work").mkdir(mode=0o700)
        built = metadata.build(
            entries, cache=cache, tools=tools, target=stage / "tree", work=stage / "work"
        )
        signer.sign(stage / "tree", built, key, tools=tools, work=stage / "work")
        return install(site, stage / "tree", entries, now=now, sweep=False)
    except OSError as error:
        raise _fail("cannot stage the build", error) from error
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def publish(
    site: Site,
    entries: Sequence[Entry],
    *,
    cache: Cache,
    tools: Tools,
    key: SigningKey,
    excluded: Collection[tuple[str, str]],
    now: float,
) -> Published:
    """Build, sign and publish `entries` as a new generation, unless nothing has changed.

    While a rollback pin is in force the pinned content set is re-signed instead and `entries`
    is ignored, so new releases wait until the pin is cleared. An exclusion beats the pin: when
    the pinned set lists a release that is excluded now, the pin is dropped and `entries` are
    published, so a yanked release is never kept alive by a rollback (`pin_dropped` says so).
    """
    _sweep(site)
    hold = _read_pin(site)
    dropped = False
    wanted: Sequence[Entry] = tuple(entries)
    if hold:
        pinned_set = read_manifest(site, hold)[1]
        if {(e.repo, e.tag) for e in pinned_set} & set(excluded):
            clear_pin(site)
            hold, dropped = None, True
        else:
            wanted = pinned_set
    if {(e.repo, e.tag) for e in wanted} & set(excluded):
        raise GenerationError("the content set lists an excluded release")
    current = _current(site)
    if current is not None:
        same = _same_content(read_manifest(site, current)[1], wanted)
        issued = _read_release_date(site.versions / current / APT_ROOT / "Release")
        if same and 0 <= now - issued < REFRESH_SECONDS:
            return Published(
                generation=None, skipped=True, pinned=hold is not None, pin_dropped=dropped
            )
    done = _build_and_install(site, wanted, cache=cache, tools=tools, key=key, now=now)
    return Published(
        generation=done.generation,
        skipped=False,
        pinned=hold is not None,
        pin_dropped=dropped,
        retire_error=done.retire_error,
    )


def rollback(
    site: Site,
    identifier: str,
    *,
    excluded: Collection[tuple[str, str]],
    cache: Cache,
    tools: Tools,
    key: SigningKey,
    now: float,
) -> Published:
    """Rebuild and re-sign an older content set as a new generation, and pin the site to it.

    `excluded` holds the (product, tag) pairs that are excluded now; a content set that lists
    one is refused. The pin is written first, so a failed rollback is retried by the next run.
    """
    _sweep(site)
    _, wanted = read_manifest(site, identifier)
    banned = sorted({(e.repo, e.tag) for e in wanted} & set(excluded))
    if banned:
        raise GenerationError(f"generation {identifier} lists an excluded release: {banned[0]}")
    current = _current(site)
    if current is not None and _same_content(read_manifest(site, current)[1], wanted):
        raise GenerationError(f"generation {identifier} has the content that is already current")
    try:
        files.write_atomic(
            site.pin,
            (json.dumps({"generation": identifier, "since": now}, sort_keys=True) + "\n").encode(),
        )
    except OSError as error:
        raise _fail("cannot write the pin", error) from error
    done = _build_and_install(site, wanted, cache=cache, tools=tools, key=key, now=now)
    return Published(
        generation=done.generation, skipped=False, pinned=True, retire_error=done.retire_error
    )
