#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Deploy a signed release tag of the publisher to this host, as root.

The release workflow logs in as the deploy user, whose key is locked to one command: this file,
run through one sudo line with no arguments, with a `git bundle` of the tag on standard input.
Nothing the client sends is trusted: the tag must carry a valid SSH signature of the pinned
release key, its name must match the signed name, and its version must not be older than the
last deploy. Only then are files read from the tag and put in place.

Only the files that `rules()` names are ever written. A file is replaced in place; the only files
deleted are those this script's own manifest lists from an earlier deploy and that the new tag
no longer carries. Before anything changes, each file it will replace or delete is copied to a
backup, and any failure puts the backup back.

Everything printed is public (the workflow log of a public repository shows it), so it is one
fixed code. The details go to the journal.

Standard library only. Installed as an executable file, it runs with no arguments as the forced
command. Local commands, run by root: `rollback`, `allow vX.Y.Z`, `check`, `record PATH...`,
`forget PATH...`.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import syslog
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import BinaryIO, Final, Protocol

CODE_DIR: Final = Path("/opt/php-pkg-publisher")
ETC_DIR: Final = Path("/etc/php-pkg-publisher")
UNITS_DIR: Final = Path("/etc/systemd/system")
CONFIG_DIR: Final = Path("/etc/php-pkg-publisher-deploy")
STATE_DIR: Final = Path("/var/lib/php-pkg-publisher-deploy")
SELF_PATH: Final = Path("/usr/local/sbin/php-pkg-publisher-deploy")

# The principal in the allowed-signers file; a fixed word, never a person's address.
PRINCIPAL: Final = "php-pkg-publisher-release"
PUBLISHER_USER: Final = "php-pkg-publisher"

GIT: Final = "/usr/bin/git"
SSH_KEYGEN: Final = "/usr/bin/ssh-keygen"
SYSTEMCTL: Final = "/usr/bin/systemctl"
CHATTR: Final = "/usr/bin/chattr"
LSATTR: Final = "/usr/bin/lsattr"
RUNUSER: Final = "/usr/sbin/runuser"
PYTHON: Final = "/usr/bin/python3"

MAX_BUNDLE_BYTES: Final = 64 * 1024 * 1024
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 16 * 1024 * 1024
MAX_FILES: Final = 500
KEEP_BACKUPS: Final = 5
COMMAND_SECONDS: Final = 120

NUMBER: Final = r"(?:0|[1-9][0-9]*)"
TAG: Final = re.compile(rf"v({NUMBER})\.({NUMBER})\.({NUMBER})")
SEGMENT: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@+-]{0,99}")
UNIT_FILE: Final = re.compile(r"php-pkg-publisher[A-Za-z0-9@._-]*\.(service|timer|path)")
BACKUP_NAME: Final = re.compile(r"[0-9]{6}-v[0-9.]+")
SETTING: Final = re.compile(r"([a-z_]+)=(/[^\s]*)")
FILE_MODES: Final = frozenset({"100644", "100755"})

# Stopped before the files change and started again after, when they were running.
SERVICES: Final = ("php-pkg-publisher.service", "php-pkg-publisher-watch.service")
SCHEDULES: Final = (
    "php-pkg-publisher.path",
    "php-pkg-publisher.timer",
    "php-pkg-publisher-watch.timer",
    "php-pkg-publisher-deploy-check.timer",
)

EXIT_REFUSED: Final = 2
EXIT_ROLLED_BACK: Final = 3
EXIT_BROKEN: Final = 4

CODES: Final = frozenset(
    {
        "bundle-invalid",
        "bundle-size",
        "config-invalid",
        "host-busy",
        "not-root",
        "products-invalid",
        "ref-invalid",
        "rolled-back",
        "signature-invalid",
        "state-invalid",
        "step-failed",
        "tag-invalid",
        "target-invalid",
        "tree-invalid",
        "usage",
        "version-denied",
        "version-older",
    }
)


class Refused(Exception):
    """The deploy stops. `code` is the only text that leaves the host; `detail` is journalled."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in CODES:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Layout:
    """Where everything is. The defaults are the host's; tests give folders of their own."""

    docroot: Path
    site_root: Path
    code_dir: Path = CODE_DIR
    etc_dir: Path = ETC_DIR
    units_dir: Path = UNITS_DIR
    config_dir: Path = CONFIG_DIR
    state_dir: Path = STATE_DIR
    self_path: Path = SELF_PATH
    owner: tuple[int, int] = (0, 0)

    @classmethod
    def load(cls, config_dir: Path = CONFIG_DIR) -> Layout:
        """Read `deploy.conf`: the docroot and the site root, both absolute, nothing else."""
        path = config_dir / "deploy.conf"
        require_owned(config_dir, os.geteuid(), directory=True)
        require_owned(path, os.geteuid(), directory=False)
        values: dict[str, str] = {}
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            found = SETTING.fullmatch(line)
            if found is None or found[1] not in {"docroot", "site_root"} or found[1] in values:
                raise Refused("config-invalid", f"{path}:{number}: not a valid setting")
            if os.path.normpath(found[2]) != found[2] or found[2] == "/":
                raise Refused("config-invalid", f"{path}:{number}: not a normal absolute path")
            values[found[1]] = found[2]
        if set(values) != {"docroot", "site_root"}:
            raise Refused("config-invalid", f"{path}: needs docroot and site_root")
        return cls(
            docroot=Path(values["docroot"]),
            site_root=Path(values["site_root"]),
            config_dir=config_dir,
        )

    @property
    def allowed_signers(self) -> Path:
        return self.config_dir / "allowed_signers"

    @property
    def manifest(self) -> Path:
        return self.state_dir / "manifest.json"

    @property
    def extra(self) -> Path:
        return self.state_dir / "extra.json"

    @property
    def backups(self) -> Path:
        return self.state_dir / "backups"

    @property
    def denied(self) -> Path:
        return self.state_dir / "denied.json"

    @property
    def pending(self) -> Path:
        return self.state_dir / "pending"

    @property
    def keyring_dir(self) -> Path:
        return self.docroot / "keyring"


def require_owned(path: Path, uid: int, *, directory: bool, code: str = "config-invalid") -> None:
    """Accept only a real file or folder of `uid` that group and others cannot write."""
    try:
        info = path.lstat()
    except OSError as error:
        raise Refused(code, f"{path}: {error.strerror or error}") from error
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise Refused(code, f"{path}: wrong type, owner or mode")


class Host(Protocol):
    """What the deploy asks of the machine; tests replace it."""

    def unit_active(self, unit: str) -> bool: ...

    def systemctl(self, *arguments: str) -> None: ...

    def immutable(self, path: Path) -> bool: ...

    def set_immutable(self, path: Path, *, on: bool) -> None: ...

    def products_valid(self, publisher_dir: Path, products: Path) -> bool: ...


class SystemHost:
    """The real machine."""

    @staticmethod
    def _run(arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        return run(arguments)

    def unit_active(self, unit: str) -> bool:
        return self._run([SYSTEMCTL, "is-active", "--quiet", unit]).returncode == 0

    def systemctl(self, *arguments: str) -> None:
        result = self._run([SYSTEMCTL, *arguments])
        if result.returncode != 0:
            raise Refused("step-failed", f"systemctl {' '.join(arguments)}: {result.returncode}")

    def immutable(self, path: Path) -> bool:
        result = self._run([LSATTR, "-d", os.fspath(path)])
        flags = result.stdout.decode("utf-8", "replace").split(maxsplit=1)
        return result.returncode == 0 and bool(flags) and "i" in flags[0]

    def set_immutable(self, path: Path, *, on: bool) -> None:
        result = self._run([CHATTR, "+i" if on else "-i", os.fspath(path)])
        if result.returncode != 0:
            raise Refused("step-failed", f"chattr {path}: {result.returncode}")

    def products_valid(self, publisher_dir: Path, products: Path) -> bool:
        """Load the new `products.yml` with the new loader, as the publisher user, not as root."""
        program = (
            "import pathlib, sys; sys.path.insert(0, sys.argv[1]);"
            " from publisher import config; config.load_products(pathlib.Path(sys.argv[2]))"
        )
        result = self._run(
            [
                RUNUSER,
                "-u",
                PUBLISHER_USER,
                "--",
                PYTHON,
                "-I",
                "-c",
                program,
                os.fspath(publisher_dir.parent),
                os.fspath(products),
            ]
        )
        return result.returncode == 0


def run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """One program as an argument array, with a time limit and a minimal environment."""
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        return subprocess.run(  # noqa: S603
            list(arguments),
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=environment,
            timeout=COMMAND_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused("step-failed", f"{arguments[0]}: {error}") from error


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    """Replace `path` with `data`, mode 0600: a temporary file, fsync, rename."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Entry:
    path: Path
    data: bytes
    mode: int

    @property
    def digest(self) -> str:
        return sha256(self.data)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Signed:
    name: str
    version: tuple[int, int, int]
    commit: str
    repository: Path


def parse_version(name: str) -> tuple[int, int, int]:
    found = TAG.fullmatch(name)
    if found is None:
        raise Refused("tag-invalid", f"{name!r} is not vX.Y.Z")
    return (int(found[1]), int(found[2]), int(found[3]))


def verify_bundle(bundle: bytes, work: Path, layout: Layout) -> Signed:
    """Check that the bundle holds one version tag, signed by the pinned key, under its own name."""
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise Refused("bundle-size")
    path = work / "in.bundle"
    path.write_bytes(bundle)
    repository = work / "repository"
    git = [GIT, f"--git-dir={repository}"]
    if run([GIT, "init", "--quiet", "--bare", os.fspath(repository)]).returncode != 0:
        raise Refused("step-failed", "git init")
    if run([*git, "bundle", "verify", os.fspath(path)]).returncode != 0:
        raise Refused("bundle-invalid", "git bundle verify")
    heads = run([*git, "bundle", "list-heads", os.fspath(path)])
    lines = heads.stdout.decode("utf-8", "replace").splitlines()
    if heads.returncode != 0 or len(lines) != 1:
        raise Refused("ref-invalid", f"{len(lines)} refs")
    reference = lines[0].partition(" ")[2]
    name = reference.removeprefix("refs/tags/")
    if name == reference or TAG.fullmatch(name) is None:
        raise Refused("ref-invalid", f"{reference!r} is not a version tag")
    version = parse_version(name)
    refspec = f"+{reference}:{reference}"
    fetched = run(
        [*git, "-c", "fetch.fsckObjects=true", "fetch", "--quiet", os.fspath(path), refspec]
    )
    if fetched.returncode != 0:
        raise Refused("bundle-invalid", "git fetch")
    kind = run([*git, "cat-file", "-t", reference])
    if kind.stdout.strip() != b"tag":
        raise Refused("tag-invalid", "not an annotated tag")
    headers: dict[str, str] = {}
    body = run([*git, "cat-file", "tag", reference]).stdout.decode("utf-8", "replace")
    for line in body.split("\n\n", 1)[0].splitlines():
        key, _, value = line.partition(" ")
        headers.setdefault(key, value)
    # `git verify-tag` checks the signed object, not the ref name: the name inside must be this one.
    if headers.get("tag") != name or headers.get("type") != "commit":
        raise Refused("tag-invalid", f"signed name {headers.get('tag')!r}, ref {name!r}")
    commit = headers.get("object", "")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise Refused("tag-invalid", "no commit")
    verified = run(
        [
            GIT,
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={layout.allowed_signers}",
            "-c",
            f"gpg.ssh.program={SSH_KEYGEN}",
            # a tag signed another way must not start gpg or smimesign as root
            "-c",
            "gpg.program=/bin/false",
            "-c",
            "gpg.openpgp.program=/bin/false",
            "-c",
            "gpg.x509.program=/bin/false",
            f"--git-dir={repository}",
            "verify-tag",
            name,
        ]
    )
    text = verified.stdout.decode("utf-8", "replace")
    good = f'Good "git" signature for {PRINCIPAL} with '
    if verified.returncode != 0 or not any(line.startswith(good) for line in text.splitlines()):
        raise Refused("signature-invalid", text[:300])
    return Signed(name=name, version=version, commit=commit, repository=repository)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Rule:
    """A part of the tree and where it goes; a prefix ending in `/` is a whole folder."""

    source: str
    target: Path
    mode: int
    pattern: re.Pattern[str] | None = None


def rules(layout: Layout) -> list[Rule]:
    """The only files a deploy writes, in the order they are written; this file is last."""
    return [
        Rule(source="publisher/", target=layout.code_dir / "publisher", mode=0o644),
        Rule(
            source="deploy/systemd/",
            target=layout.units_dir,
            mode=0o644,
            pattern=UNIT_FILE,
        ),
        Rule(source="products.yml", target=layout.etc_dir / "products.yml", mode=0o644),
        Rule(source="web/docroot.htaccess", target=layout.docroot / ".htaccess", mode=0o644),
        Rule(source="web/sync.php", target=layout.docroot / "sync.php", mode=0o644),
        Rule(source="deploy/pkg_deploy.py", target=layout.self_path, mode=0o755),
    ]


REQUIRED: Final = (
    "publisher/__init__.py",
    "publisher/__main__.py",
    "products.yml",
    "web/docroot.htaccess",
    "web/sync.php",
    "deploy/pkg_deploy.py",
)


def read_entries(signed: Signed, layout: Layout) -> list[Entry]:
    """Read the known files from the signed commit: blobs only, no link, no submodule."""
    sources = [rule.source.rstrip("/") for rule in rules(layout)]
    git = [GIT, f"--git-dir={signed.repository}"]
    listing = run([*git, "ls-tree", "-r", "-z", "--full-tree", signed.commit, "--", *sources])
    if listing.returncode != 0:
        raise Refused("tree-invalid", "git ls-tree")
    records = [record for record in listing.stdout.split(b"\0") if record]
    if not records or len(records) > MAX_FILES:
        raise Refused("tree-invalid", f"{len(records)} files")
    found: dict[str, tuple[str, str]] = {}
    for record in records:
        meta, _, raw = record.partition(b"\t")
        mode, kind, sha = meta.decode("ascii", "replace").split(" ")
        repo_path = raw.decode("utf-8", "replace")
        segments = repo_path.split("/")
        if mode not in FILE_MODES or kind != "blob":
            raise Refused("tree-invalid", f"{repo_path!r}: mode {mode}")
        if not all(SEGMENT.fullmatch(segment) for segment in segments):
            raise Refused("tree-invalid", f"{repo_path!r}: bad name")
        found[repo_path] = (sha, mode)
    if any(name not in found for name in REQUIRED):
        raise Refused("tree-invalid", "a required file is missing")
    entries: list[Entry] = []
    total = 0
    for rule in rules(layout):
        for repo_path in sorted(found):
            if rule.source.endswith("/"):
                if not repo_path.startswith(rule.source):
                    continue
                relative = repo_path.removeprefix(rule.source)
                if rule.pattern is not None and (
                    "/" in relative or rule.pattern.fullmatch(relative) is None
                ):
                    raise Refused("tree-invalid", f"{repo_path!r}: not a unit file")
                target = rule.target / relative
            elif repo_path == rule.source:
                target = rule.target
            else:
                continue
            # the size comes from the object header, so a blob that inflates is never read
            sized = run([*git, "cat-file", "-s", found[repo_path][0]])
            size = int(sized.stdout) if sized.stdout.strip().isdigit() else MAX_FILE_BYTES + 1
            total += size
            if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise Refused("tree-invalid", f"{repo_path!r}: too large")
            blob = run([*git, "cat-file", "blob", found[repo_path][0]])
            if blob.returncode != 0 or len(blob.stdout) != size:
                raise Refused("tree-invalid", f"{repo_path!r}: unreadable")
            entries.append(Entry(path=target, data=blob.stdout, mode=rule.mode))
    return entries


def under(path: Path, folder: Path) -> bool:
    return folder == path or folder in path.parents


class Broken(Exception):
    """The backup could not be put back either; the host needs an operator."""


class RolledBack(Exception):
    """A step failed after files changed, and the backup was put back."""


def read_regular(path: Path) -> tuple[bytes, os.stat_result] | None:
    """Read a regular file without following a link; None when it is anything else."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None
        return handle.read(), info


class Deployer:
    """One deploy, rollback or check, against a layout and a host."""

    def __init__(self, layout: Layout, host: Host, log: Callable[[str], None]) -> None:
        self.layout = layout
        self.host = host
        self.log = log

    # state -----------------------------------------------------------------------------------

    def _require_state(self, *, signers: bool = False) -> None:
        """The state, and for a deploy the signer list, must be root's and closed to others."""
        uid = self.layout.owner[0]
        for path in (self.layout.state_dir, self.layout.backups):
            require_owned(path, uid, directory=True, code="state-invalid")
        if signers:
            require_owned(self.layout.config_dir, uid, directory=True)
            require_owned(self.layout.allowed_signers, uid, directory=False)

    def _require_clean(self) -> None:
        """An earlier deploy that did not finish must be rolled back before anything else."""
        if self.layout.pending.exists():
            raise Refused("state-invalid", "an earlier deploy did not finish")

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        with (self.layout.state_dir / "lock").open("ab") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise Refused("host-busy") from error
            yield

    def _installed(self) -> tuple[tuple[int, int, int] | None, dict[str, dict[str, object]]]:
        """The version and the files of the last deploy, or nothing before the first."""
        try:
            loaded = json.loads(self.layout.manifest.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, {}
        except (OSError, ValueError) as error:
            raise Refused("state-invalid", f"manifest: {error}") from error
        version = loaded.get("version") if isinstance(loaded, dict) else None
        files = loaded.get("files") if isinstance(loaded, dict) else None
        if not isinstance(version, str) or not isinstance(files, dict):
            raise Refused("state-invalid", "manifest: wrong shape")
        for name, record in files.items():
            if (
                not isinstance(name, str)
                or os.path.normpath(name) != name
                or not name.startswith("/")
                or not isinstance(record, dict)
                or not isinstance(record.get("sha256"), str)
                or not isinstance(record.get("mode"), int)
            ):
                raise Refused("state-invalid", "manifest: wrong record")
        return parse_version(version), files

    def _denied(self) -> list[str]:
        """Versions an operator rolled back from: a replay of their tag is refused."""
        try:
            loaded = json.loads(self.layout.denied.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as error:
            raise Refused("state-invalid", f"denied: {error}") from error
        if not isinstance(loaded, list) or not all(isinstance(name, str) for name in loaded):
            raise Refused("state-invalid", "denied: wrong shape")
        return loaded

    # writing ---------------------------------------------------------------------------------

    def _owner(self, descriptor: int) -> None:
        os.fchown(descriptor, *self.layout.owner)

    def _place(self, entry: Entry) -> None:
        """Put one file in place: a temporary file in the same folder, then a rename."""
        path = entry.path
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise Refused("target-invalid", f"{path}: not a regular file")
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.deploy-tmp")
        temporary.unlink(missing_ok=True)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as out:
                self._owner(out.fileno())
                os.fchmod(out.fileno(), entry.mode)
                out.write(entry.data)
                out.flush()
                os.fsync(out.fileno())
            temporary.replace(path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        sync_directory(path.parent)

    @contextlib.contextmanager
    def _docroot_open(self) -> Iterator[None]:
        """The docroot's immutable flag is off only while root writes there."""
        self.host.set_immutable(self.layout.docroot, on=False)
        try:
            yield
        finally:
            self.host.set_immutable(self.layout.docroot, on=True)

    def _prune(self, path: Path) -> None:
        stop = self.layout.code_dir / "publisher"
        parent = path.parent
        while under(parent, stop) and parent != stop.parent:
            try:
                parent.rmdir()
            except OSError:
                return
            parent = parent.parent

    # backups ---------------------------------------------------------------------------------

    def _backup_names(self) -> list[str]:
        """The complete backups, oldest first: a folder counts only once its index is written."""
        return sorted(
            entry.name
            for entry in self.layout.backups.iterdir()
            if BACKUP_NAME.fullmatch(entry.name) and (entry / "index.json").is_file()
        )

    def _backup(self, tag: str, paths: Sequence[Path]) -> Path:
        """Copy every file a deploy will replace or delete; the folder appears complete or not."""
        for leftover in self.layout.backups.glob(".partial-*"):
            shutil.rmtree(leftover)
        numbers = [int(name[:6]) for name in self._backup_names()]
        name = f"{max(numbers, default=0) + 1:06d}-{tag}"
        partial = self.layout.backups / f".partial-{name}"
        (partial / "files").mkdir(mode=0o700, parents=True)
        try:
            index: list[dict[str, object]] = []
            for number, path in enumerate(paths):
                found = read_regular(path)
                if found is None and (path.exists() or path.is_symlink()):
                    raise Refused("target-invalid", f"{path}: not a regular file")
                record: dict[str, object] = {"path": os.fspath(path), "existed": found is not None}
                if found is not None:
                    write_private(partial / "files" / str(number), found[0])
                    record["mode"] = stat.S_IMODE(found[1].st_mode)
                index.append(record)
            manifest = self.layout.manifest
            write_private(
                partial / "previous.json", manifest.read_bytes() if manifest.exists() else b""
            )
            write_private(partial / "index.json", json.dumps(index).encode("utf-8"))
        except BaseException:
            shutil.rmtree(partial, ignore_errors=True)
            raise
        folder = self.layout.backups / name
        partial.rename(folder)
        sync_directory(self.layout.backups)
        return folder

    def _restore(self, folder: Path) -> None:
        index = json.loads((folder / "index.json").read_text(encoding="utf-8"))
        with self._docroot_open():
            for number, record in reversed(list(enumerate(index))):
                path = Path(record["path"])
                if os.path.normpath(path) != os.fspath(path) or not self._writable_place(path):
                    raise Refused("state-invalid", f"backup lists {path}")
                if record["existed"]:
                    self._place(
                        Entry(
                            path=path,
                            data=(folder / "files" / str(number)).read_bytes(),
                            mode=record["mode"],
                        )
                    )
                else:
                    path.unlink(missing_ok=True)
                    self._prune(path)
        previous = (folder / "previous.json").read_bytes()
        if previous:
            write_private(self.layout.manifest, previous)
        else:
            self.layout.manifest.unlink(missing_ok=True)

    def _prune_backups(self) -> None:
        for name in self._backup_names()[:-KEEP_BACKUPS]:
            shutil.rmtree(self.layout.backups / name)

    # units -----------------------------------------------------------------------------------

    def _quiesce(self, stopped: list[str]) -> None:
        """Stop what could run the old code. `stopped` gets each schedule before its stop is
        asked for, so a stop that fails half-way is still resumed."""
        for unit in (*SCHEDULES, *SERVICES):
            if self.host.unit_active(unit):
                if unit in SCHEDULES:
                    stopped.append(unit)
                self.host.systemctl("stop", unit)

    def _resume(self, running: Sequence[str]) -> None:
        self.host.systemctl("daemon-reload")
        for unit in running:
            self.host.systemctl("start", unit)

    # deploy ----------------------------------------------------------------------------------

    def deploy(self, bundle: bytes) -> str:
        self._require_state(signers=True)
        with self._locked():
            self._require_clean()
            work = Path(tempfile.mkdtemp(prefix="work-", dir=self.layout.state_dir))
            try:
                signed = verify_bundle(bundle, work, self.layout)
                installed, previous = self._installed()
                if signed.name in self._denied():
                    raise Refused("version-denied", signed.name)
                if installed is not None and signed.version < installed:
                    raise Refused("version-older", f"{signed.name} < {installed}")
                entries = read_entries(signed, self.layout)
                dropped = self._dropped(entries, previous)
                if (
                    installed == signed.version
                    and not dropped
                    and self._unchanged(entries, previous)
                ):
                    # a replay of what is already in place changes nothing: no backup, no restart
                    return signed.name
                self._validate(entries, work)
                self._apply(signed, entries, dropped)
            finally:
                shutil.rmtree(work, ignore_errors=True)
        return signed.name

    def _dropped(
        self, entries: Sequence[Entry], previous: dict[str, dict[str, object]]
    ) -> list[Path]:
        """Files the last deploy wrote and this tag no longer carries, if still in a known place."""
        new_paths = {os.fspath(entry.path) for entry in entries}
        return [
            Path(name)
            for name in sorted(previous)
            if name not in new_paths and self._writable_place(Path(name))
        ]

    def _unchanged(self, entries: Sequence[Entry], previous: dict[str, dict[str, object]]) -> bool:
        """Whether every file is already in place with the recorded content, owner and mode."""
        for entry in entries:
            record = previous.get(os.fspath(entry.path))
            found = read_regular(entry.path)
            if (
                record is None
                or found is None
                or record["sha256"] != entry.digest
                or record["mode"] != entry.mode
                or sha256(found[0]) != entry.digest
                or stat.S_IMODE(found[1].st_mode) != entry.mode
                or (found[1].st_uid, found[1].st_gid) != self.layout.owner
            ):
                return False
        return True

    def _validate(self, entries: Sequence[Entry], work: Path) -> None:
        """Write the code to a folder the publisher user can read, and load `products.yml`."""
        stage = work / "stage"
        for entry in entries:
            if under(entry.path, self.layout.code_dir):
                target = stage / entry.path.relative_to(self.layout.code_dir)
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                target.write_bytes(entry.data)
                target.chmod(0o644)
        products = work / "products.yml"
        wanted = self.layout.etc_dir / "products.yml"
        products.write_bytes(next(e.data for e in entries if e.path == wanted))
        products.chmod(0o644)
        for folder in (work, stage, stage / "publisher"):
            folder.chmod(0o755)
        if not self.host.products_valid(stage / "publisher", products):
            raise Refused("products-invalid")

    def _apply(self, signed: Signed, entries: Sequence[Entry], dropped: Sequence[Path]) -> None:
        backup = self._backup(signed.name, [*(entry.path for entry in entries), *dropped])
        # from here a crash leaves this marker, and only `rollback` may clear it
        write_private(self.layout.pending, backup.name.encode("utf-8"))
        running: list[str] = []
        try:
            self._quiesce(running)
            with self._docroot_open():
                for entry in entries:
                    self._place(entry)
                for path in dropped:
                    path.unlink(missing_ok=True)
                    self._prune(path)
            manifest = {
                "version": signed.name,
                "files": {
                    os.fspath(entry.path): {"sha256": entry.digest, "mode": entry.mode}
                    for entry in entries
                },
            }
            write_private(self.layout.manifest, json.dumps(manifest, indent=1).encode("utf-8"))
            self._resume(running)
        except BaseException as error:
            self.log(f"apply failed ({type(error).__name__}), restoring backup {backup.name}")
            try:
                self._restore(backup)
                self._resume(running)
            except BaseException as failure:
                # half-restored code is not started again: the host waits for an operator
                self.log(f"restore failed too: {failure!r}")
                raise Broken from failure
            self.layout.pending.unlink(missing_ok=True)
            # the deploy never took hold: its backup is not a rollback point
            shutil.rmtree(backup, ignore_errors=True)
            raise RolledBack from error
        self.layout.pending.unlink(missing_ok=True)
        try:
            self._prune_backups()
        except OSError as error:
            self.log(f"could not prune old backups: {error!r}")

    def _writable_place(self, path: Path) -> bool:
        """Where a deploy may write or delete: the known files, and nothing else."""
        layout = self.layout
        return (
            under(path, layout.code_dir / "publisher")
            or (path.parent == layout.units_dir and UNIT_FILE.fullmatch(path.name) is not None)
            or path
            in {
                layout.docroot / ".htaccess",
                layout.docroot / "sync.php",
                layout.etc_dir / "products.yml",
                layout.self_path,
            }
        )

    # rollback --------------------------------------------------------------------------------

    def rollback(self) -> str:
        """Undo the last deploy, or finish undoing one that did not end; a local root command.

        The version it undoes is denied, so a replay of its signed tag cannot put it back; the
        backup is used up, so a second rollback goes one deploy further back.
        """
        self._require_state()
        with self._locked():
            names = self._backup_names()
            if not names:
                raise Refused("usage", "no backup")
            name = names[-1]
            undone = name.partition("-")[2]
            running: list[str] = []
            try:
                self._quiesce(running)
            except BaseException:
                with contextlib.suppress(Exception):
                    self._resume(running)  # nothing has changed yet: start what was stopped
                raise
            try:
                self._restore(self.layout.backups / name)
                self._resume(running)
            except BaseException as failure:
                self.log(f"rollback failed: {failure!r}")
                raise Broken from failure
            write_private(self.layout.denied, json.dumps([*self._denied(), undone]).encode("utf-8"))
            self.layout.pending.unlink(missing_ok=True)
            shutil.rmtree(self.layout.backups / name)
        return name

    def allow(self, version: str) -> None:
        """Lift the ban on a version an operator rolled back from."""
        self._require_state()
        with self._locked():
            remaining = [name for name in self._denied() if name != version]
            write_private(self.layout.denied, json.dumps(remaining).encode("utf-8"))

    # records of files placed by hand ---------------------------------------------------------

    def _extra(self) -> dict[str, str]:
        try:
            loaded = json.loads(self.layout.extra.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as error:
            raise Refused("state-invalid", f"extra: {error}") from error
        if not isinstance(loaded, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in loaded.items()
        ):
            raise Refused("state-invalid", "extra: wrong shape")
        return loaded

    def record(self, paths: Sequence[Path], *, forget: bool = False) -> None:
        """Record (or drop) the hash of a file placed by hand in the docroot's `keyring` folder."""
        self._require_state()
        with self._locked():
            extra = self._extra()
            for path in paths:
                if path.parent != self.layout.keyring_dir:
                    raise Refused("usage", f"{path}: not in the keyring folder")
                if forget:
                    extra.pop(os.fspath(path), None)
                    continue
                found = read_regular(path)
                if found is None:
                    raise Refused("usage", f"{path}: not a regular file")
                if not self._closed(found[1]) or self._keyring_open():
                    raise Refused("usage", f"{path}: owner or mode is wrong")
                extra[os.fspath(path)] = sha256(found[0])
            write_private(self.layout.extra, json.dumps(extra, indent=1).encode("utf-8"))

    def _closed(self, info: os.stat_result) -> bool:
        """Owned by the deploy's owner and not writable by group or others."""
        return (info.st_uid, info.st_gid) == self.layout.owner and not info.st_mode & 0o022

    def _keyring_open(self) -> bool:
        """Whether the keyring folder is missing, a link, another's or writable by others."""
        try:
            info = self.layout.keyring_dir.lstat()
        except OSError:
            return True
        return not stat.S_ISDIR(info.st_mode) or not self._closed(info)

    # check -----------------------------------------------------------------------------------

    def check(self) -> list[str]:
        """Compare the host with what the last deploy wrote and the last record said."""
        self._require_state()
        with self._locked():
            return self._check()

    def _check(self) -> list[str]:
        layout = self.layout
        problems: list[str] = []
        if layout.pending.exists():
            problems.append("an earlier deploy did not finish; run rollback")
        version, files = self._installed()
        if version is None:
            return [*problems, "no deploy recorded"]
        uid, gid = layout.owner
        for name, record in sorted(files.items()):
            path = Path(name)
            try:
                info = path.lstat()
            except OSError:
                problems.append(f"missing: {name}")
                continue
            if not stat.S_ISREG(info.st_mode):
                problems.append(f"not a regular file: {name}")
            elif (info.st_uid, info.st_gid) != (uid, gid):
                problems.append(f"owner changed: {name}")
            elif stat.S_IMODE(info.st_mode) != record["mode"]:
                problems.append(f"mode changed: {name}")
            elif sha256(path.read_bytes()) != record["sha256"]:
                problems.append(f"content changed: {name}")
        problems += self._check_docroot(files)
        problems += self._check_code(files)
        return problems

    def _check_docroot(self, files: dict[str, dict[str, object]]) -> list[str]:
        layout = self.layout
        problems: list[str] = []
        uid = layout.owner[0]
        if not self.host.immutable(layout.docroot):
            problems.append("the docroot is not immutable")
        parent = layout.docroot.parent.lstat()
        if parent.st_uid != uid or parent.st_mode & 0o022:
            problems.append("the folder above the docroot is not closed")
        known = {Path(name).name for name in files if Path(name).parent == layout.docroot}
        for entry in sorted(layout.docroot.iterdir()):
            if entry.name not in known | {"apt", "rpm", "keyring"}:
                problems.append(f"unknown entry in the docroot: {entry.name}")
        for name in ("apt", "rpm"):
            link = layout.docroot / name
            expected = layout.site_root / "current" / name
            if not link.is_symlink() or link.readlink() != expected:
                problems.append(f"link {name} does not point at {expected.name}")
        keyring = layout.keyring_dir
        if self._keyring_open():
            problems.append("the keyring folder is missing, or not closed to others")
        else:
            extra = self._extra()
            for entry in sorted(keyring.iterdir()):
                recorded = extra.get(os.fspath(entry))
                found = read_regular(entry)
                if recorded is None:
                    problems.append(f"keyring file not recorded: {entry.name}")
                elif found is None:
                    problems.append(f"keyring entry not a file: {entry.name}")
                elif not self._closed(found[1]):
                    problems.append(f"keyring file owner or mode changed: {entry.name}")
                elif sha256(found[0]) != recorded:
                    problems.append(f"keyring file changed: {entry.name}")
            for name in sorted(extra):
                if not Path(name).exists():
                    problems.append(f"keyring file missing: {Path(name).name}")
        return problems

    def _check_code(self, files: dict[str, dict[str, object]]) -> list[str]:
        code = self.layout.code_dir / "publisher"
        return [
            f"unknown file in the code: {path.relative_to(code)}"
            for path in sorted(code.rglob("*"))
            if not path.is_dir() and os.fspath(path) not in files
        ]


def journal(message: str) -> None:
    syslog.syslog(syslog.LOG_INFO, message[:900])


def read_stdin(stream: BinaryIO) -> bytes:
    return stream.read(MAX_BUNDLE_BYTES + 1)


def main(
    argv: Sequence[str] | None = None,
    *,
    layout: Layout | None = None,
    host: Host | None = None,
    stdin: BinaryIO | None = None,
    log: Callable[[str], None] = journal,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if layout is None:
            # the real host: root, a dropped connection finishes the deploy, a stop restores
            if os.geteuid() != 0:
                raise Refused("not-root")
            syslog.openlog("php-pkg-publisher-deploy")
            os.umask(0o022)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(EXIT_ROLLED_BACK))
            layout = Layout.load()
        deployer = Deployer(layout, host or SystemHost(), log)
        if not arguments:
            name = deployer.deploy(read_stdin(stdin or sys.stdin.buffer))
            log(f"deployed {name}")
            say(f"deployed {name}")
        elif arguments == ["rollback"]:
            name = deployer.rollback()
            log(f"rolled back {name}")
            say(f"rolled back {name}")
        elif arguments == ["check"]:
            problems = deployer.check()
            for problem in problems:
                say(f"FAIL: {problem}")
            if problems:
                return 1
            say("DEPLOY CHECK PASSED")
        elif arguments[0] in {"record", "forget"} and len(arguments) > 1:
            deployer.record(
                [Path(argument) for argument in arguments[1:]], forget=arguments[0] == "forget"
            )
        elif arguments[0] == "allow" and len(arguments) == 2 and TAG.fullmatch(arguments[1]):
            deployer.allow(arguments[1])
        else:
            raise Refused("usage")
    except Refused as refusal:
        if arguments == ["check"] and refusal.code == "host-busy":
            say("DEPLOY CHECK SKIPPED: a deploy is running")
            return 0
        log(f"refused {refusal.code}: {refusal.detail}")
        say(f"refused: {refusal.code}", err=True)
        return EXIT_REFUSED
    except RolledBack:
        say("refused: rolled-back", err=True)
        return EXIT_ROLLED_BACK
    except Broken:
        say("broken: restore failed", err=True)
        return EXIT_BROKEN
    except Exception as error:  # nothing but a fixed code may reach the public log
        log(f"failed: {error!r}")
        say("refused: step-failed", err=True)
        return EXIT_ROLLED_BACK
    return 0


def say(text: str, *, err: bool = False) -> None:
    """Print one line; a client that has gone away is not a failed deploy."""
    with contextlib.suppress(OSError):
        print(text, file=sys.stderr if err else sys.stdout, flush=True)


if __name__ == "__main__":
    sys.exit(main())
