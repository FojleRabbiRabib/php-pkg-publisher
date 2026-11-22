# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The deploy script: it installs a signed tag and refuses everything else, with real git."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import pkg_deploy
import pytest
from pkg_deploy import Broken, Deployer, Layout, Refused

ROOT: Final = Path(__file__).resolve().parents[2]
BACKUP: Final = re.compile(r"[0-9]{6}-v[0-9.]+")
GIT: Final = "/usr/bin/git"
ENVIRONMENT: Final = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}

TREE: Final = {
    "publisher/__init__.py": b"# one\n",
    "publisher/__main__.py": b"print('one')\n",
    "publisher/old.py": b"# only in the first release\n",
    "products.yml": b"products: []\n",
    "web/docroot.htaccess": b"# rules one\n",
    "web/sync.php": b"<?php // one\n",
    "deploy/pkg_deploy.py": b"# the deploy script, one\n",
    "deploy/systemd/php-pkg-publisher.service": b"[Service]\n",
    "deploy/systemd/php-pkg-publisher.timer": b"[Timer]\n",
}


def _run(arguments: list[str], cwd: Path | None = None) -> str:
    done = subprocess.run(  # noqa: S603
        arguments, cwd=cwd, env=ENVIRONMENT, capture_output=True, check=True, text=True
    )
    return done.stdout


def _generate_key(path: Path) -> None:
    _run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.fspath(path)])


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    folder = tmp_path_factory.mktemp("keys")
    for name in ("release", "other"):
        _generate_key(folder / name)
    return {"release": folder / "release.pub", "other": folder / "other.pub"}


@dataclass
class FakeHost:
    """A machine that records what the deploy asks of it."""

    active: set[str] = field(default_factory=set)
    calls: list[str] = field(default_factory=list)
    flag: bool = True
    valid: bool = True
    validated: bytes = b""
    fail_on: str = ""

    def unit_active(self, unit: str) -> bool:
        return unit in self.active

    def systemctl(self, *arguments: str) -> None:
        call = "systemctl " + " ".join(arguments)
        self.calls.append(call)
        if self.fail_on and self.fail_on in call:
            self.fail_on = ""  # one failure; the restore that follows may run
            raise Refused("step-failed", call)

    def immutable(self, path: Path) -> bool:
        return self.flag

    def set_immutable(self, path: Path, *, on: bool) -> None:
        self.calls.append(f"chattr {'+' if on else '-'}i")
        self.flag = on

    def products_valid(self, publisher_dir: Path, products: Path) -> bool:
        self.calls.append("validate")
        self.validated = products.read_bytes()
        return self.valid


@dataclass
class Site:
    layout: Layout
    host: FakeHost
    root: Path
    log: list[str] = field(default_factory=list)

    @property
    def deployer(self) -> Deployer:
        return Deployer(self.layout, self.host, self.log.append)

    def read(self, relative: str) -> bytes:
        return (self.root / relative).read_bytes()


@pytest.fixture
def site(tmp_path: Path, keys: dict[str, Path]) -> Site:
    docroot = tmp_path / "home" / "docroot"
    layout = Layout(
        docroot=docroot,
        site_root=tmp_path / "srv",
        code_dir=tmp_path / "opt",
        etc_dir=tmp_path / "etc",
        units_dir=tmp_path / "units",
        config_dir=tmp_path / "config",
        state_dir=tmp_path / "state",
        self_path=tmp_path / "sbin" / "php-pkg-publisher-deploy",
        owner=(os.geteuid(), os.getegid()),
    )
    for folder in (docroot / "keyring", layout.config_dir, layout.backups, layout.etc_dir):
        folder.mkdir(parents=True)
    key = keys["release"].read_text(encoding="utf-8").split()
    layout.allowed_signers.write_text(
        f'{pkg_deploy.PRINCIPAL} namespaces="git" {key[0]} {key[1]}\n', encoding="utf-8"
    )
    # closed to group and others, whatever the umask of the machine that runs the tests
    for closed in (docroot.parent, docroot, docroot / "keyring", layout.config_dir):
        closed.chmod(0o755)
    for closed in (layout.state_dir, layout.backups, layout.allowed_signers):
        closed.chmod(0o755 if closed.is_dir() else 0o644)
    (docroot / "apt").symlink_to(layout.site_root / "current" / "apt")
    (docroot / "rpm").symlink_to(layout.site_root / "current" / "rpm")
    return Site(layout=layout, host=FakeHost(active={"php-pkg-publisher.path"}), root=tmp_path)


def _bundle(
    folder: Path,
    keys: dict[str, Path],
    files: dict[str, bytes],
    tag: str,
    *,
    signer: str | None = "release",
    present: tuple[str, ...] = ("one",),
) -> bytes:
    """A bundle of one tag over a commit holding `files`, signed by the named key."""
    repo = folder / f"repo-{tag}-{signer}"
    repo.mkdir()
    base = ["-c", "gpg.format=ssh", "-c", "user.name=T", "-c", "user.email=t@example.invalid"]
    _run([GIT, "init", "-q", "-b", "main"], repo)
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _run([GIT, "add", "-A"], repo)
    _run([GIT, *base, "commit", "-q", "-m", "x"], repo)
    if signer is None:
        _run([GIT, *base, "tag", "-a", tag, "-m", f"Release {tag}"], repo)
    else:
        key = ["-c", f"user.signingkey={keys[signer]}"]
        _run([GIT, *base, *key, "tag", "-s", tag, "-m", f"Release {tag}"], repo)
    done = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", tag],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    )
    return done.stdout


def _second(files: dict[str, bytes]) -> dict[str, bytes]:
    changed = {name: data.replace(b"one", b"two") for name, data in files.items()}
    del changed["publisher/old.py"]
    return changed


def test_a_signed_tag_installs_the_known_files_and_records_them(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    name = site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert name == "v1.0.0"
    layout = site.layout
    assert site.read("opt/publisher/__main__.py") == b"print('one')\n"
    assert site.read("etc/products.yml") == b"products: []\n"
    assert site.read("units/php-pkg-publisher.timer") == b"[Timer]\n"
    assert site.read("home/docroot/.htaccess") == b"# rules one\n"
    assert site.read("home/docroot/sync.php") == b"<?php // one\n"
    assert layout.self_path.read_bytes() == b"# the deploy script, one\n"
    assert stat.S_IMODE(layout.self_path.stat().st_mode) == 0o755
    assert stat.S_IMODE((layout.code_dir / "publisher" / "__main__.py").stat().st_mode) == 0o644
    manifest = json.loads(layout.manifest.read_text(encoding="utf-8"))
    assert manifest["version"] == "v1.0.0"
    assert len(manifest["files"]) == 9
    assert site.deployer.check() == []


def test_the_units_stop_before_the_files_change_and_start_again_after(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert site.host.calls == [
        "validate",
        "systemctl stop php-pkg-publisher.path",
        "chattr -i",
        "chattr +i",
        "systemctl daemon-reload",
        "systemctl start php-pkg-publisher.path",
    ]
    assert site.host.flag is True


def test_the_deploy_script_is_the_last_file_written(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    signed = pkg_deploy.verify_bundle(
        _bundle(tmp_path, keys, TREE, "v1.0.0"), tmp_path, site.layout
    )
    entries = pkg_deploy.read_entries(signed, site.layout)
    assert entries[-1].path == site.layout.self_path
    assert len({entry.path for entry in entries}) == len(entries)


def test_a_later_release_replaces_files_and_deletes_only_what_it_dropped(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    stranger = site.layout.code_dir / "publisher" / "by_hand.py"
    stranger.write_bytes(b"# placed by hand\n")
    elsewhere = site.layout.units_dir / "other.service"
    elsewhere.write_bytes(b"[Service]\n")
    site.deployer.deploy(_bundle(tmp_path, keys, _second(TREE), "v1.0.1"))
    assert site.read("opt/publisher/__main__.py") == b"print('two')\n"
    assert not (site.layout.code_dir / "publisher" / "old.py").exists()
    assert stranger.read_bytes() == b"# placed by hand\n"
    assert elsewhere.exists()
    assert json.loads(site.layout.manifest.read_text(encoding="utf-8"))["version"] == "v1.0.1"
    assert site.deployer.check() == ["unknown file in the code: by_hand.py"]


def test_the_same_version_may_run_again_and_an_older_one_may_not(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    newer = _bundle(tmp_path, keys, _second(TREE), "v1.0.1")
    older = _bundle(tmp_path, keys, TREE, "v1.0.0")
    site.deployer.deploy(newer)
    site.host.calls.clear()
    backups = sorted(path.name for path in site.layout.backups.iterdir())
    assert site.deployer.deploy(newer) == "v1.0.1"
    # a replay of what is in place changes nothing: no stop, no write, no new backup
    assert site.host.calls == []
    assert sorted(path.name for path in site.layout.backups.iterdir()) == backups
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(older)
    assert caught.value.code == "version-older"
    assert not [call for call in site.host.calls if "stop" in call or "chattr" in call]
    assert site.read("opt/publisher/__main__.py") == b"print('two')\n"


def _refusal(site: Site, bundle: bytes) -> str:
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(bundle)
    assert not site.host.calls or site.host.calls == ["validate"]
    assert not site.layout.manifest.exists()
    assert not (site.layout.code_dir / "publisher").exists()
    return caught.value.code


def test_a_tag_signed_by_another_key_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    bundle = _bundle(tmp_path, keys, TREE, "v1.0.0", signer="other")
    assert _refusal(site, bundle) == "signature-invalid"


def test_an_unsigned_annotated_tag_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    assert _refusal(site, _bundle(tmp_path, keys, TREE, "v1.0.0", signer=None)) == (
        "signature-invalid"
    )


def test_a_tag_signed_with_openpgp_is_refused_and_starts_no_gpg(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    home = tmp_path / "g"
    home.mkdir(mode=0o700)
    env = {**ENVIRONMENT, "GNUPGHOME": os.fspath(home)}
    subprocess.run(
        [
            "/usr/bin/gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "T <t@example.invalid>",
        ],
        env=env,
        capture_output=True,
        check=True,
    )
    repo = tmp_path / "pgp"
    repo.mkdir()
    base = ["-c", "user.name=T", "-c", "user.email=t@example.invalid"]
    _run([GIT, "init", "-q", "-b", "main"], repo)
    (repo / "x").write_text("x", encoding="utf-8")
    _run([GIT, "add", "x"], repo)
    _run([GIT, *base, "commit", "-q", "-m", "x"], repo)
    subprocess.run(  # noqa: S603
        [GIT, *base, "-c", "user.signingkey=t@example.invalid", "tag", "-s", "v1.0.0", "-m", "m"],
        cwd=repo,
        env=env,
        capture_output=True,
        check=True,
    )
    bundle = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", "v1.0.0"],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    ).stdout
    assert _refusal(site, bundle) == "signature-invalid"


def test_a_lightweight_tag_is_refused(site: Site, keys: dict[str, Path], tmp_path: Path) -> None:
    repo = tmp_path / "light"
    repo.mkdir()
    base = ["-c", "user.name=T", "-c", "user.email=t@example.invalid"]
    _run([GIT, "init", "-q", "-b", "main"], repo)
    (repo / "x").write_text("x", encoding="utf-8")
    _run([GIT, "add", "x"], repo)
    _run([GIT, *base, "commit", "-q", "-m", "x"], repo)
    _run([GIT, "tag", "v1.0.0"], repo)
    bundle = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", "v1.0.0"],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    ).stdout
    assert _refusal(site, bundle) == "tag-invalid"


def test_a_signed_tag_under_another_name_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    """`git verify-tag` accepts it, because it checks the signed object and not the ref name."""
    _bundle(tmp_path, keys, TREE, "v1.0.0")
    repo = tmp_path / "repo-v1.0.0-release"
    signed_object = _run([GIT, "rev-parse", "v1.0.0"], repo).strip()
    _run([GIT, "update-ref", "refs/tags/v9.9.9", signed_object], repo)
    bundle = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", "v9.9.9"],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    ).stdout
    assert _refusal(site, bundle) == "tag-invalid"


def test_a_bundle_with_two_refs_or_a_branch_or_a_pre_release_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    _bundle(tmp_path, keys, TREE, "v1.0.0")
    repo = tmp_path / "repo-v1.0.0-release"
    _run([GIT, "tag", "-f", "v1.0.1", "v1.0.0"], repo)

    def bundle_of(*refs: str) -> bytes:
        return subprocess.run(  # noqa: S603
            [GIT, "bundle", "create", "-", *refs],
            cwd=repo,
            env=ENVIRONMENT,
            capture_output=True,
            check=True,
        ).stdout

    assert _refusal(site, bundle_of("v1.0.0", "v1.0.1")) == "ref-invalid"
    assert _refusal(site, bundle_of("main")) == "ref-invalid"
    _run([GIT, "update-ref", "refs/tags/v1.0.0-rc1", "v1.0.0"], repo)
    assert _refusal(site, bundle_of("v1.0.0-rc1")) == "ref-invalid"


def test_a_bundle_that_is_not_a_bundle_or_is_too_big_is_refused(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _refusal(site, b"not a bundle") == "bundle-invalid"
    monkeypatch.setattr(pkg_deploy, "MAX_BUNDLE_BYTES", 10)
    assert _refusal(site, b"x" * 11) == "bundle-size"


def test_a_tree_with_a_link_a_missing_file_or_a_stray_unit_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    without = {name: data for name, data in TREE.items() if name != "web/sync.php"}
    assert _refusal(site, _bundle(tmp_path, keys, without, "v1.0.0")) == "tree-invalid"
    stray = {**TREE, "deploy/systemd/evil.service": b"[Service]\n"}
    assert _refusal(site, _bundle(tmp_path, keys, stray, "v1.0.1")) == "tree-invalid"
    linked = tmp_path / "linked"
    linked.mkdir()
    _bundle(linked, keys, TREE, "v1.0.2")  # the tree; the link replaces a file in it below
    repo = linked / "repo-v1.0.2-release"
    (repo / "publisher" / "old.py").unlink()
    (repo / "publisher" / "old.py").symlink_to("/etc/passwd")
    base = ["-c", "gpg.format=ssh", "-c", "user.name=T", "-c", "user.email=t@example.invalid"]
    key = ["-c", f"user.signingkey={keys['release']}"]
    _run([GIT, "add", "-A"], repo)
    _run([GIT, *base, "commit", "-q", "-m", "link"], repo)
    _run([GIT, *base, *key, "tag", "-s", "v1.0.3", "-m", "Release v1.0.3"], repo)
    bundle = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", "v1.0.3"],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    ).stdout
    assert _refusal(site, bundle) == "tree-invalid"


def test_a_products_file_the_new_loader_rejects_stops_the_deploy_before_any_change(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.host.valid = False
    assert _refusal(site, _bundle(tmp_path, keys, TREE, "v1.0.0")) == "products-invalid"
    assert not site.layout.etc_dir.joinpath("products.yml").exists()


def test_a_failed_step_puts_the_old_files_and_the_manifest_back(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    second = _bundle(tmp_path, keys, _second(TREE), "v1.0.1")

    def snapshot() -> dict[Path, bytes]:
        return {
            path: path.read_bytes()
            for folder in ("opt", "etc", "units", "sbin", "home/docroot")
            for path in (site.root / folder).rglob("*")
            if path.is_file() and not path.is_symlink()
        }

    before = snapshot()
    manifest = site.layout.manifest.read_bytes()
    site.host.fail_on = "start"
    site.host.calls.clear()
    with pytest.raises(pkg_deploy.RolledBack):
        site.deployer.deploy(second)
    assert snapshot() == before
    assert site.layout.manifest.read_bytes() == manifest
    assert site.host.flag is True
    assert any("restoring backup" in line for line in site.log)
    # the units were started again after the restore, and no marker of an unfinished deploy stays
    assert site.host.calls[-2:] == [
        "systemctl daemon-reload",
        "systemctl start php-pkg-publisher.path",
    ]
    assert not site.layout.pending.exists()


def test_a_deploy_that_was_restored_leaves_no_backup_and_rollback_still_undoes_the_last_one(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    first = _bundle(tmp_path, keys, TREE, "v1.0.0")
    second = _bundle(tmp_path, keys, _second(TREE), "v1.0.1")
    third_files = {name: data.replace(b"one", b"three") for name, data in TREE.items()}
    site.deployer.deploy(first)
    site.deployer.deploy(second)
    count = len(list(site.layout.backups.iterdir()))
    site.host.fail_on = "start"
    with pytest.raises(pkg_deploy.RolledBack):
        site.deployer.deploy(_bundle(tmp_path, keys, third_files, "v1.0.2"))
    assert len(list(site.layout.backups.iterdir())) == count
    assert site.deployer.rollback().endswith("v1.0.1")
    assert site.read("opt/publisher/__main__.py") == b"print('one')\n"
    assert json.loads(site.layout.manifest.read_text(encoding="utf-8"))["version"] == "v1.0.0"


def test_a_write_that_fails_half_way_puts_the_old_files_back(
    site: Site, keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    original = Deployer._place
    count = {"n": 0}

    def flaky(self: Deployer, entry: pkg_deploy.Entry) -> None:
        count["n"] += 1
        if count["n"] == 4:
            raise OSError("disk full")
        original(self, entry)

    monkeypatch.setattr(Deployer, "_place", flaky)
    with pytest.raises(pkg_deploy.RolledBack):
        site.deployer.deploy(_bundle(tmp_path, keys, _second(TREE), "v1.0.1"))
    monkeypatch.setattr(Deployer, "_place", original)
    assert site.read("opt/publisher/__main__.py") == b"print('one')\n"
    assert (site.layout.code_dir / "publisher" / "old.py").exists()
    assert site.deployer.check() == []


def test_a_restore_that_fails_too_is_reported_as_broken(
    site: Site, keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    site.host.fail_on = "start"

    def broken(self: Deployer, folder: Path) -> None:
        raise OSError("no")

    monkeypatch.setattr(Deployer, "_restore", broken)
    with pytest.raises(Broken):
        site.deployer.deploy(_bundle(tmp_path, keys, _second(TREE), "v1.0.1"))
    # the marker stays: nothing else may run until `rollback` has put the host right
    assert site.layout.pending.exists()
    monkeypatch.undo()
    with pytest.raises(Refused, match="state-invalid"):
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.2"))
    assert any("did not finish" in problem for problem in site.deployer.check())
    site.host.fail_on = ""
    site.deployer.rollback()
    assert not site.layout.pending.exists()
    assert site.deployer.check() == []


def test_rollback_undoes_the_last_deploy_and_bans_its_version(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    second = _bundle(tmp_path, keys, _second(TREE), "v1.0.1")
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    site.deployer.deploy(second)
    assert site.deployer.rollback().endswith("v1.0.1")
    assert site.read("opt/publisher/__main__.py") == b"print('one')\n"
    assert (site.layout.code_dir / "publisher" / "old.py").exists()
    assert json.loads(site.layout.manifest.read_text(encoding="utf-8"))["version"] == "v1.0.0"
    assert site.deployer.check() == []
    # a replay of the signed tag that was rolled back cannot put it back
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(second)
    assert caught.value.code == "version-denied"
    assert site.read("opt/publisher/__main__.py") == b"print('one')\n"
    site.deployer.allow("v1.0.1")
    site.deployer.deploy(second)
    assert site.read("opt/publisher/__main__.py") == b"print('two')\n"


def test_a_second_rollback_goes_one_deploy_further_back(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    for minor in range(3):
        files = TREE if minor == 0 else _second(TREE)
        site.deployer.deploy(_bundle(tmp_path, keys, files, f"v1.{minor}.0"))
    assert site.deployer.rollback().endswith("v1.2.0")
    assert site.deployer.rollback().endswith("v1.1.0")
    assert json.loads(site.layout.manifest.read_text(encoding="utf-8"))["version"] == "v1.0.0"
    assert site.deployer.rollback().endswith("v1.0.0")
    assert not site.layout.manifest.exists()
    assert not (site.layout.code_dir / "publisher").exists()
    with pytest.raises(Refused, match="usage"):
        site.deployer.rollback()


def test_a_stop_that_fails_mid_way_starts_again_what_was_stopped(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.host.active = {"php-pkg-publisher.path", "php-pkg-publisher.timer"}
    site.host.fail_on = "stop php-pkg-publisher.timer"
    site.host.calls.clear()
    with pytest.raises(pkg_deploy.RolledBack):
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert "systemctl start php-pkg-publisher.path" in site.host.calls
    assert "systemctl start php-pkg-publisher.timer" in site.host.calls
    assert site.host.calls[-1].startswith("systemctl start")
    assert not site.layout.pending.exists()
    assert not site.layout.manifest.exists()


def test_a_backup_that_cannot_be_finished_leaves_no_folder_and_rollback_still_works(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    (site.layout.docroot / "sync.php").unlink()
    (site.layout.docroot / "sync.php").symlink_to(site.root / "elsewhere")
    site.host.calls.clear()
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(_bundle(tmp_path, keys, _second(TREE), "v1.0.1"))
    assert caught.value.code == "target-invalid"
    names = [path.name for path in site.layout.backups.iterdir()]
    assert len(names) == 1
    assert all(BACKUP.fullmatch(name) for name in names)  # no half-built folder
    assert not site.layout.pending.exists()
    assert not [call for call in site.host.calls if "stop" in call]
    (site.layout.docroot / "sync.php").unlink()
    (site.layout.docroot / "sync.php").write_bytes(b"<?php // one\n")
    (site.layout.docroot / "sync.php").chmod(0o644)
    assert site.deployer.rollback().endswith("v1.0.0")


def test_only_the_newest_backups_are_kept(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    for minor in range(8):
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, f"v1.{minor}.0"))
    names = sorted(path.name for path in site.layout.backups.iterdir())
    assert len(names) == pkg_deploy.KEEP_BACKUPS
    assert names[-1].endswith("v1.7.0")


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda s: (s.layout.docroot / "sync.php").write_bytes(b"x"), "content changed"),
        (lambda s: (s.layout.docroot / "sync.php").chmod(0o666), "mode changed"),
        (lambda s: (s.layout.docroot / "sync.php").unlink(), "missing"),
        (lambda s: (s.layout.docroot / "evil.php").write_bytes(b"x"), "unknown entry"),
        (lambda s: setattr(s.host, "flag", False), "not immutable"),
        (lambda s: s.layout.docroot.parent.chmod(0o777), "above the docroot"),
        (lambda s: (s.layout.docroot / "apt").unlink(), "link apt"),
        (lambda s: (s.layout.docroot / "rpm").unlink(), "link rpm"),
        (lambda s: (s.layout.keyring_dir / "x.deb").write_bytes(b"x"), "keyring file not recorded"),
        (lambda s: s.layout.manifest.unlink(), "no deploy recorded"),
    ],
)
def test_the_check_reports_what_changed_since_the_deploy(
    site: Site,
    keys: dict[str, Path],
    tmp_path: Path,
    mutate: Callable[[Site], object],
    expected: str,
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert site.deployer.check() == []
    mutate(site)
    problems = site.deployer.check()
    assert any(expected in problem for problem in problems), problems


def test_a_keyring_package_is_recorded_when_placed_and_checked_after(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    package = site.layout.keyring_dir / "rabib-release.rpm"
    package.write_bytes(b"package")
    package.chmod(0o644)
    site.deployer.record([package])
    assert site.deployer.check() == []
    package.write_bytes(b"swapped")
    assert site.deployer.check() == ["keyring file changed: rabib-release.rpm"]
    site.deployer.record([package], forget=True)
    assert site.deployer.check() == ["keyring file not recorded: rabib-release.rpm"]
    with pytest.raises(Refused, match="usage"):
        site.deployer.record([site.layout.docroot / "sync.php"])


def test_only_the_known_places_may_be_deleted_even_if_the_manifest_lists_more(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    precious = site.root / "precious.txt"
    precious.write_bytes(b"keep")
    manifest = json.loads(site.layout.manifest.read_text(encoding="utf-8"))
    manifest["files"][os.fspath(precious)] = {"sha256": "0" * 64, "mode": 0o644}
    site.layout.manifest.write_text(json.dumps(manifest), encoding="utf-8")
    site.deployer.deploy(_bundle(tmp_path, keys, _second(TREE), "v1.0.1"))
    assert precious.read_bytes() == b"keep"


def test_a_target_that_is_a_link_is_refused_not_followed(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    victim = site.root / "victim"
    victim.write_bytes(b"keep")
    (site.layout.docroot / "sync.php").symlink_to(victim)
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert caught.value.code == "target-invalid"
    assert victim.read_bytes() == b"keep"


def test_the_settings_file_is_strict(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    config.chmod(0o755)
    path = config / "deploy.conf"
    path.write_text("# a comment\ndocroot=/a/b\nsite_root=/c\n", encoding="utf-8")
    path.chmod(0o644)
    loaded = Layout.load(config)
    assert (loaded.docroot, loaded.site_root) == (Path("/a/b"), Path("/c"))
    for text in (
        "docroot=/a/b\n",
        "docroot=/a/b\nsite_root=/c\nextra=/d\n",
        "docroot=/a/b\ndocroot=/a/c\nsite_root=/c\n",
        "docroot=a/b\nsite_root=/c\n",
        "docroot=/a/../b\nsite_root=/c\n",
        "docroot=/a/b/\nsite_root=/c\n",
        "docroot=/\nsite_root=/c\n",
    ):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(Refused, match="config-invalid"):
            Layout.load(config)
    path.write_text("docroot=/a/b\nsite_root=/c\n", encoding="utf-8")
    path.chmod(0o666)
    with pytest.raises(Refused, match="config-invalid"):
        Layout.load(config)


def test_what_leaves_the_host_is_one_fixed_code(
    site: Site, keys: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle(tmp_path, keys, TREE, "v1.0.0", signer="other")
    code = pkg_deploy.main(
        [], layout=site.layout, host=site.host, stdin=io.BytesIO(bundle), log=site.log.append
    )
    printed = capsys.readouterr()
    assert code == pkg_deploy.EXIT_REFUSED
    assert printed.out == ""
    assert re.fullmatch(r"refused: [a-z-]+\n", printed.err)
    assert printed.err.strip().removeprefix("refused: ") in pkg_deploy.CODES
    assert any("SHA256:" in line for line in site.log)  # the detail went to the journal
    assert "SHA256" not in printed.err + printed.out


def test_a_good_deploy_prints_only_the_tag_and_a_check_prints_a_verdict(
    site: Site, keys: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle(tmp_path, keys, TREE, "v1.0.0")
    arguments = {"layout": site.layout, "host": site.host, "log": site.log.append}
    assert pkg_deploy.main([], stdin=io.BytesIO(bundle), **arguments) == 0  # type: ignore[arg-type]
    assert capsys.readouterr().out == "deployed v1.0.0\n"
    assert pkg_deploy.main(["check"], **arguments) == 0  # type: ignore[arg-type]
    assert capsys.readouterr().out == "DEPLOY CHECK PASSED\n"
    (site.layout.docroot / "sync.php").write_bytes(b"x")
    assert pkg_deploy.main(["check"], **arguments) == 1  # type: ignore[arg-type]
    assert capsys.readouterr().out.startswith("FAIL: content changed")
    assert pkg_deploy.main(["nonsense"], **arguments) == pkg_deploy.EXIT_REFUSED  # type: ignore[arg-type]
    assert capsys.readouterr().err == "refused: usage\n"


def test_two_deploys_cannot_run_at_once(site: Site, keys: dict[str, Path], tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, keys, TREE, "v1.0.0")
    with site.deployer._locked(), pytest.raises(Refused) as caught:
        site.deployer.deploy(bundle)
    assert caught.value.code == "host-busy"


def test_the_deploy_stops_without_the_state_folders(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.layout.backups.rmdir()
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert caught.value.code == "state-invalid"


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("allowed_signers", "config-invalid"),
        ("config_dir", "config-invalid"),
        ("state_dir", "state-invalid"),
        ("backups", "state-invalid"),
    ],
)
def test_the_signer_list_and_the_state_must_be_closed_to_everyone_else(
    site: Site, keys: dict[str, Path], tmp_path: Path, target: str, code: str
) -> None:
    path = getattr(site.layout, target)
    path.chmod(0o775 if path.is_dir() else 0o664)
    with pytest.raises(Refused) as caught:
        site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    assert caught.value.code == code
    assert not site.layout.manifest.exists()


def test_a_keyring_file_or_folder_that_others_can_write_is_not_recorded_and_is_reported(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    package = site.layout.keyring_dir / "rabib-release.rpm"
    package.write_bytes(b"package")
    package.chmod(0o666)
    with pytest.raises(Refused, match="usage"):
        site.deployer.record([package])
    package.chmod(0o644)
    site.deployer.record([package])
    assert site.deployer.check() == []
    package.chmod(0o666)
    assert site.deployer.check() == ["keyring file owner or mode changed: rabib-release.rpm"]
    package.chmod(0o644)
    site.layout.keyring_dir.chmod(0o777)
    assert any("keyring folder" in problem for problem in site.deployer.check())
    with pytest.raises(Refused, match="usage"):
        site.deployer.record([package])
    site.layout.keyring_dir.chmod(0o755)
    package.unlink()
    package.symlink_to(site.root / "elsewhere")
    with pytest.raises(Refused, match="usage"):
        site.deployer.record([package])


def test_a_manifest_that_lists_a_path_with_dots_is_refused(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    site.deployer.deploy(_bundle(tmp_path, keys, TREE, "v1.0.0"))
    manifest = json.loads(site.layout.manifest.read_text(encoding="utf-8"))
    manifest["files"][f"{site.layout.code_dir}/publisher/../../x"] = {"sha256": "0", "mode": 420}
    site.layout.manifest.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(Refused, match="state-invalid"):
        site.deployer.check()


def test_products_yml_is_validated_from_the_file_that_is_deployed(
    site: Site, keys: dict[str, Path], tmp_path: Path
) -> None:
    files = {**TREE, "publisher/products.yml": b"not the deployed file\n"}
    site.deployer.deploy(_bundle(tmp_path, keys, files, "v1.0.0"))
    assert site.host.validated == b"products: []\n"


def test_a_blob_or_a_tree_over_the_size_limits_is_refused_unread(
    site: Site, keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(tmp_path, keys, TREE, "v1.0.0")
    monkeypatch.setattr(pkg_deploy, "MAX_FILE_BYTES", 10)
    assert _refusal(site, bundle) == "tree-invalid"
    monkeypatch.setattr(pkg_deploy, "MAX_FILE_BYTES", 1000)
    monkeypatch.setattr(pkg_deploy, "MAX_TOTAL_BYTES", 100)
    assert _refusal(site, bundle) == "tree-invalid"


def test_the_exit_code_tells_a_refusal_from_a_rollback_from_a_broken_host(
    site: Site,
    keys: dict[str, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run_main(bundle: bytes) -> int:
        return pkg_deploy.main(
            [], layout=site.layout, host=site.host, stdin=io.BytesIO(bundle), log=site.log.append
        )

    assert run_main(_bundle(tmp_path, keys, TREE, "v1.0.0")) == 0
    capsys.readouterr()
    site.host.fail_on = "start"
    assert run_main(_bundle(tmp_path, keys, _second(TREE), "v1.0.1")) == pkg_deploy.EXIT_ROLLED_BACK
    assert capsys.readouterr().err == "refused: rolled-back\n"
    monkeypatch.setattr(Deployer, "_restore", lambda self, folder: (_ for _ in ()).throw(OSError()))
    site.host.fail_on = "start"
    assert run_main(_bundle(tmp_path, keys, _second(TREE), "v1.0.2")) == pkg_deploy.EXIT_BROKEN
    assert capsys.readouterr().err == "broken: restore failed\n"


def test_an_unexpected_error_prints_a_fixed_code_not_a_traceback(
    site: Site, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Deployer, bundle: bytes) -> str:
        raise KeyError("/secret/path")

    monkeypatch.setattr(Deployer, "deploy", boom)
    code = pkg_deploy.main(
        [], layout=site.layout, host=site.host, stdin=io.BytesIO(b""), log=site.log.append
    )
    printed = capsys.readouterr()
    assert code == pkg_deploy.EXIT_ROLLED_BACK
    assert printed.err == "refused: step-failed\n"
    assert "/secret/path" in "".join(site.log)


def test_the_installed_file_runs_by_itself_and_prints_only_a_fixed_code(tmp_path: Path) -> None:
    """Run as the forced command is: the file itself, no arguments, no module import."""
    installed = tmp_path / "php-pkg-publisher-deploy"
    shutil.copy(ROOT / "deploy" / "pkg_deploy.py", installed)
    installed.chmod(0o755)
    done = subprocess.run(  # noqa: S603
        [os.fspath(installed)], stdin=subprocess.DEVNULL, capture_output=True, check=False
    )
    assert (done.returncode, done.stdout, done.stderr) == (2, b"", b"refused: not-root\n")
    assert (
        (ROOT / "deploy" / "pkg_deploy.py")
        .read_text(encoding="utf-8")
        .startswith("#!/usr/bin/python3 -I\n")
    )


def test_a_check_that_meets_a_running_deploy_says_so_and_passes(
    site: Site, capsys: pytest.CaptureFixture[str]
) -> None:
    with site.deployer._locked():
        code = pkg_deploy.main(["check"], layout=site.layout, host=site.host, log=site.log.append)
    assert code == 0
    assert capsys.readouterr().out == "DEPLOY CHECK SKIPPED: a deploy is running\n"


def test_the_real_host_reads_the_flag_and_loads_products_as_the_publisher_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = pkg_deploy.SystemHost()
    done = subprocess.CompletedProcess

    def lsattr(out: bytes, code: int = 0) -> None:
        monkeypatch.setattr(pkg_deploy, "run", lambda arguments, **_: done(arguments, code, out))

    lsattr(b"----i---------e------- /x\n")
    assert host.immutable(tmp_path) is True
    lsattr(b"--------------e------- /x\n")
    assert host.immutable(tmp_path) is False
    lsattr(b"----i---------e------- /x\n", code=1)
    assert host.immutable(tmp_path) is False
    monkeypatch.undo()
    # `runuser` is replaced by a stub that drops its `-u user --` and runs the rest, so the real
    # isolated interpreter runs the real loader of this checkout against a good and a bad file
    stub = tmp_path / "runuser"
    stub.write_text('#!/bin/sh\nshift 3\nexec "$@"\n', encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setattr(pkg_deploy, "RUNUSER", os.fspath(stub))
    monkeypatch.setattr(pkg_deploy, "PYTHON", sys.executable)
    stage = tmp_path / "stage"
    shutil.copytree(ROOT / "publisher", stage / "publisher")
    good = tmp_path / "good.yml"
    good.write_bytes((ROOT / "products.yml").read_bytes())
    bad = tmp_path / "bad.yml"
    bad.write_bytes(b"products: nonsense\n")
    assert host.products_valid(stage / "publisher", good) is True
    assert host.products_valid(stage / "publisher", bad) is False
