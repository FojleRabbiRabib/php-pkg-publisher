# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The deploy script on a real host: sshd, sudo, `runuser` and `chattr`; only `systemctl` is faked.

The installed file is the forced command of a locked key, as the runbook sets it up. A client
sends a signed tag as a `git bundle` over ssh, exactly as the release workflow does, and the
tests read back what a real root, a real ext4 folder with the immutable flag and a real web user
make of the result. The unit tests cover every refusal of the script itself; this layer proves
what only a real host can: the key's restrictions, the one sudo line, the folder modes, the
publisher user's view of the new code, and what a client is told (a public log shows it all).

The tests run in order on one host: each starts from what the one before it left.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pkg_deploy
import pytest
from box import Box, Done, docker_available
from deploykit import GIT, generate_key, run, signed_bundle
from images import IMAGES

pytestmark = pytest.mark.container

ROOT: Final = Path(__file__).resolve().parents[2]
SOURCES: Final = (
    "publisher",
    "products.yml",
    "web/docroot.htaccess",
    "web/sync.php",
    "deploy/pkg_deploy.py",
    "deploy/systemd",
)
# The site as a panel lays it out, on its own ext4 file system so that `chattr +i` works.
SITE_HOME: Final = "/srv/www/site"
DOCROOT: Final = f"{SITE_HOME}/public_html"
SITE_ROOT: Final = "/srv/pkg/site"
SCRIPT: Final = pkg_deploy.SELF_PATH.as_posix()
STATE: Final = pkg_deploy.STATE_DIR.as_posix()
SUDOERS: Final = "/etc/sudoers.d/php-pkg-publisher-deploy"
SYSTEMCTL_LOG: Final = "/var/log/systemctl-calls"
PORT: Final = "2222"

# `systemctl` is the one thing the container cannot run: it records each call, and answers
# `is-active` for the units listed in `/etc/stub-active-units`.
SYSTEMCTL_STUB: Final = """#!/bin/sh
echo "$*" >> /var/log/systemctl-calls
if [ "$1" = is-active ]; then
    for unit; do :; done
    grep -qx "$unit" /etc/stub-active-units
    exit $?
fi
exit 0
"""

PACKAGES: Final = (
    "e2fsprogs",
    "git",
    "openssh-client",
    "openssh-server",
    "python3",
    "python3-yaml",
    "sudo",
)

# the file each target comes from, and its mode
INSTALLED: Final = {
    "/opt/php-pkg-publisher/publisher/__main__.py": ("publisher/__main__.py", "644"),
    "/etc/php-pkg-publisher/products.yml": ("products.yml", "644"),
    "/etc/systemd/system/php-pkg-publisher.service": (
        "deploy/systemd/php-pkg-publisher.service",
        "644",
    ),
    f"{DOCROOT}/.htaccess": ("web/docroot.htaccess", "644"),
    f"{DOCROOT}/sync.php": ("web/sync.php", "644"),
    SCRIPT: ("deploy/pkg_deploy.py", "755"),
}


@dataclass(frozen=True)
class Release:
    tag: str
    bundle: bytes
    files: dict[str, bytes]


@dataclass(frozen=True)
class Releases:
    first: Release
    second: Release
    third: Release
    stranger: Release
    broken: Release


def _tracked_files() -> dict[str, bytes]:
    """The files a deploy reads, as they are in this checkout."""
    listed = run([GIT, "ls-files", "-z", "--", *SOURCES], ROOT)
    return {name: (ROOT / name).read_bytes() for name in listed.split("\0") if name}


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    folder = tmp_path_factory.mktemp("keys")
    for name in ("release", "other", "client", "server"):
        generate_key(folder / name)
    return {name: folder / f"{name}.pub" for name in ("release", "other", "client", "server")}


@pytest.fixture(scope="module")
def releases(keys: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> Releases:
    folder = tmp_path_factory.mktemp("tags")
    files = _tracked_files()
    script = "deploy/pkg_deploy.py"
    second = {**files, script: files[script] + b"\n# second\n", "publisher/probe.py": b"# probe\n"}
    third = {**files, script: files[script] + b"\n# third\n"}
    broken = {**files, "products.yml": b"products: not-a-list\n"}

    def release(tag: str, tree: dict[str, bytes], signer: str = "release") -> Release:
        return Release(tag, signed_bundle(folder, keys, tree, tag, signer=signer), tree)

    return Releases(
        first=release("v1.0.0", files),
        second=release("v1.0.1", second),
        third=release("v1.0.2", third),
        stranger=release("v1.0.3", files, signer="other"),
        broken=release("v1.0.4", broken),
    )


def _key_text(public: Path) -> str:
    kind, key, *_ = public.read_text(encoding="utf-8").split()
    return f"{kind} {key}"


def _write_kit(kit: Path, keys: dict[str, Path]) -> None:
    """Everything the host is built from, given to the container read-only."""
    (kit / "deploy.conf").write_text(
        f"docroot={DOCROOT}\nsite_root={SITE_ROOT}\n", encoding="utf-8"
    )
    signers = f'{pkg_deploy.PRINCIPAL} namespaces="git" {_key_text(keys["release"])}\n'
    (kit / "allowed_signers").write_text(signers, encoding="utf-8")
    (kit / "sudoers").write_text(f'deploy ALL=(root) NOPASSWD: {SCRIPT} ""\n', encoding="utf-8")
    forced = f'restrict,command="/usr/bin/sudo {SCRIPT}" {_key_text(keys["client"])}\n'
    (kit / "authorized_keys").write_text(forced, encoding="utf-8")
    (kit / "known_hosts").write_text(
        f"[127.0.0.1]:{PORT} {_key_text(keys['server'])}\n", encoding="utf-8"
    )
    (kit / "systemctl").write_text(SYSTEMCTL_STUB, encoding="utf-8")
    (kit / "stub-active-units").write_text(
        "php-pkg-publisher.path\nphp-pkg-publisher.timer\n", encoding="utf-8"
    )
    # not the release's bytes and not its mode, so the first deploy has to replace it
    script = (ROOT / "deploy/pkg_deploy.py").read_bytes() + b"\n# provisioned, never deployed\n"
    (kit / "php-pkg-publisher-deploy").write_bytes(script)
    for name in ("client", "other", "server"):
        (kit / f"{name}_key").write_bytes(keys[name].with_suffix("").read_bytes())


class Host:
    """The container, with the commands the tests keep needing."""

    def __init__(self, box: Box) -> None:
        self.box = box

    def ok(self, *command: str) -> str:
        done = self.box.run(*command)
        assert done.code == 0, (command, done.output)
        return done.output

    def ssh(
        self,
        *options: str,
        command: str | None = None,
        key: str = "client",
        stdin: bytes = b"",
    ) -> Done:
        """The release workflow's client, from inside the host: pinned host key, one identity."""
        return self.box.run(
            "timeout",
            "30",
            "ssh",
            "-p",
            PORT,
            "-i",
            f"/root/{key}_key",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=/root/known_hosts",
            "-o",
            "BatchMode=yes",
            *options,
            "deploy@127.0.0.1",
            *([command] if command is not None else []),
            stdin=stdin,
        )

    def deploy(self, release: Release) -> Done:
        # `-T`: with no command, ssh would otherwise say that it cannot allocate a terminal
        return self.ssh("-T", stdin=release.bundle)

    def local(self, *arguments: str) -> Done:
        """A command of the script run by root on the host, as an operator or a timer would."""
        return self.box.run(SCRIPT, *arguments)

    def sha256(self, path: str) -> str:
        return self.ok("sha256sum", path).split()[0]

    def stat(self, path: str) -> str:
        return self.ok("stat", "-c", "%U:%G %a", path).strip()

    def calls(self) -> list[str]:
        """What the deploy asked of `systemctl` since the log was last cleared."""
        lines = self.ok("cat", SYSTEMCTL_LOG).splitlines()
        return [line for line in lines if not line.startswith("is-active")]

    def clear_calls(self) -> None:
        self.ok("truncate", "-s", "0", SYSTEMCTL_LOG)

    def immutable(self) -> bool:
        return "i" in self.ok("lsattr", "-d", DOCROOT).split()[0]


def _provision(host: Host) -> None:
    host.ok("apt-get", "update", "-qq")
    host.ok("apt-get", "install", "-y", "-qq", "--no-install-recommends", *PACKAGES)
    # after apt, which could pull in a real systemctl
    host.ok("install", "-m", "0755", "/kit/systemctl", "/usr/bin/systemctl")
    host.ok("install", "-m", "0644", "/kit/stub-active-units", "/etc/stub-active-units")
    host.ok("touch", SYSTEMCTL_LOG)
    host.ok(
        "useradd", "--system", "--no-create-home", "-s", "/usr/sbin/nologin", "php-pkg-publisher"
    )
    host.ok("useradd", "--no-create-home", "-s", "/bin/sh", "siteuser")
    # the deploy user needs a real shell for sshd to run the forced command; its password stays
    # locked, as `useradd` leaves it
    host.ok("useradd", "--create-home", "-s", "/bin/sh", "deploy")
    host.ok("install", "-d", "-m", "0700", "-o", "deploy", "-g", "deploy", "/home/deploy/.ssh")
    host.ok(
        *("install", "-m", "0600", "-o", "deploy", "-g", "deploy"),
        *("/kit/authorized_keys", "/home/deploy/.ssh/authorized_keys"),
    )
    host.ok("install", "-m", "0440", "/kit/sudoers", SUDOERS)
    host.ok("visudo", "-cf", SUDOERS)
    # the site's file system and the docroot as the runbook leaves them, links included
    host.ok("dd", "if=/dev/zero", "of=/site.img", "bs=1M", "count=16", "status=none")
    host.ok("mkfs.ext4", "-q", "/site.img")
    host.ok("mkdir", "-p", SITE_HOME)
    host.ok("mount", "-o", "loop", "/site.img", SITE_HOME)
    host.ok("install", "-d", "-m", "0755", DOCROOT, f"{DOCROOT}/keyring")
    for name in ("apt", "rpm"):
        host.ok("ln", "-s", f"{SITE_ROOT}/current/{name}", f"{DOCROOT}/{name}")
    host.ok("chattr", "+i", DOCROOT)
    # the deploy's own folders; the state folder's mode is the subject of the second test
    host.ok("install", "-d", "-m", "0755", pkg_deploy.CONFIG_DIR.as_posix())
    for name in ("deploy.conf", "allowed_signers"):
        host.ok("install", "-m", "0644", f"/kit/{name}", f"{pkg_deploy.CONFIG_DIR}/{name}")
    host.ok("install", "-d", "-m", "0700", STATE, f"{STATE}/backups")
    host.ok("install", "-m", "0750", "/kit/php-pkg-publisher-deploy", SCRIPT)
    # the ssh client side and sshd
    for name in ("client", "other"):
        host.ok("install", "-m", "0600", f"/kit/{name}_key", f"/root/{name}_key")
    host.ok("install", "-m", "0644", "/kit/known_hosts", "/root/known_hosts")
    host.ok("install", "-m", "0600", "/kit/server_key", "/etc/ssh/test_host_key")
    host.ok("install", "-d", "-m", "0755", "/run/sshd")
    host.ok(
        *("/usr/sbin/sshd", "-p", PORT, "-h", "/etc/ssh/test_host_key"),
        *("-o", "ListenAddress=127.0.0.1", "-o", "PasswordAuthentication=no"),
        *("-E", "/var/log/sshd.log"),
    )
    for _ in range(40):
        if host.box.run("ssh-keyscan", "-p", PORT, "-T", "3", "127.0.0.1").output.strip():
            return
        time.sleep(0.5)
    raise AssertionError(host.box.run("cat", "/var/log/sshd.log").output)


@pytest.fixture(scope="module", params=["ubuntu-22.04"])
def host(
    request: pytest.FixtureRequest,
    keys: dict[str, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Host]:
    assert docker_available(), "the container layer needs a running docker"
    kit = tmp_path_factory.mktemp("kit")
    _write_kit(kit, keys)
    # privileged for the loop mount and `chattr`; setuid `sudo` needs no-new-privileges off
    with Box(
        IMAGES[request.param], kit, privileged=True, no_new_privileges=False, network="bridge"
    ) as box:
        machine = Host(box)
        try:
            _provision(machine)
            yield machine
        finally:
            # let go of the loop device
            box.run("chattr", "-i", DOCROOT)
            box.run("umount", SITE_HOME)


def test_the_locked_key_runs_only_the_deploy_command(host: Host) -> None:
    # a client that asks for something else gets the script, not its command
    canary = "/home/deploy/canary"
    done = host.ssh(command=f"touch {canary}; id")
    assert (done.code, done.output) == (2, "refused: bundle-invalid\n")
    assert host.box.run("test", "-e", canary).code == 1
    # the deploy user could have made it: the command was not run
    assert host.box.run("runuser", "-u", "deploy", "--", "touch", canary).code == 0
    host.ok("rm", canary)
    # no terminal, no tunnel of either kind, and no other key
    done = host.ssh("-tt")
    assert done.code == 255 and "PTY allocation request failed" in done.output, done.output
    assert "refused" not in done.output, done.output
    done = host.ssh("-W", f"127.0.0.1:{PORT}")
    assert done.code == 255 and "administratively prohibited" in done.output, done.output
    done = host.ssh("-N", "-R", "19999:127.0.0.1:22", "-o", "ExitOnForwardFailure=yes")
    assert done.code == 255 and "forwarding failed" in done.output, done.output
    done = host.ssh(key="other")
    assert done.code == 255 and "Permission denied" in done.output, done.output
    # the sudo line is for the script with no arguments; the deploy user may not use it for more
    for command in ([SCRIPT, "rollback"], ["/usr/bin/id"]):
        done = host.box.run("runuser", "-u", "deploy", "--", "sudo", "-n", *command)
        assert done.code == 1 and "a password is required" in done.output, done.output


def test_the_publisher_user_must_be_able_to_pass_the_state_folder(
    host: Host, releases: Releases
) -> None:
    """The new `products.yml` is loaded as the publisher user, from a folder in the state folder."""
    try:
        done = host.deploy(releases.first)
        assert (done.code, done.output) == (2, "refused: products-invalid\n")
        assert host.box.run("test", "-e", "/etc/php-pkg-publisher").code == 1
        assert host.box.run("test", "-e", f"{STATE}/manifest.json").code == 1
    finally:
        # what the runbook sets; the tests after this one need it even if an assertion failed
        host.ok("chmod", "0711", STATE)


def test_a_signed_tag_installs_root_owned_files_behind_the_immutable_docroot(
    host: Host, releases: Releases
) -> None:
    host.clear_calls()
    done = host.deploy(releases.first)
    assert (done.code, done.output) == (0, "deployed v1.0.0\n")
    for target, (source, mode) in INSTALLED.items():
        assert host.stat(target) == f"root:root {mode}", target
        digest = hashlib.sha256(releases.first.files[source]).hexdigest()
        assert host.sha256(target) == digest, target
    assert host.immutable()
    assert sorted(host.ok("ls", "-A", DOCROOT).split()) == [
        ".htaccess",
        "apt",
        "keyring",
        "rpm",
        "sync.php",
    ]
    # the running units stop before the files change and start again after
    assert host.calls() == [
        "stop php-pkg-publisher.path",
        "stop php-pkg-publisher.timer",
        "daemon-reload",
        "start php-pkg-publisher.path",
        "start php-pkg-publisher.timer",
    ]
    assert host.stat(f"{STATE}/manifest.json") == "root:root 600"
    assert host.box.run("test", "-e", f"{STATE}/pending").code == 1
    # the web server's user reads the receiver and can change nothing in the docroot
    web = ("runuser", "-u", "siteuser", "--")
    assert host.box.run(*web, "cat", f"{DOCROOT}/sync.php").code == 0
    for attempt in (
        ("touch", f"{DOCROOT}/evil"),
        ("rm", "-f", f"{DOCROOT}/sync.php"),
        ("mv", f"{DOCROOT}/sync.php", f"{DOCROOT}/moved.php"),
        ("mv", DOCROOT, f"{DOCROOT}.old"),
    ):
        assert host.box.run(*web, *attempt).code != 0, attempt
    # the flag stops root too: it is what holds when the folder's owner is not the one to fear
    for attempt in (("touch", f"{DOCROOT}/evil"), ("rm", "-f", f"{DOCROOT}/sync.php")):
        assert host.box.run(*attempt).code != 0, attempt
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"


def test_the_deploy_replaces_itself_and_deletes_only_what_it_dropped(
    host: Host, releases: Releases
) -> None:
    done = host.deploy(releases.second)
    assert (done.code, done.output) == (0, "deployed v1.0.1\n")
    probe = "/opt/php-pkg-publisher/publisher/probe.py"
    assert host.stat(probe) == "root:root 644"
    new_script = hashlib.sha256(releases.second.files["deploy/pkg_deploy.py"]).hexdigest()
    assert host.sha256(SCRIPT) == new_script
    # the next deploy runs through the file the last one installed, and drops the probe
    done = host.deploy(releases.third)
    assert (done.code, done.output) == (0, "deployed v1.0.2\n")
    assert host.box.run("test", "-e", probe).code == 1
    assert (
        host.sha256(SCRIPT)
        == hashlib.sha256(releases.third.files["deploy/pkg_deploy.py"]).hexdigest()
    )
    assert host.immutable()
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"


def test_a_refused_tag_changes_nothing_and_says_one_fixed_code(
    host: Host, releases: Releases
) -> None:
    manifest = host.sha256(f"{STATE}/manifest.json")
    host.clear_calls()
    for release, line in (
        (releases.stranger, "refused: signature-invalid\n"),
        (releases.broken, "refused: products-invalid\n"),
        (releases.first, "refused: version-older\n"),
    ):
        done = host.deploy(release)
        assert (done.code, done.output) == (2, line), release.tag
    assert host.sha256(f"{STATE}/manifest.json") == manifest
    assert host.calls() == []
    assert host.immutable()
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"


def test_rollback_puts_the_last_deploy_back_and_bans_its_version(
    host: Host, releases: Releases
) -> None:
    done = host.local("rollback")
    assert done.code == 0 and done.output.endswith("-v1.0.2\n"), done.output
    # back to the second release, with its probe file and its copy of the script
    probe = "/opt/php-pkg-publisher/publisher/probe.py"
    assert host.stat(probe) == "root:root 644"
    expected = hashlib.sha256(releases.second.files["deploy/pkg_deploy.py"]).hexdigest()
    assert host.sha256(SCRIPT) == expected
    assert host.immutable()
    assert host.ok("cat", f"{STATE}/denied.json") == '["v1.0.2"]'
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"
    done = host.deploy(releases.third)
    assert (done.code, done.output) == (2, "refused: version-denied\n")
