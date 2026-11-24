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
import re
import textwrap
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import pkg_deploy
import pytest
import yaml
from box import Box, Done, docker_available
from deploykit import GIT, generate_key, openpgp_bundle, run, signed_bundle
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
    "gnupg",
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
    workflow: Release
    byhand: Release
    installer: Release
    forged: Release
    openpgp: Release
    openpgp_key: bytes


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
    marked = {**files, script: files[script] + b"\n# provisioned, never deployed\n"}

    def release(tag: str, tree: dict[str, bytes], signer: str = "release") -> Release:
        return Release(tag, signed_bundle(folder, keys, tree, tag, signer=signer), tree)

    openpgp_bundle_, openpgp_key = openpgp_bundle(folder, marked, "v0.9.2")

    return Releases(
        first=release("v1.0.0", files),
        second=release("v1.0.1", second),
        third=release("v1.0.2", third),
        stranger=release("v1.0.3", files, signer="other"),
        broken=release("v1.0.4", broken),
        workflow=release("v1.0.5", files),
        byhand=release("v1.0.7", files),
        # what the runbook has the operator install by hand: not the first release's bytes, so the
        # first deploy has to replace it
        installer=release("v0.9.0", marked),
        forged=release("v0.9.1", marked, signer="other"),
        openpgp=Release("v0.9.2", openpgp_bundle_, marked),
        openpgp_key=openpgp_key,
    )


def _key_text(public: Path) -> str:
    kind, key, *_ = public.read_text(encoding="utf-8").split()
    return f"{kind} {key}"


def _known_hosts(server: Path) -> str:
    return f"[127.0.0.1]:{PORT} {_key_text(server)}\n"


def _write_kit(kit: Path, keys: dict[str, Path]) -> None:
    """What the container is given, read-only: the stub and the keys.

    The deploy user, its key, the sudo line, the folders and the script are not here: the
    runbook's own commands make them (`_provision`).
    """
    (kit / "systemctl").write_text(SYSTEMCTL_STUB, encoding="utf-8")
    (kit / "stub-active-units").write_text(
        "php-pkg-publisher.path\nphp-pkg-publisher.timer\n", encoding="utf-8"
    )
    for name in ("client", "other", "server"):
        (kit / f"{name}_key").write_bytes(keys[name].with_suffix("").read_bytes())
    (kit / "server_key.pub").write_bytes(keys["server"].read_bytes())


RUNBOOK: Final = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
# measured: `git verify-tag` prints the first line for any valid signature, even by a key that is
# not in the signer file, and then the second with exit status 1
GOOD_SIGNATURE: Final = 'Good "git" signature'
NO_PRINCIPAL: Final = "No principal matched."
GOOD_FOR_RELEASE: Final = f'Good "git" signature for {pkg_deploy.PRINCIPAL} with '
# a program a checkout's own configuration could name in place of `ssh-keygen`: it agrees to all
ALWAYS_YES: Final = """#!/bin/sh
case "$*" in
  *find-principals*) echo principal ;;
  *) echo 'Good "git" signature for principal with ED25519 key SHA256:fake' ;;
esac
"""
ALWAYS_YES_PATH: Final = "/usr/local/bin/always-yes"


def _blocks(containing: str) -> list[str]:
    """Every `sh` block of the runbook that holds `containing`, dedented."""
    found = re.findall(r"^[ ]*```sh\n(.*?)^[ ]*```$", RUNBOOK, re.MULTILINE | re.DOTALL)
    return [textwrap.dedent(block) for block in found if containing in block]


def _block(containing: str) -> str:
    """The one block of the runbook that holds `containing`; repeats of it must be identical."""
    blocks = _blocks(containing)
    assert blocks and all(block == blocks[0] for block in blocks), containing
    return blocks[0]


def _fill(text: str, table: dict[str, str]) -> str:
    """Fill the placeholders from a closed table: one the table lacks is an error."""
    return re.sub(r"<([a-z-]+)>", lambda found: table[found[1]], text)


class Host:
    """The container, with the commands the tests keep needing."""

    def __init__(self, box: Box) -> None:
        self.box = box
        # the host key lines the runbook's own command printed, for the two forms of a target
        self.known_hosts = ""
        self.known_hosts_port_22 = ""

    def ok(self, *command: str) -> str:
        done = self.box.run(*command)
        assert done.code == 0, (command, done.output)
        return done.output

    def put(self, path: str, data: bytes) -> None:
        assert self.box.run("dd", "status=none", f"of={path}", stdin=data).code == 0

    def runbook(self, containing: str, table: dict[str, str], workdir: str = "/") -> Done:
        """Run a block of the runbook as written, as root, with its placeholders filled."""
        script = _fill(_block(containing), table)
        return self.box.run(
            *("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script), workdir=workdir
        )

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


def _by_hand(
    host: Host,
    release: Release,
    label: str,
    *,
    tamper: bool = False,
    alias: str | None = None,
    owner: str | None = None,
    program: str | None = None,
) -> Done:
    """The runbook's block that checks the tag and installs the script, in a checkout of it.

    `tamper` edits the file in the working tree and has git ignore the edit; `alias` stores the
    tag object under another name and gives the block that name; `owner` makes the checkout
    belong to that user, not to root; `program` is written into the checkout's own configuration
    as the program that checks SSH signatures.
    """
    name = f"{release.tag}-{label}"
    if owner is None:
        work = _clone(host, name, release.bundle)
    else:
        work = f"/work/{name}/repo"
        host.ok("mkdir", "-p", "/work")
        host.put(f"/work/{name}.bundle", release.bundle)
        host.ok("install", "-d", "-o", owner, f"/work/{name}")
        host.ok("runuser", "-u", owner, "--", "git", "clone", "-q", f"/work/{name}.bundle", work)
    if program is not None:
        host.ok("git", "-C", work, "config", "gpg.ssh.program", program)
    if alias is not None:
        tag_object = host.ok("git", "-C", work, "rev-parse", f"refs/tags/{release.tag}").strip()
        host.ok("git", "-C", work, "update-ref", f"refs/tags/{alias}", tag_object)
    if tamper:
        host.ok("git", "-C", work, "checkout", "-q", release.tag)
        host.put(f"{work}/deploy/pkg_deploy.py", b"# not what the tag holds\n")
        host.ok("git", "-C", work, "update-index", "--skip-worktree", "deploy/pkg_deploy.py")
        assert host.box.run("git", "-C", work, "diff", "--quiet").code == 0  # git sees no edit
    return host.runbook("verify-tag", {"tag": alias or release.tag}, workdir=work)


def _install_script_by_hand(host: Host, releases: Releases) -> None:
    """Step 7's last block: it refuses four tags and installs the tag's bytes, not the tree's."""
    # root's own keyring trusts the OpenPGP key. Without the block's pins the tag is accepted,
    # so it is the pins that refuse it below
    done = host.box.run("gpg", "--batch", "--import", stdin=releases.openpgp_key)
    assert done.code == 0, done.output
    work = _clone(host, "unpinned", releases.openpgp.bundle)
    signers = f"gpg.ssh.allowedSignersFile={pkg_deploy.CONFIG_DIR}/allowed_signers"
    done = host.box.run(
        *("git", "-C", work, "-c", "gpg.format=ssh", "-c", signers),
        *("verify-tag", releases.openpgp.tag),
    )
    assert done.code == 0, done.output
    # likewise a checkout whose own configuration names a program that agrees to everything:
    # a tag signed by a key that is not in the signer file passes unless the command line decides
    host.put(ALWAYS_YES_PATH, ALWAYS_YES.encode())
    host.ok("chmod", "0755", ALWAYS_YES_PATH)
    work = _clone(host, "swapped", releases.forged.bundle)
    host.ok("git", "-C", work, "config", "gpg.ssh.program", ALWAYS_YES_PATH)
    done = host.box.run(
        *("git", "-C", work, "-c", "gpg.format=ssh", "-c", signers),
        *("verify-tag", releases.forged.tag),
    )
    assert done.code == 0, done.output
    cases: tuple[tuple[str, Release, dict[str, Any], str], ...] = (
        # signed by a key that is not in the signer file
        ("forged", releases.forged, {}, NO_PRINCIPAL),
        # the same, in a checkout whose configuration swaps the checking program
        ("swapped", releases.forged, {"program": ALWAYS_YES_PATH}, NO_PRINCIPAL),
        # signed with OpenPGP by a key of root's keyring: nothing is checked, so nothing is said
        ("openpgp", releases.openpgp, {}, ""),
        # a genuine tag object stored under another name: the signature is good, the name is not
        ("alias", releases.installer, {"alias": "v9.9.9"}, GOOD_FOR_RELEASE),
        # a checkout that belongs to another user
        ("owned", releases.installer, {"owner": "siteuser"}, "dubious ownership"),
    )
    for label, release, options, said in cases:
        done = _by_hand(host, release, label, **options)
        assert done.code != 0 and "script not installed" in done.output, (label, done.output)
        assert said in done.output, (label, done.output)
        # a signature was checked and found good only where the refusal comes after that check
        checked = said in (NO_PRINCIPAL, GOOD_FOR_RELEASE)
        assert (GOOD_SIGNATURE in done.output) is checked, (label, done.output)
        assert host.box.run("test", "-e", SCRIPT).code == 1, label
    # the file in the working tree was edited and git was told to ignore it: the tag's file is
    # what is installed
    done = _by_hand(host, releases.installer, "genuine", tamper=True)
    assert done.code == 0, done.output
    source = releases.installer.files["deploy/pkg_deploy.py"]
    assert host.sha256(SCRIPT) == hashlib.sha256(source).hexdigest()
    assert host.stat(SCRIPT) == "root:root 755"


def _provision(host: Host, keys: dict[str, Path], releases: Releases) -> None:
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
    # the site's file system, and the docroot as a panel leaves it: a folder that exists
    host.ok("dd", "if=/dev/zero", "of=/site.img", "bs=1M", "count=16", "status=none")
    host.ok("mkfs.ext4", "-q", "/site.img")
    host.ok("mkdir", "-p", SITE_HOME)
    host.ok("mount", "-o", "loop", "/site.img", SITE_HOME)
    host.ok("mkdir", DOCROOT)
    # the runbook's own commands, as written, make the lock, the deploy user and the script
    table = {
        "docroot": DOCROOT,
        "docroot-parent": SITE_HOME,
        "site-root": SITE_ROOT,
        "deploy-user": "deploy",
        "deploy-public-key": _key_text(keys["client"]),
        "release-public-key": _key_text(keys["release"]),
    }
    done = host.runbook("chattr +i <docroot>", table)
    assert done.code == 0, done.output
    done = host.runbook("useradd --create-home", table)
    assert done.code == 0, done.output
    _install_script_by_hand(host, releases)
    # the ssh client side and sshd, with the host key where sshd looks for one
    for name in ("client", "other"):
        host.ok("install", "-m", "0600", f"/kit/{name}_key", f"/root/{name}_key")
    host.ok("install", "-m", "0600", "/kit/server_key", "/etc/ssh/ssh_host_ed25519_key")
    host.ok("install", "-m", "0644", "/kit/server_key.pub", "/etc/ssh/ssh_host_ed25519_key.pub")
    host.ok("install", "-d", "-m", "0755", "/run/sshd")
    host.ok(
        *("/usr/sbin/sshd", "-p", PORT, "-p", "22", "-o", "ListenAddress=127.0.0.1"),
        *("-o", "PasswordAuthentication=no", "-E", "/var/log/sshd.log"),
    )
    # the host key lines the runbook has the operator make, for a port and for port 22
    done = host.runbook("ssh_host_ed25519_key.pub", {"origin-host": "127.0.0.1", "ssh-port": PORT})
    assert done.code == 0, done.output
    # the runbook says `sshd -T` prints this, for the locked password of the deploy user
    assert "usepam yes\n" in host.ok("/usr/sbin/sshd", "-T")
    host.known_hosts, host.known_hosts_port_22 = (f"{line}\n" for line in done.output.splitlines())
    assert host.known_hosts == _known_hosts(keys["server"])
    assert host.known_hosts_port_22 == f"127.0.0.1 {_key_text(keys['server'])}\n"
    host.put("/root/known_hosts", host.known_hosts.encode())
    for _ in range(40):
        if host.box.run("ssh-keyscan", "-p", PORT, "-T", "3", "127.0.0.1").output.strip():
            return
        time.sleep(0.5)
    raise AssertionError(host.box.run("cat", "/var/log/sshd.log").output)


@pytest.fixture(scope="module", params=["ubuntu-22.04"])
def host(
    request: pytest.FixtureRequest,
    keys: dict[str, Path],
    releases: Releases,
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
            _provision(machine, keys, releases)
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
        # the runbook made it `0711`; closed to everyone but root, the deploy is refused
        host.ok("chmod", "0700", STATE)
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
    # the documented way back: the operator lifts the ban
    assert host.local("allow", "v1.0.2").code == 0
    assert host.ok("cat", f"{STATE}/denied.json") == "[]"


RELEASE_WORKFLOW: Final = ROOT / ".github" / "workflows" / "release.yml"
RUNNER_TEMP: Final = "/root/runner"


def _expression(text: str, context: dict[str, str]) -> str:
    """Fill the `${{ ... }}` of a workflow value from a closed table: an unknown one is an error."""
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda found: context[found[1]], text)


def _run_deploy_job(
    host: Host,
    tag: str,
    keys: dict[str, Path],
    *,
    workdir: str,
    known_hosts: str,
    target: str = f"ssh://deploy@127.0.0.1:{PORT}",
) -> tuple[int, Done]:
    """The deploy job's own scripts, read from `release.yml` and run as the runner runs them.

    They run in order until one fails; the result is the number of the step that ended it (the
    count of steps when none failed) and that step's output.
    """
    workflow: dict[str, Any] = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    context = {
        "github.ref_name": tag,
        "secrets.DEPLOY_SSH_KEY": keys["client"]
        .with_suffix("")
        .read_text(encoding="utf-8")
        .strip(),
        "secrets.DEPLOY_KNOWN_HOSTS": known_hosts.strip(),
        "secrets.DEPLOY_TARGET": target,
    }
    scripts = [step for step in workflow["jobs"]["deploy"]["steps"] if "run" in step]
    host.ok("rm", "-rf", RUNNER_TEMP)
    host.ok("mkdir", RUNNER_TEMP)
    done = Done(0, "")
    for number, step in enumerate(scripts):
        assert step["shell"] == "bash"
        variables = [
            f"{name}={_expression(value, context)}" for name, value in step.get("env", {}).items()
        ]
        done = host.box.run(
            *("env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"),
            f"RUNNER_TEMP={RUNNER_TEMP}",
            *variables,
            *("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]),
            workdir=workdir,
        )
        if done.code != 0:
            return number, done
    return len(scripts), done


def _clone(host: Host, name: str, bundle: bytes) -> str:
    """A checkout of what a bundle holds, with the bundle as its `origin`."""
    host.ok("mkdir", "-p", "/work")
    path = f"/work/{name}"
    assert host.box.run("dd", "status=none", f"of={path}.bundle", stdin=bundle).code == 0
    host.ok("git", "clone", "-q", f"{path}.bundle", path)
    return path


def test_the_workflow_steps_deploy_a_tag_through_the_locked_key(
    host: Host, releases: Releases, keys: dict[str, Path]
) -> None:
    """The scripts of the deploy job, not a copy of them, against the real sshd and script."""
    tag = releases.workflow.tag
    work = _clone(host, "workflow", releases.workflow.bundle)
    # a checkout can leave a lightweight tag where the tag object was; the job must not use it
    commit = host.ok("git", "-C", work, "rev-parse", f"{tag}^{{commit}}").strip()
    host.ok("git", "-C", work, "update-ref", f"refs/tags/{tag}", commit)
    assert host.ok("git", "-C", work, "cat-file", "-t", f"refs/tags/{tag}").strip() == "commit"
    ended, done = _run_deploy_job(host, tag, keys, workdir=work, known_hosts=host.known_hosts)
    # the last step prints what a public log shows, which is the host's one line
    assert (ended, done.output) == (2, f"deployed {tag}\n")
    assert host.ok("git", "-C", work, "cat-file", "-t", f"refs/tags/{tag}").strip() == "tag"
    assert f'"version": "{tag}"' in host.ok("cat", f"{STATE}/manifest.json")
    assert host.box.run("test", "-e", f"{RUNNER_TEMP}/deploy_key").code == 1
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"


def test_the_workflow_stops_at_a_lightweight_tag_and_at_a_host_key_it_does_not_know(
    host: Host, releases: Releases, keys: dict[str, Path]
) -> None:
    manifest = host.sha256(f"{STATE}/manifest.json")
    # an origin that holds a lightweight tag only: the job stops before it reaches ssh
    commit = host.ok("git", "-C", "/work/workflow", "rev-parse", "v1.0.5^{commit}").strip()
    host.ok("git", "init", "-q", "--bare", "/work/light.git")
    host.ok(
        "git", "-C", "/work/workflow", "push", "-q", "/work/light.git", f"{commit}:refs/tags/v1.0.6"
    )
    host.ok("git", "clone", "-q", "/work/light.git", "/work/light")
    ended, done = _run_deploy_job(
        host, "v1.0.6", keys, workdir="/work/light", known_hosts=host.known_hosts
    )
    assert ended == 0 and done.code != 0, done.output
    # it stopped at the type check: the tag was fetched, it is a commit, and no bundle was made
    assert host.ok("git", "-C", "/work/light", "cat-file", "-t", "refs/tags/v1.0.6").strip() == (
        "commit"
    )
    assert host.box.run("test", "-e", f"{RUNNER_TEMP}/tag.bundle").code == 1
    assert host.box.run("test", "-e", f"{RUNNER_TEMP}/deploy_key").code == 1
    # a host key that is not the one pinned: ssh refuses, though the same tag would be accepted
    ended, done = _run_deploy_job(
        host,
        releases.workflow.tag,
        keys,
        workdir="/work/workflow",
        known_hosts=_known_hosts(keys["other"]),
    )
    assert ended == 1 and done.code == 255, done.output
    # ssh is quiet, so its own messages (they name the target) stay out of a public log
    assert done.output == "", done.output
    assert host.sha256(f"{STATE}/manifest.json") == manifest


def test_a_tag_the_host_refuses_fails_the_job_and_only_the_hosts_line_reaches_the_log(
    host: Host, releases: Releases, keys: dict[str, Path]
) -> None:
    """Quiet ssh must not hide the host's own line, and nothing the job sends is deployed unsigned.

    The tag is signed by another key; the signature is checked before the version, so the
    older number does not hide the refusal.
    """
    manifest = host.sha256(f"{STATE}/manifest.json")
    work = _clone(host, "stranger", releases.stranger.bundle)
    ended, done = _run_deploy_job(
        host,
        releases.stranger.tag,
        keys,
        workdir=work,
        known_hosts=host.known_hosts,
    )
    assert (ended, done.code, done.output) == (1, 2, "refused: signature-invalid\n")
    assert host.sha256(f"{STATE}/manifest.json") == manifest


def test_the_host_key_line_and_the_target_of_port_22_are_the_bare_host(
    host: Host, releases: Releases, keys: dict[str, Path]
) -> None:
    """The second form the runbook gives: no brackets and no port, for sshd on port 22."""
    work = _clone(host, "port22", releases.workflow.bundle)
    ended, done = _run_deploy_job(
        host,
        releases.workflow.tag,
        keys,
        workdir=work,
        known_hosts=host.known_hosts_port_22,
        target="ssh://deploy@127.0.0.1",
    )
    # the tag may be the one in place, which the host answers as it answers a new one
    assert (ended, done.output) == (2, f"deployed {releases.workflow.tag}\n")


def test_a_deploy_by_hand_runs_the_commands_of_the_runbook_and_keeps_every_check(
    host: Host, releases: Releases
) -> None:
    tag = releases.byhand.tag
    work = _clone(host, "byhand", releases.byhand.bundle)
    table = {"bundle-file": "/work/byhand.out.bundle", "tag": tag}
    done = host.runbook("git bundle create <bundle-file> refs/tags/<tag>", table, workdir=work)
    assert done.code == 0 and done.output.endswith(f"deployed {tag}\n"), done.output
    assert f'"version": "{tag}"' in host.ok("cat", f"{STATE}/manifest.json")
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"


def test_a_keyring_package_is_recorded_before_the_check_accepts_it(
    host: Host, releases: Releases
) -> None:
    """The flag on the docroot does not stop entries inside `keyring/`; the record does."""
    if host.box.run("test", "-e", f"{STATE}/manifest.json").code != 0:
        assert host.deploy(releases.first).code == 0  # run alone, the check needs a deploy
    package = f"{DOCROOT}/keyring/rabib-test.deb"
    host.put(package, b"package")
    done = host.local("check")
    assert done.code == 1 and "FAIL: keyring file not recorded: rabib-test.deb\n" in done.output
    assert host.local("record", package).code == 0
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"
    host.ok("rm", package)
    done = host.local("check")
    assert done.code == 1 and "FAIL: keyring file missing: rabib-test.deb\n" in done.output
    assert host.local("forget", package).code == 0
    assert host.local("check").output == "DEPLOY CHECK PASSED\n"
