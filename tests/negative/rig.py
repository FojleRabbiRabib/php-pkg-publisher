# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""A whole publisher pass over throwaway keys and real packages, with only the network faked.

Real: the run pass, the admit stage and its state files, the verifier (`rpmkeys`, `rpm`,
`dpkg-deb`, `gpg`), the metadata builder (`apt-ftparchive`, `createrepo_c`), the signer, the
generation publisher and the run lock. Faked at the edge: the release feed (`Feed`), the asset
download (`Feed.fetch`), the Sigstore trusted-root refresh and `cosign` itself.

The `cosign` stand-in checks what the real one checks for a bundle: the certificate identity it
is given must be the one the bundle was made for, and the bundle must be for these exact bytes.
Keyless bundles cannot be made offline, so the real tool is proven against a real bundle in
`tests/unit/test_verify.py`; nothing here claims to prove it again.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import itertools
import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pkgkit import Key, build_deb, build_rpm, make_key, stop_agent, subkeys_only

from publisher import admit, generation, lock, run
from publisher.cache import Cache, Chunks, DownloadError
from publisher.config import Exclusion, ExclusionList, Product, ProductList
from publisher.feed import Asset, Listing, Release, download_url
from publisher.lock import RunLock
from publisher.settings import Settings, SigningPins, WatchTarget
from publisher.signer import SigningKey
from publisher.tools import ToolError, Tools
from publisher.verify import Package, TrustedRoot, expected_packages, identity

TRUSTED_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "sigstore" / "trusted_root.json"
SUMS = "SHA256SUMS"
BUNDLE = ".bundle"
DAY = 24 * 3600.0

COSIGN = """#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) bundle="$2"; shift ;;
    --certificate-identity) who="$2"; shift ;;
    --trusted-root|--certificate-oidc-issuer) shift ;;
    verify-blob) ;;
    *) blob="$1" ;;
  esac
  shift
done
{ read -r signed_for; read -r signed_sum; } < "$bundle" || exit 1
sum=$(sha256sum "$blob")
if [ "$signed_for" = "$who" ] && [ "${sum%% *}" = "$signed_sum" ]; then
  echo "Verified OK" >&2
  exit 0
fi
echo "Error: no matching signatures" >&2
exit 1
"""


def product(repo: str, extension: str) -> Product:
    return Product(
        repo=repo, extension=extension, php=("8.3",), arch=("amd64",), ts=("nts",), exclude=()
    )


def package_names(files: dict[str, bytes]) -> frozenset[str]:
    """The packages of a release, read from the release files themselves."""
    return frozenset(name for name in files if name != SUMS and not name.endswith(BUNDLE))


@dataclass(frozen=True)
class Kit:
    """What every test shares: the tools, the keys and the packages built so far."""

    tools: Tools
    master: Key
    vps: Key
    rpm_keys: dict[str, Key]
    work: Path
    built: dict[tuple[str, str, str], bytes] = field(default_factory=dict)
    counter: Iterator[int] = field(default_factory=itertools.count)

    @property
    def signing(self) -> SigningKey:
        return SigningKey(
            home=self.vps.home,
            fingerprint=self.master.subkey_fingerprint,
            certificate=self.master.public,
            primary=self.master.primary_fingerprint,
        )

    def _package(self, item: Package, rpm_key: str | None, deb_version: str | None) -> bytes:
        memo = (item.name, rpm_key or "unsigned", deb_version or "")
        if memo in self.built:
            return self.built[memo]
        root = self.work / f"b{next(self.counter)}"
        root.mkdir()
        if item.kind == "deb":
            data = build_deb(
                self.tools,
                root,
                package=item.package,
                version=deb_version or item.version,
                architecture=item.machine,
            )
        else:
            data = build_rpm(
                root,
                name=item.package,
                version=item.version,
                release=item.release,
                arch=item.machine,
                key=None if rpm_key is None else self.rpm_keys[rpm_key],
            )
        self.built[memo] = data
        return data

    def release(
        self,
        who: Product,
        tag: str,
        *,
        signed_for: tuple[str, str] | None = None,
        rpm_key: str | None = "good",
        deb_version: str | None = None,
    ) -> dict[str, bytes]:
        """The files of one release of `who`: packages, a bundle for each, and `SHA256SUMS`.

        `signed_for` is the (repo, tag) whose release workflow the bundles name; `rpm_key` is
        the key the rpms are signed with (None: unsigned); `deb_version` builds the debs with
        another version than the tag says.
        """
        workflow = identity(*(signed_for or (who.repo, tag)))
        files: dict[str, bytes] = {}
        for package in expected_packages(who, tag):
            data = self._package(package, rpm_key, deb_version)
            files[package.name] = data
            digest = hashlib.sha256(data).hexdigest()
            files[package.name + BUNDLE] = f"{workflow}\n{digest}\n".encode()
        listing = "".join(
            f"{hashlib.sha256(data).hexdigest()}  ./{name}\n"
            for name, data in sorted(files.items())
            if not name.endswith(BUNDLE)
        )
        files[SUMS] = listing.encode()
        return files


def make_kit(root: Path) -> Iterator[Kit]:
    cosign = root / "cosign"
    cosign.write_text(COSIGN, encoding="utf-8")
    cosign.chmod(0o755)
    real = Tools.locate(os.environ["PATH"])
    tools = dataclasses.replace(real, cosign=cosign)
    keys = root / "keys"
    keys.mkdir()
    master = make_key(real, keys, "repo")
    vps = subkeys_only(real, master, keys, "vps")
    rpm_keys = {name: make_key(real, keys, name) for name in ("good", "other")}
    work = root / "packages"
    work.mkdir()
    yield Kit(tools=tools, master=master, vps=vps, rpm_keys=rpm_keys, work=work)
    for key in (master, vps, *rpm_keys.values()):
        stop_agent(key)


class Feed:
    """The release feed and the asset download, served from memory."""

    def __init__(self) -> None:
        self._releases: dict[str, dict[str, Release]] = {}
        self._bytes: dict[str, bytes] = {}
        self.fail_once: set[str] = set()
        self.during_fetch: Callable[[], None] | None = None
        self.fetched: list[str] = []

    def add(
        self,
        repo: str,
        tag: str,
        files: dict[str, bytes],
        *,
        immutable: bool = True,
        kind: Literal["final", "prerelease"] = "final",
    ) -> None:
        assets = []
        for name, data in files.items():
            url = download_url(repo, tag, name)
            self._bytes[url] = data
            assets.append(
                Asset(
                    name=name,
                    size=len(data),
                    digest="sha256:" + hashlib.sha256(data).hexdigest(),
                    url=url,
                )
            )
        self._releases.setdefault(repo, {})[tag] = Release(
            tag=tag, kind=kind, immutable=immutable, assets=tuple(assets)
        )

    def lister(self, repo: str, *, etag: str | None) -> Listing:
        releases = tuple(self._releases.get(repo, {}).values())
        return Listing(etag=None, releases=releases, rejected=(), ignored=())

    def fetch(self, url: str, size: int) -> Chunks:
        name = url.rsplit("/", 1)[-1]
        self.fetched.append(name)
        if self.during_fetch is not None:
            hook, self.during_fetch = self.during_fetch, None
            hook()
        if name in self.fail_once:
            self.fail_once.discard(name)
            raise DownloadError("connection reset")
        yield self._bytes[url]


class _Stages(run.LiveStages):
    """The real stages with the two network edges replaced."""

    def __init__(
        self,
        settings: Settings,
        products: ProductList,
        exclusions: ExclusionList,
        *,
        feed: Feed,
        sigstore_up: bool,
        held: RunLock,
        tools: Tools,
        cache: Cache,
    ) -> None:
        super().__init__(settings, products, exclusions, lock=held, tools=tools, cache=cache)
        self._feed = feed
        self._sigstore_up = sigstore_up

    def trusted_root(self, now: float) -> TrustedRoot:
        if not self._sigstore_up:
            raise ToolError("no trusted root and the refresh failed: the Sigstore is unreachable")
        self._trusted = TrustedRoot(path=TRUSTED_ROOT, age_seconds=0.0, refreshed=True)
        return self._trusted

    def _lister(self) -> admit.Lister:
        return self._feed.lister


class Rig:
    """One publisher installation in a temporary directory, driven pass by pass."""

    def __init__(self, root: Path, kit: Kit, products: tuple[Product, ...]) -> None:
        self.kit = kit
        self.root = root
        for name in ("state", "cache", "trust", "work", "lock", "nudge"):
            (root / name).mkdir(mode=0o700)
        (root / "site").mkdir(mode=0o755)
        self.settings = Settings(
            source=root / "publisher.yml",
            products=root / "products.yml",
            exclude=root / "exclude.yml",
            site=root / "site",
            state=root / "state",
            cache=root / "cache",
            trust=root / "trust",
            work=root / "work",
            lock=root / "lock",
            nudge=root / "nudge" / "sync",
            rpm_key=kit.rpm_keys["good"].public,
            token_file=root / "token",
            token_expires=datetime.date(2099, 1, 1),
            alert_file=root / "alert",
            signing=SigningPins(
                home=kit.signing.home,
                fingerprint=kit.signing.fingerprint,
                certificate=kit.signing.certificate,
                primary=kit.signing.primary,
            ),
            watch=WatchTarget(host="pkg.example.org", origin="93.184.216.34"),
        )
        self.products = ProductList(
            source=self.settings.products, sha256="0" * 64, products=products
        )
        self.excluded: list[Exclusion] = []
        self.feed = Feed()
        self.cache = Cache(self.settings.cache, self.feed.fetch)
        self.log: list[str] = []

    @property
    def exclusions(self) -> ExclusionList:
        return ExclusionList(
            source=self.settings.exclude, sha256="0" * 64, exclusions=tuple(self.excluded)
        )

    @property
    def current(self) -> Path:
        return self.settings.site / "current"

    @property
    def nudge(self) -> Path:
        return self.settings.nudge

    def _stages(self, held: RunLock, *, sigstore_up: bool) -> _Stages:
        return _Stages(
            self.settings,
            self.products,
            self.exclusions,
            feed=self.feed,
            sigstore_up=sigstore_up,
            held=held,
            tools=self.kit.tools,
            cache=self.cache,
        )

    def run_pass(self, now: float, *, sigstore_up: bool = True) -> run.Result:
        """One locked pass: refresh the trust, admit, publish."""
        with RunLock(self.settings.lock) as held:
            return run.run_pass(
                self._stages(held, sigstore_up=sigstore_up),
                self.products,
                self.exclusions,
                now=now,
                log=self.log.append,
            )

    def run_nudged(self, now: float) -> list[run.Result]:
        """What the `run` command does: passes while nudges keep arriving."""
        with RunLock(self.settings.lock) as held:

            def one_pass() -> run.Result:
                return run.run_pass(
                    self._stages(held, sigstore_up=True),
                    self.products,
                    self.exclusions,
                    now=now,
                    log=self.log.append,
                )

            return lock.run_passes(held, self.nudge, one_pass)

    def rollback(self, identifier: str, now: float) -> generation.Published:
        with RunLock(self.settings.lock):
            return generation.rollback(
                generation.open_site(self.settings.site),
                identifier,
                excluded={(item.product, item.tag) for item in self.excluded},
                cache=self.cache,
                tools=self.kit.tools,
                key=run.signing_key(self.settings),
                now=now,
            )

    def state(self, repo: str) -> dict[str, Any]:
        """The product's state file as the admit stage wrote it, read as plain JSON."""
        path = self.settings.state / "products" / f"{repo}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        return document

    def current_id(self) -> str:
        return self.current.readlink().name
