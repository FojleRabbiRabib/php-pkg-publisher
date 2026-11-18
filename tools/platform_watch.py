# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The weekly outside watch: `PYTHONPATH=. python tools/platform_watch.py --site URL ...`.

It runs on a GitHub runner, so it shares nothing with the publishing host and still sees what a
client sees. It fails (exit 1, one `FAIL:` line each) when:

- the primary key of the served keyring package is not the pinned one;
- the served `InRelease` does not verify against that key, its `Date` is older than 4 days, or its
  `Valid-Until` is fewer than 7 days away;
- one of the six `repomd.xml.asc` files does not verify against `repomd.xml`, or was signed (by
  the signature's own time) or served (by `Last-Modified`) more than 4 days ago;
- the first deb listed in the `Packages` index (which must match the verified `InRelease`) or the
  first rpm listed in a `primary.xml` (which must match the verified `repomd.xml`) does not answer
  302 with the exact GitHub Releases URL of a declared product.

An empty package list fails the last check. The pin is the primary fingerprint, which does not
change when a signing subkey rotates; a placeholder in the pin file fails the run.
"""

from __future__ import annotations

import argparse
import email.utils
import hashlib
import http.client
import io
import os
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final
from urllib.parse import urljoin, urlsplit

from publisher import alert, net
from publisher.config import FINGERPRINT, RELEASE_TAG, ConfigError, load_products
from publisher.feed import download_url
from publisher.watch import DAY, FUTURE_SLACK_SECONDS, WatchError, release_dates

DATE_MAX_AGE_DAYS: Final = 4
VALID_UNTIL_MIN_DAYS: Final = 7
SIGNATURE_MAX_AGE_DAYS: Final = 4
PHP_VERSIONS: Final = ("8.3", "8.4", "8.5")
RPM_ARCHITECTURES: Final = ("x86_64", "aarch64")
APT_ARCHITECTURE: Final = "amd64"
RELEASE_PATH: Final = "apt/dists/stable/InRelease"
PACKAGES_NAME: Final = f"main/binary-{APT_ARCHITECTURE}/Packages"
KEYRING_PATH: Final = "keyring/rabib-archive-keyring.deb"
KEY_MEMBER: Final = "usr/share/keyrings/rabib-archive-keyring.gpg"
MAX_PACKAGE_BYTES: Final = 1024 * 1024
MAX_KEY_BYTES: Final = 1024 * 1024
MAX_TAR_BYTES: Final = 64 * 1024 * 1024
MAX_INDEX_BYTES: Final = 64 * 1024 * 1024
MAX_INFLATED_BYTES: Final = 128 * 1024 * 1024
MAX_REDIRECT_BODY_BYTES: Final = 8192
TIMEOUT_SECONDS: Final = 30.0
TOOL_SECONDS: Final = 60.0
USER_AGENT: Final = "php-pkg-publisher-platform-watch"
SINGLE_HEADERS: Final = frozenset({"last-modified", "location", "content-length"})
FILENAME: Final = re.compile(r"^Filename: pool/([^/\s]+)/([^/\s]+)/([^/\s]+)$", re.MULTILINE)
POOL_PATH: Final = re.compile(r"/pool/([^/]+)/([^/]+)/([^/]+)")
ASSET_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
REPO_NAME: Final = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9_-])?")
SHA256_LINE: Final = re.compile(r"^ ([0-9a-f]{64}) +([0-9]+) +(\S+)$")
SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")
STATUS_BAD: Final = ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")
CRASHES: Final = (WatchError, ValueError, OSError, UnicodeError, ET.ParseError)


@dataclass(frozen=True, slots=True)
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes


class Site:
    """The public site: https only, no proxy, no redirect followed, bounded and timed reads."""

    _SCHEMES: tuple[str, ...] = ("https://",)

    def __init__(self, base: str) -> None:
        self._base = base.rstrip("/")
        self._opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            # plain http is refused by `_SCHEMES`; only a test's subclass widens it
            urllib.request.HTTPHandler(),
            net.NoRedirect(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
            urllib.request.UnknownHandler(),
        ):
            self._opener.add_handler(handler)

    def request(self, path: str, *, limit: int = MAX_INDEX_BYTES) -> Reply:
        url = f"{self._base}/{path}"
        if not url.startswith(self._SCHEMES):
            raise WatchError("only https is allowed")
        request = urllib.request.Request(  # noqa: S310
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        try:
            try:
                with self._opener.open(request, timeout=TIMEOUT_SECONDS) as reply:
                    return self._reply(reply.status, reply.headers.items(), reply, limit)
            except urllib.error.HTTPError as error:
                with error:
                    return self._reply(error.code, error.headers.items(), error, limit)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
            raise WatchError(f"cannot reach {path} ({type(error).__name__})") from None

    @staticmethod
    def _reply(
        status: int,
        pairs: Sequence[tuple[str, str]],
        body: http.client.HTTPResponse | urllib.error.HTTPError,
        limit: int,
    ) -> Reply:
        headers = net.headers(pairs, SINGLE_HEADERS)
        chunks: list[bytes] = []
        total = 0
        deadline = time.monotonic() + 2 * TIMEOUT_SECONDS
        while chunk := body.read(65536):
            total += len(chunk)
            if total > limit:
                raise WatchError("a served file is larger than the allowed size")
            if time.monotonic() > deadline:
                raise WatchError("a served file took too long")
            chunks.append(chunk)
        return Reply(status, headers, b"".join(chunks))

    def get(self, path: str, *, limit: int = MAX_INDEX_BYTES) -> Reply:
        reply = self.request(path, limit=limit)
        if reply.status != 200:
            raise WatchError(f"{path} answered {reply.status}")
        return reply


def _environment() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603
            list(argv),
            capture_output=True,
            text=True,
            timeout=TOOL_SECONDS,
            check=False,
            env=_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WatchError(f"{argv[0]} could not run ({type(error).__name__})") from None


def read_pin(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise WatchError("the pin file cannot be read") from None
    if not FINGERPRINT.fullmatch(text):
        raise WatchError("the pin file does not hold a primary key fingerprint")
    return text


def declared_products(path: Path) -> frozenset[str]:
    """The repositories the product list declares: the only ones a package may come from."""
    try:
        return frozenset(item.repo for item in load_products(path).products)
    except (ConfigError, OSError):
        raise WatchError("the product list cannot be read") from None


def primary_fingerprints(key: Path, home: Path) -> set[str]:
    """The fingerprints of every primary key in a keyring file."""
    home.mkdir(mode=0o700, exist_ok=True)
    done = _run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--no-tty",
            "--with-colons",
            "--fixed-list-mode",
            "--show-keys",
            str(key),
        ]
    )
    if done.returncode != 0:
        raise WatchError("gpg cannot read the served keyring")
    found: set[str] = set()
    primary = False
    for line in done.stdout.splitlines():
        record = line.split(":")
        if record[0] == "pub":
            primary = True
        elif record[0] == "fpr" and primary and len(record) > 9:
            found.add(record[9].upper())
            primary = False
        elif record[0] in ("sub", "sec", "ssb"):
            primary = False
    return found


class _Capped(io.RawIOBase):
    """A pipe read that stops, with an error, after a fixed number of bytes."""

    def __init__(self, source: IO[bytes], limit: int) -> None:
        self._source = source
        self._left = limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._source.read(min(len(buffer), self._left + 1))
        if len(data) > self._left:
            raise WatchError("the served keyring package is larger than the allowed size")
        self._left -= len(data)
        buffer[: len(data)] = data
        return len(data)


def keyring_file(package: Path) -> bytes:
    """The key file inside a deb, read from its file system archive without unpacking to disk."""
    try:
        process = subprocess.Popen(  # noqa: S603
            ["dpkg-deb", "--fsys-tarfile", str(package)],  # noqa: S607
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_environment(),
        )
    except OSError as error:
        raise WatchError(f"dpkg-deb could not run ({type(error).__name__})") from None
    pipe = process.stdout
    try:
        if pipe is None:
            raise WatchError("dpkg-deb gave no output")
        stream = io.BufferedReader(_Capped(pipe, MAX_TAR_BYTES))
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                if member.name.removeprefix("./") != KEY_MEMBER:
                    continue
                handle = archive.extractfile(member) if member.isreg() else None
                if handle is None or member.size > MAX_KEY_BYTES:
                    break
                return handle.read(MAX_KEY_BYTES)
    except tarfile.TarError:
        raise WatchError("the served keyring package cannot be read") from None
    finally:
        process.kill()
        process.wait()
        if pipe is not None:
            pipe.close()
    raise WatchError("the served keyring package does not hold the key file")


def served_key(site: Site, pin: str, work: Path) -> Path:
    """The key file of the served keyring package, once its primary key is the pinned one."""
    package = work / "keyring.deb"
    package.write_bytes(site.get(KEYRING_PATH, limit=MAX_PACKAGE_BYTES).body)
    key = work / "key.gpg"
    key.write_bytes(keyring_file(package))
    if primary_fingerprints(key, work / "gnupg") != {pin}:
        raise WatchError("the primary key of the served keyring is not the pinned one")
    return key


def verify(key: Path, pin: str, name: str, *files: Path) -> int:
    """gpgv must accept one signature made by the pinned primary key; return its time (epoch)."""
    done = _run(["gpgv", "--status-fd", "1", "--keyring", str(key), *map(str, files)])
    signed: list[tuple[str, int]] = []
    bad = False
    for line in done.stdout.splitlines():
        words = line.split()
        if len(words) < 2 or words[0] != "[GNUPG:]":
            continue
        if words[1] == "VALIDSIG" and len(words) >= 12 and words[4].isdigit():
            signed.append((words[11].upper(), int(words[4])))
        elif words[1] in STATUS_BAD:
            bad = True
    if done.returncode != 0 or bad or len(signed) != 1 or signed[0][0] != pin:
        raise WatchError(f"{name} does not verify against the pinned key")
    return signed[0][1]


def release_alerts(
    site: Site, key: Path, pin: str, work: Path, now: float
) -> tuple[list[str], bytes]:
    """The failures of the verified `InRelease`, and its bytes."""
    body = site.get(RELEASE_PATH, limit=MAX_PACKAGE_BYTES * 8).body
    file = work / "InRelease"
    file.write_bytes(body)
    verify(key, pin, "InRelease", file)
    issued, until = release_dates(body)
    failures = []
    age = (now - issued) / DAY
    if age < -FUTURE_SLACK_SECONDS / DAY:
        failures.append("the served InRelease Date is in the future")
    elif age > DATE_MAX_AGE_DAYS:
        failures.append(f"the served InRelease Date is {age:.1f} days old")
    left = (until - now) / DAY
    if left < VALID_UNTIL_MIN_DAYS:
        failures.append(f"the served InRelease Valid-Until is {max(left, 0):.1f} days away")
    return failures, body


def trees() -> list[str]:
    return [f"rpm/{php}/{arch}" for php in PHP_VERSIONS for arch in RPM_ARCHITECTURES]


def signature_alerts(
    site: Site, key: Path, pin: str, work: Path, now: float
) -> tuple[list[str], dict[str, bytes]]:
    """The failures of the six signature files, and the verified `repomd.xml` of each tree."""
    failures = []
    verified: dict[str, bytes] = {}
    for tree in trees():
        name = f"{tree}/repodata/repomd.xml.asc"
        try:
            signed = site.get(name, limit=MAX_PACKAGE_BYTES)
            data = site.get(f"{tree}/repodata/repomd.xml", limit=MAX_PACKAGE_BYTES * 8)
            stem = work / tree.replace("/", "_")
            stem.with_suffix(".asc").write_bytes(signed.body)
            stem.with_suffix(".xml").write_bytes(data.body)
            made = verify(key, pin, name, stem.with_suffix(".asc"), stem.with_suffix(".xml"))
            verified[tree] = data.body
            failures.extend(_signature_age(name, float(made), now))
            failures.extend(_age(name, signed.headers.get("last-modified"), now))
        except CRASHES as error:
            failures.append(_text(error))
    return failures, verified


def _signature_age(name: str, made: float, now: float) -> list[str]:
    """The age by the signature's own time, which a replayed old file cannot fake."""
    age = (now - made) / DAY
    if age < -FUTURE_SLACK_SECONDS / DAY:
        return [f"{name} was signed in the future"]
    if age > SIGNATURE_MAX_AGE_DAYS:
        return [f"{name} was signed {age:.1f} days ago"]
    return []


def _age(name: str, stamp: str | None, now: float) -> list[str]:
    if stamp is None:
        return [f"{name} has no Last-Modified"]
    try:
        parsed = email.utils.parsedate_to_datetime(stamp)
    except (TypeError, ValueError):
        return [f"{name} has an unreadable Last-Modified"]
    if parsed.tzinfo is None:
        return [f"{name} has a Last-Modified with no time zone"]
    age = (now - parsed.timestamp()) / DAY
    if age < -FUTURE_SLACK_SECONDS / DAY:
        return [f"{name} Last-Modified is in the future"]
    if age > SIGNATURE_MAX_AGE_DAYS:
        return [f"{name} is {age:.1f} days old"]
    return []


def _text(error: Exception) -> str:
    return (
        str(error) if isinstance(error, WatchError) else f"a check failed ({type(error).__name__})"
    )


def _inflate(data: bytes) -> bytes:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        text = inflater.decompress(data, MAX_INFLATED_BYTES)
    except zlib.error:
        raise WatchError("a served index is not valid gzip") from None
    if inflater.unconsumed_tail:
        raise WatchError("a served index is larger than the allowed size")
    if not inflater.eof or inflater.unused_data:
        raise WatchError("a served index is cut short or has data after the end")
    return text


def _xml(data: bytes) -> ET.Element:
    """Parse an index that has no document type or entity declaration."""
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise WatchError("a served index declares a document type")
    return ET.fromstring(data)  # noqa: S314


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in parent if _local(item.tag) == name), None)


def _signed_sha256(release: bytes, name: str) -> tuple[str, int]:
    """The SHA256 and size a verified `InRelease` lists for `name`."""
    inside = False
    signed = release.split(b"-----BEGIN PGP SIGNATURE-----", 1)[0]
    for line in signed.decode("utf-8", errors="replace").splitlines():
        if line.startswith("SHA256:"):
            inside = True
        elif inside and not line.startswith(" "):
            break
        elif inside:
            found = SHA256_LINE.match(line)
            if found is not None and found[3] == name:
                return found[1], int(found[2])
    raise WatchError(f"the signed InRelease does not list {name}")


def _redirect(
    site: Site, path: str, parts: Sequence[str], products: frozenset[str], github: str
) -> None:
    """The site must answer a client's GET for the package with 302 to the exact release asset."""
    product, tag, name = parts
    if (
        product not in products
        or not REPO_NAME.fullmatch(product)
        or not RELEASE_TAG.fullmatch(tag)
        or not ASSET_NAME.fullmatch(name)
    ):
        raise WatchError("the first listed package is not one of a declared product")
    reply = site.request(path, limit=MAX_REDIRECT_BODY_BYTES)
    expected = download_url(product, tag, name).replace("https://github.com/", github, 1)
    if reply.status != 302 or reply.headers.get("location") != expected:
        raise WatchError(f"{path} does not redirect to the GitHub release asset")


def apt_redirect(site: Site, release: bytes, products: frozenset[str], github: str) -> None:
    listing = site.get(f"apt/dists/stable/{PACKAGES_NAME}").body
    digest, size = _signed_sha256(release, PACKAGES_NAME)
    if hashlib.sha256(listing).hexdigest() != digest or len(listing) != size:
        raise WatchError("the apt package index does not match the signed InRelease")
    found = FILENAME.search(listing.decode("utf-8", errors="replace"))
    if found is None:
        raise WatchError("the apt index lists no package")
    _redirect(site, f"apt/pool/{'/'.join(found.groups())}", found.groups(), products, github)


def _primary(repomd: bytes) -> tuple[str, str, int]:
    """The location, sha256 and size of the primary index a verified `repomd.xml` lists."""
    for data in _xml(repomd):
        if _local(data.tag) != "data" or data.get("type") != "primary":
            continue
        place, check, size = (_child(data, n) for n in ("location", "checksum", "size"))
        if place is None or check is None or size is None or check.get("type") != "sha256":
            break
        href = place.get("href") or ""
        digest = (check.text or "").strip()
        if (
            re.fullmatch(r"repodata/[^/]+", href)
            and SHA256_HEX.fullmatch(digest)
            and (size.text or "").strip().isdigit()
        ):
            return href, digest, int((size.text or "").strip())
    raise WatchError("a signed repomd.xml lists no usable primary index")


def _first_location(primary: bytes) -> str | None:
    """The `href` of the first package in a primary index, or None when it lists none."""
    for _, item in ET.iterparse(io.BytesIO(primary), events=("end",)):  # noqa: S314
        if _local(item.tag) == "location":
            return item.get("href") or ""
    return None


def rpm_redirect(
    site: Site, verified: dict[str, bytes], products: frozenset[str], github: str
) -> None:
    for tree in trees():
        if tree not in verified:
            continue
        href, digest, size = _primary(verified[tree])
        packed = site.get(f"{tree}/{href}").body
        if hashlib.sha256(packed).hexdigest() != digest or len(packed) != size:
            raise WatchError(f"{tree} primary index does not match the signed repomd.xml")
        location = _first_location(_inflate(packed))
        if location is None:
            continue
        try:
            path = urlsplit(urljoin(f"https://host/{tree}/", location)).path
        except ValueError:
            raise WatchError(f"{tree} lists an unreadable package location") from None
        parts = POOL_PATH.fullmatch(path)
        if parts is None:
            raise WatchError(f"{tree} lists a package outside /pool/")
        _redirect(site, path.removeprefix("/"), parts.groups(), products, github)
        return
    # a tree that did not verify is already reported, so say nothing more about it
    if len(verified) == len(trees()):
        raise WatchError("no rpm tree lists a package")


def check(
    site: Site,
    pin: str,
    now: float,
    *,
    products: frozenset[str],
    github: str = "https://github.com/",
) -> list[str]:
    """Every failure of one pass; the signature checks need a key that matches the pin."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        try:
            key = served_key(site, pin, work)
        except CRASHES as error:
            return [_text(error)]
        release = b""
        verified: dict[str, bytes] = {}

        def release_step() -> list[str]:
            nonlocal release
            problems, release = release_alerts(site, key, pin, work, now)
            return problems

        def signature_step() -> list[str]:
            nonlocal verified
            problems, verified = signature_alerts(site, key, pin, work, now)
            return problems

        def apt_step() -> list[str]:
            # without a verified InRelease the failure is already reported above
            if release:
                apt_redirect(site, release, products, github)
            return []

        def rpm_step() -> list[str]:
            rpm_redirect(site, verified, products, github)
            return []

        steps: list[Callable[[], list[str]]] = [release_step, signature_step, apt_step, rpm_step]
        for step in steps:
            try:
                failures.extend(step())
            except CRASHES as error:
                failures.append(_text(error))
    return failures


def notify(failures: Sequence[str]) -> None:
    """Send the failures to the chat when the two environment variables are set."""
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not chat and not token:
        print("no chat credentials are set; the failed run itself is the notice", file=sys.stderr)
        return
    if not alert.CHAT_ID.fullmatch(chat) or not alert.BOT_TOKEN.fullmatch(token):
        print("the chat credentials have the wrong shape", file=sys.stderr)
        return
    text = "platform watch failed:\n" + "\n".join(alert.clean(item) for item in failures)
    try:
        alert.Telegram(alert.Credentials(chat_id=int(chat), token=token)).send(text, silent=False)
    except alert.AlertError as error:
        print(f"the chat message was not delivered: {alert.clean(str(error))}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="platform_watch.py")
    parser.add_argument("--site", required=True, help="the public https address, no trailing slash")
    parser.add_argument("--pin-file", type=Path, required=True)
    parser.add_argument("--products", type=Path, required=True, help="the products.yml")
    parser.add_argument("--notify", action="store_true", help="send a failure to the chat")
    arguments = parser.parse_args(argv)
    try:
        failures = check(
            Site(arguments.site),
            read_pin(arguments.pin_file),
            time.time(),
            products=declared_products(arguments.products),
        )
    except Exception as error:
        failures = [_text(error)]
    for item in failures:
        print(f"FAIL: {alert.clean(item)}")
    if failures:
        if arguments.notify:
            notify(failures)
        return 1
    print("PLATFORM WATCH PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
