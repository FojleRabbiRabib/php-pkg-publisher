# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Sign the finished metadata tree with exactly one signing subkey, then check every signature.

Outputs: `dists/stable/InRelease` (clearsigned `Release`), `dists/stable/Release.gpg` (detached)
and `rpm/<php>/<basearch>/repodata/repomd.xml.asc` (detached) for every rpm tree. Each file carries
exactly one signature: a detached `repomd.xml.asc` with two signatures is rejected by EL10 and
Fedora 44, so a key rotation switches the configured subkey, it never signs with two.

Every signature is verified against the pinned public certificate that clients receive (the
keyring package), never against a key exported from the signing home, so a VPS key that differs
from the shipped keyring fails here and not on every client. The check requires one good
signature, made by the configured subkey of the pinned primary key, with SHA-256, close to the
clock, and `InRelease` must carry exactly the text of `Release`.

The signing home holds the signing subkeys only: a home that holds the primary secret key is
refused (the master key stays offline). The subkey must not expire before the `Valid-Until` of
the `Release` being signed, because `gpgv` clients reject a signature once its subkey expired.
The subkey has no passphrase; if gpg would ask for one, signing fails.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from publisher import config, files, metadata, net
from publisher.metadata import Built
from publisher.tools import Result, ToolError, Tools, run

GPG_TIMEOUT_SECONDS: Final = 60.0
MAX_HOME_BYTES: Final = 80  # a Unix socket path holds 107 bytes; the longest name adds 20
DIGEST_ALGORITHM: Final = "SHA256"
DIGEST_NUMBER: Final = "8"
MAX_SIGNATURE_BYTES: Final = 64 * 1024
MAX_CLEAR_BYTES: Final = 16 * 1024 * 1024  # a Release, an InRelease or a repomd.xml
BAD_STATUS: Final = frozenset(
    {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "FAILURE", "NODATA"}
)
STUB: Final = "#"  # field 15 of a gpg colon listing: the secret key is not in this home
UNUSABLE_VALIDITY: Final = frozenset({"e", "r", "d", "i"})
DETACHED_HEADER: Final = "-----BEGIN PGP SIGNATURE-----"
CLEARSIGN_HEADER: Final = "-----BEGIN PGP SIGNED MESSAGE-----"
INRELEASE: Final = "InRelease"
RELEASE_SIGNATURE: Final = "Release.gpg"
REPOMD_SIGNATURE: Final = "repomd.xml.asc"


class SigningError(Exception):
    """The key is unusable, a signature failed its check, or the tree cannot be signed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SigningKey:
    """The signing subkey and the pins it is checked against."""

    home: Path
    fingerprint: str
    certificate: Path
    primary: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Signed:
    signatures: int
    subkey_expires: float | None


@dataclass(frozen=True, slots=True)
class _Packet:
    kind: str
    validity: str
    expires: str
    capabilities: str
    token: str
    fingerprint: str = ""


def _gpg(
    home: Path, args: Sequence[str | Path], *, tools: Tools, scratch: Path, what: str
) -> Result:
    command: list[str | Path] = [
        tools.gpg,
        "--homedir",
        home,
        "--batch",
        "--no-tty",
        "--no-options",
        *args,
    ]
    return _checked(run(command, home=scratch, timeout=GPG_TIMEOUT_SECONDS), what)


def _checked(result: Result, what: str) -> Result:
    if result.code != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SigningError(f"{what} failed: {net.safe(detail)}")
    return result


def _packets(listing: str) -> list[_Packet]:
    packets: list[_Packet] = []
    for line in listing.splitlines():
        fields = line.split(":") + [""] * 15
        if fields[0] in ("pub", "sub", "sec", "ssb"):
            packets.append(
                _Packet(
                    kind=fields[0],
                    validity=fields[1],
                    expires=fields[6],
                    capabilities=fields[11],
                    token=fields[14],
                )
            )
        elif fields[0] == "fpr" and packets and not packets[-1].fingerprint:
            last = packets[-1]
            packets[-1] = _Packet(
                last.kind, last.validity, last.expires, last.capabilities, last.token, fields[9]
            )
    return packets


def _validate_key(key: SigningKey) -> None:
    if not config.FINGERPRINT.fullmatch(key.fingerprint) or not config.FINGERPRINT.fullmatch(
        key.primary
    ):
        raise SigningError("the key fingerprints must be 40 upper-case hex characters")
    if key.fingerprint == key.primary:
        raise SigningError("the signing key must be a subkey, not the primary key")
    try:
        files.require_private_directory(key.home)
    except files.FileError as error:
        raise SigningError(str(error)) from error
    if len(os.fsencode(key.home)) > MAX_HOME_BYTES:
        raise SigningError(f"{key.home}: too long; gpg-agent's socket path would not fit")
    if not key.certificate.is_file() or key.certificate.is_symlink():
        raise SigningError(f"{key.certificate}: the pinned certificate must be a regular file")


def _check_certificate(
    key: SigningKey, verify_home: Path, *, tools: Tools, scratch: Path
) -> float | None:
    """Import the pinned certificate; return when the configured subkey expires (None: never)."""
    _gpg(
        verify_home,
        ["--import", key.certificate],
        tools=tools,
        scratch=scratch,
        what="importing the pinned certificate",
    )
    listing = _gpg(
        verify_home,
        ["--list-keys", "--with-colons", "--fixed-list-mode"],
        tools=tools,
        scratch=scratch,
        what="listing the pinned certificate",
    ).stdout
    packets = _packets(listing)
    primaries = [p for p in packets if p.kind == "pub"]
    if len(primaries) != 1 or primaries[0].fingerprint != key.primary:
        raise SigningError("the pinned certificate is not the one primary key that is pinned")
    if primaries[0].validity in UNUSABLE_VALIDITY:
        raise SigningError("the pinned primary key is expired or revoked")
    subkeys = [p for p in packets if p.kind == "sub" and p.fingerprint == key.fingerprint]
    if len(subkeys) != 1:
        raise SigningError("the signing subkey is not in the pinned certificate")
    subkey = subkeys[0]
    if subkey.validity in UNUSABLE_VALIDITY or "s" not in subkey.capabilities:
        raise SigningError("the signing subkey is expired, revoked or cannot sign")
    # A client rejects the signature once the primary key expires, too: the earlier date counts.
    dates = [float(p.expires) for p in (primaries[0], subkey) if p.expires]
    return min(dates) if dates else None


def _check_secret(key: SigningKey, *, tools: Tools, scratch: Path) -> None:
    """The home must hold the signing subkey's secret and no primary secret."""
    listing = _gpg(
        key.home,
        ["--list-secret-keys", "--with-colons", "--fixed-list-mode"],
        tools=tools,
        scratch=scratch,
        what="listing the signing keys",
    ).stdout
    packets = _packets(listing)
    primaries = [p for p in packets if p.kind == "sec"]
    if len(primaries) != 1 or primaries[0].fingerprint != key.primary:
        raise SigningError("the signing home must hold exactly the pinned primary key")
    if primaries[0].token != STUB:
        raise SigningError("the signing home holds the primary secret key; it must stay offline")
    subkeys = [p for p in packets if p.kind == "ssb" and p.fingerprint == key.fingerprint]
    if len(subkeys) != 1 or subkeys[0].token == STUB:
        raise SigningError("the signing home does not hold the secret of the signing subkey")


def _release_valid_until(release: Path) -> float:
    try:
        text = release.read_text(encoding="utf-8")
        fields, _ = metadata.parse_release(text)
        until = datetime.strptime(fields["Valid-Until"], metadata.RELEASE_DATE_FORMAT)
    except (OSError, UnicodeDecodeError, KeyError, ValueError, metadata.MetadataError) as error:
        raise SigningError(f"{release}: Release cannot be read for signing: {error}") from error
    return until.replace(tzinfo=timezone.utc).timestamp()


def _status(result: Result) -> list[list[str]]:
    lines = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    return [line[1:] for line in lines]


def _check_status(key: SigningKey, status: list[list[str]], name: str) -> None:
    tags = [line[0] for line in status]
    valid = [line for line in status if line[0] == "VALIDSIG"]
    if any(tag in BAD_STATUS for tag in tags) or tags.count("NEWSIG") != 1 or len(valid) != 1:
        raise SigningError(f"{name}: does not carry exactly one good signature")
    fields = valid[0][1:]
    if len(fields) < 10 or fields[0] != key.fingerprint or fields[9] != key.primary:
        raise SigningError(f"{name}: was not made by the configured subkey of the pinned key")
    if fields[7] != DIGEST_NUMBER:
        raise SigningError(f"{name}: was not signed with {DIGEST_ALGORITHM}")
    try:
        made = int(fields[2])
    except ValueError as error:
        raise SigningError(f"{name}: has an unreadable signature time") from error
    if abs(time.time() - made) > metadata.MAX_CLOCK_SKEW_SECONDS:
        raise SigningError(f"{name}: signature time is not near the clock")


def _check_armor(text: str, header: str, name: str) -> None:
    if (
        not text.startswith(header)
        or text.count(DETACHED_HEADER) != 1
        or text.count("-----BEGIN PGP") != (2 if header == CLEARSIGN_HEADER else 1)
    ):
        raise SigningError(f"{name}: is not exactly one armored signature")


def _sign_detached(
    key: SigningKey, source: Path, name: str, staging: Path, verify_home: Path, tools: Tools
) -> bytes:
    output = staging / f"{_flat(name)}.out"
    _gpg(
        key.home,
        [*_signing_options(key), "--detach-sign", "--armor", "--output", output, source],
        tools=tools,
        scratch=staging,
        what=f"signing {name}",
    )
    signature = _read(output, name, MAX_SIGNATURE_BYTES)
    _check_armor(signature.decode("utf-8", errors="replace"), DETACHED_HEADER, name)
    verified = _gpg(
        verify_home,
        [*_verify_options(), "--verify", output, source],
        tools=tools,
        scratch=staging,
        what=f"verifying {name}",
    )
    _check_status(key, _status(verified), name)
    return signature


def _sign_clear(
    key: SigningKey, source: Path, name: str, staging: Path, verify_home: Path, tools: Tools
) -> bytes:
    output = staging / f"{_flat(name)}.out"
    _gpg(
        key.home,
        [*_signing_options(key), "--clearsign", "--armor", "--output", output, source],
        tools=tools,
        scratch=staging,
        what=f"signing {name}",
    )
    signed = _read(output, name, MAX_CLEAR_BYTES)
    _check_armor(signed.decode("utf-8", errors="replace"), CLEARSIGN_HEADER, name)
    content = staging / f"{_flat(name)}.content"
    verified = _gpg(
        verify_home,
        [*_verify_options(), "--output", content, "--decrypt", output],
        tools=tools,
        scratch=staging,
        what=f"verifying {name}",
    )
    _check_status(key, _status(verified), name)
    if _read(content, name, MAX_CLEAR_BYTES) != source.read_bytes():
        raise SigningError(f"{name}: does not carry exactly the text of Release")
    return signed


def _flat(name: str) -> str:
    return name.replace("/", "_")


def _signing_options(key: SigningKey) -> list[str]:
    return [
        "--pinentry-mode",
        "error",
        "--no-emit-version",
        "--digest-algo",
        DIGEST_ALGORITHM,
        "--local-user",
        f"{key.fingerprint}!",
    ]


def _verify_options() -> list[str]:
    return ["--status-fd", "1", "--trust-model", "always"]


def _read(path: Path, name: str, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as error:
        raise SigningError(f"{name}: cannot be read: {error.strerror or error}") from error
    if not data or len(data) > limit:
        raise SigningError(f"{name}: is empty or larger than allowed")
    return data


def _stop_agents(homes: Sequence[Path], tools: Tools, scratch: Path) -> bool:
    """Stop the gpg-agent that gpg starts for each home; False when one could not be stopped."""
    stopped = True
    for home in homes:
        try:
            result = run(
                [tools.gpgconf, "--kill", "gpg-agent"],
                home=scratch,
                timeout=GPG_TIMEOUT_SECONDS,
                env={"GNUPGHOME": str(home)},
            )
        except ToolError:
            stopped = False
        else:
            stopped = stopped and result.code == 0
    return stopped


@contextlib.contextmanager
def _agents(homes: Sequence[Path], tools: Tools, scratch: Path) -> Iterator[None]:
    """Stop the agents on the way out; a failure to stop one fails the run, unless another error
    is already on its way, which then wins."""
    try:
        yield
    except BaseException:
        _stop_agents(homes, tools, scratch)
        raise
    if not _stop_agents(homes, tools, scratch):
        raise SigningError("cannot stop gpg-agent; it would keep running after the run")


def sign(tree: Path, built: Built, key: SigningKey, *, tools: Tools, work: Path) -> Signed:
    """Sign the metadata in `tree` and verify every signature before any file is written.

    The signatures are written only after all of them passed, so a failed check leaves the tree
    exactly as it was. A fault while writing leaves a partial tree, which the caller discards.
    """
    if not tree.is_absolute():
        raise SigningError(f"{tree}: must be an absolute path")
    _validate_key(key)
    try:
        files.require_private_directory(work)
    except files.FileError as error:
        raise SigningError(str(error)) from error
    dists = tree / "dists" / metadata.SUITE
    targets: list[tuple[str, Path, Path]] = [
        (INRELEASE, dists / "Release", dists / INRELEASE),
        (RELEASE_SIGNATURE, dists / "Release", dists / RELEASE_SIGNATURE),
    ]
    for rpm_tree in built.rpm_trees:
        repodata = tree / rpm_tree / "repodata"
        targets.append(
            (f"{rpm_tree}/{REPOMD_SIGNATURE}", repodata / "repomd.xml", repodata / REPOMD_SIGNATURE)
        )
    for _, source, output in targets:
        if not source.is_file() or source.is_symlink():
            raise SigningError(f"{source}: there is nothing to sign")
        if output.exists() or output.is_symlink():
            raise SigningError(f"{output}: already exists")
    valid_until = _release_valid_until(dists / "Release")
    staging = Path(tempfile.mkdtemp(prefix="signing-", dir=work))
    # A short path: gpg-agent's socket lives inside the home and a socket path is limited.
    verify_home = Path(tempfile.mkdtemp(prefix="pkgv-"))
    try:
        if len(os.fsencode(verify_home)) > MAX_HOME_BYTES:
            raise SigningError(f"{verify_home}: too long; set TMPDIR to a shorter directory")
        with _agents([key.home, verify_home], tools, staging):
            expires = _check_certificate(key, verify_home, tools=tools, scratch=staging)
            if expires is not None and expires <= valid_until:
                raise SigningError(
                    "the signing subkey or its primary key expires before the Release stops "
                    "being valid"
                )
            _check_secret(key, tools=tools, scratch=staging)
            signatures: list[tuple[Path, bytes]] = []
            snapshots: list[tuple[Path, bytes]] = []
            for name, source, output in targets:
                # Sign a private copy, so what is signed and what is checked are the same bytes.
                text = _read(source, name, MAX_CLEAR_BYTES)
                snapshots.append((source, text))
                copy = staging / f"{_flat(name)}.src"
                copy.write_bytes(text)
                sign_one = _sign_clear if name == INRELEASE else _sign_detached
                signatures.append((output, sign_one(key, copy, name, staging, verify_home, tools)))
            for source, text in snapshots:
                if _read(source, str(source), MAX_CLEAR_BYTES) != text:
                    raise SigningError(f"{source}: changed while it was signed")
        try:
            for output, data in signatures:
                files.write_atomic(output, data, mode=metadata.PUBLISHED_MODE)
        except OSError as error:
            raise SigningError(f"cannot write the signatures: {error.strerror or error}") from error
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(verify_home, ignore_errors=True)
    return Signed(signatures=len(targets), subkey_expires=expires)
