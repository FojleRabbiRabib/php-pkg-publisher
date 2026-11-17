# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""What a client that did not upgrade its keyring reports after a signing subkey rotation.

Measured by the key drill (`test_key_drill.py`) on every tested distribution; the install guide
and the security notes quote these texts, and `test_install_guide.py` checks that they do.
"""

from __future__ import annotations

from typing import Final

APT_DEFAULT: Final = "NO_PUBKEY"
DNF_PREFIX: Final = "repomd.xml GPG signature verification error: "
# After a refused refresh dnf 5 (Fedora) drops the repository's data and offers nothing; dnf 4
# keeps its cached metadata, so the version that was offered before is still offered.
DROPS_THE_DATA: Final = frozenset({"fedora-44"})
SQV_TAIL: Final = "which is needed to verify signature"
# the exceptions: apt on Debian 13 checks signatures with `sqv`; dnf on EL8 and EL9 reports the
# signature bad against the key file it has, EL10 and Fedora report that the signing key is not
# found, because they keep the first repository key they imported
REFUSALS: Final = {
    "debian-trixie": "Missing key",
    "almalinux-8": DNF_PREFIX + "Bad GPG signature",
    "almalinux-9": DNF_PREFIX + "Bad GPG signature",
    "almalinux-10": DNF_PREFIX + "Signing key not found",
    "fedora-44": DNF_PREFIX + "Signing key not found",
}
