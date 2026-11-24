# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`docs/security.md` against the code it describes: the cosign pins, the validity period and the
rpm check, so a change in the code that the notes do not follow fails here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pkg_deploy

from publisher import metadata, verify

DOC: Final = Path(__file__).resolve().parents[2] / "docs" / "security.md"
TEXT: Final = DOC.read_text(encoding="utf-8")


def test_the_cosign_command_in_the_notes_has_the_pins_the_publisher_uses() -> None:
    (command,) = re.findall(r"```sh\n(cosign verify-blob.*?)\n```", TEXT, re.DOTALL)
    assert f"--certificate-oidc-issuer {verify.OIDC_ISSUER}" in command
    assert f"/{verify.WORKFLOW_PATH}@refs/tags/<tag>" in command
    for flag in ("--bundle", "--trusted-root", "--certificate-identity"):
        assert flag in command
    assert "--insecure-ignore-tlog" not in TEXT


def test_the_validity_period_in_the_notes_is_the_one_the_metadata_uses() -> None:
    days = metadata.VALID_SECONDS // (24 * 3600)
    assert days == 14
    assert f"{days} days after it is signed" in TEXT


def test_the_notes_say_what_the_rpm_check_requires() -> None:
    assert "digests signatures OK" in TEXT
    assert "exits 0 for an unsigned rpm" in TEXT


def test_the_deploy_notes_name_the_refusals_the_script_has() -> None:
    (section,) = re.findall(r"## The deploy channel\n(.*?)\n## ", TEXT, re.DOTALL)
    for code in ("signature-invalid", "tag-invalid", "version-older", "version-denied"):
        assert f"`{code}`" in section, code
        assert code in pkg_deploy.CODES, code
    assert "rotate it, change `allowed_signers`" in " ".join(section.split())


def test_the_notes_carry_no_fingerprint_and_no_host_detail() -> None:
    assert not re.search(r"\b[0-9A-F]{40}\b", TEXT)
    assert not re.search(r"\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b", TEXT)
