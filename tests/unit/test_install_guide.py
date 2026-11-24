# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The install guide against the code: the files it tells a person to write are the files
`setup.sh` writes, and its placeholders are the only ones it uses. The commands themselves are
run on real clients by `tests/container/test_docs.py`.
"""

from __future__ import annotations

import re

import yaml
from docblocks import GUIDE, SITE, blocks
from refusals import APT_DEFAULT, DNF_PREFIX, REFUSALS, SQV_TAIL
from setupkit import repo, sources


def _block(family: str, *, containing: str) -> str:
    (found,) = [b.text for b in blocks() if b.family == family and containing in b.text]
    return found


def test_the_apt_sources_file_in_the_guide_is_the_one_setup_sh_writes() -> None:
    block = _block("apt", containing="Types: deb")
    written = block.split("<<'EOF'\n")[1].split("EOF\n")[0]
    assert written == sources(SITE)


def test_the_dnf_repository_file_in_the_guide_is_the_one_setup_sh_writes() -> None:
    block = _block("dnf", containing="[rabib-php83]")
    written = block.split("<<'EOF'\n")[1].split("\nEOF")[0] + "\n"
    assert written == repo(SITE, {"8.3"})


def test_the_guide_has_both_flows_and_removes_what_it_installs() -> None:
    found = blocks()
    for family in ("apt", "dnf"):
        assert any(b.family == family and not b.remove for b in found)
        assert any(b.family == family and b.remove for b in found)


def test_the_guide_quotes_what_each_client_reports_after_a_key_rotation() -> None:
    text = " ".join(GUIDE.read_text(encoding="utf-8").split())
    assert f"`{APT_DEFAULT}`" in text
    assert DNF_PREFIX.strip() in text
    for refusal in REFUSALS.values():
        assert refusal.removeprefix(DNF_PREFIX) in text, refusal
    # which distributions the key drill measured each text on
    assert set(REFUSALS) == {
        "debian-trixie",
        "almalinux-8",
        "almalinux-9",
        "almalinux-10",
        "fedora-44",
    }
    assert f'"{SQV_TAIL}"' in text
    assert "Debian 13: `Missing key`" in text
    assert "`Bad GPG signature` on Enterprise Linux 8 and 9" in text
    assert "`Signing key not found` on Enterprise Linux 10 and Fedora" in text


def _guide_text() -> str:
    return " ".join(GUIDE.read_text(encoding="utf-8").split())


def test_the_guide_describes_the_setup_script_as_it_behaves() -> None:
    script = (GUIDE.parents[1] / "setup.sh").read_text(encoding="utf-8")
    text = _guide_text()
    assert "--fingerprint" in script
    assert "sh setup.sh --fingerprint <fingerprint published with the key ceremony>" in text
    assert "stops, before the keyring package is installed, imported or written" in text
    assert "a missing gpg is installed from your distribution first" in text
    assert "the keyring package stays installed" in text
    assert "takes out the key it imported" in text
    # the script turns on the section of an installed PHP and never turns one off
    assert "turns on the section of each PHP version it finds installed" in text
    assert "never turns one off" in text
    assert "dnf 5's `dnf config-manager setopt`" in text
    assert "With dnf 4, turn the section off again after a re-run." in text


def test_the_guide_claims_the_architectures_the_ci_container_jobs_run_natively() -> None:
    """The guide says arm64 and aarch64 are tested only while a native arm runner runs them."""
    text = " ".join(_guide_text().split())
    workflow = yaml.safe_load((GUIDE.parents[1] / ".github/workflows/ci.yml").read_text("utf-8"))
    matrix = workflow["jobs"]["container-image"]["strategy"]["matrix"]
    assert workflow["jobs"]["container-image"]["runs-on"] == "${{ matrix.runner }}"
    assert matrix["runner"] == ["ubuntu-24.04", "ubuntu-24.04-arm"]
    # every distribution image runs on both runners; only the image-less "rest" stays on amd64
    assert matrix["exclude"] == [{"image": "rest", "runner": "ubuntu-24.04-arm"}]
    # the arm64 runner runs the client tests only, never the deploy host test, and never emulates
    steps = workflow["jobs"]["container-image"]["steps"]
    (script,) = [s["run"] for s in steps if s.get("name") == "Container tests"]
    assert 'elif [ "$RUNNER_ARCH" = ARM64 ]' in script
    assert (
        "--ignore=tests/container/test_deploy_host.py" in script.split("elif")[1].split("else")[0]
    )
    assert "CONTAINER_ARCH" not in (GUIDE.parents[1] / ".github/workflows/ci.yml").read_text(
        "utf-8"
    )
    assert "each on `amd64` and `arm64` (apt) or on `x86_64` and `aarch64` (dnf)" in text
    assert "tested on their own hardware, not under emulation" in text
    assert "nothing tests them yet" not in text


def test_the_dnf_removal_block_takes_the_imported_key_out_of_rpm() -> None:
    (block,) = [b.text for b in blocks() if b.family == "dnf" and b.remove]
    assert "rpm -e" in block and "gpg-pubkey" in block
    # the fingerprint is read before the package that holds the key file is removed
    assert block.index("--show-keys") < block.index("dnf remove")


def test_the_guide_uses_one_placeholder_for_the_extension_and_one_for_the_fingerprint() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    assert set(re.findall(r"<[a-z][a-z -]*>", text)) <= {
        "<extension>",
        "<fingerprint published with the key ceremony>",
    }
    assert not re.search(r"\b[0-9A-F]{40}\b", text), "a real fingerprint must not be in the guide"
