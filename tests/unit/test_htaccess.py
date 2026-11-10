# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The docroot .htaccess: its patterns are exercised as regular expressions and held to the
publisher's own name rules, so the redirect and the metadata cannot drift apart."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from publisher import admit, config, feed, metadata

FILE = Path(__file__).resolve().parents[2] / "web" / "docroot.htaccess"
OWNER = "https://github.com/FojleRabbiRabib/"


@dataclass(frozen=True)
class Rule:
    pattern: str
    target: str
    flags: str


def _lines() -> list[str]:
    return [
        line.strip()
        for line in FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _rules() -> list[Rule]:
    found = []
    for line in _lines():
        if line.startswith("RewriteRule "):
            pattern, target, flags = line.split()[1:4]
            found.append(Rule(pattern, target, flags.strip("[]")))
    return found


REDIRECT = _rules()[2]


def _redirect(path: str) -> str | None:
    """The Location a request path gets, or None when the rule does not match."""
    match = re.search(REDIRECT.pattern, path.removeprefix("/"))
    if match is None:
        return None
    return re.sub(r"\$([0-9])", lambda m: str(match.group(int(m[1]))), REDIRECT.target)


def test_the_file_holds_exactly_the_three_rules_in_order() -> None:
    lines = _lines()
    assert lines[0] == "RewriteEngine On"
    assert lines[1].startswith("RewriteCond %{THE_REQUEST} ")
    assert lines[1].endswith(" [NC]")
    rules = _rules()
    assert [rule.flags for rule in rules] == ["R=404,L", "L", "R=302,L"]
    assert rules[0].pattern == "^" and rules[0].target == "-"
    assert (rules[1].pattern, rules[1].target) == ("^hooks/sync$", "hooks/sync.php")
    assert len(lines) == 5
    assert not any(" [P" in line or "[P]" in line for line in lines)


def test_the_target_is_fixed_to_one_host_and_owner() -> None:
    assert REDIRECT.target.startswith(OWNER + "$1/releases/download/$2/$3")
    assert "$" not in REDIRECT.target.removeprefix(OWNER).replace("$1", "").replace(
        "$2", ""
    ).replace("$3", "")


@pytest.mark.parametrize("prefix", ["", "apt/"])
def test_a_pool_path_redirects_to_the_release_asset(prefix: str) -> None:
    path = f"{prefix}pool/usearch-php/v1.2.3/php8.3-usearch_1.2.3-1_amd64.deb"
    assert _redirect(path) == (
        f"{OWNER}usearch-php/releases/download/v1.2.3/php8.3-usearch_1.2.3-1_amd64.deb"
    )


def test_every_path_the_metadata_lists_is_redirected() -> None:
    for name in ("php8.3-usearch_1.2.3-1_amd64.deb", "php8.4-usearch-1.2.3-1.el9.x86_64.rpm"):
        package = admit.AdmittedPackage(
            name=name, kind="deb", layout="x", php="8.3", arch="amd64", sha256="0" * 64, size=1
        )
        pool = metadata.Entry(repo="usearch-php", tag="v1.2.3", package=package).pool_path
        assert _redirect(pool) == f"{OWNER}usearch-php/releases/download/v1.2.3/{name}"
        assert _redirect("apt/" + pool) is not None
        # an rpm's href is relative to rpm/<php>/<arch>/ and reaches the same pool path
        href = metadata.LOCATION_PREFIX + pool
        assert posixpath.normpath(posixpath.join("rpm/8.3/x86_64", href)) == pool


@pytest.mark.parametrize(
    "path",
    [
        "pool/Usearch-php/v1.2.3/a.deb",  # uppercase product
        "pool/usearch-php/V1.2.3/a.deb",
        "pool/usearch-php/1.2.3/a.deb",  # no v
        "pool/usearch-php/v01.2.3/a.deb",  # leading zero
        "pool/usearch-php/v1.2/a.deb",
        "pool/usearch-php/v1.2.3-RC1/a.deb",
        "pool/usearch-php/v1.2.3/",
        "pool/usearch-php/v1.2.3",
        "pool/usearch-php/v1.2.3/a.deb/",
        "pool/usearch-php/v1.2.3/a/b.deb",
        "pool/../v1.2.3/a.deb",
        "pool/usearch-php/../a.deb",
        "pool/usearch-php/v1.2.3/..",
        "pool/usearch-php/v1.2.3/.hidden",
        "pool/usearch-php/v1.2.3/a%2f.deb",
        "pool/usearch-php/v1.2.3/a b.deb",
        "pool//v1.2.3/a.deb",
        "pool/-bad/v1.2.3/a.deb",
        "pool/.bad/v1.2.3/a.deb",
        "x/pool/usearch-php/v1.2.3/a.deb",
        "apt/apt/pool/usearch-php/v1.2.3/a.deb",
        "rpm/pool/usearch-php/v1.2.3/a.deb",
        "pool/usearch-php/v1.2.3/a.deb?x=1",
        "pool/" + "a" * 101 + "/v1.2.3/a.deb",
        "pool/usearch-php/v1.2.3/" + "a" * 129,
    ],
)
def test_a_path_outside_the_allow_list_is_not_redirected(path: str) -> None:
    assert _redirect(path) is None


def test_a_trailing_newline_cannot_reach_the_location() -> None:
    # `$` also matches before a final newline, but no captured group admits one
    location = _redirect("pool/usearch-php/v1.2.3/a.deb\n")
    assert location == f"{OWNER}usearch-php/releases/download/v1.2.3/a.deb"
    assert location is not None and not set(location) & {"\r", "\n"}


def test_the_captured_groups_are_the_publishers_own_patterns() -> None:
    assert _segment(1) == config.REPO_NAME.pattern
    assert _segment(2) == config.RELEASE_TAG.pattern
    assert _segment(3) == feed.ASSET_NAME.pattern


def _segment(index: int) -> str:
    """Group `index` of the redirect pattern, as a standalone pattern."""
    groups: list[str] = re.findall(r"\((?!\?:)(.*?)\)(?=/|\$)", REDIRECT.pattern)
    assert len(groups) == 3, groups
    return groups[index - 1]


REPOS = [
    "usearch-php",
    "a",
    "a1",
    "a.b",
    "a_b",
    "a-b",
    "-a",
    ".a",
    "a.",
    "a-",
    "_a",
    "A",
    "a" * 100,
    "a" * 101,
    "",
    "a/b",
    "..",
    "a b",
    "ab_",
]
TAGS = [
    "v1.2.3",
    "v0.0.0",
    "v10.20.30",
    "v1.2.3-rc1",
    "v1.2.3-beta12",
    "v1.2.3-RC1",
    "v1.2.3-rc",
    "v01.2.3",
    "v1.02.3",
    "v1.2.03",
    "1.2.3",
    "v1.2",
    "v1.2.3.4",
    "v1.2.3-1",
    "v1.2.3-rc1-x",
    "",
    "v1.2.3 ",
]
ASSETS = [
    "a.deb",
    "php8.3-usearch_1.2.3-1_amd64.deb",
    "a-b_c.d",
    "A",
    "0",
    ".a",
    "-a",
    "_a",
    "a" * 128,
    "a" * 129,
    "",
    "a b",
    "a/b",
    "a+b",
    "a~b",
    "a..b",
    "SHA256SUMS",
    "x.bundle",
]


@pytest.mark.parametrize("value", REPOS)
def test_the_product_pattern_matches_the_repo_name_rule(value: str) -> None:
    ours = re.fullmatch(_segment(1), value) is not None
    assert ours == (config.REPO_NAME.fullmatch(value) is not None)


@pytest.mark.parametrize("value", TAGS)
def test_the_tag_pattern_matches_the_release_tag_rule(value: str) -> None:
    ours = re.fullmatch(_segment(2), value) is not None
    assert ours == (config.RELEASE_TAG.fullmatch(value) is not None)


@pytest.mark.parametrize("value", ASSETS)
def test_the_file_pattern_matches_the_asset_name_rule(value: str) -> None:
    ours = re.fullmatch(_segment(3), value) is not None
    assert ours == (feed.ASSET_NAME.fullmatch(value) is not None)


@pytest.mark.parametrize(
    "path",
    [
        "hooks/sync.php",
        "a.php",
        "hooks/sync.php/x",
        "x/y.PHP",
        "setup.sh.php",
        "hooks/sync.p%68p",
        "hooks/sync%2ephp",
        "hooks/sync%2Ephp",
        "hooks/sync.%70hp",
        "hooks/sync.php%2fx",
        "hooks/sync.PHP%3fx",
        "hooks/sync.php%00.jpg",
    ],
)
def test_the_php_rule_condition_matches_any_php_request_line(path: str) -> None:
    condition = next(line for line in _lines() if line.startswith("RewriteCond"))
    pattern = condition.split()[2]
    line = f"POST /{path}?q=1 HTTP/1.1"
    assert re.search(pattern.replace("[:space:]", r"\s"), line, re.IGNORECASE)


@pytest.mark.parametrize(
    "line",
    [
        "POST /hooks/sync HTTP/1.1",
        "GET /apt/pool/a/v1.0.0/a.deb HTTP/1.1",
        "GET /php-extensions HTTP/1.1",
        "GET /a.phpx HTTP/1.1",
        "GET /a%2ephpx HTTP/1.1",
        "GET /a.p%68px HTTP/1.1",
        "GET /pool/p/v1.0.0/a.deb HTTP/1.1",
    ],
)
def test_the_php_rule_condition_leaves_other_requests_alone(line: str) -> None:
    condition = next(line for line in _lines() if line.startswith("RewriteCond"))
    pattern = condition.split()[2].replace("[:space:]", r"\s")
    assert re.search(pattern, line, re.IGNORECASE) is None
