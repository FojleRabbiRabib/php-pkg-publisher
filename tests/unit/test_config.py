# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from publisher import config
from publisher.config import ConfigError, Exclusion, Product

VALID = (
    "products:\n"
    "  - repo: usearch-php\n"
    "    extension: usearch\n"
    '    php: ["8.3", "8.4"]\n'
    "    arch: [amd64, arm64]\n"
    "    ts: [nts]\n"
    "    exclude: [v0.3.0, v0.3.1-rc1]\n"
    "  - repo: resvg-php\n"
    "    extension: resvg\n"
    '    php: ["8.5"]\n'
    "    arch: [amd64]\n"
    "    ts: [nts, zts]\n"
)


def _write(tmp_path: Path, body: str, name: str = "products.yml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _product(fields: str) -> str:
    return f"products:\n  - {fields}"


def _fail(tmp_path: Path, body: str) -> str:
    with pytest.raises(ConfigError) as caught:
        config.load_products(_write(tmp_path, body))
    return str(caught.value)


def test_valid_file_loads_every_field(tmp_path: Path) -> None:
    loaded = config.load_products(_write(tmp_path, VALID))
    assert loaded.products == (
        Product(
            repo="usearch-php",
            extension="usearch",
            php=("8.3", "8.4"),
            arch=("amd64", "arm64"),
            ts=("nts",),
            exclude=("v0.3.0", "v0.3.1-rc1"),
        ),
        Product(
            repo="resvg-php",
            extension="resvg",
            php=("8.5",),
            arch=("amd64",),
            ts=("nts", "zts"),
            exclude=(),
        ),
    )


def test_shipped_products_file_loads() -> None:
    shipped = Path(__file__).resolve().parents[2] / "products.yml"
    assert all(product.ts for product in config.load_products(shipped).products)


def test_digest_is_the_sha256_of_the_file_bytes(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID)
    assert config.load_products(path).sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("missing", ["repo", "extension", "php", "arch", "ts"])
def test_every_required_field_is_enforced(tmp_path: Path, missing: str) -> None:
    fields = {"repo": "a-php", "extension": "a", "php": '["8.3"]', "arch": "[amd64]", "ts": "[nts]"}
    del fields[missing]
    body = "products:\n  - " + "\n    ".join(f"{k}: {v}" for k, v in fields.items()) + "\n"
    assert f"missing required key '{missing}'" in _fail(tmp_path, body)


def test_ts_has_no_default(tmp_path: Path) -> None:
    body = _product('{repo: a-php, extension: a, php: ["8.3"], arch: [amd64]}\n')
    message = _fail(tmp_path, body)
    assert "missing required key 'ts'" in message
    assert message.startswith(f"{tmp_path / 'products.yml'}:2:")


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("php", '["8.2"]', "php '8.2' is not one of"),
        ("php", '["8.10"]', "php '8.10' is not one of"),
        ("arch", "[x86_64]", "arch 'x86_64' is not one of"),
        ("arch", "[ARM64]", "arch 'ARM64' is not one of"),
        ("ts", "[ntS]", "ts 'ntS' is not one of"),
        ("ts", "[both]", "ts 'both' is not one of"),
        ("ts", "[]", "ts must not be empty"),
        ("php", '["8.3", "8.3"]', "duplicate php '8.3'"),
        ("ts", "[nts, nts]", "duplicate ts 'nts'"),
        ("ts", "nts", "expected a list"),
        ("ts", "", "expected a list"),
        ("ts", "[[nts]]", "expected a string"),
    ],
)
def test_field_values_are_validated(tmp_path: Path, field: str, value: str, fragment: str) -> None:
    fields = {"repo": "a-php", "extension": "a", "php": '["8.3"]', "arch": "[amd64]", "ts": "[nts]"}
    fields[field] = value
    body = "products:\n  - " + "\n    ".join(f"{k}: {v}" for k, v in fields.items()) + "\n"
    assert fragment in _fail(tmp_path, body)


@pytest.mark.parametrize("version", ["8.3", "8.10", "8"])
def test_unquoted_version_is_rejected_with_a_hint(tmp_path: Path, version: str) -> None:
    body = _product(f"{{repo: a-php, extension: a, php: [{version}], arch: [amd64], ts: [nts]}}\n")
    assert 'expected a string (quote numbers such as "8.3")' in _fail(tmp_path, body)


def test_repeated_key_is_rejected(tmp_path: Path) -> None:
    body = _product(
        '{repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts], ts: [zts]}\n'
    )
    assert "duplicate key 'ts'" in _fail(tmp_path, body)


def test_unknown_product_key_is_rejected(tmp_path: Path) -> None:
    body = _product(
        '{repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts], tsx: [nts]}\n'
    )
    assert "unknown key 'tsx'" in _fail(tmp_path, body)


def test_merge_key_is_rejected(tmp_path: Path) -> None:
    body = _product(
        '{repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts], <<: {ts: [zts]}}\n'
    )
    assert "merge keys are not allowed" in _fail(tmp_path, body)


@pytest.mark.parametrize("key", ["1", "true", "~", "[a]"])
def test_non_string_keys_are_rejected(tmp_path: Path, key: str) -> None:
    body = _product(
        f'{{repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts], {key}: x}}\n'
    )
    assert "keys must be strings" in _fail(tmp_path, body)


def test_python_object_tag_is_rejected(tmp_path: Path) -> None:
    body = _product(
        "{repo: !!python/object:os.system a-php, extension: a,"
        ' php: ["8.3"], arch: [amd64], ts: [nts]}\n'
    )
    assert "expected a string" in _fail(tmp_path, body)


def test_duplicate_product_is_rejected(tmp_path: Path) -> None:
    one = '  - {repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]}\n'
    assert "duplicate product 'a-php'" in _fail(tmp_path, f"products:\n{one}{one}")


@pytest.mark.parametrize(
    "repo",
    [
        '""',
        "Usearch-php",
        "usearch/php",
        "../x",
        "a..b",
        ".hidden",
        "-lead",
        "a b",
        '"a\\nb"',
        "é",
        "a.git",
        "a.",
    ],
)
def test_hostile_repo_names_are_rejected(tmp_path: Path, repo: str) -> None:
    body = _product(f'{{repo: {repo}, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]}}\n')
    assert "invalid repo name" in _fail(tmp_path, body)


def test_repo_longer_than_a_github_name_is_rejected(tmp_path: Path) -> None:
    body = _product(
        f'{{repo: {"a" * 101}, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]}}\n'
    )
    assert "invalid repo name" in _fail(tmp_path, body)


@pytest.mark.parametrize(
    "extension",
    ['""', "Usearch", "use-arch", "use_arch", "use.arch", "1usearch", "usé", "a b", "x" * 33],
)
def test_hostile_extension_names_are_rejected(tmp_path: Path, extension: str) -> None:
    body = _product(
        f'{{repo: a-php, extension: {extension}, php: ["8.3"], arch: [amd64], ts: [nts]}}\n'
    )
    assert "invalid extension name" in _fail(tmp_path, body)


def test_duplicate_extension_is_rejected(tmp_path: Path) -> None:
    first = '  - {repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]}\n'
    second = '  - {repo: b-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]}\n'
    assert "duplicate extension 'a'" in _fail(tmp_path, f"products:\n{first}{second}")


def _with_exclude(exclude: str) -> str:
    fields = 'repo: a-php, extension: a, php: ["8.3"], arch: [amd64], ts: [nts]'
    return _product(f"{{{fields}, exclude: {exclude}}}\n")


@pytest.mark.parametrize(
    "tag",
    [
        "0.3.0",
        "v1",
        "v1.2",
        "v1.2.3.4",
        "v1.2.3-RC1",
        "v1.2.3-1",
        "v\\u06611.2.3",
        "v1.2.3\\n",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
    ],
)
def test_malformed_exclude_tags_are_rejected(tmp_path: Path, tag: str) -> None:
    assert "invalid release tag" in _fail(tmp_path, _with_exclude(f'["{tag}"]'))


def test_duplicate_exclude_tag_is_rejected(tmp_path: Path) -> None:
    assert "duplicate tag 'v1.0.0'" in _fail(tmp_path, _with_exclude("[v1.0.0, v1.0.0]"))


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ("", "empty document"),
        ("# only a comment\n", "empty document"),
        ("a: [unclosed\n", "invalid YAML"),
        ("products: []\n---\nproducts: []\n", "invalid YAML"),
        ("- just\n- a list\n", "expected a mapping"),
        ("products:\n", "expected a list"),
        ("products: {}\n", "expected a list"),
        ("products: []\nextra: 1\n", "unknown key 'extra'"),
        ("extra: 1\n", "unknown key 'extra'"),
        ("{}\n", "missing required key 'products'"),
        ("products:\n  - just-a-string\n", "expected a mapping"),
    ],
)
def test_malformed_documents_fail_closed(tmp_path: Path, body: str, fragment: str) -> None:
    assert fragment in _fail(tmp_path, body)


def test_unreadable_files_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        config.load_products(tmp_path / "missing.yml")
    bad = tmp_path / "binary.yml"
    bad.write_bytes(b"products: []\n\xff\xfe")
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        config.load_products(bad)


def test_deeply_nested_document_fails_closed(tmp_path: Path) -> None:
    assert "invalid YAML" in _fail(tmp_path, "products: " + "[" * 100000 + "]" * 100000)


def test_oversized_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "products.yml"
    path.write_bytes(b"#" * (1024 * 1024 + 1))
    with pytest.raises(ConfigError, match="larger than 1048576 bytes"):
        config.load_products(path)


def test_directory_and_nul_byte_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        config.load_products(tmp_path)
    assert "invalid YAML" in _fail(tmp_path, "products: []\x00\n")


def test_null_exclude_is_rejected(tmp_path: Path) -> None:
    assert "expected a list" in _fail(tmp_path, _with_exclude("~"))


def test_error_names_the_file_and_line(tmp_path: Path) -> None:
    body = VALID.replace("ts: [nts, zts]", "ts: [nts, both]")
    assert _fail(tmp_path, body).startswith(f"{tmp_path / 'products.yml'}:12:")


EXCLUDE_VALID = (
    "exclude:\n"
    "  - product: usearch-php\n"
    "    tag: v0.3.0\n"
    "  - {product: resvg-php, tag: v1.0.0-rc1}\n"
)


def _declared(tmp_path: Path) -> config.ProductList:
    return config.load_products(_write(tmp_path, VALID))


def _exclusion_fail(tmp_path: Path, body: str) -> str:
    declared = _declared(tmp_path)
    with pytest.raises(ConfigError) as caught:
        config.load_exclusions(_write(tmp_path, body, "exclude.yml"), declared)
    return str(caught.value)


def test_valid_exclusions_load(tmp_path: Path) -> None:
    path = _write(tmp_path, EXCLUDE_VALID, "exclude.yml")
    loaded = config.load_exclusions(path, _declared(tmp_path))
    assert loaded.exclusions == (
        Exclusion(product="usearch-php", tag="v0.3.0"),
        Exclusion(product="resvg-php", tag="v1.0.0-rc1"),
    )
    assert loaded.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_empty_exclusion_list_is_valid(tmp_path: Path) -> None:
    path = _write(tmp_path, "exclude: []\n", "exclude.yml")
    assert config.load_exclusions(path, _declared(tmp_path)).exclusions == ()


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ("exclude:\n  - {product: nope-php, tag: v1.0.0}\n", "unknown product 'nope-php'"),
        ("exclude:\n  - {product: usearch-php, tag: latest}\n", "invalid release tag"),
        ("exclude:\n  - {product: usearch-php}\n", "missing required key 'tag'"),
        ("exclude:\n  - {tag: v1.0.0}\n", "missing required key 'product'"),
        ("exclude:\n  - {product: usearch-php, tag: v1.0.0, why: bad}\n", "unknown key 'why'"),
        (
            "exclude:\n  - {product: usearch-php, tag: v1.0.0}\n"
            "  - {product: usearch-php, tag: v1.0.0}\n",
            "duplicate exclusion 'usearch-php' 'v1.0.0'",
        ),
        ("usearch-php v1.0.0\n", "expected a mapping"),
        ("", "empty document"),
    ],
)
def test_malformed_exclusions_fail_closed(tmp_path: Path, body: str, fragment: str) -> None:
    assert fragment in _exclusion_fail(tmp_path, body)
