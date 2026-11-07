# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Load and validate the product list and the emergency exclude list.

Both files are parsed as YAML node trees, not into Python objects, so that:
  * a repeated key is an error instead of silently keeping the last value;
  * an unquoted `8.3` (a YAML float) or `8.10` (which would become `8.1`) is rejected;
  * every schema error carries the file and line it came from.

Anything unknown, missing or malformed raises ConfigError, which stops the run before it
publishes anything. A product without `ts` is rejected; no field has a default.

products.yml:  products: [{repo, extension, php, arch, ts, exclude?}, ...]
exclude.yml:   exclude: [{product, tag}, ...]
Repo names are lowercase only; `extension` is the name inside package names (php8.3-<extension>);
tags are `vX.Y.Z` or `vX.Y.Z-<letters><digits>`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

ARCHITECTURES: Final = frozenset({"amd64", "arm64"})
PHP_VERSIONS: Final = frozenset({"8.3", "8.4", "8.5"})
THREAD_SAFETY: Final = frozenset({"nts", "zts"})

EXTENSION_NAME: Final = re.compile(r"[a-z][a-z0-9]{0,31}")
REPO_NAME: Final = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9_-])?")
_NUMBER = r"(?:0|[1-9][0-9]*)"
FINAL_TAG: Final = re.compile(rf"v{_NUMBER}\.{_NUMBER}\.{_NUMBER}")
RELEASE_TAG: Final = re.compile(rf"v{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-[a-z]+[0-9]+)?")
STRING_TAG: Final = "tag:yaml.org,2002:str"
MERGE_TAG: Final = "tag:yaml.org,2002:merge"
MAX_FILE_BYTES: Final = 1024 * 1024


class ConfigError(Exception):
    """A configuration file is unreadable, malformed or violates the schema."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Product:
    repo: str
    extension: str
    php: tuple[str, ...]
    arch: tuple[str, ...]
    ts: tuple[str, ...]
    exclude: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ProductList:
    source: Path
    sha256: str
    products: tuple[Product, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Exclusion:
    product: str
    tag: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExclusionList:
    source: Path
    sha256: str
    exclusions: tuple[Exclusion, ...]


class Reader:
    """Validates nodes of one file and builds line-numbered errors."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def fail(self, node: Node, message: str) -> ConfigError:
        return ConfigError(f"{self.path}:{node.start_mark.line + 1}: {message}")

    def string(self, node: Node, expected: str = "expected a string") -> str:
        if not isinstance(node, ScalarNode) or node.tag != STRING_TAG:
            raise self.fail(node, expected)
        value: str = node.value
        return value

    def key(self, node: Node) -> str:
        if isinstance(node, ScalarNode) and node.tag == MERGE_TAG:
            raise self.fail(node, "merge keys are not allowed")
        return self.string(node, "keys must be strings")

    def sequence(self, node: Node) -> list[Node]:
        if not isinstance(node, SequenceNode):
            raise self.fail(node, "expected a list")
        items: list[Node] = node.value
        return items

    def mapping(
        self, node: Node, *, required: tuple[str, ...], optional: tuple[str, ...] = ()
    ) -> dict[str, Node]:
        if not isinstance(node, MappingNode):
            raise self.fail(node, "expected a mapping")
        found: dict[str, Node] = {}
        for key_node, value_node in node.value:
            key = self.key(key_node)
            if key in found:
                raise self.fail(key_node, f"duplicate key {key!r}")
            if key not in required and key not in optional:
                raise self.fail(key_node, f"unknown key {key!r}")
            found[key] = value_node
        for key in required:
            if key not in found:
                raise self.fail(node, f"missing required key {key!r}")
        return found

    def choices(self, node: Node, allowed: frozenset[str], name: str) -> tuple[str, ...]:
        items = self.sequence(node)
        if not items:
            raise self.fail(node, f"{name} must not be empty")
        values: list[str] = []
        for item in items:
            value = self.string(item, 'expected a string (quote numbers such as "8.3")')
            if value not in allowed:
                raise self.fail(item, f"{name} {value!r} is not one of {sorted(allowed)}")
            if value in values:
                raise self.fail(item, f"duplicate {name} {value!r}")
            values.append(value)
        return tuple(values)

    def repo(self, node: Node) -> str:
        value = self.string(node)
        if not REPO_NAME.fullmatch(value) or ".." in value or value.endswith(".git"):
            raise self.fail(node, f"invalid repo name {value!r}")
        return value

    def extension(self, node: Node) -> str:
        value = self.string(node)
        if not EXTENSION_NAME.fullmatch(value):
            raise self.fail(node, f"invalid extension name {value!r}")
        return value

    def tag(self, node: Node) -> str:
        value = self.string(node)
        if not RELEASE_TAG.fullmatch(value):
            raise self.fail(node, f"invalid release tag {value!r}")
        return value

    def tags(self, node: Node) -> tuple[str, ...]:
        values: list[str] = []
        for item in self.sequence(node):
            value = self.tag(item)
            if value in values:
                raise self.fail(item, f"duplicate tag {value!r}")
            values.append(value)
        return tuple(values)


def open_document(path: Path) -> tuple[Reader, Node, str]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        raise ConfigError(f"{path}: cannot read: {error.strerror or error}") from error
    if len(raw) > MAX_FILE_BYTES:
        raise ConfigError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigError(f"{path}: not valid UTF-8: {error.reason}") from error
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ConfigError(f"{path}: invalid YAML: {error}") from error
    if root is None:
        raise ConfigError(f"{path}: empty document")
    return Reader(path), root, hashlib.sha256(raw).hexdigest()


def load_products(path: Path) -> ProductList:
    reader, root, digest = open_document(path)
    top = reader.mapping(root, required=("products",))
    products: list[Product] = []
    for node in reader.sequence(top["products"]):
        fields = reader.mapping(
            node, required=("repo", "extension", "php", "arch", "ts"), optional=("exclude",)
        )
        repo = reader.repo(fields["repo"])
        if any(product.repo == repo for product in products):
            raise reader.fail(fields["repo"], f"duplicate product {repo!r}")
        extension = reader.extension(fields["extension"])
        if any(product.extension == extension for product in products):
            raise reader.fail(fields["extension"], f"duplicate extension {extension!r}")
        exclude = reader.tags(fields["exclude"]) if "exclude" in fields else ()
        products.append(
            Product(
                repo=repo,
                extension=extension,
                php=reader.choices(fields["php"], PHP_VERSIONS, "php"),
                arch=reader.choices(fields["arch"], ARCHITECTURES, "arch"),
                ts=reader.choices(fields["ts"], THREAD_SAFETY, "ts"),
                exclude=exclude,
            )
        )
    return ProductList(source=path, sha256=digest, products=tuple(products))


def load_exclusions(path: Path, declared: ProductList) -> ExclusionList:
    reader, root, digest = open_document(path)
    known = {product.repo for product in declared.products}
    top = reader.mapping(root, required=("exclude",))
    exclusions: list[Exclusion] = []
    for node in reader.sequence(top["exclude"]):
        fields = reader.mapping(node, required=("product", "tag"))
        product = reader.string(fields["product"])
        if product not in known:
            raise reader.fail(fields["product"], f"unknown product {product!r}")
        entry = Exclusion(product=product, tag=reader.tag(fields["tag"]))
        if entry in exclusions:
            raise reader.fail(node, f"duplicate exclusion {product!r} {entry.tag!r}")
        exclusions.append(entry)
    return ExclusionList(source=path, sha256=digest, exclusions=tuple(exclusions))
