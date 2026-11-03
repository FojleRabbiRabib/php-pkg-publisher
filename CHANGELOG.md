# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Repository scaffold: licence and notice, empty product list, Python tooling configuration, and a
  CI workflow with a lint that fails on any GitHub Action or container image that is not pinned to
  a commit SHA or an image digest.
- Strict loader for `products.yml` and `exclude.yml`: rejects a product without `ts`, unknown
  keys, repeated keys, unquoted versions, malformed repo names and tags, and an exclusion that
  names an undeclared product.
