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
- Repository hygiene: `.gitattributes` (LF normalization, binary markers), pre-commit hooks that
  run the pinned development tools, and `CODEOWNERS`.
- The pin lint now also checks `.pre-commit-config.yaml`: it fails on a non-local repository that
  is not pinned to a commit SHA, on `additional_dependencies`, on a local hook that installs
  packages, on merge keys, and on a malformed `repos` list. CI runs the pre-commit hooks.
- GitHub release feed client: lists a product's releases and assets over `api.github.com` only,
  with conditional requests, bounded pagination, no redirects and a private token file. It
  rejects a release whose asset name, upload state or download URL breaks the rules, ignores
  unsupported tags, and reports each release's `immutable` flag.
