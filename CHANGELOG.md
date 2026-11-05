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
- Release asset cache: downloads an asset through its single GitHub redirect to the fixed CDN host
  with no credentials, and keeps it only if its size and sha256 digest match what GitHub lists.
  An asset without a digest is refused. The cache directory must be private to the current user,
  and files are written atomically under their digest.
- Release verifier: admits a release only if every expected package and its cosign bundle are
  present, each bundle proves the product's release workflow at that exact tag signed the file
  (checked offline against a Sigstore trusted-root file, transparency log on), `SHA256SUMS`
  agrees with the release, and each deb or rpm declares the expected name, version, release,
  epoch and architecture. An rpm must carry a signature by a valid signing key of the pinned RPM
  key; an unsigned rpm, an unpinned key and an expired or revoked key are refused. A product that
  declares `zts` is refused until ZTS packages can be verified.
- Sigstore trusted-root refresh: `cosign initialize` keeps a persistent, private TUF store and a
  validated copy of the trusted root. If the refresh fails, a copy up to seven days old is used
  and reported as not refreshed; an older, missing or future-dated copy stops the run.
- Admit stage: decides per tag which releases may be served. A release is admitted only if it is
  immutable and passes the verifier; the admitted packages (name, layout, PHP, architecture,
  sha256, size) are recorded per product in a strict, private, atomically written state file.
  A failed tag is retried with backoff (1 h, 6 h, then daily) and quarantined after five
  attempts over three days, with one alert a day until it is excluded or requeued. A failing tag
  never blocks a later tag or another product, and an admitted tag is never dropped. A fault of
  the host (missing tool, unusable cache or state, low disk space, rejected token, rate limit)
  stops the stage without touching any counter. The etag is sent only when nothing waits, and a
  full listing is made at least weekly.
- Run lock: an exclusive `flock` on a private file, waited for with a deadline, and a nudge file
  that earns one more pass when it arrives during a pass.
- Metadata builder: writes the unsigned APT and RPM metadata for the admitted packages with the
  standard tools (`apt-ftparchive`, `createrepo_c`) and checks their output against the admitted
  records by exact set, so a package a tool drops, adds or changes fails the build. The `Release`
  file carries by-hash copies and a 14-day `Valid-Until`; the rpm locations are relative so a
  client resolves them to the shared pool path; six rpm trees (PHP 8.3 to 8.5, both
  architectures) always exist. Both hash sections of `Release` (SHA256, SHA512) and their by-hash
  copies are checked, because apt asks for the SHA512 path. The declaration in `products.yml`
  decides what is listed. The
  tree holds metadata only, never a package or a link, and every file is 0644 and every directory
  0755 whatever umask the tools ran under.
- `products.yml` entries now require `extension`, the name inside package names
  (`php8.3-<extension>`); two products cannot share one.

### Changed

- Release tags may not have leading zeros in a number (`v01.0.0` is ignored), so two tags cannot
  map to one package version.
