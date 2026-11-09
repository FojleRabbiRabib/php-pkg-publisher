# php-pkg-publisher

The platform for one signed APT and RPM repository for PHP extensions.

Product repositories build, rpm-sign and release their packages on GitHub. This service
will verify each release, build and sign the merged repository metadata, and redirect every
package download to the GitHub release. It will never serve package bytes, so one repository
and one key give users every product with a single `apt install` or `dnf install`.

## Status

Early scaffold. The repository currently holds the licence, tooling configuration, an empty
product list and the CI pin lint; the publisher, webhook receiver, keyring packages and client
setup script land milestone by milestone and are listed here when they ship.

## How it will work

1. A product repository publishes a tagged release with its packages, checksums and cosign
   bundles.
2. A GitHub release webhook (plus one reconcile run per day) starts a publisher run.
3. The publisher verifies the cosign bundle against the exact release workflow identity,
   then the checksums and the package signatures, and only then admits the release.
4. It builds the APT and RPM metadata with the standard tools (`apt-ftparchive`,
   `createrepo_c`), signs it, and switches the served tree atomically.
5. `apt` and `dnf` fetch metadata from the repository host and package files from GitHub
   through a redirect.

A failed verification never publishes anything, and one failing product never blocks the
others.

## Layout

| Path | Role |
|---|---|
| `products.yml` | Shipped products only: `repo`, `extension`, `php`, `arch`, `ts` (all required, no defaults), optional `exclude` |
| `publisher/` | The publisher package: the strict loader for `products.yml` and `exclude.yml`, the GitHub release feed client, the release asset cache, the release verifier, the admit stage (per-tag state, retries, quarantine), the run lock, the metadata builder, the signer, the generation publisher, the settings loader, the `run` command, the alert sender, the failure notifier and the hourly watch |
| `tools/` | Repository tooling, including the pin lint (`python tools/lint_pins.py [root]`) |
| `tests/` | Unit tests (negative and container layers arrive with the publisher) |

## Development

Python 3.10 on Linux (the publisher is a POSIX service: its checks use file modes and owners, and
it is not supported on Windows). The development tools are pinned with hashes in
`requirements-dev.txt`, which
`pip-compile --generate-hashes --allow-unsafe --strip-extras requirements-dev.in` regenerates:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --no-deps -r requirements-dev.txt
ruff check . && ruff format --check .
mypy
pytest
python tools/lint_pins.py
```

These checks, plus file-hygiene hooks (YAML and TOML syntax, private-key and large-file
detection, line endings, trailing whitespace), run as git hooks through
[pre-commit](https://pre-commit.com): on commit, and pytest on push. CI runs the same hooks. Every
hook calls a pinned tool from the environment above, so install the hooks with that environment
active (the installed hook records its Python; a distro `pre-commit` is too old for this config)
and activate it again before each commit:

```bash
pre-commit install
pre-commit run --all-files
```

## Licence

Apache-2.0, see `LICENSE`. `NOTICE` must be preserved by anyone redistributing this work.
