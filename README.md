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
| `products.yml` | Shipped products only: `repo`, `php`, `arch`, `ts` (all required, no defaults) |
| `tools/` | Repository tooling, including the pin lint (`python tools/lint_pins.py [root]`) |
| `tests/` | Unit tests (negative and container layers arrive with the publisher) |

## Development

Python 3.10. The development tools are pinned with hashes in `requirements-dev.txt`, which
`pip-compile --generate-hashes --allow-unsafe --strip-extras requirements-dev.in` regenerates:

```bash
python -m pip install --require-hashes --no-deps -r requirements-dev.txt
ruff check . && ruff format --check .
mypy
pytest
python tools/lint_pins.py
```

## Licence

Apache-2.0, see `LICENSE`. `NOTICE` must be preserved by anyone redistributing this work.
