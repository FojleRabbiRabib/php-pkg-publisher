# Runbook

How to configure the publisher and the commands you use day to day. It covers what runs on the
publishing host as the publisher user; web server, CDN and systemd enablement steps are
host-specific and are not here. Placeholders in angle brackets are yours to fill in:
`<publisher-user>`, `<site-root>`, `<origin-public-ip>`, `<repo>`, `<tag>`, `<generation>`.

## What runs

| Unit | Role |
|---|---|
| `php-pkg-publisher.service` | One publisher run: admit new releases, then build, sign and publish. |
| `php-pkg-publisher.timer` | Starts the service daily. |
| `php-pkg-publisher.path` | Starts the service when the webhook receiver creates the nudge file. |
| `php-pkg-publisher-watch.service` | The hourly watch; it shares no code path with the run. |
| `php-pkg-publisher-watch.timer` | Starts the watch hourly. |
| `php-pkg-publisher-notify@.service` | Tells the operator that the named unit failed. |

The units run as `php-pkg-publisher`, from `/opt/php-pkg-publisher`, with the settings in
`/etc/php-pkg-publisher/publisher.yml`. They are in `deploy/systemd/`.

The watch alerts, at most once a day for each, when the GitHub token has fewer than 30 days left,
the origin certificate fewer than 21, the served `InRelease` is older than 3 days, or its
`Valid-Until` is fewer than 7 days away.

## The publisher user and its directories

The six working directories must be distinct and none may lie inside another. `<publisher-user>`
must be the `User=` of the units (`php-pkg-publisher`) and `<site-root>` the site path in the
service's `ReadWritePaths=`. The site is readable by the web server; the state, cache, trust, work
and lock directories and the signing home belong to the publisher user and are closed to everyone
else. The nudge directory is shared: the webhook receiver (running as the web server's user,
`<web-group>` below is its group) creates the nudge file and its own throttle directories in it,
and the publisher removes the nudge file. The parent directory lets that group in but not read.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin <publisher-user>
install -d -m 0755 /etc/php-pkg-publisher
install -d -m 0755 -o <publisher-user> <site-root>
install -d -m 0710 -o <publisher-user> -g <web-group> /var/lib/php-pkg-publisher
for name in state cache trust work lock gnupg; do
  install -d -m 0700 -o <publisher-user> /var/lib/php-pkg-publisher/$name
done
install -d -m 2770 -o <publisher-user> -g <web-group> /var/lib/php-pkg-publisher/nudge
```

## Settings

`/etc/php-pkg-publisher/publisher.yml` has no defaults: a missing key stops the run before it
touches anything, and a repeated or unknown key is an error with its line number. It holds
locations and public pins only, never a secret.

```yaml
products: /etc/php-pkg-publisher/products.yml
exclude: /etc/php-pkg-publisher/exclude.yml
site: <site-root>
state: /var/lib/php-pkg-publisher/state
cache: /var/lib/php-pkg-publisher/cache
trust: /var/lib/php-pkg-publisher/trust
work: /var/lib/php-pkg-publisher/work
lock: /var/lib/php-pkg-publisher/lock
nudge: /var/lib/php-pkg-publisher/nudge/sync
rpm_key: /etc/php-pkg-publisher/rpm-signing.asc
token: {file: /etc/php-pkg-publisher/github.token, expires: "2027-01-31"}
alert: {file: /etc/php-pkg-publisher/telegram.conf}
signing:
  home: /var/lib/php-pkg-publisher/gnupg
  fingerprint: <signing-subkey-fingerprint>
  certificate: /etc/php-pkg-publisher/signing-certificate.asc
  primary: <primary-key-fingerprint>
watch: {host: pkg.example.org, origin: <origin-public-ip>}
```

- Paths are absolute, with no `..`, no `//`, no trailing `/`, and at most 200 bytes.
- Fingerprints are 40 uppercase hexadecimal digits. `fingerprint` is the signing subkey and
  `primary` is the master key that certifies it; the certificate file holds the public part only.
- `watch.origin` must be a public IP address in its shortest form; `watch.host` a lower-case name.
- The signing home path is at most 80 bytes (gpg's agent socket path has a hard length limit),
  and `TMPDIR` for the run must be short too; the unit sets `TMPDIR=/tmp`.

`products.yml` lists the shipped products (see the README). `exclude.yml` is the emergency list:

```yaml
exclude: []
```

## Secrets

Each file is read only if it is a regular file owned by the publisher user and closed to group
and others (mode `0600`).

- **GitHub token** (`github.token`): the token alone on one line. It is read-only and has no
  scopes. Put its expiry date in `publisher.yml`; the watch warns 30 days before.
- **Alert credentials** (`telegram.conf`): exactly two lines, `chat_id=<id>` and `token=<bot token>`.
- **The signing home** holds the signing subkeys only. A home that holds the master secret key is
  refused: the master key stays offline. The subkey has no passphrase.
- **The rpm key** (`rpm_key`) is the public key the publisher checks every rpm against.
- **The webhook secret** is read by the receiver only, from
  `/etc/php-pkg-publisher-webhook/secret`: at least 16 bytes, readable by the web server's user
  and no one else. The same value is the secret of the GitHub webhook. Without it every delivery
  fails with a server error.

## Day-to-day commands

Run them as root, switching to the publisher user (which has no login shell) the way the unit
runs it (shown for `run`; replace it with any command below):

```sh
cd /opt/php-pkg-publisher
runuser -u <publisher-user> -- env PYTHONPATH=/opt/php-pkg-publisher TMPDIR=/tmp \
  python3 -s -m publisher --config /etc/php-pkg-publisher/publisher.yml run
```

Every command takes the same exclusive lock as a run and waits for it, then stops if it cannot get
it, so two of them never change state at once.

| Command | Use |
|---|---|
| `run` | Admit new releases and publish. The timer and the nudge do this. |
| `rollback <generation>` | Re-sign an older generation's content as a new generation and pin it. Generation ids are the directory names in `<site-root>/versions/` (the same names with `.json` added are in `<site-root>/generations/`; pass the name without it): an 8-digit sequence number, a dash and a UTC time stamp. While pinned, runs re-sign the pinned content and hold new releases back; excluding a release the pin lists drops the pin and alerts. |
| `clear-pin` | End a rollback; the next run publishes the admitted state again. |
| `requeue <repo> <tag>` | Lift a failure or a quarantine so the next run tries the tag again. It refuses a tag with no recorded failure. |

A tag that fails is retried. Once it has failed at least 5 times and the first failure is at least
3 days old it is quarantined and alerts. Fix the cause (an unsigned asset, a missing bundle) and
`requeue` it.

## Yanking a release

Add an entry for the product and tag to `exclude.yml`, then start a `run` (see above):

```yaml
exclude:
  - {product: <repo>, tag: <tag>}
```

The next run builds the repository without that tag, even if it was admitted before. The product
must be listed in `products.yml`. Remove the entry to bring it back.

## Installing cosign

Install one `cosign` binary, pinned by its published SHA-256, in a system directory the publisher
finds (`/usr/local/bin`, `/usr/bin`, `/bin`). Take the version and checksum from the release you
pin, never "latest":

```sh
curl -fsSLo cosign https://github.com/sigstore/cosign/releases/download/<version>/cosign-linux-amd64
echo "<sha256>  cosign" | sha256sum -c -
install -m 0755 cosign /usr/local/bin/cosign
```

The release lists the checksum in its `cosign_checksums.txt`; compare it with the value you
pinned, not with one fetched next to the binary at install time. Nothing else needs doing by hand:
each run itself runs `cosign initialize` into its own store under the trust directory (the host
needs outbound HTTPS to Sigstore's TUF mirror), keeps a validated copy of `trusted_root.json`, and
verifies offline against it. If the refresh fails the run uses a copy at most seven days old, and
stops when there is none.

The other host tools come from the distribution: `apt-utils`, `createrepo-c`, `gnupg` and `rpm`.

### Bumping cosign, createrepo_c, apt-ftparchive

1. Read the release notes.
2. Change the version and checksum.
3. Check that `cosign initialize` still leaves `trusted_root.json` where `publisher/verify.py`
   expects it, and that the offline `verify-blob --trusted-root` call still works.
4. Re-run all three test layers and the container matrix.
5. Check that a tampered bundle still fails.
6. Record the new version.

## The outside watch

The hourly watch needs a living publishing host. The `Platform watch` workflow
(`.github/workflows/platform-watch.yml`) is the check from outside: a GitHub runner fetches the
public site and fails, and sends a chat message, when:

- the primary key of the served keyring package is not the one pinned in
  `deploy/primary-fingerprint.txt`;
- `InRelease` or one of the six `repomd.xml.asc` files does not verify against that key;
- the `InRelease` `Date` is older than 4 days or its `Valid-Until` is fewer than 7 days away;
- a signature file was made or served more than 4 days ago;
- the first deb and rpm the indexes list (which must match the signed metadata) do not answer 302
  with the exact GitHub Releases URL of a product in `products.yml`, or no package is listed.

The pin file holds the primary fingerprint, which does not change when a signing subkey rotates:
edit it only with a new master key, in the same change as its keyring release. Until the key
ceremony it holds a placeholder, and the watch fails on it by design. The workflow is started by
hand (Actions, `Platform watch`) until the site is live; the weekly schedule is added at the
cutover. To run it from a checkout, which needs `gpg`, `gpgv` and `dpkg-deb`:

```sh
PYTHONPATH=. python3 tools/platform_watch.py --site https://pkg.rabib.me \
  --pin-file deploy/primary-fingerprint.txt --products products.yml
```

It prints one `FAIL:` line for each problem and exits 1, or prints `PLATFORM WATCH PASSED`. To
get a chat message too, add `--notify` with the repository secrets `TELEGRAM_CHAT_ID` and
`TELEGRAM_BOT_TOKEN` set in the environment (in the workflow they come from the repository's
Actions secrets); without them the failed run is the notice.

## Deploying a change

The host runs a signed tag, deployed by hand, never an automatic pull:

```sh
git fetch --tags
git verify-tag <tag>
git checkout <tag>
```

## Key rotation

A client trusts a new subkey only once it holds the updated public key, so a rotation has this
order:

1. Ship a keyring that holds the old and the new subkey at least 150 days before the old one
   expires. The repository keeps signing with the old subkey.
2. Import the new signing subkey's secret into the signing home as the publisher user. Only the
   secret subkey goes there: a home that holds the primary secret key is refused. Check, as the
   publisher user, that
   `runuser -u <publisher-user> -- gpg --homedir <signing-home> --list-secret-keys` lists the new
   subkey and shows the primary key as a stub (`sec#`). Running gpg as root would leave root-owned
   files in the home.
3. At least 120 days after step 1, and at least 14 days before the old subkey expires, change
   `signing.fingerprint` (and `signing.certificate`) to the new subkey. Never sign with both.
4. Keep the old subkey's revocation certificate offline.

Before a rotation, run the key drill from a checkout. It needs docker with the pinned images
(`tests/container/images.py`), the development tools of `requirements-dev.txt`, and the host tools
the tests build with: `apt-utils`, `createrepo-c`, `dpkg-dev`, `gnupg`, `gpgv`, `rpm` and
`rpm2cpio`:

```sh
pytest -m container tests/container/test_key_drill.py
```

It rotates a throwaway key on every tested distribution: a client with the old keyring must
refuse the repository after the switch, with the message `installation.md` quotes, and the same
client must verify it and install after it upgrades the keyring package.

The publisher refuses to sign with a subkey that expires before the metadata's `Valid-Until`.
Clients that missed the new keyring recover as described in [`installation.md`](installation.md);
the reasoning is in [`security.md`](security.md).
