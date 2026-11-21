# Runbook

How to configure the publisher and the commands you use day to day. It covers what runs on the
publishing host as the publisher user, and how to start, stop and recover its systemd units; web
server and CDN steps are host-specific and are not here. Placeholders in angle brackets are yours to fill in:
`<publisher-user>`, `<site-root>`, `<docroot>`, `<docroot-parent>`, `<origin-public-ip>`, `<repo>`,
`<tag>`, `<generation>`.

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
the origin certificate fewer than 21, the served `InRelease` is older than 3 days, its
`Valid-Until` is fewer than 7 days away, or the nudge file is older than 2 hours (no run lasts that
long, so the path unit is not starting runs).

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

A run refuses a file that is malformed, and a `products.yml` that lists no product while the
publisher holds state of earlier products (a truncated file would otherwise publish an empty
repository). It sends one urgent `config-refused` alert, ends with exit 1 and publishes nothing;
the nudge is not put back, so the daily timer is the next try. The served repository stays valid
until its `Valid-Until`, so fix the file within days. To remove every product on purpose, remove
their state files (the `products` directory inside the `state` path of `publisher.yml`) as well.

When a declaration is widened (a new PHP version or architecture), tags admitted before are not
checked again. While the newest admitted tag has no package for a declared cell the run sends an
urgent `cell-missing` alert once a day; it ends with the first release that carries the cell.

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

Every server error the receiver decides on, or catches, writes one line to PHP's error log (where
its `error_log` setting points): the prefix `pkg-hook:` and a reason, which is
`nudge-directory-missing`, `secret-unusable`, `guid-directory-unusable`, `nudge-failed`, or
`internal-error` followed by the exception class. A line never holds a path, a secret or an
exception message. A fatal error PHP cannot catch (the memory or time limit) is a bare 500 that PHP
logs itself, with its own text and a path.

The receiver also turns `display_errors` off and `log_errors` on for itself, so no PHP error text
reaches GitHub. A pool that locks `display_errors` on with an admin setting overrides this: do not
lock it on.

## Setting up the host

Do these steps in order, as root, from a checkout of a tag whose signature you have verified. The
commands were run on a clean Ubuntu 22.04 container; what the web server and systemd do with the
result is checked on the staging site, not here. `<docroot>` is the web server's document root for
the site; `<site-root>` is outside it.

One rule decides the layout: the web server's user runs PHP, so it must never be able to change
anything that runs as the publisher user. Every folder on the path to the code, the settings, the
state and the signing home is owned by root or by the publisher user and is not writable by the web
server's user or group. `<docroot-parent>`, the folder that holds `<docroot>`, is owned by root and
no one else may write in it. Of the
publisher's folders, the nudge directory is the only one the web server's group may write.
`<web-group>` must hold the web server's user and no one else, because its members can read the
webhook secret. `<site-root>` must be the site path in the service's `ReadWritePaths=`.

1. Install the tools a run needs: `python3-yaml`, `gnupg`, `rpm`, `apt-utils` and `createrepo-c`
   from the distribution, and `cosign` as described under "Installing cosign" below.

2. Install the code, owned by root and writable by no one else (the `a+rX` keeps it readable
   whatever root's umask is):

   ```sh
   install -d -m 0755 -o root -g root /opt/php-pkg-publisher
   cp -r publisher /opt/php-pkg-publisher/
   chown -R root:root /opt/php-pkg-publisher
   chmod -R go-w,a+rX /opt/php-pkg-publisher
   ```

3. Create the publisher user and its directories, with the commands of the section above.

4. Put the settings in `/etc/php-pkg-publisher/`:

   | File | Owner, mode | Content |
   |---|---|---|
   | `products.yml` | root, `0644` | The one in the checkout. |
   | `exclude.yml` | root, `0644` | `exclude: []`. A missing file stops every run. |
   | `publisher.yml` | root, `0644` | The settings above, filled in. |
   | `rpm-signing.asc`, `signing-certificate.asc` | root, `0644` | Public keys only. |
   | `github.token`, `telegram.conf` | `<publisher-user>`, `0600` | The secrets above. |

   ```sh
   install -m 0644 products.yml /etc/php-pkg-publisher/products.yml
   install -m 0644 /dev/null /etc/php-pkg-publisher/exclude.yml
   printf 'exclude: []\n' > /etc/php-pkg-publisher/exclude.yml
   install -m 0644 <rpm-key-file> /etc/php-pkg-publisher/rpm-signing.asc
   install -m 0644 <certificate-file> /etc/php-pkg-publisher/signing-certificate.asc
   install -m 0600 -o <publisher-user> <token-file> /etc/php-pkg-publisher/github.token
   install -m 0600 -o <publisher-user> <alert-file> /etc/php-pkg-publisher/telegram.conf
   ```

5. Store the webhook secret where the receiver reads it. The folder lets the web server's group in
   and no one else; the secret must hold at least 16 bytes:

   ```sh
   install -d -m 0750 -o root -g <web-group> /etc/php-pkg-publisher-webhook
   install -m 0640 -o root -g <web-group> <webhook-secret-file> /etc/php-pkg-publisher-webhook/secret
   test "$(wc -c < /etc/php-pkg-publisher-webhook/secret)" -ge 16
   ```

6. Import the signing subkey. The signer needs a subkey with no passphrase, so remove the
   passphrase on the offline machine, in a throwaway home, and export the subkey alone (the export
   holds no master secret key). The new export is not protected: keep it private and delete it
   after the import.

   ```sh
   gpg --armor --export-secret-subkeys <signing-subkey-fingerprint>! > <subkey-export>
   export GNUPGHOME="$(mktemp -d)"
   gpg --import <subkey-export>
   gpg --change-passphrase <primary-key-fingerprint>
   gpg --armor --export-secret-subkeys <signing-subkey-fingerprint>! > <plain-export>
   gpgconf --kill gpg-agent
   rm -r "$GNUPGHOME"; unset GNUPGHOME
   ```

   `--change-passphrase` asks for the old passphrase and then the new one: leave the new one
   empty and confirm. On the host, as the publisher user, import the file from a folder only that
   user can enter, check, and remove the file and the agent it started. Delete `<subkey-export>`
   and `<plain-export>` on the offline machine once the host has the key:

   ```sh
   install -m 0600 -o <publisher-user> <plain-export> /var/lib/php-pkg-publisher/work/subkey.asc
   runuser -u <publisher-user> -- gpg --homedir <signing-home> --import /var/lib/php-pkg-publisher/work/subkey.asc
   runuser -u <publisher-user> -- gpg --homedir <signing-home> --list-secret-keys
   rm /var/lib/php-pkg-publisher/work/subkey.asc
   runuser -u <publisher-user> -- gpgconf --homedir <signing-home> --kill gpg-agent
   ```

   The listing must show the primary key as a stub (`sec#`). Then prove that the subkey signs
   with no passphrase and no pinentry:

   ```sh
   runuser -u <publisher-user> -- gpg --homedir <signing-home> --batch --pinentry-mode error \
     --local-user <signing-subkey-fingerprint>! --detach-sign -o /dev/null /dev/null
   runuser -u <publisher-user> -- gpgconf --homedir <signing-home> --kill gpg-agent
   ```

7. Put the web files in `<docroot>`. `sync.php` is served as `/hooks/sync` by the rule in
   `.htaccess`. Root owns every file there: the publisher never writes in `<docroot>` (it flips
   `current` inside `<site-root>`) and the web server's user only reads. Root makes the two links
   once; they point into `<site-root>`, so the links never change. `keyring/` holds the two keyring
   packages, built offline and placed by hand.

   Two locks keep the web server's user from replacing the folder, and with it the redirect rules
   and the keyring packages: `<docroot-parent>` is owned by root, so nobody else can rename
   `<docroot>`, and `<docroot>` carries the immutable flag, which stops a rename, a delete and any
   new entry in it, even by its owner. `<docroot>` must already exist and hold only the site's
   files: the commands make root the owner of everything in it. The site user can no longer create
   entries in `<docroot-parent>`, so anything it must write there (logs, caches, uploads) has to
   live in folders it already owns or somewhere else. The flag needs a file system that supports
   it (ext4 and xfs do), and a tool
   that writes into `<docroot>`, such as a certificate client leaving challenge files there, then
   fails: keep those files elsewhere. To change a file later, clear the flag, change it and set the
   flag again. A control panel may reset an owner, a mode or the flag when it fixes permissions:
   run the check below after any panel action.

   ```sh
   chown root:root <docroot-parent>
   chmod 0755 <docroot-parent>
   chattr -i <docroot>
   install -d -m 0755 -o root -g root <docroot> <docroot>/keyring
   install -m 0644 -o root web/docroot.htaccess <docroot>/.htaccess
   install -m 0644 -o root web/sync.php <docroot>/sync.php
   ln -s <site-root>/current/apt <docroot>/apt
   ln -s <site-root>/current/rpm <docroot>/rpm
   chown -hR root:root <docroot>
   chmod -R go-w,a+rX <docroot>
   chattr +i <docroot>
   ```

   The two links are made once: on a repeat, leave out the `ln` lines.

8. Install the units, then enable them as in "Starting, stopping and recovering the units":

   ```sh
   install -m 0644 deploy/systemd/* /etc/systemd/system/
   ```

Check the result. The web server's user must read the webhook secret and write in the nudge
directory, and do nothing else: it must not read the state or the secrets, write in the code or in
`<docroot>`, or create a link there. Look at the path to each, then try it as that user (`<web-user>`
is the web server's user; the first two commands must succeed, the others must fail):

```sh
namei -l /opt/php-pkg-publisher/publisher/__main__.py <docroot>/sync.php
runuser -u <web-user> -- test -r /etc/php-pkg-publisher-webhook/secret
runuser -u <web-user> -- test -w /var/lib/php-pkg-publisher/nudge
runuser -u <web-user> -- test -w /opt/php-pkg-publisher
runuser -u <web-user> -- test -w <docroot>
runuser -u <web-user> -- test -w <docroot>/..
runuser -u <web-user> -- test -r /var/lib/php-pkg-publisher/state
runuser -u <web-user> -- test -r /var/lib/php-pkg-publisher/gnupg
runuser -u <web-user> -- test -r /etc/php-pkg-publisher/github.token
```

The flag must show as `i` in the listing of `<docroot>`, and nothing in it may belong to another
user (the second command must print nothing):

```sh
lsattr -d <docroot>
find <docroot> ! -user root -print
```

As a further limit, set PHP's `open_basedir` for the site to `<docroot>`, the nudge directory, the
webhook secret folder and `/tmp`: the receiver needs no other path (`/tmp` is for PHP itself), and
a script that breaks cannot then read or write elsewhere.

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

## Starting, stopping and recovering the units

Install the six files of `deploy/systemd/` into `/etc/systemd/system/`, then enable the path unit
and the two timers. Never enable the service itself: they start it.

```sh
systemctl daemon-reload
systemctl enable --now php-pkg-publisher.path php-pkg-publisher.timer php-pkg-publisher-watch.timer
```

How a run ends:

| Exit status | Meaning |
|---|---|
| 0 | Done. |
| 1 | A pass failed, or the alert file is unusable. The nudge was handled and is not put back; the daily timer is the next try, and an alert says why. |
| 143 | The run was stopped (a stop, a reboot). It put its nudge back and the unit does not count 143 as a failure. The one-hour timeout also ends the run with 143 and puts the nudge back, but systemd records it as a failed unit and an alert follows. |

A run that raises also puts its nudge back, so the path unit starts it again at once. Systemd
allows five starts within ten minutes and refuses the sixth (the journal says "Start request
repeated too quickly"); the path unit fails too, so webhooks no longer start runs (the daily timer
keeps trying). The watch alerts
`nudge-stale` when the nudge file is older than 2 hours. Find the cause in
`journalctl -u php-pkg-publisher.service`, then clear the limit and start watching again:

```sh
systemctl reset-failed php-pkg-publisher.service php-pkg-publisher.path
systemctl start php-pkg-publisher.path
```

To stop publishing for good, stop the path unit and the timer. A run in progress goes on until it
ends; `systemctl stop php-pkg-publisher.service` ends it (exit 143).

```sh
systemctl disable --now php-pkg-publisher.path php-pkg-publisher.timer
```

A stopped run leaves its nudge file, and the receiver keeps making one for every release, so
nothing takes it. The watch then sends `nudge-stale` once a day. Either stop the watch as well
(`systemctl disable --now php-pkg-publisher-watch.timer`) or take the webhook out of the web
server and remove the nudge file.

The web server's group may create entries in the nudge directory. If one named `sync` is not a
file, the run sets it aside as `sync.rejected-` and a number, logs an error and goes on. Nothing
removes them: look at what the web server's user put there, then delete them as root.

```sh
ls -l /var/lib/php-pkg-publisher/nudge
rm -r /var/lib/php-pkg-publisher/nudge/sync.rejected-*
```

## A stored file is missing

The publisher keeps in `<site-root>/store/` every hash-named file that a client holding the index of
one of the last three generations may still ask for. When such a file is missing or damaged, a run
restores it from the newest kept tree under `<site-root>/versions/` that still has its right bytes,
or replaces it with the copy of the build it is making, and sends a `store-repaired` alert (not
urgent). Nothing needs doing except finding out what removed or damaged the file, such as a power
cut or a clean-up that went too far.

When no kept tree has the file either, the file is gone: clients that hold the index of an older
generation cannot fetch it from the served tree, and refusing to publish would help none of them
and would stop the re-signing. The run goes on without that file and sends an urgent
`store-lost` alert, repeated once a day while that older index is still one of the last three
generations. The alert counts the files and names none. The clients concerned fetch the new index
and carry on, so there is nothing to restore; find out what removed the file.

## Yanking a release

Add an entry for the product and tag to `exclude.yml`, then start a `run` (see above):

```yaml
exclude:
  - {product: <repo>, tag: <tag>}
```

The next run builds the repository without that tag, even if it was admitted before. The product
must be listed in `products.yml`. Remove the entry to bring it back.

An entry whose tag GitHub does not list for the product and the publisher never admitted (usually
a typo) yanks nothing: the run sends an urgent `exclusion-unmatched` alert once a day until the
entry is corrected or removed.

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

## Releasing

A release is a signed tag on `main`:

1. In `CHANGELOG.md`, move the entries of `## [Unreleased]` under a new
   `## [<version>] - YYYY-MM-DD` heading, and merge that change to `main`.
2. Check the notes the release will carry. This fails in the same way the workflow does:

   ```sh
   python3 tools/release_notes.py v<version>
   ```

3. Tag the merge commit, signed, and push the tag:

   ```sh
   git tag -s v<version> -m "Release v<version>"
   git push origin v<version>
   ```

The `Release` workflow starts on the pushed tag, runs every CI gate, and then makes the GitHub
Release titled `PHP Package Publisher – v<version>` with those notes. It makes no release when
the tag is not `vX.Y.Z` (no leading zeros), is not an annotated tag, is not on `main`, when the
changelog has no dated section for it, or when `[Unreleased]` still has entries. It does not
deploy, and it does not check the tag's signature: the host does that before it uses a tag, as
described below.

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
   files in the home. Prepare the secret subkey as in step 6 of "Setting up the host": the signer
   needs one with no passphrase.
3. At least 120 days after step 1, and at least 21 days before the old subkey expires, change
   `signing.fingerprint` (and `signing.certificate`) to the new subkey. Never sign with both. The
   publisher refuses a subkey that expires within 14 days of a run, so the old subkey is already
   unusable at 14 days left and 21 leaves a week of margin.
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
