# Runbook

How to configure the publisher and the commands you use day to day. It covers what runs on the
publishing host as the publisher user, and how to start, stop and recover its systemd units; web
server and CDN steps are host-specific and are not here. Placeholders in angle brackets are yours to fill in:
`<publisher-user>`, `<site-root>`, `<docroot>`, `<docroot-parent>`, `<origin-public-ip>`, `<repo>`,
`<tag>`, `<generation>`, and for the deploy `<deploy-user>`, `<deploy-public-key>`,
`<release-public-key>`, `<deploy-key-file>`, `<origin-host>`, `<ssh-port>`, `<bundle-file>`,
`<keyring-file>`.

## What runs

| Unit | Role |
|---|---|
| `php-pkg-publisher.service` | One publisher run: admit new releases, then build, sign and publish. |
| `php-pkg-publisher.timer` | Starts the service daily. |
| `php-pkg-publisher.path` | Starts the service when the webhook receiver creates the nudge file. |
| `php-pkg-publisher-watch.service` | The hourly watch; it shares no code path with the run. |
| `php-pkg-publisher-watch.timer` | Starts the watch hourly. |
| `php-pkg-publisher-notify@.service` | Tells the operator that the named unit failed. |
| `php-pkg-publisher-deploy-check.service` | Compares the host with what the last deploy wrote; it fails, and the failure is alerted, when anything differs. Runs as root. |
| `php-pkg-publisher-deploy-check.timer` | Starts the check hourly. |

The publisher's units run as `php-pkg-publisher`, from `/opt/php-pkg-publisher`, with the settings
in `/etc/php-pkg-publisher/publisher.yml`. The deploy check runs as root, because the docroot
belongs to the site (see "Deploying a change"). They are in `deploy/systemd/`.

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
`<web-group>` below is its group) creates the nudge file, its own throttle and delivery-id
directories and a small count file of repeated deliveries (`duplicates`) in it, and the publisher
removes the nudge file and only reads the count file. The parent directory lets that group in but
not read.

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

Do these steps in order, as root, from a checkout of the release tag you will deploy (step 7
checks its signature before anything from it is installed). The commands were run on a clean
Ubuntu 22.04 container; what the web server and systemd do with the result is checked on the
staging site, not here. `<docroot>` is the web server's document root for the site; `<site-root>`
is outside it. Nothing from the checkout is copied by hand except the deploy script (step 7): the
first deploy (step 8) installs the code, `products.yml`, the units and the two web files, so every
later deploy replaces exactly what the first one put there.

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

2. Create the publisher user and its directories, with the commands of the section above.

3. Put the settings in `/etc/php-pkg-publisher/`. `products.yml`, the file `publisher.yml` points
   at, is not among them: it comes with the first deploy, owned by root and mode `0644`.

   | File | Owner, mode | Content |
   |---|---|---|
   | `exclude.yml` | root, `0644` | `exclude: []`. A missing file stops every run. |
   | `publisher.yml` | root, `0644` | The settings above, filled in. |
   | `rpm-signing.asc`, `signing-certificate.asc` | root, `0644` | Public keys only. |
   | `github.token`, `telegram.conf` | `<publisher-user>`, `0600` | The secrets above. |

   ```sh
   install -m 0644 /dev/null /etc/php-pkg-publisher/exclude.yml
   printf 'exclude: []\n' > /etc/php-pkg-publisher/exclude.yml
   install -m 0644 <rpm-key-file> /etc/php-pkg-publisher/rpm-signing.asc
   install -m 0644 <certificate-file> /etc/php-pkg-publisher/signing-certificate.asc
   install -m 0600 -o <publisher-user> <token-file> /etc/php-pkg-publisher/github.token
   install -m 0600 -o <publisher-user> <alert-file> /etc/php-pkg-publisher/telegram.conf
   ```

4. Store the webhook secret where the receiver reads it. The folder lets the web server's group in
   and no one else; the secret must hold at least 16 bytes:

   ```sh
   install -d -m 0750 -o root -g <web-group> /etc/php-pkg-publisher-webhook
   install -m 0640 -o root -g <web-group> <webhook-secret-file> /etc/php-pkg-publisher-webhook/secret
   test "$(wc -c < /etc/php-pkg-publisher-webhook/secret)" -ge 16
   ```

5. Import the signing subkey. The signer needs a subkey with no passphrase, so remove the
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

6. Lock the docroot. The deploy (step 8) puts the two web files in it: `sync.php`, which the rule
   in `.htaccess` serves as `/hooks/sync`, and `.htaccess`. Root owns every file there: the
   publisher never writes in `<docroot>` (it flips `current` inside `<site-root>`) and the web
   server's user only reads. Root makes the two links once; they point into `<site-root>`, so the
   links never change. `keyring/` holds the two keyring packages, built offline and placed by hand;
   record each with the deploy script (see "Deploying a change").

   Two locks keep the web server's user from replacing the folder, and with it the redirect rules
   and the keyring packages: `<docroot-parent>` is owned by root, so nobody else can rename
   `<docroot>`, and `<docroot>` carries the immutable flag, which stops a rename, a delete and any
   new entry in it, even by its owner. `<docroot>` must already exist and hold only the site's
   files: the commands make root the owner of everything in it, and the deploy check reports every
   entry except `.htaccess`, `sync.php`, `apt`, `rpm` and `keyring`, so remove a panel's default
   files first. The site user can no longer create entries in `<docroot-parent>`, so anything it
   must write there (logs, caches, uploads) has to live in folders it already owns or somewhere
   else. The flag needs a file system that supports it (ext4 and xfs do), and a tool that writes
   into `<docroot>`, such as a certificate client leaving challenge files there, then fails: keep
   those files elsewhere. The deploy clears the flag and sets it again around its own writes: do
   not change files here by hand. A control panel may reset an owner, a mode or the flag when it
   fixes permissions: run the check below after any panel action.

   ```sh
   chown root:root <docroot-parent>
   chmod 0755 <docroot-parent>
   chattr -i <docroot>
   install -d -m 0755 -o root -g root <docroot> <docroot>/keyring
   ln -s <site-root>/current/apt <docroot>/apt
   ln -s <site-root>/current/rpm <docroot>/rpm
   chown -hR root:root <docroot>
   chmod -R go-w,a+rX <docroot>
   chattr +i <docroot>
   ```

   The two links are made once: on a repeat, leave out the `ln` lines.

7. Set up the deploy: the user the release workflow logs in as, its locked key, the one sudo line,
   the files the script reads, and the script itself, which is the only file you copy by hand.
   `<deploy-public-key>` is the public half of a new key pair made for this alone (see "Deploying a
   change"), written as the key type and the key, such as `ssh-ed25519 AAAA...`, with no comment.
   `<release-public-key>` is the public half of the key you sign release tags with, in the same
   form. The user needs `/bin/sh`: sshd runs the forced command through the shell of the user, and
   a `nologin` shell refuses it. Its password stays locked, as `useradd` leaves it, which needs
   `UsePAM yes` in sshd (the default on Debian and Ubuntu, and the setting this was run with:
   `sshd -T` prints `usepam yes`). The sudoers line is written to a temporary file and installed
   only if `visudo` accepts it, because a broken file in `/etc/sudoers.d` stops sudo for everyone.
   The key allows one thing: it runs the script, through sudo, with no arguments, and with no
   terminal and no forwarding (`restrict`); sudo allows that one command with no arguments (the
   empty `""`). The folder of the state may be entered by everyone (`0711`), because the new code
   is read, as the publisher user, from a folder inside it before anything is replaced; the
   backups stay closed.

   ```sh
   useradd --create-home --shell /bin/sh <deploy-user>
   install -d -m 0700 -o <deploy-user> -g <deploy-user> /home/<deploy-user>/.ssh
   install -m 0600 -o <deploy-user> -g <deploy-user> /dev/null /home/<deploy-user>/.ssh/authorized_keys
   printf '%s\n' 'restrict,command="/usr/bin/sudo /usr/local/sbin/php-pkg-publisher-deploy" <deploy-public-key>' \
     > /home/<deploy-user>/.ssh/authorized_keys
   sudoers="$(mktemp)"
   printf '<deploy-user> ALL=(root) NOPASSWD: /usr/local/sbin/php-pkg-publisher-deploy ""\n' \
     > "$sudoers"
   visudo -cf "$sudoers" && install -m 0440 "$sudoers" /etc/sudoers.d/php-pkg-publisher-deploy
   rm "$sudoers"
   install -d -m 0755 /etc/php-pkg-publisher-deploy
   install -m 0644 /dev/null /etc/php-pkg-publisher-deploy/deploy.conf
   printf 'docroot=<docroot>\nsite_root=<site-root>\n' > /etc/php-pkg-publisher-deploy/deploy.conf
   install -m 0644 /dev/null /etc/php-pkg-publisher-deploy/allowed_signers
   printf 'php-pkg-publisher-release namespaces="git" <release-public-key>\n' \
     > /etc/php-pkg-publisher-deploy/allowed_signers
   install -d -m 0711 /var/lib/php-pkg-publisher-deploy
   install -d -m 0700 /var/lib/php-pkg-publisher-deploy/backups
   ```

   If sshd has an `AllowUsers` or `AllowGroups` line, it must name `<deploy-user>`.

   Then install the script from your checkout. It is the one file the deploy cannot check for
   itself, because root runs it before any deploy has happened, so check the tag first against
   the signer file just written, with the same settings the script uses: only an SSH signature
   counts (a tag signed with OpenPGP would otherwise be checked by `gpg` against root's own
   keyring), the global and system git configuration is not read, the settings that choose the
   program that checks are fixed on the command line (so the checkout's own configuration cannot
   swap it for one that always agrees), and the name inside the signed tag must be `<tag>` (git
   checks the signed object, not the name it is stored under). The file installed is the one in
   the tag itself, read with `git cat-file`, not the file in the working tree, which `git diff`
   can be told to ignore. Read the exit status, not the first line: for a valid signature by a
   key that is not in the file, git prints `Good "git" signature`, then `No principal matched.`,
   and exits 1. Every step of the block depends on the one before it (`set -e` would not do
   this: bash ignores it in a subshell that is followed by `||`), so it stops at the first one
   that fails and then prints `script not installed`. The checkout must be made as root: git
   refuses one that belongs to another user (`dubious ownership`), and `safe.directory` must not
   be set to get around that.

   ```sh
   (
     script="$(mktemp)" && trap 'rm -f "$script"' EXIT \
       && env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git \
         -c gpg.format=ssh \
         -c gpg.ssh.allowedSignersFile=/etc/php-pkg-publisher-deploy/allowed_signers \
         -c gpg.ssh.program=/usr/bin/ssh-keygen \
         -c gpg.program=/bin/false -c gpg.openpgp.program=/bin/false -c gpg.x509.program=/bin/false \
         verify-tag <tag> \
       && test "$(git for-each-ref --format='%(tag)' refs/tags/<tag>)" = <tag> \
       && git cat-file blob <tag>:deploy/pkg_deploy.py > "$script" \
       && install -m 0755 "$script" /usr/local/sbin/php-pkg-publisher-deploy
   ) || { echo 'script not installed' >&2; false; }
   ```

8. Deploy the first tag by hand, from the same checkout. This installs the
   code in `/opt/php-pkg-publisher/publisher`, `products.yml`, the units and the two web files,
   and records them, so that later deploys and the check know what they put there. It prints
   `deployed <tag>`. Then enable the units, with the deploy check last, as in "Starting,
   stopping and recovering the units":

   ```sh
   git bundle create <bundle-file> refs/tags/<tag>
   /usr/local/sbin/php-pkg-publisher-deploy < <bundle-file>
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

Every command except `status` takes the same exclusive lock as a run and waits for it, then stops
if it cannot get it, so two of them never change state at once.

| Command | Use |
|---|---|
| `run` | Admit new releases and publish. The timer and the nudge do this. |
| `rollback <generation>` | Re-sign an older generation's content as a new generation and pin it. Generation ids are the directory names in `<site-root>/versions/` (the same names with `.json` added are in `<site-root>/generations/`; pass the name without it): an 8-digit sequence number, a dash and a UTC time stamp. While pinned, runs re-sign the pinned content and hold new releases back; excluding a release the pin lists drops the pin and alerts. |
| `clear-pin` | End a rollback; the next run publishes the admitted state again. |
| `requeue <repo> <tag>` | Lift a failure or a quarantine so the next run tries the tag again. It refuses a tag with no recorded failure. |
| `status [--json]` | Show whether a run is working and what was accepted, what failed and what was repeated. It changes nothing. |

A tag that fails is retried. Once it has failed at least 5 times and the first failure is at least
3 days old it is quarantined and alerts. Fix the cause (an unsigned asset, a missing bundle) and
`requeue` it.

`status` takes no lock, creates nothing and changes nothing, so it is safe while a run is working.
Run it as `<publisher-user>` the same way: the state is closed to everyone else, and another user
sees `unreadable` where the state should be. Exit status 0 means that the view was printed. It
shows, with every time in UTC:

| Line | Meaning |
|---|---|
| `publisher: working` | A run, or a `rollback`, `clear-pin` or `requeue`, holds the lock. `idle` when none does, `unknown` when the lock file cannot be opened. |
| `run requested: yes` | The nudge file is there: a run was asked for and has not started. |
| `accepted (newest 5 of N)` | Per product, the 5 tags admitted last and when. |
| `failed` | Per product, each failed tag with its attempts and its next try (`retry due` when the next run tries it), or `quarantined`, which waits for `requeue` or an exclusion. The reason is cut short and holds no path. |
| `repeated deliveries` | How often GitHub's delivery id came again within 120 seconds, and the last time. The receiver counts them in `duplicates` in the nudge directory. A redelivery after 120 seconds nudges again and is not counted. The count is a total since the file was made; removing the file as root resets it. |

`status --json` prints the same facts as JSON (`publisher`, `run_requested`, `products` and
`repeated_deliveries`).

## Starting, stopping and recovering the units

The first deploy installs the eight files of `deploy/systemd/` into `/etc/systemd/system/`. Then
enable the path unit and the three timers. Never enable the services themselves: the path unit and
the timers start them. Enable the deploy check only after the first deploy: before it, the check
fails with "no deploy recorded", and the failure is alerted every hour.

```sh
systemctl daemon-reload
systemctl enable --now php-pkg-publisher.path php-pkg-publisher.timer php-pkg-publisher-watch.timer
systemctl enable --now php-pkg-publisher-deploy-check.timer
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

3. Tag the merge commit, signed with the SSH key whose public half is the `<release-public-key>` in
   `allowed_signers` on the host (`gpg.format` is `ssh` and `user.signingkey` names that key), and
   push the tag:

   ```sh
   git tag -s v<version> -m "Release v<version>"
   git push origin v<version>
   ```

The `Release` workflow starts on the pushed tag, runs every CI gate, and then makes the GitHub
Release titled `PHP Package Publisher – v<version>` with those notes. It makes no release when
the tag is not `vX.Y.Z` (no leading zeros), is not an annotated tag, is not on `main`, when the
changelog has no dated section for it, or when `[Unreleased]` still has entries. After the
release, its `deploy` job sends the tag to the host. The workflow does not check the tag's
signature: the host does that before it uses a tag, as described below. Do the GitHub setup of
"Deploying a change" before the first tag: until then, a tag makes the release and the deploy job
fails.

## Deploying a change

A pushed tag deploys itself, and the host never pulls. After the `Release` workflow has made the
release, its `deploy` job sends a `git bundle` of the tag over ssh to the host, to the locked key
of step 7 of "Setting up the host". The host does not trust the job. The script accepts a bundle
only when it holds exactly one ref, an annotated tag named `vX.Y.Z` whose signed name is the same,
signed by the key in `allowed_signers`, and the version is not older than the last deploy and was
not rolled back. Only then does it read the known files from the signed commit, load the new
`products.yml` as the publisher user, stop the units, replace each file by a rename, replace
itself last, and start the units again. Whatever fails after the first file changed puts the
backup back. The signing key never leaves you: what GitHub holds can only carry bundles.

### Before the first tag

1. Make a key pair for this alone, never the key that signs tags. Its public half is the
   `<deploy-public-key>` of step 7; its private half goes into a GitHub secret and nowhere else:

   ```sh
   ssh-keygen -q -t ed25519 -N '' -f <deploy-key-file>
   ```

   Delete the file once the secret is saved.

2. In the repository's settings, create the environment `production` and limit its deployment
   tags to `v*`. Do this first: GitHub creates an environment that a workflow names but that does
   not exist yet, with no rule at all.

3. Add three secrets to that environment (not to the repository):

   | Secret | Content |
   |---|---|
   | `DEPLOY_SSH_KEY` | The private key of step 1, whole. |
   | `DEPLOY_KNOWN_HOSTS` | The host key line below. |
   | `DEPLOY_TARGET` | `ssh://<deploy-user>@<origin-host>:<ssh-port>`, or without `:<ssh-port>` for port 22. |

4. Take the host key line from the host itself, never from a scan over the network. On a port
   other than 22 the line names the host in brackets with the port, as the `known_hosts` format
   has it; on port 22 it is the bare host. Both forms were run against OpenSSH 8.9, each with its
   own target:

   ```sh
   printf '[<origin-host>]:<ssh-port> %s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
   printf '<origin-host> %s\n' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
   ```

5. `<origin-host>` must reach sshd directly: the public name of the site is behind a CDN that
   carries no ssh, so use the origin's address or a name the CDN does not proxy. The port must
   accept GitHub-hosted runners, whose addresses are many and change.

### What the log shows

The workflow log of a public repository is public, so the host prints one fixed line and ssh is
quiet; the detail goes to the journal (`journalctl -t php-pkg-publisher-deploy`). Anything but the
first row is a failed job:

| Line | Exit | Meaning |
|---|---|---|
| `deployed <tag>` | 0 | Done. The same tag again changes nothing and prints this too. |
| `refused: <code>` | 2 | Nothing changed. The code says why (below). |
| `refused: rolled-back` | 3 | A step failed after files changed and the backup was put back; the units run again. |
| `refused: step-failed` | 2 or 3 | A command failed, or an unexpected error; look in the journal. |
| `broken: restore failed` | 4 | The backup could not be put back either: see "A deploy that did not finish". |
| nothing | 255 | ssh could not log in: the host key, the key, the target or the network. |

| Code | Meaning |
|---|---|
| `bundle-invalid` | Not a bundle, one that does not verify, or one that cannot be fetched. |
| `bundle-size` | Over 64 MiB. |
| `config-invalid` | `deploy.conf` or `allowed_signers` is missing, not root's, writable by others, or malformed. |
| `host-busy` | A deploy, a rollback or a command is running. Run the job again. |
| `not-root` | The script was not started as root. |
| `products-invalid` | The new `products.yml` does not load, or the publisher user cannot read the new code (the state folder must be `0711`). |
| `ref-invalid` | The bundle does not hold exactly one `refs/tags/vX.Y.Z`. |
| `rolled-back` | As above. |
| `signature-invalid` | The tag is unsigned or not signed by the key in `allowed_signers`. |
| `state-invalid` | The state folder, the manifest, a backup or the marker is wrong, or an earlier deploy did not finish. |
| `step-failed` | A command failed, such as `git`, or an unexpected error. |
| `tag-invalid` | A lightweight tag, a signed name that differs from the ref, or a name that is not `vX.Y.Z`. |
| `target-invalid` | A file the deploy would replace is not a regular file. |
| `tree-invalid` | The commit holds a link, a missing required file, a stray unit file, or a file over the size limits. |
| `usage` | A wrong local command, or a rollback with no backup. |
| `version-denied` | That version was rolled back; `allow` lifts the ban. |
| `version-older` | Older than the last deploy. |

### Commands on the host

Run them as root. Each takes the lock of a deploy, so a command and a deploy never overlap.

| Command | Use |
|---|---|
| `php-pkg-publisher-deploy rollback` | Undo the last deploy, or finish undoing one that did not end. It bans that version, so a replay of its tag is refused, and uses up its backup, so a second rollback goes one deploy further back. The 5 newest backups are kept. |
| `php-pkg-publisher-deploy allow v<version>` | Lift the ban on a version that was rolled back. |
| `php-pkg-publisher-deploy check` | Compare the host with the last deploy: the hash, owner and mode of every file it wrote, the immutable flag, the folder above the docroot, the two links, every entry in the docroot and the code, and the keyring packages. It prints one `FAIL:` line for each difference and exits 1, or prints `DEPLOY CHECK PASSED`. The hourly timer runs it, and a failure is alerted. While a deploy runs it prints that it skipped and exits 0. |
| `php-pkg-publisher-deploy record <keyring-file>` | Record the hash of a keyring package you placed in `<docroot>/keyring`, owned by root and writable by no one else. The flag on `<docroot>` does not stop entries inside `keyring/`, so the check would report an unrecorded file. |
| `php-pkg-publisher-deploy forget <keyring-file>` | Drop that record, after you removed the file. |

### A deploy that did not finish

A deploy that is cut off, or whose restore failed, leaves a marker, and every later deploy is
refused with `state-invalid` until `rollback` has run. The hourly check says so too, once its
timer runs again (a deploy stops it, and a cut-off deploy leaves it stopped). The units
were stopped for the deploy, and `rollback` starts only what it found running, so start them
again by hand once it has finished:

```sh
php-pkg-publisher-deploy rollback
systemctl start php-pkg-publisher.path php-pkg-publisher.timer php-pkg-publisher-watch.timer php-pkg-publisher-deploy-check.timer
```

`rollback` bans the version it undid, so the same tag is refused with `version-denied` when the
job runs again. Run `php-pkg-publisher-deploy allow v<version>` first, or deploy a newer tag.

### Deploying by hand

When GitHub cannot run the job, do what step 8 of "Setting up the host" does with the new tag: make
its bundle in a checkout and give it to the script as root. Every check of the script still runs.

```sh
git bundle create <bundle-file> refs/tags/<tag>
/usr/local/sbin/php-pkg-publisher-deploy < <bundle-file>
```

### Changing the release key

The key in `allowed_signers` is the root of trust of the deploy. To change it, edit that file on
the host to hold the new `<release-public-key>`; a tag signed by the old key is refused from then
on. Do it as part of the change that moves the signing to the new key.

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
   files in the home. Prepare the secret subkey as in step 5 of "Setting up the host": the signer
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
