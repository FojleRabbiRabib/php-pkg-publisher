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
- Metadata signer: signs `InRelease`, `Release.gpg` and every `repomd.xml.asc` with exactly one
  configured signing subkey, one signature per file. Each signature is checked against the pinned
  public certificate that clients receive (the keyring), so a key that differs from the shipped
  keyring fails the run and not every client: one good signature, by that subkey of the pinned
  primary key, SHA-256, close to the clock, and `InRelease` carrying exactly the `Release` text.
  It refuses a signing home that holds the primary secret key, a subkey that is expired, revoked
  or missing from the certificate, a subkey or primary key that expires before the `Release` stops
  being valid, and a subkey that would need a passphrase. It signs a private copy of each file and
  refuses if the file changed meanwhile, writes nothing until every signature has passed, writes
  the signatures and `Release` world-readable (0644), and fails if it cannot stop the `gpg-agent`
  it started.
- Generation publisher: turns a signed tree into the newest generation (`versions/<id>/apt` and
  `rpm`) and flips `current` with a temporary symlink renamed into place. Hash-named files
  (`by-hash/SHA256|SHA512/*`, `repodata/<sha256>-*`) are hard-linked into a shared store and
  carried into every new tree while one of the last three generations lists them or they are
  under seven days old, so an index fetched before a publish is still served after it; what a
  generation lists is read from its own `Release` and `repomd.xml`. The new tree must resolve
  every path named by the last three generations before the flip, `current` must be a link to a
  generation, generations are ordered by a sequence number and not by the clock, and a crashed
  run is cleaned up by the next one. Only the newest three trees are kept; a manifest of each
  generation's content set (60 kept) feeds rollback and skips a publish when the content is
  unchanged and under a day old. `rollback` rebuilds and re-signs an older content set as a new
  generation and pins the site to it until the pin is cleared; it refuses a set that lists an
  excluded release, and a release excluded later drops the pin and is never published. The new
  tree is flushed to disk before the flip, a clean-up failure after the flip is reported and not
  raised, and manifests and pins are read strictly (no boolean or NaN numbers, no links).
- Publisher settings and run command: `publisher.yml` (strict, no defaults, absolute normal paths,
  the six working directories distinct and none inside another, no keys or pins inside a tree a
  run rewrites) names where the publisher works and which keys it uses, and holds no secret.
  `python -m publisher --config publisher.yml run | rollback ID | clear-pin` takes the run lock
  and makes passes while nudges arrive; each pass refreshes the trusted root, admits, and then
  publishes from what is admitted even if admitting stopped. Each pass reports its alerts as it
  ends, so a later failing pass cannot lose them. A fault while setting up the admit stage (trusted
  root, token, RPM key) stops only that stage, so the daily re-sign still runs. A run exits 1 when
  the admit stage stopped, publishing failed or anything raised; a failed tag, a quarantine, a pin dropped by an exclusion
  and a clean-up failure after the flip alert without failing the run. Alert text is ASCII, capped
  and free of host paths and key fingerprints; a pinned site says so in every publish alert.
- Operator alerts: each pass sends its alerts as plain-text Telegram messages (urgent first, split
  into several messages instead of cut, at most five a pass) through the Bot API over https only,
  with no proxy, redirect or retry, a bounded reply and a deadline. The credentials file
  (`alert.file` in `publisher.yml`: `chat_id=` and `token=`, one line each) must be private to
  the user, a regular file and not a link; the bot token is part of the request URL, so no error
  text is built from the URL, errors are not chained and the token is scrubbed from every message.
  An event that repeats on every full listing (`changed`, `vanished`) is said once a day; it is
  remembered only after the message that carried it was accepted, and forgotten when a pass no
  longer has it. A failed delivery never fails the run: every undelivered alert goes to the
  journal in full and is tried again on the next run. The credentials are checked on every pass,
  so a broken file fails the run before the day an alert is needed. `python -m
  publisher.notifier --alert-file F --unit NAME` is the failure notifier for `OnFailure=`: it
  imports only the sender, takes the path as its own argument and sends fixed text, so a broken
  `publisher.yml` cannot silence it.
- Signing-subkey expiry alert: a publish that signs reports when the subkey (or the primary key,
  whichever ends first) has fewer than 30 days left. The text also says when signing stops,
  because the signer refuses a key that ends before the new `Valid-Until`, 14 days earlier. The
  alert is urgent and repeats on each publish that signs, which happens at least daily.
- Hourly watch, `python -m publisher.watch --config publisher.yml`: shares no schedule and no
  publish module with the daily run. It alerts, once a day for each, when the GitHub token has
  fewer than 30 days left (the date is in `publisher.yml`), when the origin certificate, read by
  connecting to the origin address with the public name, has fewer than 21 days left or does not
  verify, when the served `InRelease` `Date` is older than 3 days (or in the future), when its
  `Valid-Until` is less than 7 days away, and when the file cannot be fetched or read. It uses its
  own alert memory and exits 1 on unusable settings or credentials.
- systemd units in `deploy/systemd`: the publisher service (started by a daily 03:17 UTC timer and by
  a path unit on the nudge file), the hourly watch service and timer, and a notifier template
  that every service and the path unit name in `OnFailure=` with `%n`. All run as the
  `php-pkg-publisher` user, one shot, with a start timeout (the notifier's is 60 seconds), a
  strict file-system fence and no capabilities. The publisher alone may write the site tree; the
  watch may write only the state directory; the notifier reads only `/etc/php-pkg-publisher`.
  A start limit of five in ten minutes stops a failed run's restored nudge from restarting the
  publisher for ever. The notifier gets `%i`, because `%I` would turn the dashes of the unit name
  into slashes.
- Webhook receiver `web/sync.php` (PHP 8.3, one file, no dependencies): answers a fixed
  status with an empty body, checks in order the method (405), a per-address throttle of 20 posts
  a minute (429), `Content-Length` and a 1 MiB body cap (413), the `X-Hub-Signature-256` HMAC
  (401), the event and action (ping, other events and other actions get 200), the delivery GUID
  (400 if malformed; a repeat inside 120 s gets 200 and no second nudge), then touches the nudge
  file (202). The secret is read from `/etc/php-pkg-publisher-webhook/secret` and the state
  (`thr/`, `guid/`, `sync`) lives in `/var/lib/php-pkg-publisher/nudge`. Both tables stop growing
  at 1000 entries and stale entries are removed twenty at a time. A delivery is remembered only
  after its nudge was made. PSR-12 (`phpcs.xml`, phpcs 4.0.4), PHPStan 2.3.5 at level max (`phpstan.neon`), both pinned in
  `composer.json` and `composer.lock` and run by pre-commit, and a PHP-driven test file pin the
  behaviour. The throttle keys an IPv4 address, or an IPv6 /64, whatever its spelling. A nudge
  the receiver cannot open still counts as success (the publisher may have re-created it), a
  link is refused, and a missing nudge directory is a 500: the operator creates it.
- OpenLiteSpeed docroot `.htaccess` template, `web/docroot.htaccess`: three rules and nothing
  else. A request line that names a `.php` file, also written with percent-escapes (`.p%68p`,
  `%2ephp`, `.php%2fx`), is a 404; `/hooks/sync` is served by the
  receiver; `/pool/<product>/<tag>/<file>` and `/apt/pool/...` are a 302 to the GitHub release
  asset under one fixed owner. The patterns are allow-lists held to the publisher's own repo name,
  release tag and asset name rules (compared character for character by a test), and reject
  uppercase products, dot segments, leading zeros and encoded slashes.
- Negative test layer, `tests/negative/`: whole publisher passes over throwaway keys and real
  debs and rpms, with only the release feed, the download, the Sigstore refresh and `cosign`
  faked. Each case reads the published tree back as a client would (`gpgv` on `InRelease`,
  `Release.gpg` and the six `repomd.xml.asc`, and the package lists from `Packages` and the
  `primary.xml` that `repomd.xml` names). It covers eleven kinds of bad release (a package
  changed after signing, bundles of another repo or tag, a missing bundle or package, a wrong
  `SHA256SUMS`, an unsigned rpm or one signed by another key, a deb of another version, a
  mutable release), an `-rc` tag with or without the prerelease flag, a tag that fails while a
  later one is valid, a product that fails while
  another publishes, a download that fails once, an unreachable Sigstore, 20 daily passes
  with the admit stage down, a yanked release, a rollback, a second run while one is running,
  and a nudge that arrives during a run.
- Container test layer, `tests/container/`, run with `pytest -m container` (bare `pytest` skips
  it; it needs docker and the pinned images pulled first, see the README): a real `apt` or `dnf`
  in each of Ubuntu 22.04, 24.04 and 26.04, Debian bookworm and trixie, AlmaLinux 8, 9 and 10
  and Fedora 44 (images pinned by digest), for PHP 8.3, 8.4 and 8.5, installs from a tree built
  by the real pass. A local mirror serves the tree and applies the shipped
  `.htaccess` redirect rule to a stand-in for GitHub's downloads. Each client installs through the
  redirect, refuses metadata with one flipped byte (`InRelease`/`Release`, or `repomd.xml.asc`)
  while a new release is published, upgrades once the metadata is intact, and sees the older set
  after a rollback. The client trusts the repository key and the RPM key, as a user's would.
  The packages are fakes, so `php -m` is left to the product repositories.
- CI gates for the receiver and the test layers: the `static` job installs the PHP tools from
  `composer.lock` (PHP 8.3 and Composer 2.11.1, pinned by checksum, through a setup action pinned by commit SHA) and runs
  `php -l`, phpcs and phpstan next to the pin lint, ruff, mypy, the unit and negative tests and
  the pre-commit hooks (and `shellcheck setup.sh`). The container layer runs as one
  `container-image` job per pinned image, each pulling only its own image, plus a `rest` job for
  any container test that names no image, and a `container` job that passes only when all of them
  passed (the check name branch protection requires). The jobs share one local setup action
  (Python 3.10, the hash-pinned development tools and the verification tools, `cosign` by
  checksum). A container run stops at the start with a named error when the disk has less than
  1.5 GiB free, the headroom above the admit stage's floor.
- Keyring packages and their builder, `tools/build_keyring.py` with the sources in `keyring/`:
  `rabib-archive-keyring` (a deb for apt) and `rabib-release` (a noarch rpm for dnf), built from a
  public certificate, a primary fingerprint and the repository and RPM signing subkeys, with
  versions like `2026.1`. The apt keyring holds the primary key and the repository subkeys only, so
  apt trusts no signature by the RPM subkey and a key rotation needs no change to the sources
  entry. The rpm installs `RPM-GPG-KEY-rabib` with the primary key and both subkeys and deletes the
  `rabib-*` repository key caches of dnf and dnf5 after a transaction, which EL10 and Fedora need
  after a key change. It does not import the key: rpm 6 (Fedora 44) cannot import inside a
  transaction, and dnf imports the key from the `.repo` file. The builder refuses secret key
  material, a wrong primary fingerprint, a missing, expired or revoked key, a subkey that cannot
  sign, a subkey named for both jobs, a bad version, and a maintainer outside `Name <address>` (a
  `%` is refused, because `rpmbuild` would run a `%(command)` in the changelog). Nothing is left
  in the output on failure: files are staged before any rename, and a directory the run created is
  removed. It reads the exported keys back and requires the exact set. It signs the rpm with
  exactly one RPM subkey from an offline key home, checks the result against the certificate and
  the key id, and stops the gpg-agent it started; or it builds unsigned. The packages are
  byte-identical for the same inputs and carry `LICENSE` and `NOTICE`; the output holds each
  package under its versioned name and under a fixed name (`rabib-archive-keyring.deb`,
  `rabib-release.rpm`) that is always the newest. `lintian --pedantic` reports only the
  `.gpg` extension, which is the name Debian's own archive keyrings use; `rpmlint` reports only the
  key file under `/etc` that is not a config file (a rotation must replace it) and the `rm` of the
  fixed cache glob. The container layer installs the built packages in each of the nine images,
  points `Signed-By:` or `gpgkey=` at the key file the package installed, and checks that the
  published metadata verifies; on dnf it also checks that an install and an upgrade of the keyring
  remove the key caches of a `rabib-` repository and keep those of another, and that the signed
  rpm verifies with the distribution's own `rpmkeys` against the installed key file.
- `setup.sh`, the client setup script (POSIX sh, run as root, no arguments). It detects apt or dnf
  from `/etc/os-release`, refuses an unknown distribution or architecture, downloads the keyring
  package over TLS without following redirects, checks its package name, and installs it. On apt
  it writes a deb822 sources file with `Signed-By:` and runs `apt-get update --error-on=any` over
  that source alone (without deleting the index files of the others); on dnf it imports the key
  outside the transaction, writes one repository section per PHP version (`gpgcheck=1`,
  `repo_gpgcheck=1`), enables the sections of the PHP it finds installed (and keeps those already
  enabled, never disabling one) and refreshes the metadata of those sections alone, with
  `skip_if_unavailable=0`, so another repository that is down cannot stop the script and a
  signature error is an error (measured: dnf5 then exits non-zero by itself; a read of its output
  for the signature error stays as a second check). The enabled sections are read from the
  repository file and from dnf5's override files, where `config-manager` stores them; a section an
  override file turns off explicitly stays off even when its PHP is installed. A refresh that
  fails (or an interrupt before it is confirmed) puts the previous sources or repository file
  back, or removes the new one, and apt's earlier index of ours with it; apt must have fetched a
  fresh index of ours. It installs gnupg when missing, and prints the primary and signing-subkey
  fingerprints with their expiry to compare with the published ones. A re-run changes no byte of
  the files the script wrote: keys added by hand to a section of the dnf repository file (such as
  `priority=50`) are kept, while the keys the script writes and the ones that change what is
  trusted (`pkg_gpgcheck`, `localpkg_gpgcheck`, `mirrorlist`, `metalink`) are not, with a warning,
  and neither are their indented continuation lines or any line that is not `key=value`; a
  symbolic link to either file stays a link, and a dangling link or a directory stops the script. `shellcheck` (pinned as `shellcheck-py`) runs in
  pre-commit and in the CI `static` job. Tests: host-side checks that the script parses under dash and bash and that a
  truncated download runs nothing, and, in all nine images, a full lifecycle (install through the
  redirect, re-run, tampered index refused), the refusals, PHP detection and the gnupg install.
- The manuals in `docs/`. `installation.md` is the client guide for apt and dnf (fingerprint
  comparison first, upgrade, recovery of a server on an old key, removal); its command blocks are
  run in order on all nine images by the container layer, and a unit test checks that the files it
  writes are the files `setup.sh` writes. `security.md` states the trust chain, a cosign command
  for checking a package yourself, key rotation and the limits. `runbook.md` covers the publisher's
  settings, directories, secrets, commands, yanking a release, cosign installation and bump, signed
  tag deployment and key rotation; its example settings load through the real loader and its
  commands, units and quoted numbers are checked against the code. The live one-line install
  command and the host-only steps are not documented yet.
- `python -m publisher --config publisher.yml requeue <repo> <tag>`: lifts a failure or a
  quarantine so the next run tries the tag again. It takes the run lock and refuses a tag with no
  recorded failure.
- Weekly outside watch (`tools/platform_watch.py`, started by hand from the `Platform watch`
  workflow until the site is live): from a runner, it takes the primary key of the served keyring
  package and compares it with the pinned fingerprint, checks that `InRelease` and the six
  `repomd.xml.asc` files verify against that key, that the `InRelease` `Date` is at most 4 days old
  with at least 7 days of `Valid-Until` left, that each signature file was made (by the signature's
  own time) and served (by `Last-Modified`) at most 4 days ago, and that the first listed deb and
  rpm, whose indexes must match the signed `InRelease` and `repomd.xml`, answer a GET with 302 to
  the exact GitHub release asset of a declared product. An empty package list or a placeholder pin
  fails. A failure goes to the chat when the two secrets are set, and fails the run.
- Key drill (`tests/container/test_key_drill.py`, every tested distribution, throwaway keys): a
  client with the first keyring verifies the repository; after the repository switches to the next
  signing subkey it refuses it with the message of its distribution, and after it upgrades the
  keyring package (which lists both subkeys) it verifies and installs. Without the key cache
  clean-up of `rabib-release`, EL10 and Fedora 44 fail the drill.
- `products.yml` entries now require `extension`, the name inside package names
  (`php8.3-<extension>`); two products cannot share one.
- Unit tests for checks that no test covered: the signature status of `InRelease` alone (a wrong
  subkey, another digest, two signatures), the armor shape of a signature, a pinned certificate that
  is a link, the message for an expired primary key, the `Valid-Until` boundary, a quarantined tag
  that a changed listing must not retry, a package in the published tree, a `current` that points
  to a missing generation, a carried store file whose content does not match its name, a key file
  with two certificates, a failed `rpmkeys --import`, a `cosign initialize` that fails but leaves a
  valid file, an asset digest that is not sha256, and three receiver checks (a repeated delivery in
  another letter case, the duplicate window, and the JSON depth cap, on both sides of 16 levels).
- A time limit for every test (`pytest-timeout`: 120 seconds, 20 minutes for a container test), so a
  test that hangs fails with its stack instead of stalling the run.
- Two urgent alerts, each repeated once a day: an `exclude.yml` or `exclude:` entry whose tag is
  neither listed by GitHub nor admitted (a typo yanked nothing, silently), and a product whose
  newest admitted tag has no package for a declared PHP version or architecture (a widened
  declaration is not applied to tags admitted before).
- An urgent `nudge-stale` alert from the hourly watch when the nudge file is older than 2 hours
  (no run lasts that long): the path unit is not starting runs, for example after a start limit.
  A nudge that cannot be examined alerts as `nudge-unreadable`.
- Runbook: how to enable the units, what exit statuses 0, 1 and 143 mean, how to recover from the
  start limit (`reset-failed`, then start the path unit), how to stop publishing for good, and what
  to do with the `sync.rejected-` entries that a directory in the nudge directory leaves behind.
- `setup.sh --fingerprint FINGERPRINT`: the script reads the key out of the keyring package without
  installing it, prints its fingerprint and expiry, and stops before the keyring package is
  installed, imported or written when the primary key is not the one given (a missing gpg is
  installed from the distribution first, to read the key). With the option, a key file that holds
  more than one primary key is refused too, because the whole file would be trusted. The script
  checks that the installed key file is the key it showed.
- Security notes: the origin must accept Cloudflare only for the webhook throttle to trust
  `CF-Connecting-IP`, and what a forged address can do (real deliveries refused with 429 for as long
  as the forged requests continue, so publishing waits for the daily run).
- The pin lint follows a local `uses: ./path` and checks the action it names wherever it lives. It
  fails on a path that leaves the repository or does not exist, on a `run:` script that runs
  `pip install` without `--require-hashes`, and on one that pipes `curl` or `wget` into a shell.
- Dependabot also watches the Composer dependencies, and a test fails when a dependency file, a
  workflow folder or a local action has no matching entry.
- A test makes the PHP versions, architectures and distributions that several files repeat (the
  client script, the outside watch, the container helpers, the CI matrix, the install guide) agree
  with `publisher/config.py` and the container image list.
- Every tracked file that can hold a comment now carries the licence header, and a test fails when
  one does not; the files that cannot are listed with the reason.
- Release workflow (`release.yml`): a pushed `v*` tag runs every CI gate through the same
  workflow, then makes the GitHub Release titled `PHP Package Publisher – vX.Y.Z` with the notes
  of that version from this changelog. Only the release job may write. It makes no release when
  the tag is not `vX.Y.Z` (no leading zeros), is not annotated, is not on `main`, when the
  changelog has no dated section for the version, or when `[Unreleased]` still has entries
  (`tools/release_notes.py` decides the first and the last two). It does not check the tag's
  signature, which needs the pinned key; the runbook has the steps to cut a release.

### Changed

- `publisher.yml` requires a `watch:` section (`host`: the public name, `origin`: the public IP
  address of the origin). The settings loader no longer imports the signer, so the watch does not
  load the publish modules.
- Release tags may not have leading zeros in a number (`v01.0.0` is ignored), so two tags cannot
  map to one package version.
- CI caches the pip downloads of the development tools; every file is still checked against its
  pinned hash.
- A `products.yml` that lists no product is refused while state of earlier products exists, so a
  truncated file cannot publish an empty signed repository.
- A listing fails as a whole when a release's own API URL does not name the product's repository,
  whichever form the page links take (`/repos/<owner>/<repo>` or `/repositories/<id>`). A release
  without that URL fails it too.
- `setup.sh` shows the key before it installs the keyring package, not after the repository was
  trusted. It needs `tar`, and `rpm2archive` on dnf. Without `--fingerprint` the key is still
  trusted on first use, and the script and the install guide say so.
- The install guide says it was tested on `amd64` and `x86_64` only; no container test runs
  `arm64` or `aarch64`, which the repository accepts. A test fails if one is added without the
  guide changing.
- The install guide explains `setup.sh` and what a second run does on dnf: it turns on the section
  of each PHP it finds installed, so a section turned off by hand in the repository file is turned
  on again.
- The pin lint skips `vendor`, `node_modules`, `.venv` and the caches only at the top of the
  repository; a folder of that name lower down is checked, and `.github` is never skipped.
- The key rotation step now says to switch to the new subkey at least 21 days before the old one
  expires, not 14: the publisher refuses a subkey with 14 days or fewer left, so 14 days left no
  margin.

### Fixed

- A refused configuration (a malformed `products.yml` or `exclude.yml`, or the empty list above)
  made the run raise, so its nudge was put back and the path unit started the service again until
  the start limit. It is now one urgent alert and exit 1, and the nudge stays consumed.
- The install guide and the security notes named `NO_PUBKEY` and `Signing key not found` for every
  client. Measured: apt on Debian 13 says `Missing key`, and dnf on Enterprise Linux 8 and 9 says
  `Bad GPG signature`; the guide now quotes each, and a test checks it.
- A program that had ended was reaped before its process group was killed, so in theory the
  process id could pass to another process in between. The group is now killed while the ended
  program is still unreaped, and a test checks the order. A program whose exit status is lost
  because the process ignores SIGCHLD now fails the run; it used to count as exit code 0.
- An unusable alert file (owner, mode, shape) made the run raise after it had published, so its
  nudge was put back and the path unit started the service again until the start limit stopped
  the webhook runs. The run now logs the alerts, ends with exit 1 and keeps the nudge consumed. A
  chat-service reply nested too deep for the JSON parser is now a failed delivery, not a crash.
- A directory named like the nudge file (the web server's group may create one) made every run
  fail before it started. It is now set aside under another name, with a log line, and counts as
  a nudge.
- When publishing raised, the alerts of the admit stage in that pass (a first quarantine, a
  stopped stage) were never sent. They are sent before the error is raised.
- A run stopped by SIGTERM (a stop, a reboot, the one-hour timeout) lost the nudge it had consumed,
  so the release waited for the daily timer. It now puts the nudge back and ends with exit 143,
  which the service counts as a clean exit (`SuccessExitStatus=143`). The comment of the unit,
  which said a failed run puts its nudge back, now says which runs do. A program that a tool call
  had started is now stopped when the run is stopped, not only on a timeout or a flood of output.
- The hourly watch ended green when its alerts could not be delivered; it now exits 1.
- A Sigstore trusted-root file, or a generation manifest, nested deeper than the JSON parser allows
  ended the run with an unhandled error. A refreshed trusted root like that now falls back to the
  stored copy, a stored one stops the run with the usual message, and a manifest like that is
  refused as not valid.

- A hash-named file that is missing or damaged in the store (a power cut, a deletion) no longer
  blocks every later publish, which would have stopped the daily re-signing until `Valid-Until`
  ran out. It is restored from the newest kept tree that still has its right bytes, or replaced by
  the copy of the build in progress, and a `store-repaired` alert says so. A file that no tree has
  is left out and an urgent `store-lost` alert (once a day) says so, because the publish used to
  refuse and clients of that index could not fetch the file anyway. A damaged file that only its
  age keeps (no kept index lists it) is dropped. The `rollback` command prints when it restored or
  lost files, and the store directories that get a new link are now flushed too.
- Temporary files that a crashed write left in `generations/` and in the site root were never
  removed; the sweep at the start of every run now removes them.
- A delivery that arrived in the instant the publisher took the nudge file got a 500, a failed
  delivery in GitHub's webhook log, although nothing was lost. The receiver now makes a new nudge
  (one retry; a second failure is still a 500); the publisher skips a pass that finds no change.
- The rpm key stayed trusted after the install guide's removal block, and after a `setup.sh` run
  that was refused. The dnf removal block now takes the imported key out of rpm's key store (one
  rule for rpm 4 and for rpm 6, which names the key differently), and `setup.sh` takes out a key
  only if that run imported it. Its comment now says what is put back and what is not.

### Security

- Key fingerprints are now replaced before error text is cut to its length, so one that straddled
  the cut is no longer left half visible in the journal. The shared text helper also replaces host
  paths now. Only text built through that helper and the alert text is covered, and only the
  patterns they already had: a fingerprint written with spaces and a path with a space or a colon
  are not.
- The webhook receiver no longer lets PHP error text reach the client on a host that shows errors:
  it turns `display_errors` off and `log_errors` on, and anything the handler throws becomes a bare
  500. Each 500 the receiver decides on or catches writes one `pkg-hook: <reason>` line to the
  error log with a fixed reason code and never a path, a secret or an exception message. A fatal
  error PHP cannot catch (the memory or time limit) is logged by PHP itself.
