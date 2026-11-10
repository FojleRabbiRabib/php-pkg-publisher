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
- Webhook receiver `web/hooks/sync.php` (PHP 8.3, one file, no dependencies): answers a fixed
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
- `products.yml` entries now require `extension`, the name inside package names
  (`php8.3-<extension>`); two products cannot share one.

### Changed

- `publisher.yml` requires a `watch:` section (`host`: the public name, `origin`: the public IP
  address of the origin). The settings loader no longer imports the signer, so the watch does not
  load the publish modules.
- Release tags may not have leading zeros in a number (`v01.0.0` is ignored), so two tags cannot
  map to one package version.
