# Security notes

What the repository verifies before it signs anything, how you can check a package yourself,
how the signing keys are rotated, and what the design does not protect against. To report a
vulnerability, see [`.github/SECURITY.md`](../.github/SECURITY.md).

## The trust chain

The publisher admits a release only if every step passes; one failed step stops that tag, never
publishes anything unverified, and never drops what was already admitted.

1. **The cosign bundle is the root of trust.** Every package has a `.bundle` that proves which
   workflow signed it. The publisher requires the identity
   `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>` of the
   product's own repository at that exact tag, and the issuer
   `https://token.actions.githubusercontent.com`, checked offline against Sigstore's trusted
   root with the transparency-log check on. There is no regular expression and no bypass flag.
   The publisher also refuses a release that is not marked immutable on GitHub.
2. **`SHA256SUMS` proves integrity only.** It is not signed, so it never decides who made a file.
3. **The rpm signature.** Every rpm must carry a signature by the pinned rpm key (an
   expired or revoked key is refused), and `rpmkeys --checksig` must print
   `<file>: digests signatures OK`. That exit status alone is not enough: `rpmkeys --checksig`
   exits 0 for an unsigned rpm, so the output is read as well.
4. **The metadata is signed by one repository subkey.** `InRelease`, `Release.gpg` and each
   `repomd.xml.asc` carry exactly one signature, by a subkey of a master key that stays offline.
5. **The webhook is only a nudge.** A delivery cannot name what to publish; at worst a forged one
   causes one extra check. The receiver holds no publishing privilege.

## Checking a package yourself

You can repeat step 1 on any release asset. Download the asset and its `.bundle` from the
release, and use Sigstore's `trusted_root.json` (the publisher refreshes its own copy with
`cosign initialize`). This command was run against a real release with cosign 3.1.1:

```sh
cosign verify-blob \
  --bundle <file>.bundle \
  --trusted-root trusted_root.json \
  --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <file>
```

It prints `Verified OK` and exits 0. A file with one changed byte fails with `invalid signature`
and a non-zero status. After you install the repository, apt checks the signed metadata and the
package hashes, and dnf (with `gpgcheck=1` and `repo_gpgcheck=1`) checks the metadata and every
package signature.

## Keys, expiry and rotation

- The master key is offline. A repository subkey signs the metadata and an rpm subkey signs the
  rpms; both expire yearly, and revocation certificates for both are kept offline.
- The publisher refuses to sign with a subkey, or under a primary key, that expires before the
  metadata's `Valid-Until`, which is 14 days after it is signed, so a subkey with 14 days or
  fewer left cannot be used.
- **One signature per file.** A repository file carries one subkey's signature at a time:
  EL10 and Fedora 44 reject a detached `repomd.xml.asc` that holds two.
- **Rotation order.** A client trusts a new subkey only once it holds the updated public key. So
  the keyring that contains the old and the new subkey ships at least 150 days before the old one
  expires; the repository keeps signing with the old subkey; and it switches to the new one at
  least 120 days after the keyring shipped and at least 21 days before the old one expires.
  Clients with the new keyring verify before and after the switch. Clients without it fail at the
  switch and recover as described in [`installation.md`](installation.md), which quotes what each
  client reports. The key drill (`tests/container/test_key_drill.py`) proves both outcomes, on
  every tested distribution, with throwaway keys.
- **Expiry is weaker than revocation on some clients.** On Debian 13's apt (`sqv`), a signature
  made while a subkey was valid is still accepted after it expired. There, a revocation shipped
  in a keyring update is the control.

## The deploy channel

A pushed tag is sent to the host by the `deploy` job of the release workflow. The runbook
("Deploying a change") has the steps; this is what the channel does and does not allow.

- **The key in GitHub can only send a bundle.** It logs in as a user whose key is locked: it runs
  one script, through one sudo line with no arguments, with no terminal, no forwarding and no
  other command (the client's own command is ignored). The job pins the host key, and ssh never
  turns the check off.
- **The host decides, not GitHub.** The script deploys a bundle only if it holds one annotated
  tag named `vX.Y.Z`, whose signed name is the same and which is signed by the key in
  `allowed_signers` (refusals: `signature-invalid`, `tag-invalid`). The signing key is never in
  GitHub, so whoever controls the workflow, the secrets or the network can make a deploy fail or
  repeat a tag already in place (which changes nothing), but cannot make the host run code the
  release key did not sign.
- **An old or rolled-back tag cannot come back.** A version older than the last deploy is refused
  (`version-older`), and so is one the operator rolled back (`version-denied`), until the operator
  lifts the ban.
- **The release key is the root of trust of the deploy.** Whoever holds it can sign a newer tag,
  and a deployed tag runs as root (the script replaces itself) and as the publisher user. To
  rotate it, change `allowed_signers` on the host. Keep it where a tag is signed and nowhere else.
- **Drift is reported.** An hourly check, as root, compares every file the last deploy wrote and
  the docroot with what was recorded, and a difference is alerted.
- **The log is public.** The host prints one fixed code and ssh is quiet, so a failed deploy
  shows nothing about the host in the workflow log; the detail is in the host's journal.

## Limits

- **dnf has no `Valid-Until`.** apt rejects metadata older than `Valid-Until`; dnf keeps trusting
  the last metadata it fetched, so a client cut off from the repository does not learn that the
  metadata is stale. The publisher re-signs at least every two days (the timer runs daily) and
  alerts if the served `Date` is older than three days, which is the only freshness control for
  dnf.
- **The first download is trust on first use.** Nothing vouches for the keyring package the first
  time. The defence is the fingerprint comparison with the one published on a second channel,
  described in [`installation.md`](installation.md). A reader who skips it trusts whoever
  controls the download path.
- **A leaked rpm key** lets an attacker sign a file that someone installs directly with `rpm -i`.
  It cannot reach repository users on its own: the repository lists only packages that also pass
  the cosign identity and checksum checks. Recovery is to revoke the subkey and ship a keyring
  update.
- **A compromised publishing host** could sign forged metadata; `Valid-Until` does not limit a
  signer who holds the key. The controls are a dedicated no-login user under a hardened service,
  subkey expiry and revocation, and the offline master key. No independent verifier checks the
  repository content before it is signed, so these controls are what limits a compromise.
- **The webhook throttle trusts a header, and that holds only behind Cloudflare.** The receiver
  limits each client address to 20 requests in 60 seconds and takes the address from
  `CF-Connecting-IP`, which Cloudflare sets. The origin must therefore accept connections from
  Cloudflare only: a client that reaches the origin directly can write any address into that
  header, and so can use any address's allowance. Someone who sends 20 requests in a minute with
  GitHub's address in the header makes the receiver answer GitHub's real deliveries with 429
  until the minute is over, and keeps doing so while the requests continue. GitHub does not retry,
  so publishing then falls back to the daily run, up to a day late. A forged request cannot start
  a run on its own: the delivery must carry a valid signature. When
  the table of counters is full, the throttle lets requests through instead of refusing them.
- **Package bytes never come from the repository host.** Every download is redirected to the
  matching GitHub release asset, so the host cannot alter a package without also forging its
  hash in signed metadata.
