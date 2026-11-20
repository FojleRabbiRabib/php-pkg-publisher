# Installing from the repository

One signed repository serves every extension: after the steps below, `apt install` or
`dnf install` works for each of them, and normal upgrades keep them current.

Supported and tested: Ubuntu 22.04, 24.04 and 26.04, Debian 12 (bookworm) and 13 (trixie),
AlmaLinux 8, 9 and 10, and Fedora 44, on `amd64` (apt) and `x86_64` (dnf). The repository also
accepts `arm64` and `aarch64` clients, but nothing tests them yet. Other apt and dnf
distributions are untested. cPanel, EasyApache and CloudLinux are not supported yet.

Every command block marked `family=apt` or `family=dnf` below is run, in that order, on a real
`apt` or `dnf` of each tested distribution by `tests/container/test_docs.py`, against a local
copy of the site. Run the commands as root, or put `sudo` in front.

## Before you trust anything: the fingerprint

The first download is trust on first use: nothing yet proves the keyring package came from us.
The defence is to compare the key fingerprint it installs with the one published on a second
channel (the project README and the release notes) before the repository is allowed to sign
anything on your machine. Both flows below stop at that comparison.

The fingerprint to compare with:

```text
<fingerprint published with the key ceremony>
```

The primary key and the signing subkey that signs the repository are both listed; the primary
key is the one to compare. A key that differs from the published one means: stop, delete what you
downloaded, and report it (see `.github/SECURITY.md`).

The steps below are the manual flow. The script `setup.sh` of the project repository does the
same in one step, as root, for apt and dnf: it downloads the keyring package, reads the key out of
it and prints its fingerprint and expiry before it installs anything, then installs the package,
writes the repository file and refreshes the indexes. Give it the published fingerprint and it
stops, before the keyring package is installed, imported or written, when the key in the package
is another (a missing gpg is installed from your distribution first, to read the key):

```sh
sh setup.sh --fingerprint <fingerprint published with the key ceremony>
```

Without the option the key is installed whatever it is, so compare the printed fingerprint with
the published one. If a step fails the script puts back the repository file and takes out the key
it imported; the keyring package stays installed.

Running the script again is safe. On dnf it turns on the section of each PHP version it finds
installed (the system's or Remi's) and never turns one off. A section you turned off by hand with
`enabled=0` in the repository file is therefore turned on again while that PHP is installed. A
setting made with dnf 5's `dnf config-manager setopt` is kept in an override file, which a run
respects. With dnf 4, turn the section off again after a re-run.

## Debian and Ubuntu (apt)

Needs `curl`, `gpg` and the CA certificates; minimal images ship none of them.

```sh {family=apt}
apt-get update
apt-get install -y curl gnupg ca-certificates
```

Download and install the keyring package. Installing it only places the key file; nothing trusts
it yet.

```sh {family=apt}
curl -fsSLO https://pkg.rabib.me/keyring/rabib-archive-keyring.deb
apt-get install -y ./rabib-archive-keyring.deb
```

Show the fingerprint and expiry of the installed key, and compare it with the published one:

```sh {family=apt}
gpg --show-keys --with-fingerprint /usr/share/keyrings/rabib-archive-keyring.gpg
```

Only when it matches, add the repository. `Signed-By` limits the key to this repository; the key
is never added to apt's global trust.

```sh {family=apt}
tee /etc/apt/sources.list.d/rabib.sources >/dev/null <<'EOF'
Types: deb
URIs: https://pkg.rabib.me/apt
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/rabib-archive-keyring.gpg
EOF
apt-get update
```

Install an extension (`<extension>` is its name; the PHP version is part of the package name):

```sh {family=apt}
apt-get install -y php8.3-<extension>
```

## Enterprise Linux and Fedora (dnf)

Needs `gpg`; some images ship none.

```sh {family=dnf}
dnf install -y gnupg2
```

Download and install the keyring package. This only places the key file at
`/etc/pki/rpm-gpg/RPM-GPG-KEY-rabib`; nothing trusts it yet.

```sh {family=dnf}
curl -fsSLO https://pkg.rabib.me/keyring/rabib-release.rpm
dnf install -y ./rabib-release.rpm
```

Show the fingerprint and expiry of the key, and compare it with the published one:

```sh {family=dnf}
gpg --show-keys --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-rabib
```

Only when it matches, import the key and add the repository. There is one section per PHP
version, and only the one for your PHP is enabled; this file enables PHP 8.3. For PHP 8.4 or 8.5
enable `rabib-php84` or `rabib-php85` instead (and set `enabled=0` on `rabib-php83`). Both
`repo_gpgcheck` and `gpgcheck` stay on, so dnf verifies the metadata and every package.

```sh {family=dnf}
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-rabib
tee /etc/yum.repos.d/rabib.repo >/dev/null <<'EOF'
[rabib-php83]
name=Rabib PHP extensions for PHP 8.3
baseurl=https://pkg.rabib.me/rpm/8.3/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rabib

[rabib-php84]
name=Rabib PHP extensions for PHP 8.4
baseurl=https://pkg.rabib.me/rpm/8.4/$basearch
enabled=0
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rabib

[rabib-php85]
name=Rabib PHP extensions for PHP 8.5
baseurl=https://pkg.rabib.me/rpm/8.5/$basearch
enabled=0
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rabib
EOF
dnf -y makecache
```

dnf 4 asks once more, on the first metadata download, to import the same key for repository
checks; `-y` answers yes for the key whose fingerprint you just compared.

Install an extension. Use `php-<extension>` with the distribution's own PHP, or
`php83-php-<extension>` (`php84-`, `php85-`) with a Remi versioned PHP:

```sh {family=dnf}
dnf install -y php-<extension>
```

## Upgrading

Extensions and the keyring package upgrade with the rest of the system (`apt-get upgrade`,
`dnf upgrade`). A new repository signing key reaches you the same way, through a new
`rabib-archive-keyring` or `rabib-release`.

## A server that no longer accepts the repository

After the repository switched to a new signing key, a server whose keyring predates the switch
cannot verify it. `apt-get update` reports `NO_PUBKEY` (Debian 13: `Missing key`, "which is needed
to verify signature"), and the previous index files stay in use. `dnf` reports
`repomd.xml GPG signature verification error:` followed by `Bad GPG signature` on Enterprise Linux
8 and 9, or `Signing key not found` on Enterprise Linux 10 and Fedora. Repeat
the download and install step of your flow: it brings the current keyring, and the `rabib-release`
package also removes dnf's cached copy of the old repository key, which EL10 and Fedora otherwise
keep. Then compare the fingerprint again.

## Removing the repository

```sh {family=apt phase=remove}
apt-get remove -y --purge rabib-archive-keyring
rm /etc/apt/sources.list.d/rabib.sources
```

Removing the keyring package does not take the key out of rpm's key store, so the dnf block ends
by removing it. rpm names a key after the end of its fingerprint (all of it on Fedora 44), and
the block finds it by that.

```sh {family=dnf phase=remove}
fingerprint=$(gpg --show-keys --with-colons /etc/pki/rpm-gpg/RPM-GPG-KEY-rabib | grep -m1 '^fpr' | cut -d: -f10 | tr A-F a-f)
dnf remove -y rabib-release
rm /etc/yum.repos.d/rabib.repo
for version in $(rpm -qa gpg-pubkey --qf '%{VERSION} '); do
  case $fingerprint in *"$version") rpm -e "gpg-pubkey-$version" ;; esac
done
```

## Limits worth knowing

- apt rejects repository metadata older than its `Valid-Until`; dnf has no such check, so a
  server that is cut off from fresh metadata keeps trusting the last copy it fetched.
- The fingerprint comparison above is the only defence of the first download; keep the published
  fingerprint from a second channel.
