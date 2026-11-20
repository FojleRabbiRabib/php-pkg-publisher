#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
#
# Adds the Rabib PHP extension repository to this host: apt on Debian and Ubuntu, dnf on
# Enterprise Linux and Fedora. Run it as root.
#
# It downloads the keyring package from BASE/keyring/, reads the key out of it without
# installing it and prints the key's fingerprint and expiry. Only then does it install the
# package, write the repository definition and refresh the package indexes.
#
#   sh setup.sh --fingerprint FINGERPRINT
#
# stops, before the keyring package is installed, imported or written, when the primary key in
# the package is not the one given. (Reading the key needs gpg: one that is missing is installed
# from the distribution first.) Without the option the first download is trust on first use: the
# key is installed whatever it is, so compare the printed fingerprint with the one published in
# the project's README, and give it to the option the next time. With the option, a key file
# that holds more than one primary key is refused too, because the whole file is trusted.
#
# Everything is defined in functions and runs from the last line, so a download that is cut
# short runs nothing.

set -eu
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

BASE='https://pkg.rabib.me'
APT_PACKAGE='rabib-archive-keyring'
RPM_PACKAGE='rabib-release'
APT_KEY='/usr/share/keyrings/rabib-archive-keyring.gpg'
RPM_KEY='/etc/pki/rpm-gpg/RPM-GPG-KEY-rabib'
APT_SOURCES='/etc/apt/sources.list.d/rabib.sources'
APT_LISTS='/var/lib/apt/lists'
DNF_REPO='/etc/yum.repos.d/rabib.repo'
DNF_OVERRIDES='/etc/dnf/repos.override.d'
PHP_VERSIONS='8.3 8.4 8.5'

FAMILY=''
TMP=''
PENDING=''
HAD_FILE=0
HAD_INDEX=0
ROLLBACK=''
FINGERPRINT=''
PRIMARY=''
PRIMARIES=0
ALL_PRIMARIES=''
IMPORTED=''

die() {
	printf 'setup.sh: %s\n' "$*" >&2
	exit 1
}

say() {
	printf '%s\n' "$*"
}

# Runs on every exit, so a failure, a set -e abort and a signal all put back what this run
# changed and had not confirmed: the repository definition and its index, and the rpm key this
# run imported. The keyring package, once installed, stays installed.
cleanup() {
	if [ -n "$PENDING" ]; then
		rm -f -- "$PENDING"
	fi
	if [ -n "$ROLLBACK" ]; then
		roll_back "$ROLLBACK" || true
		restore_index || true
	fi
	for version in $IMPORTED; do
		rpm -e "gpg-pubkey-$version" >/dev/null 2>&1 || true
	done
	if [ -n "$TMP" ]; then
		rm -rf -- "$TMP"
	fi
}

has_word() {
	case " $1 " in
	*" $2 "*) return 0 ;;
	esac
	return 1
}

os_value() {
	grep "^$1=" /etc/os-release | head -n 1 | cut -d= -f2- | tr -d "\"'"
}

detect_family() {
	[ -r /etc/os-release ] || die 'cannot read /etc/os-release, so the distribution is unknown'
	os_id=$(os_value ID)
	os_like=$(os_value ID_LIKE)
	case "$os_id" in
	debian | ubuntu)
		FAMILY=apt
		return 0
		;;
	rhel | centos | fedora | almalinux | rocky | ol)
		FAMILY=dnf
		return 0
		;;
	esac
	if has_word "$os_like" debian || has_word "$os_like" ubuntu; then
		FAMILY=apt
		return 0
	fi
	die "unsupported distribution (ID=$os_id): this repository supports Debian, Ubuntu, Enterprise Linux and Fedora"
}

check_platform() {
	command -v tar >/dev/null 2>&1 || die 'tar is required to read the key out of the package'
	if [ "$FAMILY" = apt ]; then
		command -v apt-get >/dev/null 2>&1 || die 'apt-get is not installed'
		command -v dpkg-deb >/dev/null 2>&1 || die 'dpkg-deb is not installed'
		machine=$(dpkg --print-architecture)
		case "$machine" in
		amd64 | arm64) ;;
		*) die "unsupported architecture $machine: the repository has amd64 and arm64 packages" ;;
		esac
	else
		command -v dnf >/dev/null 2>&1 || die 'dnf is not installed'
		command -v rpm >/dev/null 2>&1 || die 'rpm is not installed'
		command -v rpm2archive >/dev/null 2>&1 || die 'rpm2archive is required to read the key out of the package'
		machine=$(uname -m)
		case "$machine" in
		x86_64 | aarch64) ;;
		*) die "unsupported architecture $machine: the repository has x86_64 and aarch64 packages" ;;
		esac
	fi
	command -v curl >/dev/null 2>&1 || die 'curl is required to download the keyring package'
}

# Download BASE/keyring/$1 to $2. The protocol is the one BASE names, so the only place to
# change it is BASE; there is no redirect, because the keyring is served directly.
fetch() {
	curl -q --fail --silent --show-error --proto "=${BASE%%://*}" --tlsv1.2 \
		--connect-timeout 20 --max-time 300 --retry 2 \
		--output "$2" "$BASE/keyring/$1" || die "cannot download $BASE/keyring/$1"
}

# Write the text $2 and a newline to $1 through a temporary file in the same directory, then
# rename it. A symbolic link is followed, so it stays a link and its target gets the text. It
# runs in this shell, so a failure leaves nothing for cleanup to miss.
write_file() {
	target=$1
	if [ -L "$target" ]; then
		target=$(readlink -f -- "$target") || die "cannot resolve the symbolic link $target"
	fi
	[ ! -d "$target" ] || die "$target is a directory"
	[ -d "${target%/*}" ] || die "${target%/*} does not exist"
	PENDING=$(mktemp "${target%/*}/.rabib.XXXXXX") || die "cannot create a file in ${target%/*}"
	printf '%s\n' "$2" >"$PENDING"
	chmod 0644 "$PENDING"
	mv -f -- "$PENDING" "$target"
	PENDING=''
}

apt_sources_text() {
	printf 'Types: deb\nURIs: %s/apt\nSuites: stable\nComponents: main\nSigned-By: %s\n' \
		"$BASE" "$APT_KEY"
}

# The PHP versions that an installed php-common (system or Remi base) or phpNN-php-common
# (Remi versioned) provides, as "8.3 8.4 ".
detected_php() {
	for version in $PHP_VERSIONS; do
		digits=$(printf '%s' "$version" | tr -d .)
		found=0
		if rpm -q "php${digits}-php-common" >/dev/null 2>&1; then
			found=1
		fi
		if base=$(rpm -q --qf '%{VERSION}' php-common 2>/dev/null); then
			case "$base" in
			"$version".*) found=1 ;;
			esac
		fi
		if [ "$found" = 1 ]; then
			printf '%s ' "$version"
		fi
	done
	return 0
}

# One "8.3 1" or "8.3 0" line for each enabled setting of a rabib section in the file $1.
scan_enabled() {
	section=''
	while IFS= read -r line || [ -n "$line" ]; do
		line=${line%"${line##*[![:space:]]}"} # a CRLF file or a trailing blank is not part of a name
		case "$line" in
		'[rabib-php'[0-9][0-9]']')
			digits=${line#'[rabib-php'}
			digits=${digits%']'}
			section="${digits%?}.${digits#?}"
			;;
		'['*) section='' ;;
		*=*)
			key=$(printf '%s' "${line%%=*}" | tr -d ' \t' | tr '[:upper:]' '[:lower:]')
			if [ "$key" = enabled ] && [ -n "$section" ]; then
				value=$(printf '%s' "${line#*=}" | tr -d ' \t\r' | tr '[:upper:]' '[:lower:]')
				case "$value" in
				1 | true | yes | on) printf '%s 1\n' "$section" ;;
				*) printf '%s 0\n' "$section" ;;
				esac
			fi
			;;
		esac
	done <"$1"
}

# The last setting of each rabib section in the files given (a later file wins), as lines such
# as "8.3 1".
final_states() {
	states=' '
	for file in "$@"; do
		if [ ! -f "$file" ]; then
			continue
		fi
		scan_enabled "$file" >"$TMP/enabled.scan"
		while read -r version state; do
			kept=' '
			for entry in $states; do
				case "$entry" in
				"$version="*) ;;
				*) kept="$kept$entry " ;;
				esac
			done
			states="$kept$version=$state "
		done <"$TMP/enabled.scan"
	done
	for entry in $states; do
		printf '%s %s\n' "${entry%=*}" "${entry#*=}"
	done
}

# The versions whose last setting in the files after $1 is $1 (1 on, 0 off), as "8.3 8.5 ".
versions_set() {
	wanted=$1
	shift
	final_states "$@" >"$TMP/final.states"
	while read -r version state; do
		if [ "$state" = "$wanted" ]; then
			printf '%s ' "$version"
		fi
	done <"$TMP/final.states"
	return 0
}

# Enabled in the repository file or, as dnf5's config-manager writes it, in an override file,
# which wins.
enabled_php() {
	versions_set 1 "$DNF_REPO" "$DNF_OVERRIDES"/*.repo
}

# Turned off explicitly in an override file: a PHP that is installed does not turn those on.
override_off() {
	versions_set 0 "$DNF_OVERRIDES"/*.repo
}

# $1 without the versions listed in $2, as "8.3 8.5 ".
without_versions() {
	for version in $1; do
		if ! has_word "$2" "$version"; then
			printf '%s ' "$version"
		fi
	done
	return 0
}

# The lines of the section [$1] in the existing repository file that a person added, such as
# priority=50 or a comment. The keys this script writes are never kept, and neither are the ones
# that change what is trusted or where it comes from: a kept gpgcheck=0 or mirrorlist would
# defeat the signature checks, so those are dropped with a warning.
extra_lines() {
	if [ ! -f "$DNF_REPO" ]; then
		return 0
	fi
	inside=0
	keep=0
	while IFS= read -r line || [ -n "$line" ]; do
		line=${line%"${line##*[![:space:]]}"}
		case "$line" in
		"[$1]")
			inside=1
			keep=0
			;;
		'['*) inside=0 ;;
		'') ;;
		*)
			if [ "$inside" = 1 ]; then
				keep_line "$1"
			fi
			;;
		esac
	done <"$DNF_REPO"
}

# Decide about the line $line of the section $1: a comment is kept; an indented line belongs to
# the key before it and follows that key; a key is kept unless it is one this script writes or
# one that changes what is trusted; anything else (no =, or a : in the key) is dropped, because
# dnf might read it as a setting.
keep_line() {
	case "$line" in
	'#'* | ';'*) printf '%s\n' "$line" ;;
	[[:space:]]*)
		if [ "$keep" = 1 ]; then
			printf '%s\n' "$line"
		fi
		;;
	*=*)
		key=$(printf '%s' "${line%%=*}" | tr -d ' \t' | tr '[:upper:]' '[:lower:]')
		keep=0
		case "$key" in
		name | baseurl | enabled | gpgcheck | repo_gpgcheck | gpgkey) ;;
		pkg_gpgcheck | localpkg_gpgcheck | mirrorlist | metalink | *:*)
			printf 'setup.sh: dropped "%s" from [%s]: it would change what is trusted\n' \
				"$line" "$1" >&2
			;;
		*)
			printf '%s\n' "$line"
			keep=1
			;;
		esac
		;;
	*)
		keep=0
		printf 'setup.sh: dropped "%s" from [%s]: it is not a key=value line\n' "$line" "$1" >&2
		;;
	esac
}

# The repository file with one section per PHP version; $1 lists the enabled versions.
repo_text() {
	first=1
	for version in $PHP_VERSIONS; do
		digits=$(printf '%s' "$version" | tr -d .)
		if has_word "$1" "$version"; then
			state=1
		else
			state=0
		fi
		if [ "$first" = 0 ]; then
			printf '\n'
		fi
		first=0
		printf '[rabib-php%s]\nname=Rabib PHP extensions for PHP %s\n' "$digits" "$version"
		# shellcheck disable=SC2016 # $basearch is dnf's variable, not the shell's
		printf 'baseurl=%s/rpm/%s/$basearch\n' "$BASE" "$version"
		printf 'enabled=%s\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://%s\n' "$state" "$RPM_KEY"
		extra_lines "rabib-php$digits"
	done
}

# Keep what the file $1 held before this run, so a failed refresh can put it back. A dangling
# symbolic link stops the script here, before anything is changed, because there is nothing
# defined to put back.
remember() {
	if [ -L "$1" ] && [ ! -e "$1" ]; then
		die "$1 is a dangling symbolic link"
	fi
	if [ -f "$1" ]; then
		cp -p -- "$1" "$TMP/previous"
		HAD_FILE=1
	else
		HAD_FILE=0
	fi
}

# Leave the file $1 as it was before this run: its old content, or no file.
roll_back() {
	if [ "$HAD_FILE" = 1 ]; then
		cp -p -- "$TMP/previous" "$1"
	else
		rm -f -- "$1"
	fi
}

# apt exits 0 when the sources it was given yield nothing, so look for our index itself, and
# only a fresh one counts: an earlier run's copy is set aside before the update.
index_file() {
	name=$(printf '%s' "${BASE#*://}/apt/dists/stable/InRelease" | tr / _)
	printf '%s/%s' "$APT_LISTS" "$name"
}

index_fetched() {
	[ -s "$(index_file)" ]
}

# Move an earlier index of ours aside, so only a fresh fetch counts and a failed run can restore it.
set_index_aside() {
	if [ -f "$(index_file)" ]; then
		mv -f -- "$(index_file)" "$TMP/index.prev"
		HAD_INDEX=1
	fi
}

restore_index() {
	if [ "$HAD_INDEX" = 1 ]; then
		mv -f -- "$TMP/index.prev" "$(index_file)"
	fi
}

install_apt() {
	say "Installing $APT_PACKAGE from $BASE/keyring/"
	fetch "$APT_PACKAGE.deb" "$TMP/$APT_PACKAGE.deb"
	name=$(dpkg-deb -f "$TMP/$APT_PACKAGE.deb" Package) || die 'the downloaded file is not a deb package'
	[ "$name" = "$APT_PACKAGE" ] || die "the downloaded package is $name, not $APT_PACKAGE"
	show_key "$TMP/$APT_PACKAGE.deb" "$APT_KEY"
	DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
		"$TMP/$APT_PACKAGE.deb" </dev/null || die "cannot install $APT_PACKAGE"
	confirm_key "$APT_KEY"
	remember "$APT_SOURCES"
	ROLLBACK=$APT_SOURCES
	write_file "$APT_SOURCES" "$(apt_sources_text)"
	# Only our source is refreshed, so another repository's failure cannot stop this script.
	# List-Cleanup=0 keeps apt from deleting the index files of the sources left out.
	mkdir "$TMP/sources.d"
	cp -- "$APT_SOURCES" "$TMP/sources.d/rabib.sources"
	set_index_aside
	say 'Refreshing the package indexes'
	if ! DEBIAN_FRONTEND=noninteractive apt-get update --error-on=any \
		-o Dir::Etc::sourcelist=/dev/null -o "Dir::Etc::sourceparts=$TMP/sources.d" \
		-o APT::Get::List-Cleanup=0 </dev/null; then
		die 'apt-get update failed or refused the repository; the sources file was put back'
	fi
	if ! index_fetched; then
		die 'apt-get update did not fetch the repository index; the sources file was put back'
	fi
	ROLLBACK=''
}

# dnf5 on Fedora 44 exits 0 for a bad repomd.xml.asc unless skip_if_unavailable is 0 (measured);
# with it set, the exit status already fails. The output is still read for the signature error
# as a second check.
refresh_dnf() {
	# Only the sections turned on are refreshed, so another repository's failure cannot stop us.
	set -- --disablerepo='*'
	# A host-wide skip_if_unavailable=True must not turn our unreachable repository into success.
	for version in $PHP_VERSIONS; do
		if has_word "$enable" "$version"; then
			id=rabib-php$(printf '%s' "$version" | tr -d .)
			set -- "$@" "--enablerepo=$id" "--setopt=$id.skip_if_unavailable=0"
		fi
	done
	status=0
	dnf --assumeyes "$@" makecache --refresh </dev/null >"$TMP/makecache.log" 2>&1 || status=$?
	cat "$TMP/makecache.log"
	if [ "$status" -ne 0 ] || grep -qi 'signature verification error' "$TMP/makecache.log"; then
		return 1
	fi
	return 0
}

install_dnf() {
	say "Installing $RPM_PACKAGE from $BASE/keyring/"
	fetch "$RPM_PACKAGE.rpm" "$TMP/$RPM_PACKAGE.rpm"
	name=$(rpm -qp --nosignature --qf '%{NAME}' "$TMP/$RPM_PACKAGE.rpm") \
		|| die 'the downloaded file is not an rpm package'
	[ "$name" = "$RPM_PACKAGE" ] || die "the downloaded package is $name, not $RPM_PACKAGE"
	show_key "$TMP/$RPM_PACKAGE.rpm" "$RPM_KEY"
	# An empty reposdir keeps dnf from reading any repository for a package that needs none.
	mkdir "$TMP/no-repos"
	dnf install --assumeyes --setopt="reposdir=$TMP/no-repos" "$TMP/$RPM_PACKAGE.rpm" </dev/null \
		|| die "cannot install $RPM_PACKAGE"
	confirm_key "$RPM_KEY"
	# rpm 6 cannot import a key inside a package transaction, so the import happens here.
	import_key "$RPM_KEY"
	enable=$(without_versions "$(detected_php)$(enabled_php)" "$(override_off)")
	remember "$DNF_REPO"
	ROLLBACK=$DNF_REPO
	write_file "$DNF_REPO" "$(repo_text "$enable")"
	if [ -n "$enable" ]; then
		say 'Refreshing the package metadata'
		if ! refresh_dnf; then
			die 'dnf makecache failed or refused the repository; the repository file was put back and the key taken out'
		fi
	fi
	ROLLBACK=''
	IMPORTED=''
	REPO_ENABLED=$enable
}

ensure_gpg() {
	if command -v gpg >/dev/null 2>&1; then
		return 0
	fi
	say 'Installing gnupg to read the key fingerprint'
	if [ "$FAMILY" = apt ]; then
		DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends gnupg \
			</dev/null || die 'cannot install gnupg'
	else
		dnf install --assumeyes gnupg2 </dev/null || die 'cannot install gnupg2'
	fi
}

expiry_text() {
	if [ -z "$1" ]; then
		printf 'does not expire'
	elif day=$(date -u -d "@$1" +%Y-%m-%d 2>/dev/null); then
		printf 'expires %s' "$day"
	else
		printf 'expires at epoch %s' "$1"
	fi
}

# Print the primary key and the signing subkeys of the key file $1, headed by the name $2, and
# remember the primary key's fingerprint in PRIMARY.
print_key() {
	say "Key $2:"
	# A private home keeps gpg from creating one for root; the output is read from a file so a
	# gpg failure stops the script instead of vanishing inside a pipeline.
	mkdir "$TMP/gnupg"
	chmod 0700 "$TMP/gnupg"
	gpg --homedir "$TMP/gnupg" --batch --no-tty --with-colons --fixed-list-mode --show-keys "$1" \
		>"$TMP/key.colons" || die "gpg cannot read $1"
	kind=''
	ends=''
	shown=0
	while IFS=: read -r record _ _ _ _ _ expires _ _ value _; do
		case "$record" in
		pub)
			kind='primary key'
			ends=$expires
			PRIMARIES=$((PRIMARIES + 1))
			;;
		sub)
			kind='signing subkey'
			ends=$expires
			;;
		fpr)
			printf '  %s %s, %s\n' "$kind" "$value" "$(expiry_text "$ends")"
			if [ "$kind" = 'primary key' ]; then
				ALL_PRIMARIES="$ALL_PRIMARIES$value "
				if [ -z "$PRIMARY" ]; then
					PRIMARY=$value
				fi
			fi
			shown=1
			;;
		esac
	done <"$TMP/key.colons"
	[ "$shown" = 1 ] || die "no fingerprint found in $1"
}

# The option is the only argument: --fingerprint and the 40 hexadecimal digits of the primary key.
parse_arguments() {
	[ "$#" -eq 0 ] && return 0
	if [ "$#" -ne 2 ] || [ "$1" != --fingerprint ]; then
		die 'the only option is --fingerprint followed by the fingerprint of the primary key'
	fi
	FINGERPRINT=$(printf '%s' "$2" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
	case "$FINGERPRINT" in
	*[!0-9A-F]*) die "$2 is not a fingerprint: it has 40 hexadecimal digits" ;;
	esac
	[ "${#FINGERPRINT}" -eq 40 ] || die "$2 is not a fingerprint: it has 40 hexadecimal digits"
}

# Read the key file $2 out of the package $1 into $TMP/key.pub without installing anything.
extract_key() {
	if [ "$FAMILY" = apt ]; then
		dpkg-deb --fsys-tarfile "$1" | tar -xO ".$2" >"$TMP/key.pub" || true
	else
		rpm2archive - <"$1" | tar -xzO ".$2" >"$TMP/key.pub" || true
	fi
	[ -s "$TMP/key.pub" ] || die "the downloaded package does not hold $2"
}

# The key to be installed, shown and checked before the package is installed: installing a
# package runs its scripts as root, so the check cannot wait until afterwards.
show_key() {
	extract_key "$1" "$2"
	ensure_gpg
	print_key "$TMP/key.pub" "in the package ($2)"
	check_key
}

# With a fingerprint given, the key file must hold that primary key and no other: the file is
# trusted whole, so a second primary key would be trusted without being compared.
check_key() {
	[ -n "$FINGERPRINT" ] || return 0
	[ "$PRIMARIES" -eq 1 ] || die 'the package must hold exactly one primary key; nothing was installed'
	[ "$PRIMARY" = "$FINGERPRINT" ] \
		|| die 'the primary key in the package is not the fingerprint you gave; nothing was installed'
}

# The file the package installed is the key that was shown.
confirm_key() {
	[ -s "$1" ] || die "the package did not install $1"
	[ "$(sha256sum <"$TMP/key.pub")" = "$(sha256sum <"$1")" ] \
		|| die "$1 is not the key that was shown"
}

# The versions of the keys in rpm's key store, as "ab12cd34 ", a key's version being the end of its
# fingerprint (eight digits, or all forty in rpm 6).
key_versions() {
	rpm -qa gpg-pubkey --qf '%{VERSION} ' 2>/dev/null || true
}

# Import the key file $1 into rpm, and remember which keys of the store are new (those of the
# primary keys of the file), so that a run that fails afterwards can take them out again.
import_key() {
	before=$(key_versions)
	rpm --import "$1" || die "cannot import $1"
	for version in $(key_versions); do
		if has_word "$before" "$version"; then
			continue
		fi
		for fingerprint in $ALL_PRIMARIES; do
			lower=$(printf '%s' "$fingerprint" | tr '[:upper:]' '[:lower:]')
			case "$lower" in
			*"$version")
				IMPORTED="$IMPORTED$version "
				break
				;;
			esac
		done
	done
}

print_dnf_hint() {
	if dnf --version 2>/dev/null | grep -q dnf5; then
		enable_cmd='dnf config-manager setopt rabib-php83.enabled=1'
	else
		enable_cmd='dnf config-manager --set-enabled rabib-php83'
	fi
	say 'No PHP 8.3, 8.4 or 8.5 package from the system or from Remi was found, so no section of'
	say "$DNF_REPO is enabled. Enable the one for your PHP version, for example PHP 8.3:"
	say "  $enable_cmd"
	say 'Enable the matching section again after you move to another PHP version.'
}

main() {
	parse_arguments "$@"
	[ "$(id -u)" -eq 0 ] || die 'it must run as root, so start it with sudo'
	detect_family
	check_platform
	TMP=$(mktemp -d) || die 'cannot create a temporary directory'
	trap cleanup EXIT
	trap 'exit 1' HUP INT TERM
	chmod 0755 "$TMP"
	REPO_ENABLED=''
	if [ "$FAMILY" = apt ]; then
		install_apt
	else
		install_dnf
	fi
	if [ -n "$FINGERPRINT" ]; then
		say 'The key matches the fingerprint you gave.'
	else
		say 'No fingerprint was given, so this key is trusted on first use: compare the fingerprint'
		say 'above with the one published in the project README, and give it to --fingerprint when'
		say 'you run this script again.'
	fi
	if [ "$FAMILY" = dnf ] && [ -z "$REPO_ENABLED" ]; then
		print_dnf_hint
	else
		say 'The repository is ready. Install an extension with your package manager.'
	fi
}

main "$@"
