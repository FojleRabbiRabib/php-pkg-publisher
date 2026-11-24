# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`docs/runbook.md` against the code it describes: the settings example loads, the exclusion
example loads, every command and unit is named, and the numbers it quotes are the code's.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import textwrap
from pathlib import Path
from typing import Final

import pkg_deploy
import platform_watch
from deploykit import generate_key, signed_bundle
from pkg_deploy import Layout, rules

from publisher import admit, config, generation, metadata, signer, watch
from publisher.__main__ import _parser
from publisher.settings import DIRECTORIES, load_settings

ROOT: Final = Path(__file__).resolve().parents[2]
TEXT: Final = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
SECURITY: Final = (ROOT / "docs" / "security.md").read_text(encoding="utf-8")
FLAT: Final = " ".join(TEXT.split())
SECURITY_FLAT: Final = " ".join(SECURITY.split())
UNITS: Final = ROOT / "deploy" / "systemd"
PUBLIC_ADDRESS: Final = "93.184.216.34"


def _yaml_blocks() -> list[str]:
    return re.findall(r"```yaml\n(.*?)```", TEXT, re.DOTALL)


def _settings_block() -> str:
    (block,) = [b for b in _yaml_blocks() if b.startswith("products:")]
    return block


def test_the_settings_example_loads_once_the_placeholders_are_filled(tmp_path: Path) -> None:
    text = (
        _settings_block()
        .replace("<site-root>", "/srv/pkg/site")
        .replace("<origin-public-ip>", PUBLIC_ADDRESS)
        .replace("<signing-subkey-fingerprint>", "A" * 40)
        .replace("<primary-key-fingerprint>", "B" * 40)
    )
    path = tmp_path / "publisher.yml"
    path.write_text(text, encoding="utf-8")
    settings = load_settings(path)
    assert settings.site == Path("/srv/pkg/site")
    assert settings.watch.origin == PUBLIC_ADDRESS


def test_the_settings_example_uses_the_paths_the_units_use(tmp_path: Path) -> None:
    path_unit = (UNITS / "php-pkg-publisher.path").read_text(encoding="utf-8")
    assert f"PathExists={_value('nudge')}" in path_unit
    for unit in ("php-pkg-publisher.service", "php-pkg-publisher-watch.service"):
        assert "--config /etc/php-pkg-publisher/publisher.yml" in (UNITS / unit).read_text(
            encoding="utf-8"
        )
    assert "/etc/php-pkg-publisher/publisher.yml" in TEXT
    notify = (UNITS / "php-pkg-publisher-notify@.service").read_text(encoding="utf-8")
    assert f"--alert-file {_value('alert').split('file: ')[1].split('}')[0]}" in notify


def _value(key: str) -> str:
    (line,) = re.findall(rf"^{key}: (.*)$", _settings_block(), re.MULTILINE)
    return str(line)


def test_the_exclusion_examples_load(tmp_path: Path) -> None:
    products = tmp_path / "products.yml"
    products.write_text(
        "products:\n  - repo: usearch-php\n    extension: usearch\n"
        '    php: ["8.3"]\n    arch: [amd64]\n    ts: [nts]\n',
        encoding="utf-8",
    )
    declared = config.load_products(products)
    examples = [b for b in _yaml_blocks() if b.startswith("exclude:")]
    assert len(examples) == 2
    for number, block in enumerate(examples):
        path = tmp_path / f"exclude{number}.yml"
        path.write_text(
            block.replace("<repo>", "usearch-php").replace("<tag>", "v1.0.0"), encoding="utf-8"
        )
        loaded = config.load_exclusions(path, declared)
        assert len(loaded.exclusions) == number


def test_every_command_and_every_unit_is_named() -> None:
    (actions,) = [a for a in _parser()._actions if isinstance(a, argparse._SubParsersAction)]
    assert set(actions.choices) == {"run", "rollback", "clear-pin", "requeue"}
    for command in actions.choices:
        assert f"`{command}" in TEXT, command
    names = sorted(p.name for p in UNITS.iterdir())
    assert len(names) == 8
    assert "installs the eight files of `deploy/systemd/`" in FLAT
    for name in names:
        assert f"`{name}`" in TEXT, name


def test_the_directories_created_are_the_settings_directories() -> None:
    (names,) = re.findall(r"for name in ([a-z ]+); do", TEXT)
    created = set(names.split())
    assert created == (set(DIRECTORIES) - {"site"}) | {"gnupg"}
    # the nudge directory is shared with the receiver's group, so it is not in the private loop
    assert "nudge" not in created
    assert "-m 2770 -o <publisher-user> -g <web-group> /var/lib/php-pkg-publisher/nudge" in TEXT


def test_the_host_setup_section_names_what_the_code_the_receiver_and_setup_use() -> None:
    receiver = (ROOT / "web" / "sync.php").read_text(encoding="utf-8")
    (secret,) = re.findall(r"const SECRET_FILE = '([^']+)';", receiver)
    (minimum,) = re.findall(r"const MIN_SECRET_BYTES = (\d+);", receiver)
    assert f"-o root -g <web-group> {posixpath.dirname(secret)}\n" in TEXT
    assert f"-g <web-group> <webhook-secret-file> {secret}\n" in TEXT
    assert f'"$(wc -c < {secret})" -ge {minimum}' in TEXT
    (nudge,) = re.findall(r"const NUDGE_DIR = '([^']+)';", receiver)
    assert f"-g <web-group> {nudge}\n" in TEXT
    service = (UNITS / "php-pkg-publisher.service").read_text(encoding="utf-8")
    assert "WorkingDirectory=/opt/php-pkg-publisher" in service
    # the docroot files: the rule serves the receiver from sync.php, and the keyring packages
    # are the ones setup.sh fetches from BASE/keyring/
    assert "<docroot>/sync.php" in TEXT
    assert "RewriteRule ^hooks/sync$ sync.php [L]" in (ROOT / "web" / "docroot.htaccess").read_text(
        encoding="utf-8"
    )
    assert "<docroot>/keyring" in TEXT
    setup = (ROOT / "setup.sh").read_text(encoding="utf-8")
    assert "APT_PACKAGE='rabib-archive-keyring'" in setup
    assert "RPM_PACKAGE='rabib-release'" in setup
    assert '"$BASE/keyring/$1"' in setup
    # the two links the generation publisher's layout note names
    assert "`apt -> <root>/current/apt` and `rpm -> <root>/current/rpm`" in (
        ROOT / "publisher" / "generation.py"
    ).read_text(encoding="utf-8")
    assert "ln -s <site-root>/current/apt <docroot>/apt" in TEXT
    assert "ln -s <site-root>/current/rpm <docroot>/rpm" in TEXT
    # nothing from the checkout is copied by hand but the script: the first deploy installs the
    # rest, and what it installs is what the section says it installs
    layout = Layout(docroot=Path("/docroot"), site_root=Path("/site"))
    assert {rule.source for rule in rules(layout)} == {
        "publisher/",
        "deploy/systemd/",
        "products.yml",
        "web/docroot.htaccess",
        "web/sync.php",
        "deploy/pkg_deploy.py",
    }
    assert "installs the code in `/opt/php-pkg-publisher/publisher`, `products.yml`, the units" in (
        FLAT
    )
    assert "cp -r publisher" not in TEXT
    assert (ROOT / "publisher" / "__main__.py").is_file()


def test_the_script_installed_by_hand_is_checked_as_the_deploy_script_checks_a_tag() -> None:
    """The block that installs the one file the deploy cannot check uses the script's own pins."""
    found = re.findall(r"^[ ]*```sh\n(.*?)^[ ]*```$", TEXT, re.MULTILINE | re.DOTALL)
    (block,) = [text.rstrip() for text in map(textwrap.dedent, found) if "verify-tag" in text]
    # no `set -e`: bash ignores it in a subshell that is followed by `||`, which let a forged tag
    # through when the block was first written
    assert "set -e" not in block
    assert block.count("&&") == 5
    assert pkg_deploy.SSH_KEYGEN == "/usr/bin/ssh-keygen"
    for pin in (
        "gpg.format=ssh",
        f"gpg.ssh.allowedSignersFile={pkg_deploy.CONFIG_DIR}/allowed_signers",
        f"gpg.ssh.program={pkg_deploy.SSH_KEYGEN}",
        "gpg.program=/bin/false",
        "gpg.openpgp.program=/bin/false",
        "gpg.x509.program=/bin/false",
    ):
        assert pin in block, pin
    # the script pins the same programs, and reads no git configuration of the host or the user
    for pin in ("gpg.format=ssh", "gpg.program=/bin/false", "gpg.openpgp.program=/bin/false"):
        assert pin in DEPLOY_SOURCE, pin
    assert "gpg.x509.program=/bin/false" in DEPLOY_SOURCE
    assert '"GIT_CONFIG_NOSYSTEM": "1"' in DEPLOY_SOURCE
    assert '"GIT_CONFIG_GLOBAL": "/dev/null"' in DEPLOY_SOURCE
    assert "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git" in block
    # the signed name is compared, and the bytes are the tag's own, never the working tree's
    # (`verify-tag --format` would hide the reason a tag is refused: it omits git's status lines)
    assert "verify-tag <tag> \\" in block and "--format" not in block.split("verify-tag")[0]
    assert "test \"$(git for-each-ref --format='%(tag)' refs/tags/<tag>)\" = <tag>" in block
    assert "git cat-file blob <tag>:deploy/pkg_deploy.py" in block
    assert "git diff" not in block
    # a failed line ends the block with a non-zero status and a line that says nothing was installed
    assert "trap 'rm -f \"$script\"' EXIT" in block
    assert block.endswith(") || { echo 'script not installed' >&2; false; }")
    assert "belongs to another user (`dubious ownership`)" in FLAT
    # the checkout's own configuration is still read: only the command line outranks it
    assert "git's configuration is not read" not in FLAT
    assert "so the checkout's own configuration cannot swap it" in FLAT


def test_the_host_setup_section_gives_every_file_the_owner_and_mode_it_needs() -> None:
    etc = "/etc/php-pkg-publisher"
    for line in (
        f"install -m 0644 <rpm-key-file> {etc}/rpm-signing.asc",
        f"install -m 0644 <certificate-file> {etc}/signing-certificate.asc",
        f"install -m 0600 -o <publisher-user> <token-file> {etc}/github.token",
        f"install -m 0600 -o <publisher-user> <alert-file> {etc}/telegram.conf",
        "install -d -m 0755 -o root -g root <docroot> <docroot>/keyring",
    ):
        assert line + "\n" in TEXT, line
    # the secrets are the files the publisher reads only when they are 0600 and its own
    assert "`github.token`, `telegram.conf` | `<publisher-user>`, `0600`" in TEXT
    # the deploy writes the files it installs with these owners and modes, root's and closed
    layout = Layout(docroot=Path("/docroot"), site_root=Path("/site"))
    assert layout.owner == (0, 0)
    modes = {rule.source: rule.mode for rule in rules(layout)}
    assert modes["products.yml"] == 0o644
    assert modes["deploy/pkg_deploy.py"] == 0o755
    assert "owned by root and mode `0644`" in FLAT


def test_the_host_setup_section_strips_the_passphrase_offline_and_proves_the_subkey_signs() -> None:
    assert "gpg --change-passphrase <primary-key-fingerprint>\n" in TEXT
    assert "--export-secret-subkeys <signing-subkey-fingerprint>! > <plain-export>\n" in TEXT
    assert "--pinentry-mode error \\\n     --local-user <signing-subkey-fingerprint>!" in TEXT
    assert "stub (`sec#`)" in TEXT
    assert TEXT.count("gpgconf --homedir <signing-home> --kill gpg-agent") == 2
    assert "rm /var/lib/php-pkg-publisher/work/subkey.asc\n" in TEXT
    assert "work" in DIRECTORIES


def test_the_host_setup_check_tries_what_the_web_servers_user_may_and_may_not_do() -> None:
    probes = re.findall(r"^runuser -u <web-user> -- test (-[rw]) (\S+)$", TEXT, re.MULTILINE)
    assert probes == [
        ("-r", "/etc/php-pkg-publisher-webhook/secret"),
        ("-w", "/var/lib/php-pkg-publisher/nudge"),
        ("-w", "/opt/php-pkg-publisher"),
        ("-w", "<docroot>"),
        ("-w", "<docroot>/.."),
        ("-r", "/var/lib/php-pkg-publisher/state"),
        ("-r", "/var/lib/php-pkg-publisher/gnupg"),
        ("-r", "/etc/php-pkg-publisher/github.token"),
    ]
    assert "namei -l /opt/php-pkg-publisher/publisher/__main__.py <docroot>/sync.php\n" in TEXT


def test_the_docroot_is_locked_against_the_web_servers_user_in_the_order_that_works() -> None:
    # the folder above is root's, the flag is cleared before root writes and set after the last
    # entry, and everything in the docroot ends up root's
    (block,) = re.findall(
        r"^   ```sh\n((?:   chown root:root <docroot-parent>\n).*?)   ```$", TEXT, re.M | re.S
    )
    commands = [line.strip() for line in block.splitlines()]
    assert commands == [
        "chown root:root <docroot-parent>",
        "chmod 0755 <docroot-parent>",
        "chattr -i <docroot>",
        "install -d -m 0755 -o root -g root <docroot> <docroot>/keyring",
        "ln -s <site-root>/current/apt <docroot>/apt",
        "ln -s <site-root>/current/rpm <docroot>/rpm",
        "chown -hR root:root <docroot>",
        "chmod -R go-w,a+rX <docroot>",
        "chattr +i <docroot>",
    ]
    assert "<publisher-user>" not in block
    assert "lsattr -d <docroot>\nfind <docroot> ! -user root -print\n" in TEXT
    assert "`<docroot-parent>`, the folder that holds `<docroot>`, is owned by root" in FLAT
    # the file's own header says who owns it
    assert "owned by root and read-only to the site user" in (
        ROOT / "web" / "docroot.htaccess"
    ).read_text(encoding="utf-8")
    # open_basedir lists the docroot, the nudge directory and the secret folder (the two paths the
    # receiver's constants name, tested above)
    (sentence,) = re.findall(r"set PHP's `open_basedir` for the site to (.*?): the receiver", FLAT)
    assert sentence == "`<docroot>`, the nudge directory, the webhook secret folder and `/tmp`"


def test_the_publisher_user_is_the_one_the_units_run_as() -> None:
    users = {
        re.search(r"^User=(.*)$", (UNITS / unit).read_text(encoding="utf-8"), re.MULTILINE)
        for unit in (
            "php-pkg-publisher.service",
            "php-pkg-publisher-watch.service",
            "php-pkg-publisher-notify@.service",
        )
    }
    assert {u.group(1) for u in users if u} == {"php-pkg-publisher"}
    assert "must be the `User=` of the units (`php-pkg-publisher`)" in TEXT
    service = (UNITS / "php-pkg-publisher.service").read_text(encoding="utf-8")
    assert "ReadWritePaths=" in service
    assert "the site path in the\nservice's `ReadWritePaths=`" in TEXT


def test_the_site_layout_the_rollback_and_rotation_steps_describe_is_the_codes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "site"
    root.mkdir(mode=0o755)
    site = generation.open_site(root)
    assert site.manifests == root / "generations"
    assert site.versions == root / "versions"
    assert "directory names in `<site-root>/versions/`" in TEXT
    assert signer.STUB == "#"
    assert "shows the primary key as a stub (`sec#`)" in TEXT
    assert "runuser -u <publisher-user> -- gpg --homedir <signing-home> --list-secret-keys" in TEXT
    assert "/etc/php-pkg-publisher-webhook/secret" in TEXT
    assert "/etc/php-pkg-publisher-webhook/secret" in (ROOT / "web/sync.php").read_text(
        encoding="utf-8"
    )


def test_the_stored_file_section_quotes_what_the_code_says() -> None:
    source = (ROOT / "publisher" / "generation.py").read_text(encoding="utf-8")
    assert "lost" in source
    runner = (ROOT / "publisher" / "run.py").read_text(encoding="utf-8")
    for kind in ("store-repaired", "store-lost"):
        assert f'kind="{kind}"' in runner
        assert f"`{kind}` alert" in TEXT
    assert generation.KEEP_TREES == 3
    assert generation.LIVE_GENERATIONS == 3
    assert "one of the last three generations" in TEXT


def test_the_receiver_reasons_the_runbook_lists_are_the_codes() -> None:
    source = (ROOT / "web" / "sync.php").read_text(encoding="utf-8")
    reasons = re.findall(r"fail\('([a-z-]+)'\)", source)
    assert sorted(reasons) == [
        "guid-directory-unusable",
        "nudge-directory-missing",
        "nudge-failed",
        "secret-unusable",
    ]
    for reason in (*reasons, "internal-error"):
        assert f"`{reason}`" in TEXT
    assert "pkg-hook: " in source
    assert "`pkg-hook:`" in TEXT


def test_the_rotation_margin_is_beyond_the_last_day_the_signer_accepts() -> None:
    last_day = metadata.VALID_SECONDS / 86400
    (in_runbook,) = re.findall(r"at least (\d+) days before the old subkey expires", FLAT)
    (in_security,) = re.findall(
        r"shipped and at least (\d+) days before the old one expires", SECURITY_FLAT
    )
    assert in_runbook == in_security
    assert int(in_runbook) > last_day
    assert f"expires within {last_day:.0f} days of a run" in FLAT
    assert f"{last_day:.0f} days or fewer left cannot be used" in SECURITY_FLAT


def test_the_unit_section_quotes_what_the_units_and_the_code_say() -> None:
    service = (UNITS / "php-pkg-publisher.service").read_text(encoding="utf-8")
    assert "SuccessExitStatus=143" in service
    assert "| 143 |" in TEXT
    assert "StartLimitBurst=5" in service
    assert "StartLimitIntervalSec=600" in service
    assert "allows five starts within ten minutes and refuses the sixth" in FLAT
    for command in re.findall(r"^systemctl [a-z-]+(?: --now)? ([\w. -]+)$", TEXT, re.MULTILINE):
        for name in command.split():
            assert (UNITS / name).is_file(), name
    assert "systemctl enable --now php-pkg-publisher.path" in TEXT
    assert watch.NUDGE_STALE_HOURS == 2
    assert "or the nudge file is older than 2 hours (no run lasts that long" in FLAT
    assert "`nudge-stale` when the nudge file is older than 2 hours" in FLAT
    assert "disable --now php-pkg-publisher-watch.timer" in FLAT
    assert "also ends the run with 143" in FLAT
    assert "alerting each time" in service
    assert 'kind="nudge-stale"' in (ROOT / "publisher" / "watch.py").read_text(encoding="utf-8")
    lock_source = (ROOT / "publisher" / "lock.py").read_text(encoding="utf-8")
    assert 'f"{path.name}.rejected-' in lock_source
    assert "`sync.rejected-` and a number" in FLAT


def test_the_throttle_note_quotes_the_receivers_numbers_and_header() -> None:
    source = (ROOT / "web" / "sync.php").read_text(encoding="utf-8")
    (limit,) = re.findall(r"const THROTTLE_LIMIT = (\d+);", source)
    (window,) = re.findall(r"const THROTTLE_WINDOW = (\d+);", source)
    assert f"{limit} requests in {window} seconds" in SECURITY_FLAT
    assert "HTTP_CF_CONNECTING_IP" in source
    assert "`CF-Connecting-IP`" in SECURITY_FLAT
    assert "origin must therefore accept connections from Cloudflare only" in SECURITY_FLAT
    assert "answer GitHub's real deliveries with 429" in SECURITY_FLAT


def test_the_numbers_quoted_are_the_codes() -> None:
    assert (watch.TOKEN_WARNING_DAYS, watch.CERTIFICATE_WARNING_DAYS) == (30, 21)
    assert (watch.DATE_MAX_AGE_DAYS, watch.VALID_UNTIL_WARNING_DAYS) == (3, 7)
    assert "fewer than 30 days left" in TEXT
    assert "fewer than 21" in TEXT
    assert "older than 3 days" in TEXT
    assert "fewer than 7 days away" in TEXT
    assert admit.QUARANTINE_ATTEMPTS == 5
    assert admit.QUARANTINE_AGE_SECONDS == 3 * 86400
    assert "at least 5 times" in TEXT
    assert "at least\n3 days old" in TEXT


def test_the_outside_watch_section_names_what_the_workflow_and_the_script_use() -> None:
    workflow = (ROOT / ".github" / "workflows" / "platform-watch.yml").read_text(encoding="utf-8")
    for name in ("TELEGRAM_CHAT_ID", "TELEGRAM_BOT_TOKEN"):
        assert f"`{name}`" in TEXT
        assert f"{name}: ${{{{ secrets.{name} }}}}" in workflow
    assert "deploy/primary-fingerprint.txt" in TEXT
    assert "--pin-file deploy/primary-fingerprint.txt --products products.yml" in workflow
    assert "--pin-file deploy/primary-fingerprint.txt --products products.yml" in TEXT.replace(
        " \\\n  ", " "
    )
    assert "(Actions, `Platform watch`)" in TEXT
    assert "name: Platform watch" in workflow
    assert (platform_watch.DATE_MAX_AGE_DAYS, platform_watch.VALID_UNTIL_MIN_DAYS) == (4, 7)
    assert platform_watch.SIGNATURE_MAX_AGE_DAYS == 4
    assert "`Date` is older than 4 days or its `Valid-Until` is fewer than 7 days away" in TEXT
    assert "made or served more than 4 days ago" in TEXT


def test_the_release_section_names_what_the_workflow_and_the_tool_do() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "name: Release" in workflow
    assert "`Release` workflow" in TEXT
    en_dash = chr(0x2013)
    assert f"PHP Package Publisher {en_dash} $TAG" in workflow
    assert f"titled `PHP Package Publisher {en_dash} v<version>`" in FLAT
    assert (ROOT / "tools" / "release_notes.py").is_file()
    assert "python3 tools/release_notes.py v<version>" in TEXT
    assert 'git tag -s v<version> -m "Release v<version>"' in TEXT
    assert "git push origin v<version>" in TEXT
    assert "git merge-base --is-ancestor HEAD origin/main" in workflow
    assert "does not check the tag's signature" in FLAT


def test_the_rotation_section_names_the_key_drill_that_exists() -> None:
    assert "pytest -m container tests/container/test_key_drill.py" in TEXT
    assert (ROOT / "tests" / "container" / "test_key_drill.py").is_file()


def test_the_notes_hold_only_placeholders_no_fingerprint_and_no_address() -> None:
    allowed = {
        "<publisher-user>",
        "<web-group>",
        "<signing-home>",
        "<site-root>",
        "<docroot>",
        "<docroot-parent>",
        "<subkey-export>",
        "<plain-export>",
        "<rpm-key-file>",
        "<certificate-file>",
        "<alert-file>",
        "<web-user>",
        "<token-file>",
        "<webhook-secret-file>",
        "<origin-public-ip>",
        "<repo>",
        "<tag>",
        "<generation>",
        "<code>",
        "<deploy-user>",
        "<deploy-public-key>",
        "<release-public-key>",
        "<deploy-key-file>",
        "<origin-host>",
        "<ssh-port>",
        "<bundle-file>",
        "<keyring-file>",
        "<signing-subkey-fingerprint>",
        "<primary-key-fingerprint>",
        "<version>",
        "<sha256>",
        "<id>",
        "<bot token>",
    }
    assert set(re.findall(r"<[^<>\n]+>", TEXT)) <= allowed
    assert not re.search(r"\b[0-9A-F]{40}\b", TEXT)
    assert not re.search(r"\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b", TEXT)


DEPLOY: Final = TEXT.split("## Deploying a change")[1].split("## Key rotation")[0]
DEPLOY_SOURCE: Final = (ROOT / "deploy" / "pkg_deploy.py").read_text(encoding="utf-8")


def test_the_deploy_tables_list_every_code_and_exit_status_the_script_has() -> None:
    assert set(re.findall(r"^\| `([a-z-]+)` \|", DEPLOY, re.MULTILINE)) == set(pkg_deploy.CODES)
    refused, rolled, broken = (
        pkg_deploy.EXIT_REFUSED,
        pkg_deploy.EXIT_ROLLED_BACK,
        pkg_deploy.EXIT_BROKEN,
    )
    assert (refused, rolled, broken) == (2, 3, 4)
    for row in (
        "| `deployed <tag>` | 0 |",
        f"| `refused: <code>` | {refused} |",
        f"| `refused: rolled-back` | {rolled} |",
        f"| `refused: step-failed` | {refused} or {rolled} |",
        f"| `broken: restore failed` | {broken} |",
    ):
        assert row in DEPLOY, row
    # the lines are the ones the script prints, and the details go where the text says
    for printed in (
        'say(f"deployed {name}")',
        '"refused: rolled-back"',
        '"broken: restore failed"',
    ):
        assert printed in DEPLOY_SOURCE, printed
    assert 'syslog.openlog("php-pkg-publisher-deploy")' in DEPLOY_SOURCE
    assert "journalctl -t php-pkg-publisher-deploy" in DEPLOY
    assert pkg_deploy.MAX_BUNDLE_BYTES == 64 * 1024 * 1024
    assert "| `bundle-size` | Over 64 MiB. |" in DEPLOY


def test_the_deploy_commands_on_the_host_are_the_ones_the_script_takes() -> None:
    documented = set(re.findall(r"^\| `php-pkg-publisher-deploy (\w+)", DEPLOY, re.MULTILINE))
    assert documented == {"rollback", "allow", "check", "record", "forget"}
    for taken in ('arguments == ["rollback"]', 'arguments == ["check"]', '{"record", "forget"}'):
        assert taken in DEPLOY_SOURCE, taken
    assert 'arguments[0] == "allow"' in DEPLOY_SOURCE
    assert pkg_deploy.KEEP_BACKUPS == 5
    assert "The 5 newest backups are kept." in FLAT
    assert "prints `DEPLOY CHECK PASSED`" in FLAT
    assert 'say("DEPLOY CHECK PASSED")' in DEPLOY_SOURCE
    assert 'say(f"FAIL: {problem}")' in DEPLOY_SOURCE
    # a deploy that did not finish: the marker, the refusal, and nothing starts the units again
    assert "until `rollback` has run" in FLAT
    assert '"an earlier deploy did not finish"' in DEPLOY_SOURCE
    assert "so start them again by hand once it has finished" in FLAT


def test_the_deploy_setup_names_the_paths_the_script_and_the_unit_use() -> None:
    script = pkg_deploy.SELF_PATH.as_posix()
    for path in (
        pkg_deploy.CONFIG_DIR / "deploy.conf",
        pkg_deploy.CONFIG_DIR / "allowed_signers",
        pkg_deploy.STATE_DIR,
        pkg_deploy.STATE_DIR / "backups",
        pkg_deploy.SELF_PATH,
    ):
        assert path.as_posix() in TEXT, path
    assert f"ExecStart={script} check" in (
        UNITS / "php-pkg-publisher-deploy-check.service"
    ).read_text(encoding="utf-8")
    # the key runs the script through sudo with no terminal and no forwarding; sudo allows that
    # one command with no arguments; the state folder may be entered, the backups may not
    assert f'restrict,command="/usr/bin/sudo {script}" <deploy-public-key>\'' in TEXT
    assert f'<deploy-user> ALL=(root) NOPASSWD: {script} ""\\n\'' in TEXT
    # sudoers is checked before it goes live: a broken file there stops sudo for everyone
    assert (
        'visudo -cf "$sudoers" && install -m 0440 "$sudoers" '
        "/etc/sudoers.d/php-pkg-publisher-deploy\n"
    ) in TEXT
    assert "`rollback` bans the version it undid" in FLAT
    assert "Read the exit status, not the first line: for a valid signature by a key" in FLAT
    assert f"install -d -m 0711 {pkg_deploy.STATE_DIR}\n" in TEXT
    assert f"install -d -m 0700 {pkg_deploy.STATE_DIR}/backups\n" in TEXT
    assert "useradd --create-home --shell /bin/sh <deploy-user>\n" in TEXT
    assert "(the state folder must be `0711`)" in DEPLOY


def test_the_deploy_examples_load_and_verify_a_tag_once_the_placeholders_are_filled(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_dir.chmod(0o755)
    (settings,) = re.findall(r"printf '(docroot=<docroot>\\nsite_root=<site-root>\\n)'", TEXT)
    filled = settings.replace("<docroot>", "/srv/www/site/public_html")
    filled = filled.replace("<site-root>", "/srv/pkg/site").replace("\\n", "\n")
    conf = config_dir / "deploy.conf"
    conf.write_text(filled, encoding="utf-8")
    conf.chmod(0o644)
    layout = Layout.load(config_dir)
    assert layout.docroot == Path("/srv/www/site/public_html")
    assert layout.site_root == Path("/srv/pkg/site")
    # the signer line, filled with a throwaway key, accepts a tag signed by that key
    (signers,) = re.findall(
        r"printf '(php-pkg-publisher-release namespaces=\"git\" <release-public-key>)\\n'", TEXT
    )
    assert signers.startswith(f"{pkg_deploy.PRINCIPAL} ")
    generate_key(tmp_path / "release")
    kind, key, *_ = (tmp_path / "release.pub").read_text(encoding="utf-8").split()
    layout.allowed_signers.write_text(
        signers.replace("<release-public-key>", f"{kind} {key}") + "\n", encoding="utf-8"
    )
    folder = tmp_path / "tags"
    folder.mkdir()
    bundle = signed_bundle(folder, {"release": tmp_path / "release.pub"}, {"x": b"y"}, "v1.0.0")
    work = tmp_path / "work"
    work.mkdir()
    assert pkg_deploy.verify_bundle(bundle, work, layout).name == "v1.0.0"


def test_the_deploy_github_setup_names_what_the_workflow_uses() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "environment: production" in workflow
    assert "create the environment `production` and limit its deployment tags to `v*`" in FLAT
    assert 'tags: ["v*"]' in workflow
    for name in ("DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS", "DEPLOY_TARGET"):
        assert f"| `{name}` |" in DEPLOY, name
        assert f"secrets.{name}" in workflow, name
    assert "ssh://<deploy-user>@<origin-host>:<ssh-port>" in DEPLOY
    # the host key line comes from the host's own key, in the form ssh looks up
    assert (
        """printf '[<origin-host>]:<ssh-port> %s\\n' "$(cut -d' ' -f1,2 """
        '/etc/ssh/ssh_host_ed25519_key.pub)"\n'
    ) in DEPLOY
    assert "printf '<origin-host> %s\\n'" in DEPLOY
    assert "ssh-keygen -q -t ed25519 -N '' -f <deploy-key-file>\n" in DEPLOY
