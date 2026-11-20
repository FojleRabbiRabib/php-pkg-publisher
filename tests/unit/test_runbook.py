# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`docs/runbook.md` against the code it describes: the settings example loads, the exclusion
example loads, every command and unit is named, and the numbers it quotes are the code's.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Final

import platform_watch

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
    assert len(names) == 6
    for name in names:
        assert f"`{name}`" in TEXT, name


def test_the_directories_created_are_the_settings_directories() -> None:
    (names,) = re.findall(r"for name in ([a-z ]+); do", TEXT)
    created = set(names.split())
    assert created == (set(DIRECTORIES) - {"site"}) | {"gnupg"}
    # the nudge directory is shared with the receiver's group, so it is not in the private loop
    assert "nudge" not in created
    assert "-m 2770 -o <publisher-user> -g <web-group> /var/lib/php-pkg-publisher/nudge" in TEXT


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
    assert "/etc/php-pkg-publisher-webhook/secret" in (ROOT / "web/hooks/sync.php").read_text(
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
    source = (ROOT / "web" / "hooks" / "sync.php").read_text(encoding="utf-8")
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
    source = (ROOT / "web" / "hooks" / "sync.php").read_text(encoding="utf-8")
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
        "<origin-public-ip>",
        "<repo>",
        "<tag>",
        "<generation>",
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
