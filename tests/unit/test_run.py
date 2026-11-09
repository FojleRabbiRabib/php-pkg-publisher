# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import pytest

from publisher import admit, feed, generation, run, verify
from publisher import alert as alert_module
from publisher import lock as locking
from publisher.__main__ import main
from publisher.alert import MAX_TEXT, Alert, clean
from publisher.config import Exclusion, ExclusionList, Product, ProductList
from publisher.settings import Settings, load_settings
from publisher.tools import ToolError, Tools

PRODUCT = Product(
    repo="usearch-php",
    extension="usearch",
    php=("8.3",),
    arch=("amd64",),
    ts=("nts",),
    exclude=("v0.1.0",),
)
PRODUCTS = ProductList(source=Path("/p"), sha256="a" * 64, products=(PRODUCT,))
EXCLUSIONS = ExclusionList(
    source=Path("/e"),
    sha256="b" * 64,
    exclusions=(Exclusion(product="usearch-php", tag="v0.2.0"),),
)


@dataclass
class FakeStages:
    refreshed: bool = True
    report: admit.Report = field(default_factory=lambda: admit.Report(events=(), stopped=None))
    published: generation.Published = field(
        default_factory=lambda: generation.Published(
            generation="00000001-20260101T000000Z", skipped=False, pinned=False
        )
    )
    calls: list[str] = field(default_factory=list)

    def trusted_root(self, now: float) -> verify.TrustedRoot:
        self.calls.append("trust")
        return verify.TrustedRoot(path=Path("/t"), age_seconds=3 * 86400, refreshed=self.refreshed)

    def admit(self, now: float) -> admit.Report:
        self.calls.append("admit")
        return self.report

    def publish(
        self, products: ProductList, exclusions: ExclusionList, now: float
    ) -> generation.Published:
        self.calls.append("publish")
        return self.published


def _run(stages: FakeStages) -> tuple[run.Result, list[str]]:
    lines: list[str] = []
    result = run.run_pass(stages, PRODUCTS, EXCLUSIONS, now=1.0, log=lines.append)
    return result, lines


def _kinds(result: run.Result) -> list[str]:
    return [alert.kind for alert in result.alerts]


def test_a_clean_pass_alerts_only_the_publish() -> None:
    result, lines = _run(FakeStages())
    assert _kinds(result) == ["published"]
    assert result.failure is None
    assert lines[0] == f"products {'a' * 64} exclusions {'b' * 64}"


def test_a_skipped_publish_is_silent() -> None:
    stages = FakeStages(published=generation.Published(generation=None, skipped=True, pinned=False))
    result, _ = _run(stages)
    assert result.alerts == ()


def test_the_order_is_trust_then_admit_then_publish() -> None:
    stages = FakeStages()
    _run(stages)
    assert stages.calls == ["trust", "admit", "publish"]


def test_a_stale_trusted_root_alerts_without_failing() -> None:
    result, _ = _run(FakeStages(refreshed=False))
    assert "stale-trust-root" in _kinds(result)
    assert result.failure is None


def test_a_stopped_admit_stage_fails_the_run_but_still_publishes() -> None:
    stages = FakeStages(report=admit.Report(events=(), stopped="token rejected"))
    result, _ = _run(stages)
    assert stages.calls[-1] == "publish"
    assert result.failure is not None
    assert result.failure.startswith("admit stopped")
    stop = next(a for a in result.alerts if a.kind == "stopped")
    assert stop.urgent


@pytest.mark.parametrize(
    ("kind", "alert_kind"),
    [
        ("failed", "admit-failed"),
        ("quarantined", "quarantined"),
        ("quarantine-alert", "quarantined"),
        ("product-error", "product-error"),
    ],
)
def test_tag_and_product_faults_alert_without_failing(kind: str, alert_kind: str) -> None:
    event = admit.Event(product="usearch-php", tag="v1.0.0", kind=kind, detail="why")  # type: ignore[arg-type]
    result, _ = _run(FakeStages(report=admit.Report(events=(event,), stopped=None)))
    assert alert_kind in _kinds(result)
    assert result.failure is None
    assert next(a for a in result.alerts if a.kind == alert_kind).key is None


def test_admitted_events_do_not_alert() -> None:
    event = admit.Event(product="usearch-php", tag="v1.0.0", kind="admitted", detail="2 packages")
    result, _ = _run(FakeStages(report=admit.Report(events=(event,), stopped=None)))
    assert _kinds(result) == ["published"]


@pytest.mark.parametrize("kind", ["changed", "vanished"])
def test_repeating_events_carry_a_dedupe_key(kind: str) -> None:
    event = admit.Event(product="usearch-php", tag="v1.0.0", kind=kind, detail="x")  # type: ignore[arg-type]
    result, _ = _run(FakeStages(report=admit.Report(events=(event,), stopped=None)))
    alert = next(a for a in result.alerts if a.kind == kind)
    assert alert.key == f"{kind}:usearch-php v1.0.0"


def test_a_dropped_pin_and_a_cleanup_failure_alert_without_failing() -> None:
    stages = FakeStages(
        published=generation.Published(
            generation="00000002-20260101T000000Z",
            skipped=False,
            pinned=False,
            pin_dropped=True,
            retire_error="cannot remove an old tree",
        )
    )
    result, _ = _run(stages)
    assert _kinds(result) == ["published", "pin-dropped", "cleanup-failed"]
    assert result.failure is None


def test_alert_text_is_ascii_and_capped() -> None:
    event = admit.Event(
        product="usearch-php", tag="v1.0.0", kind="failed", detail="‮\n" + "x" * 1000
    )
    result, _ = _run(FakeStages(report=admit.Report(events=(event,), stopped=None)))
    text = next(a for a in result.alerts if a.kind == "admit-failed").text
    assert text.isascii()
    assert "\n" not in text
    assert len(text) <= MAX_TEXT
    assert len(clean("é" * 500)) == MAX_TEXT


def test_excluded_pairs_join_both_sources() -> None:
    assert run.excluded_pairs(PRODUCTS, EXCLUSIONS) == {
        ("usearch-php", "v0.1.0"),
        ("usearch-php", "v0.2.0"),
    }


def test_an_alert_defaults_are_quiet() -> None:
    alert = Alert(kind="k", text="t")
    assert (alert.urgent, alert.key) == (False, None)


def test_the_command_fails_cleanly_on_a_missing_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(tmp_path / "missing.yml"), "clear-pin"]) == 1
    assert "failed:" in capsys.readouterr().err


def test_the_command_needs_a_subcommand() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--config", "/x"])
    assert caught.value.code == 2


def _settings(tmp_path: Path) -> Settings:
    for name in ("site", "state", "cache", "trust", "work", "lock", "nudge"):
        (tmp_path / name).mkdir(mode=0o700)
    (tmp_path / "site").chmod(0o755)
    (tmp_path / "products.yml").write_text(
        "products:\n"
        "  - repo: usearch-php\n    extension: usearch\n"
        '    php: ["8.3"]\n    arch: [amd64]\n    ts: [nts]\n',
        encoding="utf-8",
    )
    (tmp_path / "exclude.yml").write_text("exclude: []\n", encoding="utf-8")
    text = (
        f"products: {tmp_path}/products.yml\nexclude: {tmp_path}/exclude.yml\n"
        + "".join(f"{n}: {tmp_path}/{n}\n" for n in ("site", "state", "cache", "trust", "work"))
        + f"lock: {tmp_path}/lock\nnudge: {tmp_path}/nudge/sync\nrpm_key: {tmp_path}/k.asc\n"
        f'token: {{file: {tmp_path}/t, expires: "2027-01-31"}}\n'
        f"alert: {{file: {tmp_path}/a}}\n"
        "watch: {host: pkg.example.org, origin: 93.184.216.34}\n"
        f"signing: {{home: {tmp_path}/g, fingerprint: {'A' * 40}, "
        f"certificate: {tmp_path}/c, primary: {'B' * 40}}}\n"
    )
    (tmp_path / "publisher.yml").write_text(text, encoding="utf-8")
    return load_settings(tmp_path / "publisher.yml")


def test_run_once_consumes_the_nudge_and_runs_one_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    fake = FakeStages()
    monkeypatch.setattr(run, "LiveStages", lambda *a, **k: fake)
    monkeypatch.setattr(Tools, "locate", classmethod(lambda cls: None))
    monkeypatch.setattr(run, "Cache", lambda *a, **k: None)
    settings.nudge.write_bytes(b"")
    seen: list[run.Result] = []
    results = run.run_once(settings, emit=seen.append, now=5.0, log=lambda _: None)
    assert seen == results
    assert [r.failure for r in results] == [None]
    assert not settings.nudge.exists()
    assert fake.calls == ["trust", "admit", "publish"]


def test_clear_pin_removes_the_pin_under_the_lock(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    site = generation.open_site(settings.site)
    site.pin.write_text("{}", encoding="utf-8")
    run.clear_pin(settings)
    assert not site.pin.exists()


def test_alerts_of_a_finished_pass_are_emitted_before_a_later_pass_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    good = FakeStages()
    calls = {"n": 0}

    def make(*args: object, **kwargs: object) -> FakeStages:
        calls["n"] += 1
        if calls["n"] == 2:
            raise verify.VerifyError("boom")
        return good

    monkeypatch.setattr(run, "LiveStages", make)
    monkeypatch.setattr(Tools, "locate", classmethod(lambda cls: None))
    monkeypatch.setattr(run, "Cache", lambda *a, **k: None)
    real_pending = locking._pending
    monkeypatch.setattr(locking, "_pending", lambda path: calls["n"] == 1 or real_pending(path))
    seen: list[run.Result] = []
    with pytest.raises(verify.VerifyError):
        run.run_once(settings, emit=seen.append, now=5.0, log=lambda _: None)
    assert [_kinds(r) for r in seen] == [["published"]]


def test_a_raising_pass_puts_the_nudge_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)

    def make(*args: object, **kwargs: object) -> FakeStages:
        raise verify.VerifyError("boom")

    monkeypatch.setattr(run, "LiveStages", make)
    monkeypatch.setattr(Tools, "locate", classmethod(lambda cls: None))
    monkeypatch.setattr(run, "Cache", lambda *a, **k: None)
    settings.nudge.write_bytes(b"")
    with pytest.raises(verify.VerifyError):
        run.run_once(settings, emit=lambda _: None, now=5.0, log=lambda _: None)
    assert settings.nudge.exists()


@pytest.mark.parametrize("broken", ["trusted_root", "admit"])
@pytest.mark.parametrize(
    "fault", [verify.VerifyError("x"), ToolError("x"), feed.FeedError("x"), PermissionError("x")]
)
def test_a_setup_fault_stops_only_the_admit_stage_and_publishing_still_runs(
    broken: str, fault: Exception
) -> None:
    stages = FakeStages()

    def fail(*args: object) -> None:
        raise fault

    setattr(stages, broken, fail)
    result, _ = _run(stages)
    assert "publish" in stages.calls
    assert result.failure is not None
    assert next(a for a in result.alerts if a.kind == "stopped").urgent
    assert "published" in _kinds(result)


def test_a_fault_outside_the_setup_faults_is_not_swallowed() -> None:
    stages = FakeStages()

    def fail(*args: object) -> None:
        raise KeyError("x")

    stages.admit = fail  # type: ignore[method-assign,assignment]
    with pytest.raises(KeyError):
        _run(stages)
    assert "publish" not in stages.calls


def test_a_pinned_publish_says_so() -> None:
    stages = FakeStages(
        published=generation.Published(generation="00000003-x", skipped=False, pinned=True)
    )
    result, _ = _run(stages)
    assert "pinned, new releases held" in result.alerts[0].text


def test_clean_removes_key_fingerprints() -> None:
    text = clean("key " + "A" * 40 + " and " + "b" * 40 + " but not " + "c" * 64)
    assert "A" * 40 not in text
    assert "b" * 40 not in text
    assert text.count("<id>") == 2 or "<id>" in text
    assert "c" * 64 in text


def test_a_publish_that_raises_after_a_stopped_admit_raises() -> None:
    stages = FakeStages(report=admit.Report(events=(), stopped="token rejected"))

    def fail(*args: object) -> None:
        raise generation.GenerationError("no")

    stages.publish = fail  # type: ignore[method-assign,assignment]
    with pytest.raises(generation.GenerationError):
        _run(stages)


class _FakeTelegram:
    sent: ClassVar[list[str]] = []
    fail: ClassVar[bool] = False

    def __init__(self, credentials: object) -> None:
        pass

    def send(self, text: str, *, silent: bool) -> None:
        if self.fail:
            raise alert_module.DeliveryError("down")
        self.sent.append(text)


def _fake_telegram(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> None:
    _FakeTelegram.sent = []
    _FakeTelegram.fail = fail
    monkeypatch.setattr(alert_module, "Telegram", _FakeTelegram)


def _write_credentials(settings: Settings) -> None:
    settings.alert_file.write_text(
        "chat_id=5\ntoken=123456789:" + "A" * 30 + "\n", encoding="utf-8"
    )
    settings.alert_file.chmod(0o600)


def _patch_run_once(monkeypatch: pytest.MonkeyPatch, results: list[run.Result]) -> None:
    _fake_telegram(monkeypatch)

    def fake(settings: Settings, *, emit: object, **kwargs: object) -> list[run.Result]:
        for result in results:
            emit(result)  # type: ignore[operator]
        return results

    monkeypatch.setattr(run, "run_once", fake)


def test_main_run_exits_one_on_a_failed_pass_and_prints_alerts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_credentials(_settings(tmp_path))
    failing = run.Result(alerts=(Alert(kind="stopped", text="x"),), failure="admit stopped: x")
    _patch_run_once(monkeypatch, [failing])
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 1
    err = capsys.readouterr().err
    assert "alert stopped: x" in err
    assert "failed: admit stopped: x" in err


def test_main_run_exits_zero_when_only_tags_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_credentials(_settings(tmp_path))
    quiet = run.Result(alerts=(Alert(kind="admit-failed", text="t"),), failure=None)
    _patch_run_once(monkeypatch, [quiet])
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 0
    assert "alert admit-failed: t" in capsys.readouterr().err
    assert _FakeTelegram.sent == ["[admit-failed] t"]


def test_main_stays_green_when_the_chat_service_is_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_credentials(_settings(tmp_path))
    _patch_run_once(monkeypatch, [run.Result(alerts=(Alert(kind="k", text="t"),), failure=None)])
    _fake_telegram(monkeypatch, fail=True)
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 0
    assert "undelivered alert [k] t" in capsys.readouterr().err


def test_main_turns_an_unexpected_exception_into_exit_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _settings(tmp_path)

    def explode(*args: object, **kwargs: object) -> None:
        raise KeyError("/var/lib/secret/place")

    monkeypatch.setattr(run, "run_once", explode)
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 1
    err = capsys.readouterr().err
    assert "unexpected KeyError" in err
    assert "Traceback" not in err
    assert "/var/lib" not in err


def test_main_rollback_reports_the_new_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _settings(tmp_path)
    seen: list[str] = []

    def fake(settings: Settings, identifier: str, **kwargs: object) -> generation.Published:
        seen.append(identifier)
        return generation.Published(generation="00000009-x", skipped=False, pinned=True)

    monkeypatch.setattr(run, "rollback", fake)
    code = main(["--config", str(tmp_path / "publisher.yml"), "rollback", "00000001-y"])
    assert code == 0
    assert seen == ["00000001-y"]
    assert "00000009-x" in capsys.readouterr().out


def test_clean_removes_host_paths() -> None:
    text = clean("/var/lib/pp/state/x.json: unreadable; also (/etc/pp/a.yml) and owner/repo")
    assert "/var" not in text
    assert "/etc" not in text
    assert "owner/repo" in text
    assert text.count("<path>") == 2


def test_log_lines_hold_no_raw_release_text() -> None:
    event = admit.Event(product="p\nq", tag="v1\x1b[31m", kind="failed", detail="d\ne")
    _, lines = _run(FakeStages(report=admit.Report(events=(event,), stopped=None)))
    line = next(entry for entry in lines if entry.startswith("failed"))
    assert "\n" not in line
    assert "\x1b" not in line


def test_an_unusable_alert_file_fails_the_run_after_the_alerts_were_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _settings(tmp_path)  # no credentials file was written
    quiet = run.Result(alerts=(), failure=None)
    _patch_run_once(monkeypatch, [run.Result(alerts=(Alert(kind="k", text="g1"),), failure=None)])
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 1
    err = capsys.readouterr().err
    assert "alert k: g1" in err
    assert "failed:" in err
    _patch_run_once(monkeypatch, [quiet])
    assert main(["--config", str(tmp_path / "publisher.yml"), "run"]) == 1


@pytest.mark.parametrize(
    ("days", "alerts"),
    [(29.5, True), (0.0, True), (-3.0, True), (30.0, False), (200.0, False)],
)
def test_the_subkey_alert_fires_under_thirty_days(days: float, alerts: bool) -> None:
    stages = FakeStages(
        published=generation.Published(
            generation="00000002-20260101T000000Z",
            skipped=False,
            pinned=False,
            subkey_expires=1.0 + days * 86400,
        )
    )
    result, _ = _run(stages)
    assert ("subkey-expiring" in _kinds(result)) is alerts
    if alerts:
        alert = next(a for a in result.alerts if a.kind == "subkey-expiring")
        assert alert.urgent
        assert alert.key == "subkey-expiring"
        assert "signing stops in" in alert.text
        assert result.failure is None


def test_the_subkey_alert_names_the_day_signing_stops() -> None:
    stages = FakeStages(
        published=generation.Published(
            generation="00000002-20260101T000000Z",
            skipped=False,
            pinned=False,
            subkey_expires=1.0 + 25 * 86400,
        )
    )
    result, _ = _run(stages)
    (alert,) = (a for a in result.alerts if a.kind == "subkey-expiring")
    assert alert.text == "the signing subkey expires in 25 days and signing stops in 11 days"
