import json
from datetime import datetime

import pytest

from nonetpass.config import Settings
from nonetpass.journal import SessionJournal
from nonetpass.reports import build_report, get_tz, maybe_send_monthly, parse_period, report_text
from nonetpass.store import StateStore

TZ = get_tz("Europe/Moscow")
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=TZ)


@pytest.mark.parametrize("text, label, start, end", [
    ("", "октябрь 2026 (по сегодня)", "2026-10-01", None),
    ("prev", "сентябрь 2026", "2026-09-01", "2026-10-01"),
    ("2026-02", "февраль 2026", "2026-02-01", "2026-03-01"),
    ("12.2025", "декабрь 2025", "2025-12-01", "2026-01-01"),
    ("7d", "последние 7 дн.", "2026-10-17", "2026-10-24"),
    ("2026-10-01 2026-10-15", "01.10.2026 — 15.10.2026", "2026-10-01", "2026-10-16"),
    ("15.10.2026-01.10.2026", "01.10.2026 — 15.10.2026", "2026-10-01", "2026-10-16"),
    ("01.10.26", "01.10.2026", "2026-10-01", "2026-10-02"),
])
def test_parse_period(text, label, start, end):
    p = parse_period(text, TZ, NOW)
    assert p.label == label and p.start.date().isoformat() == start
    if end:
        assert p.end.date().isoformat() == end


@pytest.mark.parametrize("text", ["вчерашний", "2026-13", "400d", "1.2.3.4"])
def test_parse_period_errors(text):
    with pytest.raises(ValueError):
        parse_period(text, TZ, NOW)


def write(path, *records):
    with open(path, "a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def ts(day, hour=12, month=9):
    return datetime(2026, month, day, hour, tzinfo=TZ).timestamp()


def test_build_report_counts(tmp_path):
    path = tmp_path / "log.jsonl"
    write(path,
          {"ts": ts(3), "event": "detected", "client_ip": "10.0.0.1", "gate_id": "vk"},
          {"ts": ts(3), "event": "opened", "client_ip": "10.0.0.1", "mac": "aa", "gate_name": "VK ID", "kind": "verify"},
          {"ts": ts(3), "event": "closed", "reason": "code_entered", "opened_at": ts(3), "kind": "verify"},
          {"ts": ts(4), "event": "opened", "client_ip": "10.0.0.2", "mac": "aa", "gate_name": "VK ID", "kind": "verify"},
          {"ts": ts(4), "event": "closed", "reason": "expired", "opened_at": ts(4)},
          {"ts": ts(5), "event": "opened", "client_ip": "10.0.0.3", "gate_name": "ВТБ", "kind": "pay"},
          {"ts": ts(5), "event": "grant_failed", "client_ip": "10.0.0.4"},
          {"ts": ts(5), "event": "closed", "reason": "abandoned"},  # окно не открывали
          {"ts": ts(6), "event": "reboot_sent", "audit": True},
          {"ts": ts(1, month=10), "event": "opened", "client_ip": "10.0.0.9", "gate_name": "VK ID", "kind": "verify"})
    report = build_report(SessionJournal(str(path)), parse_period("2026-09", TZ, NOW))
    assert report["authorizations"] == 3 and report["verify"] == 2 and report["pay"] == 1
    assert report["confirmed"] == 1 and report["expired"] == 1 and report["other_closed"] == 0
    assert report["devices"] == 2  # один MAC сменил IP
    assert report["grant_failed"] == 1 and report["detected"] == 1
    assert report["by_gate"] == [{"gate": "VK ID", "count": 2}, {"gate": "ВТБ", "count": 1}]
    assert [d["day"] for d in report["by_day"]] == ["2026-09-03", "2026-09-04", "2026-09-05"]
    text = report_text(report)
    assert "Авторизаций: <b>3</b>" in text and "(33%)" in text and "сентябрь 2026" in text


class Ctx:
    def __init__(self, tmp_path):
        self.settings = Settings(report_day=1, report_hour=9)
        self.tz = TZ
        self.journal = SessionJournal(str(tmp_path / "log.jsonl"))
        self.store = StateStore(str(tmp_path / "state.json"))


async def test_monthly_report_sent_once(tmp_path):
    ctx = Ctx(tmp_path)
    write(ctx.journal.path, {"ts": ts(10), "event": "opened", "client_ip": "10.0.0.1", "gate_name": "VK ID", "kind": "verify"})
    sent = []

    async def send(text):
        sent.append(text)

    assert not await maybe_send_monthly(ctx, send, datetime(2026, 10, 1, 8, 59, tzinfo=TZ))
    assert await maybe_send_monthly(ctx, send, datetime(2026, 10, 1, 9, 0, tzinfo=TZ))
    assert not await maybe_send_monthly(ctx, send, datetime(2026, 10, 2, 9, 0, tzinfo=TZ))
    assert len(sent) == 1 and "сентябрь 2026" in sent[0]
    # Отметка переживает перезапуск.
    ctx.store = StateStore(str(tmp_path / "state.json"))
    assert not await maybe_send_monthly(ctx, send, datetime(2026, 10, 5, 9, 0, tzinfo=TZ))
    # Пустой месяц только отмечается.
    assert await maybe_send_monthly(ctx, send, datetime(2026, 12, 1, 10, 0, tzinfo=TZ))
    assert len(sent) == 1


async def test_monthly_report_retries_after_send_failure(tmp_path):
    ctx = Ctx(tmp_path)
    write(ctx.journal.path, {"ts": ts(10), "event": "opened", "client_ip": "10.0.0.1", "gate_name": "VK ID", "kind": "verify"})

    async def broken(text):
        raise RuntimeError("telegram down")

    with pytest.raises(RuntimeError):
        await maybe_send_monthly(ctx, broken, datetime(2026, 10, 1, 9, 0, tzinfo=TZ))
    assert not ctx.store.report_sent("2026-09")
