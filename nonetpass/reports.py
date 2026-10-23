"""Отчёты о количестве авторизаций.

Авторизация — открытое окно шлюза (пользователь получил доступ к узлам
сервиса). Отчёт считает их за период по журналу сессий: всего, сколько
закончились введённым кодом или оплатой, сколько истекли, сколько закрыл
администратор, ошибки роутера, уникальные устройства, разбивку по сервисам
и по дням. Раз в месяц отчёт за прошлый месяц уходит в Telegram, по запросу
строится за любой промежуток в боте и в админ-панели.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time as dtime, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .journal import SessionJournal

DAY = r"(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}\.\d{1,2}\.\d{2,4})"
MONTHS = ("январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август",
          "сентябрь", "октябрь", "ноябрь", "декабрь")


def get_tz(name: str) -> tzinfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        from datetime import timezone

        return timezone(timedelta(hours=3), "MSK") if name == "Europe/Moscow" else timezone.utc


@dataclass(frozen=True)
class Period:
    start: datetime  # включительно
    end: datetime  # не включительно
    label: str

    @property
    def start_ts(self) -> float:
        return self.start.timestamp()

    @property
    def end_ts(self) -> float:
        return self.end.timestamp()


def _midnight(day: date, tz: tzinfo) -> datetime:
    return datetime.combine(day, dtime.min, tz)


def month_period(year: int, month: int, tz: tzinfo) -> Period:
    start = _midnight(date(year, month, 1), tz)
    nxt = date(year + (month == 12), month % 12 + 1, 1)
    return Period(start, _midnight(nxt, tz), f"{MONTHS[month - 1]} {year}")


def previous_month(now: datetime) -> tuple[int, int]:
    return (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)


def _parse_day(text: str) -> date:
    short_year = re.fullmatch(r"\d{1,2}\.\d{1,2}\.\d{2}", text) is not None
    for fmt in ("%d.%m.%y",) if short_year else ("%Y-%m-%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            pass
    raise ValueError(f"не понял дату {text!r}: нужен формат 2026-10-01 или 01.10.2026")


def parse_period(text: str, tz: tzinfo, now: datetime | None = None) -> Period:
    """Период из текста команды бота или параметра панели.

    Понимает: пусто или ``month`` (текущий месяц), ``prev`` (прошлый месяц),
    ``today``, ``yesterday``, ``week``, ``7d``/``30d``, ``2026-09`` или
    ``09.2026`` (месяц), ``2026-10-01`` (день), ``2026-10-01 2026-10-15``
    или ``01.10.2026-15.10.2026`` (дни включительно).
    """
    now = (now or datetime.now(tz)).astimezone(tz)
    today = now.date()
    raw = text.strip().lower()
    if raw in ("", "month", "this", "месяц"):
        p = month_period(now.year, now.month, tz)
        return Period(p.start, min(p.end, now + timedelta(seconds=1)), p.label + " (по сегодня)")
    if raw in ("prev", "last", "previous", "прошлый"):
        return month_period(*previous_month(now), tz)
    if raw in ("today", "сегодня"):
        return Period(_midnight(today, tz), _midnight(today + timedelta(days=1), tz), f"{today:%d.%m.%Y}")
    if raw in ("yesterday", "вчера"):
        day = today - timedelta(days=1)
        return Period(_midnight(day, tz), _midnight(today, tz), f"{day:%d.%m.%Y}")
    if raw in ("week", "неделя"):
        raw = "7d"
    if m := re.fullmatch(r"(\d{1,3})\s*(d|д|дн|days?)", raw):
        days = int(m.group(1))
        if not 1 <= days <= 366:
            raise ValueError("число дней от 1 до 366")
        start = _midnight(today - timedelta(days=days - 1), tz)
        return Period(start, _midnight(today + timedelta(days=1), tz), f"последние {days} дн.")
    if m := re.fullmatch(r"(\d{4})-(\d{1,2})", raw) or re.fullmatch(r"(\d{1,2})\.(\d{4})", raw):
        a, b = int(m.group(1)), int(m.group(2))
        year, month = (a, b) if a > 31 else (b, a)
        if not 1 <= month <= 12:
            raise ValueError("месяц от 1 до 12")
        return month_period(year, month, tz)
    if m := re.fullmatch(DAY + r"(?:\s*(?:—|–|\.\.|-|\s|по|to)\s*" + DAY + ")?", raw):
        first = _parse_day(m.group(1))
        last = _parse_day(m.group(2)) if m.group(2) else first
        if last < first:
            first, last = last, first
        if (last - first).days > 3660:
            raise ValueError("слишком длинный период")
        label = f"{first:%d.%m.%Y}" if first == last else f"{first:%d.%m.%Y} — {last:%d.%m.%Y}"
        return Period(_midnight(first, tz), _midnight(last + timedelta(days=1), tz), label)
    raise ValueError("не понял период: например, 2026-09, 7d или 2026-10-01 2026-10-15")


def build_report(journal: SessionJournal, period: Period) -> dict:
    tz = period.start.tzinfo
    opened = Counter()
    by_kind = Counter()
    by_day: dict[str, int] = defaultdict(int)
    closes = Counter()
    devices: set[str] = set()
    detected = grant_failed = revoke_failed = extended = 0
    for rec in journal.records(period.start_ts, period.end_ts):
        if rec.get("audit"):
            continue
        event = rec.get("event")
        if event == "detected":
            detected += 1
        elif event == "opened":
            opened[rec.get("gate_name") or rec.get("gate_id")] += 1
            by_kind[rec.get("kind", "verify")] += 1
            by_day[datetime.fromtimestamp(rec["ts"], tz).strftime("%Y-%m-%d")] += 1
            devices.add(rec.get("mac") or rec.get("client_ip"))
        elif event == "closed" and rec.get("opened_at"):
            closes[rec.get("reason") or rec.get("close_reason")] += 1
        elif event == "grant_failed":
            grant_failed += 1
        elif event == "revoke_failed":
            revoke_failed += 1
        elif event == "extended":
            extended += 1
    total = sum(opened.values())
    return {
        "period": {"label": period.label, "start": period.start.isoformat(), "end": period.end.isoformat()},
        "authorizations": total,
        "verify": by_kind.get("verify", 0),
        "pay": by_kind.get("pay", 0),
        "confirmed": closes.get("code_entered", 0),
        "expired": closes.get("expired", 0),
        "revoked": closes.get("revoked", 0),
        "other_closed": sum(v for k, v in closes.items() if k not in ("code_entered", "expired", "revoked")),
        "detected": detected,
        "extended": extended,
        "devices": len(devices),
        "grant_failed": grant_failed,
        "revoke_failed": revoke_failed,
        "by_gate": [{"gate": k, "count": v} for k, v in opened.most_common()],
        "by_day": [{"day": k, "count": by_day[k]} for k in sorted(by_day)],
    }


def report_text(report: dict) -> str:
    """Отчёт для Telegram (HTML-разметка бота)."""
    total = report["authorizations"]
    pct = f" ({round(100 * report['confirmed'] / total)}%)" if total else ""
    lines = [
        f"📊 <b>Отчёт NoNetPass: {_html(report['period']['label'])}</b>",
        "",
        f"Авторизаций: <b>{total}</b>",
        f"  вход в сеть: {report['verify']}, оплата: {report['pay']}",
        f"  код введён / оплачено: {report['confirmed']}{pct}",
        f"  истекло по таймеру: {report['expired']}, закрыл админ: {report['revoked']}",
        f"Устройств: {report['devices']}, продлений: {report['extended']}",
    ]
    if report["grant_failed"] or report["revoke_failed"]:
        lines.append(f"⚠️ Ошибки роутера: не открыл {report['grant_failed']}, не закрыл {report['revoke_failed']}")
    if report["by_gate"]:
        lines += ["", "<b>По сервисам</b>"]
        lines += [f"  {_html(row['gate'])}: {row['count']}" for row in report["by_gate"]]
    if report["by_day"]:
        busiest = max(report["by_day"], key=lambda r: r["count"])
        lines.append(f"\nСамый загруженный день: {busiest['day']} ({busiest['count']})")
    return "\n".join(lines)


def report_csv(report: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["Период", report["period"]["label"]])
    for key, title in (
        ("authorizations", "Авторизаций"), ("verify", "Вход в сеть"), ("pay", "Оплата"),
        ("confirmed", "Код введён / оплачено"), ("expired", "Истекло"), ("revoked", "Закрыл админ"),
        ("devices", "Устройств"), ("extended", "Продлений"),
        ("grant_failed", "Роутер не открыл"), ("revoke_failed", "Роутер не закрыл"),
    ):
        w.writerow([title, report[key]])
    w.writerow([])
    w.writerow(["Сервис", "Авторизаций"])
    for row in report["by_gate"]:
        w.writerow([row["gate"], row["count"]])
    w.writerow([])
    w.writerow(["День", "Авторизаций"])
    for row in report["by_day"]:
        w.writerow([row["day"], row["count"]])
    return "﻿" + out.getvalue()


def _html(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def maybe_send_monthly(ctx, send, now: datetime | None = None) -> bool:
    """Отправить отчёт за прошлый месяц, если пора и он ещё не отправлен.

    Пора — с ``report_day`` числа ``report_hour`` часов. Если NoNetPass был
    выключен в этот момент, отчёт уйдёт при следующем запуске в том же
    месяце. Пустой месяц (журнал без событий) только отмечается.
    """
    settings = ctx.settings
    now = (now or datetime.now(ctx.tz)).astimezone(ctx.tz)
    due = datetime(now.year, now.month, max(1, min(settings.report_day, 28)), settings.report_hour, tzinfo=ctx.tz)
    if now < due:
        return False
    year, month = previous_month(now)
    key = f"{year}-{month:02d}"
    if ctx.store.report_sent(key):
        return False
    report = build_report(ctx.journal, month_period(year, month, ctx.tz))
    if report["authorizations"] or report["detected"]:
        await send(report_text(report))
    ctx.store.mark_report(key, now.timestamp())
    return True


async def monthly_loop(ctx, send, poll: float = 300) -> None:
    import asyncio
    import logging

    log = logging.getLogger(__name__)
    while True:
        try:
            await maybe_send_monthly(ctx, send)
        except Exception:
            log.exception("ежемесячный отчёт не отправлен")
        await asyncio.sleep(poll)
