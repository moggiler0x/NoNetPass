"""Журнал сессий в формате JSON Lines: одна строка на каждое изменение состояния.

Действия администратора (вход в панель, перезагрузки, чёрный список) пишутся
в тот же файл с ``"audit": true`` и в отчёты об авторизациях не попадают.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Iterator

from .models import Session

log = logging.getLogger(__name__)

CSV_FIELDS = (
    "time", "event", "id", "client_ip", "mac", "gate_id", "gate_name", "kind",
    "source", "host", "state", "close_reason", "opened_at", "closed_at", "extends", "error",
)


class SessionJournal:
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self.last_error: str | None = None

    def _append(self, record: dict) -> None:
        if not self.path:
            return
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.last_error = None
        except OSError as exc:
            self.last_error = str(exc)
            log.exception("не удалось записать журнал сессий")

    def write(self, event: str, session: Session, **extra) -> None:
        record = {"ts": time.time(), "event": event, **session.to_dict(), **extra}
        log.info("session %s %s ip=%s", session.id, event, session.client_ip)
        self._append(record)

    def audit(self, event: str, **fields) -> None:
        record = {"ts": time.time(), "event": event, "audit": True, **fields}
        log.info("audit %s %s", event, fields)
        self._append(record)

    def records(self, start: float | None = None, end: float | None = None) -> Iterator[dict]:
        """Записи журнала с start <= ts < end, по порядку файла."""
        if not self.path or not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                ts = record.get("ts", 0)
                if (start is None or ts >= start) and (end is None or ts < end):
                    yield record

    def tail(self, limit: int = 100, audit_only: bool = False) -> list[dict]:
        """Последние записи: сессии или (audit_only) действия администратора."""
        return list(deque((r for r in self.records() if bool(r.get("audit")) == audit_only), maxlen=limit))

    def to_csv(self, records, tz=None) -> str:
        out = io.StringIO()
        writer = csv.writer(out, delimiter=";")
        writer.writerow(CSV_FIELDS)
        for rec in records:
            if rec.get("audit"):
                continue
            row = []
            for name in CSV_FIELDS:
                if name == "time":
                    row.append(_stamp(rec.get("ts"), tz))
                elif name in ("opened_at", "closed_at"):
                    row.append(_stamp(rec.get(name), tz) if rec.get(name) else "")
                else:
                    value = rec.get(name)
                    row.append("" if value is None else value)
            writer.writerow(row)
        # BOM, чтобы Excel открыл кириллицу без вопросов.
        return "﻿" + out.getvalue()


def _stamp(ts: float | None, tz) -> str:
    from datetime import datetime

    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M:%S")
