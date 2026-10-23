"""Состояние NoNetPass между запусками (один JSON-файл).

* ``windows`` — открытые окна: если процесс упал или роутер не дождался
  отката, при следующем старте эти записи удаляются с роутера;
* ``blocklist`` — чёрный список MAC и IP, который ведёт администратор;
* ``overrides`` — длительность окон и лимиты, изменённые в панели;
* ``reports`` — за какие месяцы отчёт уже отправлен в Telegram.

Запись атомарная: временный файл и ``os.replace``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


class StateStore:
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self.data: dict = {"windows": {}, "blocklist": {"macs": {}, "ips": {}}, "overrides": {}, "reports": {}}
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.exception("файл состояния %s не прочитан, начинаю с пустого", self.path)
            return
        for key, value in loaded.items():
            if isinstance(value, dict) and isinstance(self.data.get(key), dict):
                self.data[key].update(value)
            else:
                self.data[key] = value

    def save(self) -> None:
        if not self.path:
            return
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            log.exception("не удалось сохранить состояние в %s", self.path)

    def writable(self) -> bool:
        if not self.path:
            return True
        directory = self.path.parent if str(self.path.parent) else Path(".")
        return os.access(directory, os.W_OK)

    # --- открытые окна -------------------------------------------------------

    @property
    def windows(self) -> dict[str, dict]:
        return self.data["windows"]

    def remember_window(self, session_id: str, record: dict) -> None:
        self.windows[session_id] = record
        self.save()

    def forget_window(self, session_id: str) -> None:
        if self.windows.pop(session_id, None) is not None:
            self.save()

    # --- настройки из панели -------------------------------------------------

    @property
    def overrides(self) -> dict:
        return self.data["overrides"]

    def set_override(self, key: str, value) -> None:
        self.overrides[key] = value
        self.save()

    # --- отчёты --------------------------------------------------------------

    def report_sent(self, month: str) -> bool:
        return month in self.data["reports"]

    def mark_report(self, month: str, ts: float) -> None:
        self.data["reports"][month] = ts
        self.save()
