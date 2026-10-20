"""Журнал сессий в формате JSON Lines: одна строка на каждое изменение состояния."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from .models import Session

log = logging.getLogger(__name__)


class SessionJournal:
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None

    def write(self, event: str, session: Session, **extra) -> None:
        record = {"ts": time.time(), "event": event, **session.to_dict(), **extra}
        log.info("session %s %s ip=%s", session.id, event, session.client_ip)
        if not self.path:
            return
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            log.exception("не удалось записать журнал сессий")

    def tail(self, limit: int = 100) -> list[dict]:
        if not self.path or not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in lines if line.strip()]
