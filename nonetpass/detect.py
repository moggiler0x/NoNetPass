"""Встроенная детекция по логу DNS-запросов (dnsmasq с log-queries).

Строка вида ``query[A] id.vk.com from 192.168.1.23`` от клиента означает, что
он открыл шлюз. По узлу-триггеру определяется, какой это шлюз (VK, Сбер,
оплата ВТБ и т.д.). Другие источники (прокси, свой DNS, агент на устройстве)
шлют сигнал через POST /api/detect.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from .gates import GateCatalog
from .sessions import SessionManager

log = logging.getLogger(__name__)

DNSMASQ_QUERY = re.compile(r"query\[(?:A|AAAA|HTTPS)\]\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})")


def parse_dnsmasq_line(line: str) -> tuple[str, str] | None:
    match = DNSMASQ_QUERY.search(line)
    if not match:
        return None
    return match.group(1).lower().rstrip("."), match.group(2)


async def tail_dns_log(path: str, manager: SessionManager, catalog: GateCatalog, poll: float = 0.5) -> None:
    file = Path(path)
    position = file.stat().st_size if file.exists() else 0
    while True:
        try:
            size = file.stat().st_size
            if size < position:  # ротация лога
                position = 0
            if size > position:
                with file.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(position)
                    chunk = fh.read()
                    position = fh.tell()
                for line in chunk.splitlines():
                    parsed = parse_dnsmasq_line(line)
                    if not parsed:
                        continue
                    gate = catalog.for_host(parsed[0])
                    if gate:
                        await manager.detect(parsed[1], "dnsmasq", gate, parsed[0])
        except FileNotFoundError:
            position = 0
        except Exception:
            log.exception("ошибка чтения DNS-лога")
        await asyncio.sleep(poll)
