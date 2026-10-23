"""Встроенная детекция шлюза по DNS-запросам.

Обращение устройства к узлу-триггеру (``id.vk.com``, ``3ds.vtb.ru``…)
означает, что пользователь начал вход или оплату. По узлу определяется
шлюз, и портал этого устройства сам показывает нужный сервис.

Источники:
* лог dnsmasq с ``log-queries`` (OpenWrt, Keenetic с Entware, Pi-hole):
  ``query[A] id.vk.com from 192.168.1.23``; файл ``NONETPASS_DNS_LOG_PATH``;
* syslog роутера по UDP (``NONETPASS_SYSLOG_PORT``): те же строки dnsmasq
  или DNS-лог MikroTik (``/system logging`` с темами ``dns,packet``), где
  адрес клиента и имя приходят двумя строками:
  ``got query from 192.168.110.23:53122:`` и ``question: id.vk.com:A:IN``;
* вебхук ``POST /api/detect`` от прокси, своего DNS или агента.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from .gates import GateCatalog
from .sessions import SessionManager

log = logging.getLogger(__name__)

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
QTYPE = r"(?:A|AAAA|HTTPS)"
DNSMASQ_QUERY = re.compile(rf"query\[{QTYPE}\]\s+(\S+)\s+from\s+{IP}")
# RouterOS: «dns query from 192.168.88.10: #123 id.vk.com. A»
MIKROTIK_QUERY = re.compile(rf"query from {IP}(?::\d+)?:\s*#\d+\s+(\S+?)\.?\s+{QTYPE}\b")
# RouterOS dns,packet: две строки на один запрос.
MIKROTIK_FROM = re.compile(rf"got query from {IP}:\d+")
MIKROTIK_QUESTION = re.compile(rf"question:\s+([^\s:]+?)\.?:{QTYPE}:IN")


def parse_dnsmasq_line(line: str) -> tuple[str, str] | None:
    match = DNSMASQ_QUERY.search(line)
    if not match:
        return None
    return match.group(1).lower().rstrip("."), match.group(2)


class DnsLineParser:
    """Разбор строк DNS-логов разных роутеров; помнит адрес из «got query from»."""

    def __init__(self) -> None:
        self._client: dict[str, str] = {}

    def feed(self, line: str, sender: str = "") -> tuple[str, str] | None:
        if parsed := parse_dnsmasq_line(line):
            return parsed
        if m := MIKROTIK_QUERY.search(line):
            return m.group(2).lower().rstrip("."), m.group(1)
        if m := MIKROTIK_FROM.search(line):
            self._client[sender] = m.group(1)
            return None
        if (m := MIKROTIK_QUESTION.search(line)) and sender in self._client:
            return m.group(1).lower().rstrip("."), self._client.pop(sender)
        return None


async def _detect(manager: SessionManager, catalog: GateCatalog, parsed, source: str) -> None:
    host, ip = parsed
    gate = catalog.for_host(host)
    if gate:
        try:
            await manager.detect(ip, source, gate, host)
        except Exception:
            log.exception("детекция %s от %s", host, ip)


async def tail_dns_log(path: str, manager: SessionManager, catalog: GateCatalog, poll: float = 0.5) -> None:
    file = Path(path)
    parser = DnsLineParser()
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
                    if parsed := parser.feed(line):
                        await _detect(manager, catalog, parsed, "dnsmasq")
        except FileNotFoundError:
            position = 0
        except Exception:
            log.exception("ошибка чтения DNS-лога")
        await asyncio.sleep(poll)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager: SessionManager, catalog: GateCatalog, allow: list[str] = ()):
        self.allow = set(allow)
        self.manager = manager
        self.catalog = catalog
        self.parser = DnsLineParser()
        self.received = 0
        self.last_at: float | None = None

    def datagram_received(self, data: bytes, addr) -> None:
        if self.allow and addr[0] not in self.allow:
            return
        self.received += 1
        self.last_at = asyncio.get_running_loop().time()
        for line in data.decode("utf-8", "replace").splitlines():
            if parsed := self.parser.feed(line, addr[0]):
                asyncio.get_running_loop().create_task(_detect(self.manager, self.catalog, parsed, "syslog"))


async def start_syslog(host: str, port: int, manager: SessionManager, catalog: GateCatalog, allow=()):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(manager, catalog, list(allow)), local_addr=(host, port)
    )
    log.info("syslog DNS-детекция слушает udp/%s:%d", host, port)
    return transport, protocol
