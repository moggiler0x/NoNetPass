"""Интерфейс драйвера роутера.

Модель доступа: администратор один раз создаёт на роутере разрешающее
правило, а NoNetPass только добавляет и удаляет записи. Окно всегда точное:
клиент получает доступ только к узлам выбранного шлюза, а не ко всем
сервисам каталога. Для этого драйверы используют либо пары «клиент · узел»
(nftables, ipset, OpenWrt, Keenetic), либо отдельный список на каждый шлюз
(MikroTik, OPNsense). Где роутер это умеет, запись создаётся с таймаутом на
стороне роутера, поэтому окно закроется даже если NoNetPass упадёт.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger(__name__)


class DriverError(RuntimeError):
    pass


@dataclass(frozen=True)
class Grant:
    client_ip: str
    targets: tuple[str, ...]
    ttl: float
    comment: str
    gate: str = "default"

    @property
    def router_ttl(self) -> int:
        # Запас к таймауту на роутере: штатно окно закрывает NoNetPass,
        # таймаут роутера нужен как страховка.
        return int(self.ttl) + 10


def validate_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise DriverError(f"некорректный IPv4-адрес: {value!r}") from exc


class RouterDriver(ABC):
    name: str = "base"
    # True, если роутер сам удалит запись по таймауту.
    router_side_timeout: bool = False

    @abstractmethod
    async def grant(self, grant: Grant) -> str:
        """Открыть доступ. Возвращает handle, по которому окно закрывается."""

    @abstractmethod
    async def revoke(self, client_ip: str, handle: str) -> None:
        """Закрыть доступ. Должен быть идемпотентным."""

    async def check(self) -> dict:
        """Проверка связи с роутером для /healthz."""
        return {"ok": True}

    async def aclose(self) -> None:
        return None


async def resolve_ipv4(hosts: tuple[str, ...]) -> list[str]:
    """IPv4-адреса узлов доставки (для роутеров, которым нужны IP, а не имена)."""
    loop = asyncio.get_running_loop()
    result: set[str] = set()
    for host in hosts:
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        except socket.gaierror:
            log.warning("не удалось разрезолвить %s", host)
            continue
        result.update(info[4][0] for info in infos)
    return sorted(result)
