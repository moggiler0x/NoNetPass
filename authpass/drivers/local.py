"""Драйверы для запуска AuthPass прямо на роутере.

* ``nftables`` — OpenWrt 22.03+ (fw4) и любые Linux-роутеры с nft;
* ``ipset`` — Keenetic с Entware, ASUS Merlin, DD-WRT, старые OpenWrt (fw3),
  любые Linux-роутеры с iptables + ipset.

IP клиента кладётся в набор ``authpass_clients`` с таймаутом. Если задан
набор узлов доставки (``targets_set``), при открытии окна их IP резолвятся и
тоже добавляются (с таймаутом в час: сами по себе они доступа не дают,
а общий для всех клиентов набор не должен истекать посреди чужого окна),
так что внешний DNS-хук не обязателен.
Команды запускаются без shell, аргументы передаются списком.
"""

from __future__ import annotations

import asyncio

from .base import DriverError, Grant, RouterDriver, resolve_ipv4, validate_ipv4

TARGETS_TTL = 3600


async def run(*argv: str) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError as exc:
        raise DriverError(f"не найдена команда {argv[0]}") from exc
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
    return proc.returncode or 0, stderr.decode(errors="replace").strip()


class NftablesDriver(RouterDriver):
    name = "nftables"
    router_side_timeout = True

    def __init__(
        self,
        set_name: str,
        family: str = "inet",
        table: str = "fw4",
        targets_set: str | None = "authpass_targets",
        nft: str = "nft",
        runner=run,
        resolver=resolve_ipv4,
    ):
        self.set_name = set_name
        self.family = family
        self.table = table
        self.targets_set = targets_set
        self.nft = nft
        self.runner = runner
        self.resolver = resolver

    async def _add(self, set_name: str, addresses: list[str], ttl: int) -> None:
        elements = ", ".join(f"{ip} timeout {ttl}s" for ip in addresses)
        code, err = await self.runner(
            self.nft, "add", "element", self.family, self.table, set_name, f"{{ {elements} }}"
        )
        if code:
            raise DriverError(f"nft: {err}")

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        if self.targets_set and (targets := await self.resolver(grant.targets)):
            await self._add(self.targets_set, targets, TARGETS_TTL)
        await self._add(self.set_name, [ip], grant.router_ttl)
        return ip

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        code, err = await self.runner(
            self.nft, "delete", "element", self.family, self.table, self.set_name, f"{{ {ip} }}"
        )
        if code and "No such file" not in err:
            raise DriverError(f"nft: {err}")

    async def check(self) -> dict:
        code, err = await self.runner(self.nft, "list", "set", self.family, self.table, self.set_name)
        return {"ok": code == 0, **({"error": err} if code else {})}


class IpsetDriver(RouterDriver):
    name = "ipset"
    router_side_timeout = True

    def __init__(
        self,
        set_name: str,
        targets_set: str | None = "authpass_targets",
        ipset: str = "ipset",
        runner=run,
        resolver=resolve_ipv4,
    ):
        self.set_name = set_name
        self.targets_set = targets_set
        self.ipset = ipset
        self.runner = runner
        self.resolver = resolver

    async def _add(self, set_name: str, ip: str, ttl: int) -> None:
        code, err = await self.runner(self.ipset, "add", set_name, ip, "timeout", str(ttl), "-exist")
        if code:
            raise DriverError(f"ipset: {err}")

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        if self.targets_set:
            for target in await self.resolver(grant.targets):
                await self._add(self.targets_set, target, TARGETS_TTL)
        await self._add(self.set_name, ip, grant.router_ttl)
        return ip

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        code, err = await self.runner(self.ipset, "del", self.set_name, ip, "-exist")
        if code:
            raise DriverError(f"ipset: {err}")

    async def check(self) -> dict:
        code, err = await self.runner(self.ipset, "list", self.set_name, "-terse")
        return {"ok": code == 0, **({"error": err} if code else {})}
