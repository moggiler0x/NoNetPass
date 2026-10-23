"""Драйверы для запуска NoNetPass прямо на роутере.

* ``nftables`` — OpenWrt 22.03+ (fw4) и любые Linux-роутеры с nft;
* ``ipset`` — Keenetic с Entware, ASUS Merlin, DD-WRT, старые OpenWrt (fw3),
  любые Linux-роутеры с iptables + ipset.

Окно задаётся парами «IP клиента · IP узла шлюза» в одном наборе с
таймаутом (nft: ``ipv4_addr . ipv4_addr``, ipset: ``hash:net,net``). Так
клиент получает доступ только к узлам выбранного шлюза. Узлы резолвятся в
момент открытия окна. Команды запускаются без shell, аргументы передаются
списком.
"""

from __future__ import annotations

import asyncio
import json

from ..blocklist import arp_lookup
from .base import DriverError, Grant, RouterDriver, resolve_ipv4, validate_ipv4


async def run(*argv: str) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError as exc:
        raise DriverError(f"не найдена команда {argv[0]}") from exc
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
    return proc.returncode or 0, stderr.decode(errors="replace").strip()


class OnRouterMixin:
    """NoNetPass запущен на самом роутере: ARP и перезагрузка локальные."""

    can_reboot = True
    reboot_cmd: tuple[str, ...] = ("reboot",)
    runner = staticmethod(run)

    async def lookup_mac(self, client_ip: str) -> str | None:
        return arp_lookup(client_ip)

    async def reboot(self) -> None:
        code, err = await self.runner(*self.reboot_cmd)
        if code:
            raise DriverError(f"{' '.join(self.reboot_cmd)}: {err}")


async def _targets(grant: Grant, resolver) -> list[str]:
    targets = [validate_ipv4(ip) for ip in await resolver(grant.targets)]
    if not targets:
        raise DriverError("не удалось получить IP узлов шлюза")
    return targets


class NftablesDriver(OnRouterMixin, RouterDriver):
    name = "nftables"
    router_side_timeout = True

    def __init__(
        self,
        set_name: str,
        family: str = "inet",
        table: str = "fw4",
        nft: str = "nft",
        runner=run,
        resolver=resolve_ipv4,
    ):
        self.set_name = set_name
        self.family = family
        self.table = table
        self.nft = nft
        self.runner = runner
        self.resolver = resolver

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        targets = await _targets(grant, self.resolver)
        elements = ", ".join(f"{ip} . {t} timeout {grant.router_ttl}s" for t in targets)
        code, err = await self.runner(
            self.nft, "add", "element", self.family, self.table, self.set_name, f"{{ {elements} }}"
        )
        if code:
            raise DriverError(f"nft: {err}")
        return json.dumps(targets)

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        for target in json.loads(handle):
            code, err = await self.runner(
                self.nft, "delete", "element", self.family, self.table, self.set_name,
                f"{{ {ip} . {validate_ipv4(target)} }}",
            )
            if code and "No such file" not in err:
                raise DriverError(f"nft: {err}")

    async def check(self) -> dict:
        code, err = await self.runner(self.nft, "list", "set", self.family, self.table, self.set_name)
        return {"ok": code == 0, **({"error": err} if code else {})}


class IpsetDriver(OnRouterMixin, RouterDriver):
    name = "ipset"
    router_side_timeout = True

    def __init__(self, set_name: str, ipset: str = "ipset", runner=run, resolver=resolve_ipv4):
        self.set_name = set_name
        self.ipset = ipset
        self.runner = runner
        self.resolver = resolver

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        targets = await _targets(grant, self.resolver)
        for target in targets:
            code, err = await self.runner(
                self.ipset, "add", self.set_name, f"{ip},{target}",
                "timeout", str(grant.router_ttl), "-exist",
            )
            if code:
                raise DriverError(f"ipset: {err}")
        return json.dumps(targets)

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        for target in json.loads(handle):
            code, err = await self.runner(
                self.ipset, "del", self.set_name, f"{ip},{validate_ipv4(target)}", "-exist"
            )
            if code:
                raise DriverError(f"ipset: {err}")

    async def check(self) -> dict:
        code, err = await self.runner(self.ipset, "list", self.set_name, "-terse")
        return {"ok": code == 0, **({"error": err} if code else {})}
