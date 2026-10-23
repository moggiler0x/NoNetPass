"""OpenWrt по сети через ubus JSON-RPC (uhttpd-mod-ubus + rpcd).

Драйвер добавляет пары «IP клиента · IP узла шлюза» в nftables-набор fw4 с
таймаутом через ``file.exec`` rpcd. Пользователю rpcd нужен ACL на запуск
/usr/sbin/nft — см. deploy/openwrt/nonetpass.acl.json. Узлы шлюза резолвятся
на машине с NoNetPass. Если NoNetPass запущен на самом OpenWrt, проще
драйвер ``nftables``.
"""

from __future__ import annotations

import itertools
import json

import httpx

from ..blocklist import normalize_mac
from .base import DriverError, Grant, RouterDriver, reboot_dropped, resolve_ipv4, validate_ipv4

ANON_SESSION = "0" * 32
UBUS_PERMISSION_DENIED = 6


class OpenWrtDriver(RouterDriver):
    name = "openwrt"
    router_side_timeout = True
    can_reboot = True

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        set_name: str,
        family: str = "inet",
        table: str = "fw4",
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver=resolve_ipv4,
    ):
        self.resolver = resolver
        self.user = user
        self.password = password
        self.set_name = set_name
        self.family = family
        self.table = table
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), verify=verify_tls, timeout=10, transport=transport
        )
        self._sid: str | None = None
        self._ids = itertools.count(1)

    async def _rpc(self, sid: str, obj: str, method: str, args: dict) -> list:
        body = {
            "jsonrpc": "2.0",
            "id": next(self._ids),
            "method": "call",
            "params": [sid, obj, method, args],
        }
        try:
            resp = await self.client.post("/ubus", json=body)
        except httpx.HTTPError as exc:
            raise DriverError(f"openwrt: {exc}") from exc
        data = resp.json()
        if "error" in data:
            raise DriverError(f"openwrt: {data['error']}")
        return data["result"]

    async def _login(self) -> str:
        result = await self._rpc(
            ANON_SESSION, "session", "login", {"username": self.user, "password": self.password}
        )
        if result[0] != 0:
            raise DriverError("openwrt: вход в rpcd не удался")
        self._sid = result[1]["ubus_rpc_session"]
        return self._sid

    async def _call(self, obj: str, method: str, args: dict) -> list:
        sid = self._sid or await self._login()
        result = await self._rpc(sid, obj, method, args)
        if result[0] == UBUS_PERMISSION_DENIED:
            result = await self._rpc(await self._login(), obj, method, args)
        return result

    async def _nft(self, *params: str) -> dict:
        args = {"command": "/usr/sbin/nft", "params": list(params)}
        sid = self._sid or await self._login()
        result = await self._rpc(sid, "file", "exec", args)
        if result[0] == UBUS_PERMISSION_DENIED:
            result = await self._rpc(await self._login(), "file", "exec", args)
        if result[0] != 0:
            raise DriverError(f"openwrt: ubus code {result[0]}")
        return result[1] if len(result) > 1 else {}

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        targets = [validate_ipv4(t) for t in await self.resolver(grant.targets)]
        if not targets:
            raise DriverError("openwrt: не удалось получить IP узлов шлюза")
        elements = ", ".join(f"{ip} . {t} timeout {grant.router_ttl}s" for t in targets)
        out = await self._nft("add", "element", self.family, self.table, self.set_name, f"{{ {elements} }}")
        if out.get("code", 0) != 0:
            raise DriverError(f"openwrt: nft: {out.get('stderr', '').strip()}")
        return json.dumps(targets)

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        for target in json.loads(handle):
            out = await self._nft(
                "delete", "element", self.family, self.table, self.set_name,
                f"{{ {ip} . {validate_ipv4(target)} }}",
            )
            stderr = out.get("stderr", "")
            if out.get("code", 0) != 0 and "No such file" not in stderr:
                raise DriverError(f"openwrt: nft: {stderr.strip()}")

    async def check(self) -> dict:
        sid = self._sid or await self._login()
        result = await self._rpc(sid, "system", "board", {})
        info = result[1] if result[0] == 0 and len(result) > 1 else {}
        return {"ok": result[0] == 0, "model": info.get("model"), "release": info.get("release", {}).get("description")}

    async def lookup_mac(self, client_ip: str) -> str | None:
        result = await self._call("file", "read", {"path": "/proc/net/arp"})
        if result[0] != 0 or len(result) < 2:
            return None
        for line in result[1].get("data", "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == client_ip:
                return normalize_mac(parts[3])
        return None

    async def reboot(self) -> None:
        try:
            result = await self._call("system", "reboot", {})
        except DriverError as exc:
            if isinstance(exc.__cause__, Exception) and reboot_dropped(exc.__cause__):
                return
            raise
        if result[0] != 0:
            raise DriverError(f"openwrt: reboot, ubus code {result[0]} (нужен доступ system.reboot в ACL rpcd)")

    async def aclose(self) -> None:
        await self.client.aclose()
