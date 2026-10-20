"""OpenWrt по сети через ubus JSON-RPC (uhttpd-mod-ubus + rpcd).

Драйвер добавляет IP клиента в nftables-набор fw4 с таймаутом через
``file.exec`` rpcd. Пользователю rpcd нужен ACL на запуск /usr/sbin/nft —
см. deploy/openwrt/authpass.acl.json. Если AuthPass запущен на самом
OpenWrt, проще драйвер ``nftables``.
"""

from __future__ import annotations

import itertools

import httpx

from .base import DriverError, Grant, RouterDriver, validate_ipv4

ANON_SESSION = "0" * 32
UBUS_PERMISSION_DENIED = 6


class OpenWrtDriver(RouterDriver):
    name = "openwrt"
    router_side_timeout = True

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
    ):
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
        element = f"{{ {ip} timeout {grant.router_ttl}s }}"
        out = await self._nft("add", "element", self.family, self.table, self.set_name, element)
        if out.get("code", 0) != 0:
            raise DriverError(f"openwrt: nft: {out.get('stderr', '').strip()}")
        return ip

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        out = await self._nft(
            "delete", "element", self.family, self.table, self.set_name, f"{{ {ip} }}"
        )
        stderr = out.get("stderr", "")
        if out.get("code", 0) != 0 and "No such file" not in stderr:
            raise DriverError(f"openwrt: nft: {stderr.strip()}")

    async def check(self) -> dict:
        sid = self._sid or await self._login()
        result = await self._rpc(sid, "system", "board", {})
        info = result[1] if result[0] == 0 and len(result) > 1 else {}
        return {"ok": result[0] == 0, "model": info.get("model"), "release": info.get("release", {}).get("description")}

    async def aclose(self) -> None:
        await self.client.aclose()
