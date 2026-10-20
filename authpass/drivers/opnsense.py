"""OPNsense через API: IP клиента добавляется в алиас типа Host(s).

Алиас и правило pass (источник — алиас, назначение — узлы доставки)
создаются администратором заранее. Таймаута на стороне OPNsense нет.
"""

from __future__ import annotations

import httpx

from .base import DriverError, Grant, RouterDriver, validate_ipv4


class OPNsenseDriver(RouterDriver):
    name = "opnsense"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        alias: str,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.alias = alias
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/api",
            auth=(api_key, api_secret),
            verify=verify_tls,
            timeout=10,
            transport=transport,
        )

    async def _post(self, path: str, json: dict) -> dict:
        try:
            resp = await self.client.post(path, json=json)
        except httpx.HTTPError as exc:
            raise DriverError(f"opnsense: {exc}") from exc
        if resp.status_code != 200:
            raise DriverError(f"opnsense: {resp.status_code} {resp.text[:200]}")
        return resp.json()

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        data = await self._post(f"/firewall/alias_util/add/{self.alias}", {"address": ip})
        if data.get("status") not in ("done", None):
            raise DriverError(f"opnsense: {data}")
        return ip

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        await self._post(f"/firewall/alias_util/delete/{self.alias}", {"address": ip})

    async def check(self) -> dict:
        try:
            resp = await self.client.get("/core/firmware/status")
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": resp.status_code == 200}

    async def aclose(self) -> None:
        await self.client.aclose()
