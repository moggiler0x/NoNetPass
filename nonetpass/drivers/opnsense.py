"""OPNsense через API: IP клиента добавляется в алиас шлюза типа Host(s).

У каждого шлюза свой алиас ``<alias>_<шлюз>`` (дефисы заменяются на ``_``) и
своё правило pass (источник — алиас клиентов шлюза, назначение — его узлы).
Они создаются администратором заранее. Таймаута на стороне OPNsense нет.
"""

from __future__ import annotations

import httpx

from .base import DriverError, Grant, RouterDriver, reboot_dropped, validate_ipv4


class OPNsenseDriver(RouterDriver):
    name = "opnsense"
    can_reboot = True

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
        alias = self._alias(grant.gate)
        data = await self._post(f"/firewall/alias_util/add/{alias}", {"address": ip})
        if data.get("status") not in ("done", None):
            raise DriverError(f"opnsense: {data}")
        return alias

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        await self._post(f"/firewall/alias_util/delete/{handle}", {"address": ip})

    def _alias(self, gate: str) -> str:
        return f"{self.alias}_{gate}".replace("-", "_")

    async def check(self) -> dict:
        try:
            resp = await self.client.get("/core/firmware/status")
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": resp.status_code == 200}

    async def reboot(self) -> None:
        try:
            await self._post("/core/system/reboot", {})
        except DriverError as exc:
            if isinstance(exc.__cause__, Exception) and reboot_dropped(exc.__cause__):
                return
            raise

    async def aclose(self) -> None:
        await self.client.aclose()
