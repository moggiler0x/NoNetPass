"""Keenetic (NDMS 3.x/4.x) через RCI.

RCI принимает CLI-команды через ``{"parse": "<команда>"}``, поэтому драйвер
работает в терминах обычного CLI Keenetic. Списки доступа Keenetic не умеют
таймаут записи и принимают только IP, поэтому:

* узлы доставки резолвятся в IPv4 в момент открытия окна;
* изменения не сохраняются в startup-config (``system configuration save``
  не вызывается), так что перезагрузка роутера тоже закрывает окно;
* открытые записи пишутся в state-файл и удаляются при старте NoNetPass.

Шаблоны команд можно переопределить через NONETPASS_DRIVER_OPT_GRANT_CMD /
NONETPASS_DRIVER_OPT_REVOKE_CMD, если ваша прошивка использует другой синтаксис.

На самом роутере (Entware) RCI доступен без пароля по http://127.0.0.1:79.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import httpx

from ..blocklist import normalize_mac
from .base import DriverError, Grant, RouterDriver, reboot_dropped, resolve_ipv4, validate_ipv4

DEFAULT_GRANT_CMD = "access-list {acl} permit ip {src} 255.255.255.255 {dst} 255.255.255.255"
DEFAULT_REVOKE_CMD = "access-list {acl} no permit ip {src} 255.255.255.255 {dst} 255.255.255.255"


def challenge_password(login: str, password: str, realm: str, challenge: str) -> str:
    md5 = hashlib.md5(f"{login}:{realm}:{password}".encode()).hexdigest()
    return hashlib.sha256((challenge + md5).encode()).hexdigest()


class KeeneticDriver(RouterDriver):
    name = "keenetic"
    can_reboot = True

    def __init__(
        self,
        base_url: str,
        user: str | None,
        password: str | None,
        acl: str,
        verify_tls: bool = True,
        grant_cmd: str = DEFAULT_GRANT_CMD,
        revoke_cmd: str = DEFAULT_REVOKE_CMD,
        state_file: str | None = "nonetpass-keenetic-state.json",
        resolver=resolve_ipv4,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.user = user
        self.password = password
        self.acl = acl
        self.grant_cmd = grant_cmd
        self.revoke_cmd = revoke_cmd
        self.state_file = Path(state_file) if state_file else None
        self.resolver = resolver
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), verify=verify_tls, timeout=10, transport=transport
        )
        self._authed = False
        self._lock = asyncio.Lock()

    async def _auth(self) -> None:
        if not self.user:
            self._authed = True  # локальный RCI на 127.0.0.1:79
            return
        resp = await self.client.get("/auth")
        if resp.status_code == 200:
            self._authed = True
            return
        realm = resp.headers.get("X-NDM-Realm")
        challenge = resp.headers.get("X-NDM-Challenge")
        if resp.status_code != 401 or not realm or not challenge:
            raise DriverError(f"keenetic: неожиданный ответ /auth: {resp.status_code}")
        resp = await self.client.post(
            "/auth",
            json={
                "login": self.user,
                "password": challenge_password(self.user, self.password or "", realm, challenge),
            },
        )
        if resp.status_code != 200:
            raise DriverError("keenetic: неверный логин или пароль")
        self._authed = True

    async def _parse(self, commands: list[str]) -> list:
        payload = [{"parse": cmd} for cmd in commands]
        try:
            if not self._authed:
                await self._auth()
            resp = await self.client.post("/rci/", json=payload)
            if resp.status_code == 401:
                self._authed = False
                await self._auth()
                resp = await self.client.post("/rci/", json=payload)
        except httpx.HTTPError as exc:
            raise DriverError(f"keenetic: {exc}") from exc
        if resp.status_code != 200:
            raise DriverError(f"keenetic: RCI {resp.status_code} {resp.text[:200]}")
        results = resp.json()
        for cmd, result in zip(commands, results):
            for status in (result.get("parse") or {}).get("status", []):
                if status.get("status") == "error":
                    raise DriverError(f"keenetic: {cmd!r}: {status.get('message')}")
        return results

    def _commands(self, template: str, ip: str, targets: list[str]) -> list[str]:
        return [template.format(acl=self.acl, src=ip, dst=dst) for dst in targets]

    def _load_state(self) -> dict[str, list[str]]:
        if not self.state_file or not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text())
        except (OSError, ValueError):
            return {}

    def _save_state(self, state: dict[str, list[str]]) -> None:
        if self.state_file:
            self.state_file.write_text(json.dumps(state))

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        targets = await self.resolver(grant.targets)
        if not targets:
            raise DriverError("keenetic: не удалось получить IP узлов доставки")
        async with self._lock:
            await self._parse(self._commands(self.grant_cmd, ip, targets))
            state = self._load_state()
            state[ip] = sorted(set(state.get(ip, [])) | set(targets))
            self._save_state(state)
        return json.dumps(targets)

    async def revoke(self, client_ip: str, handle: str) -> None:
        ip = validate_ipv4(client_ip)
        async with self._lock:
            state = self._load_state()
            targets = sorted(set(json.loads(handle)) | set(state.get(ip, [])))
            for cmd in self._commands(self.revoke_cmd, ip, targets):
                try:
                    await self._parse([cmd])
                except DriverError as exc:
                    # Правила уже нет — это нормальный исход.
                    if "not found" not in str(exc).lower():
                        raise
            state.pop(ip, None)
            self._save_state(state)

    async def cleanup_stale(self) -> int:
        state = self._load_state()
        for ip, targets in state.items():
            await self.revoke(ip, json.dumps(targets))
        return len(state)

    async def check(self) -> dict:
        try:
            if not self._authed:
                await self._auth()
            resp = await self.client.get("/rci/show/version")
        except (httpx.HTTPError, DriverError) as exc:
            return {"ok": False, "error": str(exc)}
        if resp.status_code != 200:
            return {"ok": False, "status": resp.status_code}
        data = resp.json()
        return {"ok": True, "version": data.get("title") or data.get("release"), "model": data.get("model")}

    async def show(self, path: str, body: dict | None = None):
        """JSON команды через RCI, например ``show("show/running-config")``.

        С ``body`` запрос идёт POST: так RCI выполняет команды не из ``show``
        (``show("components/list", {})``)."""

        async def call():
            if body is None:
                return await self.client.get(f"/rci/{path}")
            return await self.client.post(f"/rci/{path}", json=body)

        try:
            if not self._authed:
                await self._auth()
            resp = await call()
            if resp.status_code == 401:
                self._authed = False
                await self._auth()
                resp = await call()
        except httpx.HTTPError as exc:
            raise DriverError(f"keenetic: {exc}") from exc
        if resp.status_code != 200:
            raise DriverError(f"keenetic: RCI {path}: {resp.status_code}")
        return resp.json()

    async def parse(self, commands: list[str]) -> list:
        """Выполнить команды CLI через RCI; ошибка любой команды — DriverError."""
        return await self._parse(commands)

    async def lookup_mac(self, client_ip: str) -> str | None:
        try:
            if not self._authed:
                await self._auth()
            resp = await self.client.get("/rci/show/ip/arp")
        except httpx.HTTPError as exc:
            raise DriverError(f"keenetic: {exc}") from exc
        if resp.status_code != 200:
            return None
        rows = resp.json()
        if isinstance(rows, dict):
            rows = rows.get("arp") or rows.get("entry") or list(rows.values())
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("ip") == client_ip:
                return normalize_mac(row.get("mac", ""))
        return None

    async def reboot(self) -> None:
        try:
            await self._parse(["system reboot"])
        except DriverError as exc:
            if isinstance(exc.__cause__, Exception) and reboot_dropped(exc.__cause__):
                return
            raise

    async def aclose(self) -> None:
        await self.client.aclose()
