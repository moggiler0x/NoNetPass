"""MikroTik RouterOS.

Два транспорта:
* ``mikrotik`` — REST API RouterOS 7 (``/rest``, служба www или www-ssl);
* ``mikrotik-api`` — классический API RouterOS 6/7 (порт 8728, или 8729 с TLS).

У каждого шлюза свой список клиентов ``nonetpass-clients-<шлюз>`` и свой
список узлов ``nonetpass-targets-<шлюз>`` с отдельным правилом, поэтому окно
открывает только узлы выбранного сервиса. Запись создаётся с ``timeout``,
роутер сам удалит её, если NoNetPass не успеет. Конфиг роутера генерирует
``nonetpass router-config mikrotik`` (готовый: deploy/mikrotik/nonetpass.rsc).
"""

from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlparse

import httpx

from .base import DriverError, Grant, RouterDriver, validate_ipv4

ADDRESS_LIST = "/ip/firewall/address-list"


def gate_list(base: str, gate: str) -> str:
    return f"{base}-{gate}"


class MikroTikRestDriver(RouterDriver):
    name = "mikrotik"
    router_side_timeout = True

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        list_name: str,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.list_name = list_name
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/rest",
            auth=(user, password),
            verify=verify_tls,
            timeout=10,
            transport=transport,
        )

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            resp = await self.client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise DriverError(f"mikrotik: {exc}") from exc
        return resp

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        list_name = gate_list(self.list_name, grant.gate)
        # Если запись для IP уже есть (например, после рестарта NoNetPass),
        # обновляем её таймаут вместо создания дубля.
        resp = await self._request(
            "GET", ADDRESS_LIST, params={"list": list_name, "address": ip}
        )
        if resp.status_code == 200 and resp.json():
            entry_id = resp.json()[0][".id"]
            resp = await self._request(
                "PATCH",
                f"{ADDRESS_LIST}/{entry_id}",
                json={"timeout": f"{grant.router_ttl}s", "comment": grant.comment},
            )
            if resp.status_code >= 400:
                raise DriverError(f"mikrotik: {resp.status_code} {resp.text}")
            return entry_id
        resp = await self._request(
            "PUT",
            ADDRESS_LIST,
            json={
                "list": list_name,
                "address": ip,
                "timeout": f"{grant.router_ttl}s",
                "comment": grant.comment,
            },
        )
        if resp.status_code >= 400:
            raise DriverError(f"mikrotik: {resp.status_code} {resp.text}")
        return resp.json()[".id"]

    async def revoke(self, client_ip: str, handle: str) -> None:
        resp = await self._request("DELETE", f"{ADDRESS_LIST}/{handle}")
        # 404 — запись уже удалена таймаутом роутера.
        if resp.status_code >= 400 and resp.status_code != 404:
            raise DriverError(f"mikrotik: {resp.status_code} {resp.text}")

    async def check(self) -> dict:
        resp = await self._request("GET", "/system/resource")
        if resp.status_code != 200:
            return {"ok": False, "status": resp.status_code}
        data = resp.json()
        return {"ok": True, "version": data.get("version"), "board": data.get("board-name")}

    async def aclose(self) -> None:
        await self.client.aclose()


# --- Классический API RouterOS -------------------------------------------------


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + n.to_bytes(4, "big")


async def read_length(reader: asyncio.StreamReader) -> int:
    first = (await reader.readexactly(1))[0]
    if first < 0x80:
        return first
    if first < 0xC0:
        rest = await reader.readexactly(1)
        return ((first & 0x3F) << 8) | rest[0]
    if first < 0xE0:
        rest = await reader.readexactly(2)
        return ((first & 0x1F) << 16) | int.from_bytes(rest, "big")
    if first < 0xF0:
        rest = await reader.readexactly(3)
        return ((first & 0x0F) << 24) | int.from_bytes(rest, "big")
    return int.from_bytes(await reader.readexactly(4), "big")


def encode_sentence(words: list[str]) -> bytes:
    out = bytearray()
    for word in words:
        raw = word.encode("utf-8")
        out += encode_length(len(raw)) + raw
    out += b"\x00"
    return bytes(out)


class ApiConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    async def read_sentence(self) -> list[str]:
        words = []
        while True:
            length = await read_length(self.reader)
            if length == 0:
                return words
            words.append((await self.reader.readexactly(length)).decode("utf-8", "replace"))

    async def talk(self, words: list[str]) -> list[tuple[str, dict[str, str]]]:
        self.writer.write(encode_sentence(words))
        await self.writer.drain()
        replies = []
        while True:
            sentence = await self.read_sentence()
            if not sentence:
                continue
            kind, attrs = sentence[0], {}
            for word in sentence[1:]:
                if word.startswith("="):
                    key, _, value = word[1:].partition("=")
                    attrs[key] = value
            replies.append((kind, attrs))
            if kind in ("!done", "!fatal"):
                return replies

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except OSError:
            pass


def _trap(replies: list[tuple[str, dict[str, str]]]) -> str | None:
    for kind, attrs in replies:
        if kind in ("!trap", "!fatal"):
            return attrs.get("message", kind)
    return None


class MikroTikApiDriver(RouterDriver):
    name = "mikrotik-api"
    router_side_timeout = True

    def __init__(self, url: str, user: str, password: str, list_name: str, verify_tls: bool = True):
        # url: api://host[:8728] или api-ssl://host[:8729]
        parsed = urlparse(url if "://" in url else f"api://{url}")
        self.use_tls = parsed.scheme in ("api-ssl", "apis", "ssl", "tls")
        self.host = parsed.hostname or "192.168.88.1"
        self.port = parsed.port or (8729 if self.use_tls else 8728)
        self.user = user
        self.password = password
        self.list_name = list_name
        self.verify_tls = verify_tls

    async def _connect(self) -> ApiConnection:
        ctx = None
        if self.use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx), timeout=10
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise DriverError(f"mikrotik-api: нет связи с {self.host}:{self.port}: {exc}") from exc
        conn = ApiConnection(reader, writer)
        replies = await conn.talk(["/login", f"=name={self.user}", f"=password={self.password}"])
        if err := _trap(replies):
            await conn.close()
            raise DriverError(f"mikrotik-api: вход не удался: {err}")
        return conn

    async def _run(self, words: list[str]) -> list[tuple[str, dict[str, str]]]:
        conn = await self._connect()
        try:
            return await asyncio.wait_for(conn.talk(words), timeout=10)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            raise DriverError(f"mikrotik-api: {exc}") from exc
        finally:
            await conn.close()

    async def grant(self, grant: Grant) -> str:
        ip = validate_ipv4(grant.client_ip)
        list_name = gate_list(self.list_name, grant.gate)
        found = await self._run(
            [f"{ADDRESS_LIST}/print", f"?list={list_name}", f"?address={ip}", "=.proplist=.id"]
        )
        existing = [attrs[".id"] for kind, attrs in found if kind == "!re" and ".id" in attrs]
        if existing:
            replies = await self._run(
                [
                    f"{ADDRESS_LIST}/set",
                    f"=.id={existing[0]}",
                    f"=timeout={grant.router_ttl}s",
                    f"=comment={grant.comment}",
                ]
            )
            if err := _trap(replies):
                raise DriverError(f"mikrotik-api: {err}")
            return existing[0]
        replies = await self._run(
            [
                f"{ADDRESS_LIST}/add",
                f"=list={list_name}",
                f"=address={ip}",
                f"=timeout={grant.router_ttl}s",
                f"=comment={grant.comment}",
            ]
        )
        if err := _trap(replies):
            raise DriverError(f"mikrotik-api: {err}")
        for kind, attrs in replies:
            if kind == "!done" and "ret" in attrs:
                return attrs["ret"]
        raise DriverError("mikrotik-api: роутер не вернул id записи")

    async def revoke(self, client_ip: str, handle: str) -> None:
        replies = await self._run([f"{ADDRESS_LIST}/remove", f"=.id={handle}"])
        err = _trap(replies)
        if err and "no such item" not in err.lower():
            raise DriverError(f"mikrotik-api: {err}")

    async def check(self) -> dict:
        replies = await self._run(["/system/resource/print"])
        for kind, attrs in replies:
            if kind == "!re":
                return {"ok": True, "version": attrs.get("version"), "board": attrs.get("board-name")}
        return {"ok": False}
