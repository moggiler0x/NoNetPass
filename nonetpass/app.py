from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
from pathlib import Path

import anyio

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import __version__
from .config import Settings
from .detect import tail_dns_log
from .drivers import DriverError, RouterDriver, build_driver
from .journal import SessionJournal
from .models import CloseReason
from .sessions import ALL, OpenRefused, SessionManager

log = logging.getLogger("nonetpass")
STATIC = Path(__file__).parent / "static"


class DetectIn(BaseModel):
    client_ip: str
    host: str | None = None
    gate: str | None = None
    source: str = "webhook"


class OpenIn(BaseModel):
    gate: str


def _client_ip(settings: Settings, host: str | None, forwarded: str | None) -> str:
    if settings.trust_forwarded and forwarded:
        return forwarded.split(",")[0].strip()
    return host or ""


def _token_ok(expected: str | None, authorization: str | None) -> bool:
    if not expected:
        return False
    given = (authorization or "").removeprefix("Bearer ").strip()
    return hmac.compare_digest(given, expected)


def create_app(settings: Settings | None = None, driver: RouterDriver | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    driver = driver or build_driver(settings)
    catalog = settings.catalog()
    manager = SessionManager(settings, driver, SessionJournal(settings.log_path))

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = []
        cleanup = getattr(driver, "cleanup_stale", None)
        if cleanup:
            try:
                if n := await cleanup():
                    log.warning("закрыто %d окон, оставшихся с прошлого запуска", n)
            except DriverError:
                log.exception("не удалось убрать старые записи на роутере")
        if settings.dns_log_path:
            tasks.append(asyncio.create_task(tail_dns_log(settings.dns_log_path, manager, catalog)))
        log.info("NoNetPass %s, драйвер %s, шлюзов %d", __version__, driver.name, len(catalog.all))
        yield
        for task in tasks:
            task.cancel()
        await manager.shutdown()
        await driver.aclose()

    app = FastAPI(title="NoNetPass", version=__version__, lifespan=lifespan)
    app.state.manager = manager
    app.state.settings = settings
    app.state.catalog = catalog

    def client_ip(request: Request) -> str:
        return _client_ip(
            settings, request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
        )

    def require_detect(authorization: str | None = Header(None)) -> None:
        if not (_token_ok(settings.detect_token, authorization) or _token_ok(settings.admin_token, authorization)):
            raise HTTPException(401, "нужен токен детекции")

    def require_admin(authorization: str | None = Header(None)) -> None:
        if not _token_ok(settings.admin_token, authorization):
            raise HTTPException(401, "нужен админский токен")

    def me_payload(ip: str) -> dict:
        session = manager.current(ip)
        return {
            "type": "state",
            "client_ip": ip,
            "session": session.to_dict() if session else None,
            "gates": [g.to_dict() for g in catalog.all],
        }

    @app.get("/", include_in_schema=False)
    async def panel():
        return FileResponse(STATIC / "index.html")

    @app.get("/healthz")
    async def healthz():
        try:
            router = await driver.check()
        except DriverError as exc:
            router = {"ok": False, "error": str(exc)}
        return {"ok": True, "version": __version__, "driver": driver.name,
                "gates": len(catalog.all), "router": router}

    @app.get("/api/gates")
    async def gates():
        return [g.to_dict() for g in catalog.all]

    # --- панель пользователя: действует только для IP самого запроса ---------

    @app.get("/api/me")
    async def me(request: Request):
        return me_payload(client_ip(request))

    @app.post("/api/me/open")
    async def me_open(request: Request, body: OpenIn):
        gate = catalog.get(body.gate)
        if not gate:
            raise HTTPException(404, f"нет шлюза {body.gate!r}")
        try:
            session = await manager.open(client_ip(request), gate)
        except (OpenRefused, DriverError) as exc:
            raise HTTPException(409, str(exc))
        return session.to_dict()

    @app.post("/api/me/done")
    async def me_done(request: Request):
        session = await manager.complete(client_ip(request))
        return {"session": session.to_dict() if session else None}

    # --- источники детекции -------------------------------------------------

    @app.post("/api/detect", dependencies=[Depends(require_detect)])
    async def detect(body: DetectIn):
        gate = catalog.get(body.gate) if body.gate else (catalog.for_host(body.host) if body.host else None)
        if not gate:
            return {"ignored": True}
        try:
            session = await manager.detect(body.client_ip, body.source, gate, body.host)
        except DriverError as exc:
            raise HTTPException(422, str(exc))
        return session.to_dict()

    # --- администратор ------------------------------------------------------

    @app.get("/api/admin/sessions", dependencies=[Depends(require_admin)])
    async def admin_sessions(limit: int = 50):
        return [s.to_dict() for s in manager.recent(limit)]

    @app.get("/api/admin/journal", dependencies=[Depends(require_admin)])
    async def admin_journal(limit: int = 100):
        return manager.journal.tail(limit)

    @app.post("/api/admin/sessions/{session_id}/revoke", dependencies=[Depends(require_admin)])
    async def admin_revoke(session_id: str):
        session = await manager.close(session_id, CloseReason.REVOKED)
        if not session:
            raise HTTPException(404, "нет такой сессии")
        return session.to_dict()

    # --- WebSocket ----------------------------------------------------------

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        ip = _client_ip(
            settings, websocket.client.host if websocket.client else None,
            websocket.headers.get("x-forwarded-for"),
        )
        await websocket.accept()
        queue = manager.subscribe(ip)
        try:
            await websocket.send_json(me_payload(ip))
            await _pump(websocket, queue)
        finally:
            manager.unsubscribe(ip, queue)

    @app.websocket("/ws/admin")
    async def ws_admin(websocket: WebSocket, token: str = ""):
        if not _token_ok(settings.admin_token, token):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        queue = manager.subscribe(ALL)
        try:
            await _pump(websocket, queue)
        finally:
            manager.unsubscribe(ALL, queue)

    return app


async def _pump(websocket: WebSocket, queue: asyncio.Queue) -> None:
    """Отправляет события из очереди, пока клиент не отключится."""

    async def receiver() -> None:
        while True:
            if await websocket.receive_text() == "ping":
                await websocket.send_json({"type": "pong"})

    async def sender() -> None:
        while True:
            await websocket.send_json(await queue.get())

    # Группа задач anyio, а не голые asyncio-задачи: так отмена со стороны
    # сервера (и TestClient) корректно проходит через обе половины.
    async with anyio.create_task_group() as tg:

        async def run(fn) -> None:
            with contextlib.suppress(WebSocketDisconnect, RuntimeError):
                await fn()
            tg.cancel_scope.cancel()

        tg.start_soon(run, receiver)
        tg.start_soon(run, sender)
