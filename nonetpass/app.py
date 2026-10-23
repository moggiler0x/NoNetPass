from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

import anyio

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import __version__
from .admin import COOKIE, AdminAuth, build_admin_router, token_ok
from .blocklist import Blocklist
from .config import Settings
from .context import Context
from .control import RouterSet, SystemControl
from .detect import start_syslog, tail_dns_log
from .drivers import DriverError, RouterDriver, build_driver
from .health import HealthMonitor
from .journal import SessionJournal
from .metrics import Metrics
from .reports import get_tz, monthly_loop
from .sessions import ALL, OpenRefused, SessionManager
from .store import StateStore

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


# Оставлено для совместимости импортов.
_token_ok = token_ok


def build_context(settings: Settings, driver: RouterDriver) -> Context:
    journal = SessionJournal(settings.log_path)
    store = StateStore(settings.state_path)
    blocklist = Blocklist(store, settings.blocked_macs, settings.blocked_ips)
    manager = SessionManager(settings, driver, journal, store, blocklist)
    routers = RouterSet(settings, driver)
    control = SystemControl(settings, routers, manager, journal)
    health = HealthMonitor(settings, routers, manager, store, journal)
    metrics = Metrics(manager, health, blocklist, __version__)
    ctx = Context(
        settings=settings, catalog=settings.catalog(), manager=manager, journal=journal, store=store,
        blocklist=blocklist, routers=routers, control=control, health=health, metrics=metrics,
        tz=get_tz(settings.timezone),
    )
    ctx.apply_overrides()
    if settings.telegram_token and settings.telegram_admin_ids:
        from .telegram import TelegramBot

        ctx.bot = TelegramBot(ctx)
        health.notifiers.append(ctx.bot.notify)
        health.probes["telegram"] = ("Telegram-бот", ctx.bot.probe)
    elif settings.telegram_token:
        log.warning("NONETPASS_TELEGRAM_TOKEN задан, но NONETPASS_TELEGRAM_ADMIN_IDS пуст: бот не запущен")
    return ctx


def create_app(settings: Settings | None = None, driver: RouterDriver | None = None,
               background: bool = True) -> FastAPI:
    settings = settings or Settings.from_env()
    driver = driver or build_driver(settings)
    ctx = build_context(settings, driver)
    manager, catalog = ctx.manager, ctx.catalog
    auth = AdminAuth(settings)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks: list[asyncio.Task] = []
        closers = []
        # Автооткат: окна, оставшиеся открытыми после падения или перезапуска.
        try:
            if n := await manager.recover():
                log.warning("закрыто %d окон, оставшихся с прошлого запуска", n)
        except Exception:
            log.exception("не удалось закрыть окна прошлого запуска")
        cleanup = getattr(driver, "cleanup_stale", None)
        if cleanup:
            try:
                if n := await cleanup():
                    log.warning("убрано %d записей на роутере с прошлого запуска", n)
            except DriverError:
                log.exception("не удалось убрать старые записи на роутере")
        if settings.dns_log_path:
            tasks.append(asyncio.create_task(tail_dns_log(settings.dns_log_path, manager, catalog)))
        if settings.syslog_port:
            try:
                transport, protocol = await start_syslog(
                    settings.syslog_host, settings.syslog_port, manager, catalog, settings.syslog_allow)
                closers.append(transport.close)
                ctx.health.probes["syslog"] = ("Детекция по syslog", lambda: (
                    "ok", f"udp/{settings.syslog_port}, сообщений: {protocol.received}"))
            except OSError as exc:
                log.error("syslog на порту %s не запущен: %s", settings.syslog_port, exc)
                ctx.health.probes["syslog"] = ("Детекция по syslog", lambda: (
                    "fail", f"порт udp/{settings.syslog_port} занят или недоступен: {exc}"))
        if background:
            ctx.health.start()
            if ctx.bot:
                ctx.bot.start()
                tasks.append(asyncio.create_task(monthly_loop(ctx, ctx.bot.broadcast)))
        log.info("NoNetPass %s, драйвер %s, шлюзов %d, роутеров %d, бот %s", __version__, driver.name,
                 len(catalog.all), len(ctx.routers.routers), "включён" if ctx.bot else "выключен")
        yield
        for task in tasks:
            task.cancel()
        for close in closers:
            close()
        await ctx.health.stop()
        await manager.shutdown()
        if ctx.bot:
            await ctx.bot.stop()
        await ctx.routers.aclose()
        await driver.aclose()

    app = FastAPI(title="NoNetPass", version=__version__, lifespan=lifespan)
    app.state.ctx = ctx
    app.state.manager = manager
    app.state.settings = settings
    app.state.catalog = catalog

    def client_ip(request: Request) -> str:
        return _client_ip(
            settings, request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
        )

    def require_detect(authorization: str | None = Header(None)) -> None:
        if not (token_ok(settings.detect_token, authorization) or token_ok(settings.admin_token, authorization)):
            raise HTTPException(401, "нужен токен детекции")

    def me_payload(ip: str) -> dict:
        session = manager.current(ip)
        return {
            "type": "state",
            "client_ip": ip,
            "session": session.to_dict() if session else None,
            "gates": [g.to_dict() for g in catalog.all],
            "extend": {"seconds": settings.extend_seconds, "max": settings.max_extends},
        }

    @app.get("/", include_in_schema=False)
    async def panel():
        return FileResponse(STATIC / "index.html")

    @app.get("/admin", include_in_schema=False)
    async def admin_page():
        return FileResponse(STATIC / "admin.html")

    @app.get("/static/{name}", include_in_schema=False)
    async def static(name: str):
        path = (STATIC / name).resolve()
        if path.parent != STATIC.resolve() or not path.is_file():
            raise HTTPException(404)
        return FileResponse(path)

    # PWA: манифест и service worker должны лежать в корне, чтобы покрыть портал.
    @app.get("/manifest.webmanifest", include_in_schema=False)
    async def manifest():
        return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")

    @app.get("/sw.js", include_in_schema=False)
    async def service_worker():
        return FileResponse(STATIC / "sw.js", media_type="text/javascript", headers={"Cache-Control": "no-cache"})

    @app.get("/healthz")
    async def healthz():
        try:
            router = await driver.check()
        except DriverError as exc:
            router = {"ok": False, "error": str(exc)}
        return {"ok": True, "version": __version__, "driver": driver.name,
                "gates": len(catalog.all), "router": router, "status": ctx.health.status}

    @app.get("/metrics", include_in_schema=False)
    async def metrics(authorization: str | None = Header(None)):
        if settings.metrics_token and not token_ok(settings.metrics_token, authorization):
            raise HTTPException(401, "нужен токен метрик")
        return PlainTextResponse(ctx.metrics.render(), media_type="text/plain; version=0.0.4")

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
            ctx.metrics.refuse(_refuse_reason(str(exc)))
            raise HTTPException(409, str(exc))
        return session.to_dict()

    @app.post("/api/me/extend")
    async def me_extend(request: Request):
        session = manager.current(client_ip(request))
        gate = catalog.get(session.gate_id) if session else None
        if not gate:
            raise HTTPException(409, "окно не открыто")
        try:
            session = await manager.extend(session.client_ip, gate)
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

    app.include_router(build_admin_router(ctx, auth, client_ip))

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
        ip = _client_ip(
            settings, websocket.client.host if websocket.client else None,
            websocket.headers.get("x-forwarded-for"),
        )
        actor = auth.identify(ip, f"Bearer {token}" if token else None, websocket.cookies.get(COOKIE))
        if not actor:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        queue = manager.subscribe(ALL)
        try:
            await websocket.send_json({"type": "health", "health": ctx.health.snapshot()})
            await _pump(websocket, queue)
        finally:
            manager.unsubscribe(ALL, queue)

    return app


def _refuse_reason(message: str) -> str:
    for key, reason in (("заблокир", "blocked"), ("повторное", "cooldown"), ("лимит", "hourly_limit"),
                        ("роутер", "router_error")):
        if key in message:
            return reason
    return "other"


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
