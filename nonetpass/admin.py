"""Админ-панель: вход по PIN или логину, управление окнами, мониторинг,
отчёты, чёрный список, проверка узлов и перезагрузка.

Вход:
* ``NONETPASS_ADMIN_PIN`` — PIN (удобно с телефона);
* ``NONETPASS_ADMIN_USER`` + ``NONETPASS_ADMIN_PASSWORD`` — логин и пароль;
* ``NONETPASS_ADMIN_TOKEN`` — Bearer-токен для скриптов и API.

После входа выдаётся подписанная cookie на 12 часов (HttpOnly,
SameSite=Strict). После ``NONETPASS_LOGIN_MAX_FAILURES`` неверных попыток
адрес блокируется на ``NONETPASS_LOGIN_LOCKOUT_SECONDS``. Изменяющие запросы
из панели дополнительно требуют заголовок ``X-NoNetPass: 1``.
``NONETPASS_ADMIN_NETWORKS`` ограничивает панель подсетями (например,
только сеть администратора, а не гостевой Wi-Fi).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .control import RebootRefused
from .hostcheck import check_catalog
from .config import update_env_file
from .keenetic_config import ConfigError, KeeneticSetup, bundle, bundle_zip, nonetpass_env_vars
from .keenetic_usb import download_installer
from .models import CloseReason
from .reports import build_report, parse_period, report_csv

COOKIE = "nonetpass_admin"
SESSION_TTL = 12 * 3600


class LoginIn(BaseModel):
    pin: str | None = None
    user: str | None = None
    password: str | None = None


class SettingsIn(BaseModel):
    verify_window: float | None = Field(None, ge=10, le=3600)
    pay_window: float | None = Field(None, ge=10, le=3600)
    cooldown_seconds: float | None = Field(None, ge=0, le=3600)
    max_opens_per_hour: int | None = Field(None, ge=1, le=100)
    extend_seconds: float | None = Field(None, ge=0, le=1800)
    max_extends: int | None = Field(None, ge=0, le=5)


class BlockIn(BaseModel):
    value: str
    note: str = ""


class ConfirmIn(BaseModel):
    confirm: str


class KeeneticIn(BaseModel):
    nas_id: str
    ssid: str = "Guest"
    wifi_password: str = ""
    profile: str = "Clientpulse"
    mode: str = "router"
    portal: str = ""
    rci_password: str = ""
    router_url: str = Field("http://192.168.1.1", pattern=r"^https?://[A-Za-z0-9.:-]+/?$")
    base: str | None = Field(None, max_length=2_000_000)  # текущий startup-config роутера
    apply: bool = False  # режим server: записать настройки роутера в файл настроек и перезапуститься


def token_ok(expected: str | None, authorization: str | None) -> bool:
    if not expected:
        return False
    given = (authorization or "").removeprefix("Bearer ").strip()
    return hmac.compare_digest(given.encode(), expected.encode())


class AdminAuth:
    def __init__(self, settings):
        self.settings = settings
        self.secret = (settings.secret or secrets.token_hex(32)).encode()
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.networks = [ipaddress.ip_network(n, strict=False) for n in settings.admin_networks]

    @property
    def methods(self) -> list[str]:
        out = []
        if self.settings.admin_pin:
            out.append("pin")
        if self.settings.admin_user and self.settings.admin_password:
            out.append("password")
        return out

    def network_ok(self, ip: str) -> bool:
        if not self.networks:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def locked(self, ip: str) -> float:
        """Сколько секунд адрес ещё заблокирован после неверных попыток."""
        window = self.settings.login_lockout_seconds
        fails = self.failures[ip]
        now = time.time()
        while fails and now - fails[0] > window:
            fails.popleft()
        if len(fails) >= self.settings.login_max_failures:
            return window - (now - fails[0])
        return 0

    def login(self, ip: str, body: LoginIn) -> str:
        if not self.methods:
            raise HTTPException(503, "вход в панель не настроен: задайте NONETPASS_ADMIN_PIN или ADMIN_USER и ADMIN_PASSWORD")
        if wait := self.locked(ip):
            raise HTTPException(429, f"слишком много попыток, подождите {int(wait) + 1} с")
        s = self.settings
        ok = False
        user = "admin"
        if body.pin is not None and s.admin_pin:
            ok = hmac.compare_digest(body.pin.encode(), s.admin_pin.encode())
            user = "pin"
        elif body.user is not None and s.admin_user and s.admin_password:
            ok = hmac.compare_digest(body.user.encode(), s.admin_user.encode()) & hmac.compare_digest(
                (body.password or "").encode(), s.admin_password.encode())
            user = s.admin_user
        if not ok:
            self.failures[ip].append(time.time())
            left = s.login_max_failures - len(self.failures[ip])
            raise HTTPException(401, f"неверный PIN или пароль, осталось попыток: {max(0, left)}")
        self.failures.pop(ip, None)
        return self.issue(user)

    def issue(self, user: str) -> str:
        payload = json.dumps({"u": user, "exp": int(time.time() + SESSION_TTL), "n": secrets.token_hex(4)})
        body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str | None) -> str | None:
        if not token or "." not in token:
            return None
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            return None
        try:
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except ValueError:
            return None
        return data["u"] if data.get("exp", 0) > time.time() else None

    def _sign(self, body: str) -> str:
        return hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()[:32]

    def identify(self, request_ip: str, authorization: str | None, cookie: str | None) -> str | None:
        if not self.network_ok(request_ip):
            return None
        if token_ok(self.settings.admin_token, authorization):
            return "token"
        user = self.verify(cookie)
        return f"panel:{user}" if user else None


def local_ip() -> str | None:
    """Адрес этой машины в локальной сети (пакеты не отправляются)."""
    with contextlib.suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]
    return None


def on_keenetic() -> bool:
    return os.path.exists("/opt/etc/init.d/rc.func") and os.path.exists("/opt/etc/ndm")


def build_admin_router(ctx, auth: AdminAuth, client_ip) -> APIRouter:
    router = APIRouter(prefix="/api/admin")
    manager, journal = ctx.manager, ctx.journal

    def admin(request: Request) -> str:
        ip = client_ip(request)
        if not auth.network_ok(ip):
            raise HTTPException(403, "админ-панель недоступна из этой сети")
        actor = auth.identify(ip, request.headers.get("authorization"), request.cookies.get(COOKIE))
        if not actor:
            raise HTTPException(401, "нужен вход в админ-панель")
        if actor.startswith("panel:") and request.method not in ("GET", "HEAD") and request.headers.get("x-nonetpass") != "1":
            raise HTTPException(403, "нет заголовка X-NoNetPass")
        return actor

    # --- вход -----------------------------------------------------------------

    @router.get("/auth")
    async def auth_state(request: Request):
        ip = client_ip(request)
        actor = auth.identify(ip, request.headers.get("authorization"), request.cookies.get(COOKIE))
        return {"authenticated": bool(actor), "methods": auth.methods, "network_ok": auth.network_ok(ip),
                "locked": round(auth.locked(ip))}

    @router.post("/login")
    async def login(request: Request, response: Response, body: LoginIn):
        ip = client_ip(request)
        if not auth.network_ok(ip):
            raise HTTPException(403, "админ-панель недоступна из этой сети")
        try:
            token = auth.login(ip, body)
        except HTTPException as exc:
            if exc.status_code == 401:
                journal.audit("admin_login_failed", ip=ip)
            raise
        journal.audit("admin_login", ip=ip)
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="strict", path="/")
        return {"ok": True}

    @router.post("/logout")
    async def logout(response: Response):
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    # --- обзор и окна ---------------------------------------------------------

    @router.get("/overview")
    async def overview(actor: str = Depends(admin)):
        now = time.time()
        today = build_report(journal, parse_period("today", ctx.tz))
        month = build_report(journal, parse_period("", ctx.tz))
        return {
            "health": ctx.health.snapshot(),
            "windows": [s.to_dict() for s in manager.active_windows()],
            "settings": ctx.runtime_settings(),
            "today": today, "month": month,
            "routers": ctx.control.targets(),
            "telegram": {"configured": ctx.bot is not None,
                         "admins": len(ctx.settings.telegram_admin_ids)},
            "blocklist": ctx.blocklist.entries(),
            "driver": manager.driver.name,
            "now": now,
        }

    @router.get("/sessions")
    async def sessions(limit: int = 50, actor: str = Depends(admin)):
        return [s.to_dict() for s in manager.recent(limit)]

    @router.get("/windows")
    async def windows(actor: str = Depends(admin)):
        return [s.to_dict() for s in manager.active_windows()]

    @router.post("/sessions/{session_id}/revoke")
    async def revoke(session_id: str, actor: str = Depends(admin)):
        session = await manager.close(session_id, CloseReason.REVOKED)
        if not session:
            raise HTTPException(404, "нет такой сессии")
        journal.audit("revoke", session=session_id, actor=actor)
        return session.to_dict()

    @router.post("/windows/close-all")
    async def close_all(actor: str = Depends(admin)):
        n = await manager.close_all(CloseReason.REVOKED)
        journal.audit("revoke_all", actor=actor, count=n)
        return {"closed": n}

    @router.put("/settings")
    async def update_settings(body: SettingsIn, actor: str = Depends(admin)):
        changes = body.model_dump(exclude_none=True)
        for key, value in changes.items():
            if key == "verify_window":
                ctx.catalog.set_window("verify", value)
            elif key == "pay_window":
                ctx.catalog.set_window("pay", value)
            else:
                setattr(ctx.settings, key, value)
            ctx.store.set_override(key, value)
        if changes:
            journal.audit("settings", actor=actor, **changes)
        return ctx.runtime_settings()

    # --- журнал и отчёты ------------------------------------------------------

    def period_of(period: str | None, start: str | None, end: str | None):
        text = f"{start} {end or start}" if start else (period or "")
        try:
            return parse_period(text, ctx.tz)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @router.get("/journal")
    async def journal_tail(limit: int = 100, audit: bool = False, actor: str = Depends(admin)):
        if audit:
            return journal.tail(limit, audit_only=True)
        return journal.tail(limit)

    @router.get("/journal.csv")
    async def journal_csv(period: str | None = None, start: str | None = None, end: str | None = None,
                          actor: str = Depends(admin)):
        p = period_of(period, start, end)
        body = journal.to_csv(journal.records(p.start_ts, p.end_ts), ctx.tz)
        name = f"nonetpass-journal-{p.start:%Y%m%d}-{p.end:%Y%m%d}.csv"
        return PlainTextResponse(body, media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @router.get("/report")
    async def report(period: str | None = None, start: str | None = None, end: str | None = None,
                     actor: str = Depends(admin)):
        return build_report(journal, period_of(period, start, end))

    @router.get("/report.csv")
    async def report_file(period: str | None = None, start: str | None = None, end: str | None = None,
                          actor: str = Depends(admin)):
        p = period_of(period, start, end)
        name = f"nonetpass-report-{p.start:%Y%m%d}-{p.end:%Y%m%d}.csv"
        return PlainTextResponse(report_csv(build_report(journal, p)), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # --- мониторинг -----------------------------------------------------------

    @router.get("/health")
    async def health(actor: str = Depends(admin)):
        return ctx.health.snapshot()

    @router.post("/health/check")
    async def health_check(actor: str = Depends(admin)):
        return await ctx.health.run_checks()

    @router.get("/hosts")
    async def hosts(actor: str = Depends(admin)):
        return await check_catalog(ctx.catalog)

    @router.post("/telegram/test")
    async def telegram_test(actor: str = Depends(admin)):
        if not ctx.bot:
            raise HTTPException(409, "бот не настроен: задайте NONETPASS_TELEGRAM_TOKEN и NONETPASS_TELEGRAM_ADMIN_IDS")
        try:
            await ctx.bot.broadcast("✅ Проверка связи из админ-панели NoNetPass")
        except Exception as exc:
            raise HTTPException(502, f"Telegram: {exc}")
        return {"ok": True, "status": ctx.bot.probe()}

    # --- чёрный список --------------------------------------------------------

    @router.get("/blocklist")
    async def blocklist(actor: str = Depends(admin)):
        return ctx.blocklist.entries()

    @router.post("/blocklist")
    async def block(body: BlockIn, actor: str = Depends(admin)):
        try:
            kind, key = ctx.blocklist.add(body.value, body.note, by=actor)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        journal.audit("block", value=key, actor=actor)
        closed = 0
        for s in manager.active_windows():
            if ctx.blocklist.match(s.client_ip, s.mac):
                await manager.close(s.id, CloseReason.REVOKED)
                closed += 1
        return {"kind": kind, "value": key, "closed": closed}

    @router.delete("/blocklist/{value}")
    async def unblock(value: str, actor: str = Depends(admin)):
        try:
            found = ctx.blocklist.remove(value)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        if not found:
            raise HTTPException(404, "такой записи нет")
        journal.audit("unblock", value=value, actor=actor)
        return {"ok": True}

    # --- перезагрузка ---------------------------------------------------------

    @router.get("/reboot")
    async def reboot_targets(actor: str = Depends(admin)):
        return ctx.control.targets()

    @router.post("/reboot/{target}")
    async def reboot(target: str, body: ConfirmIn, actor: str = Depends(admin)):
        # Подтверждение: в теле запроса повторяется имя цели.
        if body.confirm != target:
            raise HTTPException(422, "подтвердите перезагрузку: confirm должен совпадать с целью")
        try:
            result = await ctx.control.reboot(target, actor)
        except RebootRefused as exc:
            raise HTTPException(409, str(exc))
        if ctx.bot:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ctx.bot.broadcast(f"🔄 {result} (из админ-панели)"), 5)
        return {"ok": True, "message": result}

    # --- конфиг Keenetic ------------------------------------------------------

    @router.get("/keenetic-config")
    async def keenetic_defaults(actor: str = Depends(admin)):
        ip = local_ip()
        return {
            "portal": ip or "",
            "router_url": f"http://{ip.rsplit('.', 1)[0]}.1" if ip else "http://192.168.1.1",
            "mode": "router" if on_keenetic() else "server",
            "can_apply": bool(ctx.settings.env_file),
        }

    @router.post("/keenetic-config")
    async def keenetic_config(body: KeeneticIn, actor: str = Depends(admin)):
        setup = KeeneticSetup(nas_id=body.nas_id, ssid=body.ssid, wifi_password=body.wifi_password,
                              profile=body.profile, mode=body.mode, portal=body.portal,
                              rci_password=body.rci_password)
        try:
            setup.validate()
            installer = None
            if setup.mode == "router":
                with contextlib.suppress(OSError):
                    installer = await asyncio.to_thread(download_installer, timeout=15)
            files = bundle(setup, ctx.catalog, body.base or None, body.router_url, installer)
        except ConfigError as exc:
            raise HTTPException(422, str(exc))
        applied = body.apply and setup.mode == "server" and bool(ctx.settings.env_file)
        journal.audit("keenetic_config", actor=actor, nas_id=body.nas_id, startup_config=bool(body.base),
                      applied=applied)
        headers = {"Content-Disposition": 'attachment; filename="nonetpass-keenetic.zip"'}
        if applied:
            # Настройки роутера в файл, с которым запущен NoNetPass; служба поднимет его заново.
            update_env_file(ctx.settings.env_file, nonetpass_env_vars(setup, body.router_url))
            asyncio.get_running_loop().call_later(2, ctx.control.exit)
            headers["X-NoNetPass-Applied"] = "1"
        return Response(bundle_zip(files), media_type="application/zip", headers=headers)

    return router
