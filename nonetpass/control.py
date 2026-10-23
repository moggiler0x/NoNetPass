"""Управление системой: роутеры, перезапуск NoNetPass, перезагрузка сервера.

Основной роутер — тот, что открывает окна (``NONETPASS_DRIVER``). Ещё
роутеры можно подключить только для мониторинга и перезагрузки, например
Keenetic на входе и MikroTik с Hotspot:

    NONETPASS_ROUTERS=keenetic,office
    NONETPASS_ROUTER_KEENETIC_DRIVER=keenetic
    NONETPASS_ROUTER_KEENETIC_URL=http://192.168.1.1
    NONETPASS_ROUTER_KEENETIC_USER=admin
    NONETPASS_ROUTER_KEENETIC_PASSWORD=…

Любую перезагрузку панель и бот выполняют только после подтверждения, не
чаще раза в ``NONETPASS_REBOOT_COOLDOWN_SECONDS`` для одной цели, и каждая
попадает в журнал.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import signal
import time
from dataclasses import dataclass, replace

from .config import Settings
from .drivers import DriverError, RouterDriver, build_driver
from .journal import SessionJournal
from .models import CloseReason

log = logging.getLogger(__name__)

SELF = "nonetpass"
HOST = "host"


@dataclass
class ManagedRouter:
    name: str
    driver: RouterDriver
    primary: bool = False

    @property
    def kind(self) -> str:
        return self.driver.name


class RouterSet:
    def __init__(self, settings: Settings, primary: RouterDriver):
        self.routers: dict[str, ManagedRouter] = {
            settings.router_name: ManagedRouter(settings.router_name, primary, primary=True)
        }
        for spec in settings.routers:
            if spec.name in self.routers:
                raise ValueError(f"роутер {spec.name!r} задан дважды")
            extra = replace(
                settings, driver=spec.driver, router_url=spec.url, router_user=spec.user,
                router_password=spec.password, router_verify_tls=spec.verify_tls,
            )
            self.routers[spec.name] = ManagedRouter(spec.name, build_driver(extra))

    def add(self, name: str, driver: RouterDriver) -> None:
        self.routers[name] = ManagedRouter(name, driver)

    def __iter__(self):
        return iter(self.routers.values())

    def get(self, name: str) -> ManagedRouter | None:
        return self.routers.get(name)

    async def check(self, router: ManagedRouter, timeout: float = 10) -> dict:
        started = time.monotonic()
        try:
            info = await asyncio.wait_for(router.driver.check(), timeout)
        except asyncio.TimeoutError:
            info = {"ok": False, "error": f"нет ответа за {timeout:.0f} с"}
        except (DriverError, OSError) as exc:
            info = {"ok": False, "error": str(exc)}
        except Exception as exc:  # драйвер не должен ронять мониторинг
            log.exception("проверка роутера %s", router.name)
            info = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        info["latency_ms"] = round((time.monotonic() - started) * 1000)
        return info

    async def aclose(self) -> None:
        for router in self.routers.values():
            if not router.primary:
                await router.driver.aclose()


class RebootRefused(Exception):
    pass


class SystemControl:
    def __init__(self, settings: Settings, routers: RouterSet, manager, journal: SessionJournal):
        self.settings = settings
        self.routers = routers
        self.manager = manager
        self.journal = journal
        self._last: dict[str, float] = {}
        # Подменяется в тестах: как завершить процесс для перезапуска.
        self.exit = lambda: os.kill(os.getpid(), signal.SIGTERM)

    def targets(self) -> list[dict]:
        out = [
            {"id": r.name, "title": f"Роутер {r.name} ({r.kind})", "kind": "router",
             "available": r.driver.can_reboot, "primary": r.primary}
            for r in self.routers
        ]
        out.append({"id": SELF, "title": "NoNetPass (перезапуск службы)", "kind": "service",
                    "available": self.settings.allow_restart})
        out.append({"id": HOST, "title": "Сервер NoNetPass (перезагрузка)", "kind": "host",
                    "available": bool(self.settings.host_reboot_cmd)})
        return out

    def target(self, target_id: str) -> dict | None:
        return next((t for t in self.targets() if t["id"] == target_id), None)

    async def reboot(self, target_id: str, actor: str) -> str:
        target = self.target(target_id)
        if not target:
            raise RebootRefused(f"нет цели {target_id!r}")
        if not target["available"]:
            raise RebootRefused(f"{target['title']}: перезагрузка не настроена или не поддерживается")
        last = self._last.get(target_id)
        cooldown = self.settings.reboot_cooldown_seconds
        if last and time.time() - last < cooldown:
            wait = int(cooldown - (time.time() - last)) + 1
            raise RebootRefused(f"{target['title']}: повторная перезагрузка через {wait} с")
        self.journal.audit("reboot_requested", target=target_id, actor=actor)
        try:
            if target["kind"] == "router":
                router = self.routers.get(target_id)
                if router.primary:
                    # Окна на перезагружаемом роутере закроются сами; фиксируем это.
                    await self.manager.close_all(CloseReason.REVOKED)
                await router.driver.reboot()
                result = f"{target['title']}: команда перезагрузки отправлена"
            elif target["kind"] == "service":
                asyncio.get_running_loop().call_later(1.0, self.exit)
                result = "NoNetPass перезапускается: окна будут закрыты, служба поднимется сама"
            else:
                await self.manager.close_all(CloseReason.SHUTDOWN)
                await self._run_host_reboot()
                result = "Сервер NoNetPass уходит в перезагрузку"
        except DriverError as exc:
            self.journal.audit("reboot_failed", target=target_id, actor=actor, error=str(exc))
            raise RebootRefused(f"{target['title']}: {exc}") from exc
        self._last[target_id] = time.time()
        self.journal.audit("reboot_sent", target=target_id, actor=actor)
        return result

    async def _run_host_reboot(self) -> None:
        argv = shlex.split(self.settings.host_reboot_cmd or "")
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _, err = await asyncio.wait_for(proc.communicate(), timeout=20)
        except (OSError, asyncio.TimeoutError) as exc:
            raise DriverError(f"{argv[0]}: {exc}") from exc
        if proc.returncode:
            raise DriverError(f"{argv[0]}: код {proc.returncode} {err.decode(errors='replace').strip()}")
