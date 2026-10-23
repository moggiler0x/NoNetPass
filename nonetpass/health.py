"""Мониторинг здоровья системы и уведомления о сбоях.

Каждые ``NONETPASS_HEALTH_INTERVAL_SECONDS`` проверяются:

* связь с каждым роутером (основным и дополнительными);
* операции драйвера: роутер не открыл или не закрыл окно (это видно сразу
  по событиям сессий, без ожидания следующей проверки);
* окна, которые не закрылись вовремя;
* журнал и файл состояния: можно ли писать на диск;
* детекция по DNS: есть ли лог dnsmasq, слушается ли порт syslog;
* связь с Telegram.

Смена статуса проверки (ok → сбой и обратно) становится уведомлением: оно
появляется в админ-панели и уходит администратору в Telegram. Роутер
считается недоступным после ``NONETPASS_HEALTH_FAIL_AFTER`` неудач подряд,
чтобы одна потерянная проверка не будила администратора.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from .config import Settings
from .control import RouterSet
from .models import Session

log = logging.getLogger(__name__)

OK, WARN, FAIL, UNKNOWN = "ok", "warn", "fail", "unknown"
LEVEL = {OK: 0, UNKNOWN: 0, WARN: 1, FAIL: 2}
ICON = {OK: "✅", WARN: "⚠️", FAIL: "🔴", UNKNOWN: "❔"}
# Окно, открытое дольше своего срока на столько секунд, считается зависшим.
OVERDUE_GRACE = 30
DRIVER_ERROR_WINDOW = 600

Notify = Callable[[str, str], Awaitable[None]]


@dataclass
class Check:
    id: str
    title: str
    status: str = UNKNOWN
    detail: str = ""
    since: float = field(default_factory=time.time)
    checked_at: float | None = None
    fails: int = 0
    info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("fails")
        return data


class HealthMonitor:
    def __init__(self, settings: Settings, routers: RouterSet, manager, store, journal):
        self.settings = settings
        self.routers = routers
        self.manager = manager
        self.store = store
        self.journal = journal
        self.checks: dict[str, Check] = {}
        self.alerts: deque[dict] = deque(maxlen=200)
        self.notifiers: list[Notify] = []
        self.started_at = time.time()
        # Внешние проверки (бот, syslog): id -> функция без аргументов.
        self.probes: dict[str, tuple[str, Callable[[], tuple[str, str]]]] = {}
        self._driver_errors: deque[tuple[float, str, str]] = deque(maxlen=100)
        self._task: asyncio.Task | None = None
        manager.listeners.append(self.on_event)

    # --- состояние -------------------------------------------------------------

    @property
    def status(self) -> str:
        worst = max((LEVEL[c.status] for c in self.checks.values()), default=0)
        return {0: OK, 1: WARN, 2: FAIL}[worst]

    def snapshot(self) -> dict:
        return {
            "status": self.status,
            "uptime": round(time.time() - self.started_at),
            "checks": [c.to_dict() for c in self.checks.values()],
            "alerts": list(self.alerts)[-50:][::-1],
        }

    def summary_text(self) -> str:
        lines = [f"{ICON[self.status]} <b>NoNetPass: {_status_word(self.status)}</b>"]
        for c in self.checks.values():
            detail = f": {_html(c.detail)}" if c.detail else ""
            lines.append(f"{ICON[c.status]} {_html(c.title)}{detail}")
        active = self.manager.active_windows()
        lines.append(f"\nОткрытых окон: {len(active)}")
        lines.append(f"Работает: {_uptime(time.time() - self.started_at)}")
        return "\n".join(lines)

    # --- цикл ------------------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_checks()
            except Exception:
                log.exception("ошибка мониторинга")
            await asyncio.sleep(self.settings.health_interval_seconds)

    async def run_checks(self) -> dict:
        results = await asyncio.gather(*(self.routers.check(r) for r in self.routers))
        for router, info in zip(self.routers, results):
            title = f"Роутер {router.name} ({router.kind})"
            if info.get("ok"):
                version = info.get("version") or info.get("release") or info.get("model") or ""
                await self._set(f"router:{router.name}", title, OK,
                                f"{version} · {info['latency_ms']} мс".strip(" ·"), info)
            else:
                await self._set(f"router:{router.name}", title, FAIL,
                                info.get("error") or "нет связи", info, debounce=True)
        await self._check_driver()
        await self._check_overdue()
        await self._check_storage()
        await self._check_detection()
        for check_id, (title, probe) in self.probes.items():
            try:
                status, detail = probe()
            except Exception as exc:
                status, detail = FAIL, str(exc)
            await self._set(check_id, title, status, detail)
        return self.snapshot()

    async def _check_driver(self) -> None:
        now = time.time()
        recent = [e for e in self._driver_errors if now - e[0] < DRIVER_ERROR_WINDOW]
        revoke = [e for e in recent if e[1] == "revoke_failed"]
        grant = [e for e in recent if e[1] != "revoke_failed"]
        title = "Окна на роутере"
        if revoke:
            await self._set("driver", title, FAIL, f"не закрыто окон: {len(revoke)} ({revoke[-1][2]})")
        elif grant:
            await self._set("driver", title, WARN, f"роутер не открыл окно {len(grant)} раз за 10 мин ({grant[-1][2]})")
        else:
            await self._set("driver", title, OK, "открытие и закрытие без ошибок")

    async def _check_overdue(self) -> None:
        now = time.time()
        overdue = [s for s in self.manager.active_windows() if s.expires_at and now - s.expires_at > OVERDUE_GRACE]
        if overdue:
            ips = ", ".join(s.client_ip for s in overdue[:5])
            await self._set("overdue", "Таймеры окон", FAIL, f"окна не закрылись вовремя: {ips}")
        else:
            await self._set("overdue", "Таймеры окон", OK, "окна закрываются вовремя")

    async def _check_storage(self) -> None:
        problems = []
        if self.journal.last_error:
            problems.append(f"журнал: {self.journal.last_error}")
        elif self.journal.path and not os.access(self.journal.path.parent if str(self.journal.path.parent) else ".", os.W_OK):
            problems.append(f"нет записи в каталог журнала {self.journal.path.parent}")
        if not self.store.writable():
            problems.append(f"нет записи в каталог состояния {self.store.path.parent}")
        await self._set("storage", "Журнал и состояние", FAIL if problems else OK, "; ".join(problems) or "запись на диск работает")

    async def _check_detection(self) -> None:
        path = self.settings.dns_log_path
        if path:
            if Path(path).exists():
                await self._set("dns", "Детекция по DNS", OK, f"лог {path}")
            else:
                await self._set("dns", "Детекция по DNS", WARN, f"нет файла {path}", debounce=True)

    # --- события сессий --------------------------------------------------------

    def on_event(self, event: str, session: Session, extra: dict) -> None:
        if event not in ("grant_failed", "revoke_failed", "extend_failed"):
            return
        error = extra.get("error") or session.error or ""
        self._driver_errors.append((time.time(), event, error))
        if event == "revoke_failed":
            note = " Роутер удалит запись сам по таймауту." if extra.get("router_side_timeout") else " Закройте вручную!"
            text = f"Роутер не закрыл окно {session.gate_name} для {session.client_ip}: {error}.{note}"
            level = WARN if extra.get("router_side_timeout") else FAIL
        else:
            text = f"Роутер не открыл окно {session.gate_name} для {session.client_ip}: {error}"
            level = WARN
        asyncio.get_running_loop().create_task(self._alert(level, "driver", text))

    # --- переходы и уведомления ------------------------------------------------

    async def _set(self, check_id: str, title: str, status: str, detail: str,
                   info: dict | None = None, debounce: bool = False) -> None:
        check = self.checks.get(check_id)
        if not check:
            check = self.checks[check_id] = Check(check_id, title)
        check.checked_at = time.time()
        check.info = info or {}
        if status == OK:
            check.fails = 0
        else:
            check.fails += 1
            if debounce and check.fails < self.settings.health_fail_after:
                # Первая неудача: показываем как предупреждение, не будим админа.
                if check.status in (OK, UNKNOWN):
                    check.detail = f"{detail} (проверяю ещё раз)"
                return
        previous = check.status
        check.title, check.detail = title, detail
        if previous == status:
            return
        check.status, check.since = status, time.time()
        if previous == UNKNOWN and status == OK:
            return  # первая успешная проверка после старта
        if status == OK:
            await self._alert(OK, check_id, f"{title}: снова в норме ({detail})")
        else:
            await self._alert(status, check_id, f"{title}: {detail}")

    async def _alert(self, level: str, check_id: str, text: str) -> None:
        alert = {"ts": time.time(), "level": level, "check": check_id, "text": text}
        self.alerts.append(alert)
        self.manager.broadcast_admin({"type": "alert", "alert": alert, "status": self.status})
        log.warning("health %s: %s", level, text)
        for notify in self.notifiers:
            try:
                await notify(level, f"{ICON[level]} {text}")
            except Exception:
                log.exception("уведомление не отправлено")


def _status_word(status: str) -> str:
    return {OK: "всё работает", WARN: "есть предупреждения", FAIL: "есть сбои", UNKNOWN: "проверяется"}[status]


def _uptime(seconds: float) -> str:
    seconds = int(seconds)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} д {hours} ч"
    if hours:
        return f"{hours} ч {minutes} мин"
    return f"{minutes} мин"


def _html(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
