"""Сессии шлюзов, таймеры окон и автоматический откат."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Callable

from .blocklist import Blocklist, arp_lookup
from .config import Settings
from .drivers import DriverError, Grant, RouterDriver
from .drivers.base import validate_ipv4
from .gates import Gate
from .journal import SessionJournal
from .models import CloseReason, Session, State
from .store import StateStore

log = logging.getLogger(__name__)

REVOKE_RETRIES = (1, 2, 5, 10, 30)
ALL = "*"
MAC_TTL = 60

# Слушатель событий: (событие, сессия, доп. поля). Метрики, мониторинг, бот.
Listener = Callable[[str, Session, dict], None]


class OpenRefused(Exception):
    """Окно нельзя открыть: лимит, пауза, чёрный список или ошибка роутера."""


class SessionManager:
    def __init__(
        self,
        settings: Settings,
        driver: RouterDriver,
        journal: SessionJournal,
        store: StateStore | None = None,
        blocklist: Blocklist | None = None,
    ):
        self.settings = settings
        self.driver = driver
        self.journal = journal
        self.store = store or StateStore(None)
        self.blocklist = blocklist or Blocklist(self.store)
        self.sessions: dict[str, Session] = {}
        self.by_ip: dict[str, str] = {}  # IP -> id активной сессии
        self.listeners: list[Listener] = []
        self._timers: dict[str, asyncio.Task] = {}
        # Лимиты считаются по устройству: MAC, если известен, иначе IP.
        self._opens: dict[str, deque[float]] = defaultdict(deque)
        self._last_close: dict[str, float] = {}
        self._macs: dict[str, tuple[str | None, float]] = {}
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._lock = asyncio.Lock()

    # --- подписки для WebSocket ---------------------------------------------

    def subscribe(self, client_ip: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers[client_ip].add(queue)
        return queue

    def unsubscribe(self, client_ip: str, queue: asyncio.Queue) -> None:
        self._subscribers[client_ip].discard(queue)
        if not self._subscribers[client_ip]:
            del self._subscribers[client_ip]

    def broadcast_admin(self, message: dict) -> None:
        for queue in list(self._subscribers.get(ALL, ())):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(message)

    def _publish(self, session: Session) -> None:
        message = {"type": "session", "session": session.to_dict()}
        for key in (session.client_ip, ALL):
            for queue in list(self._subscribers.get(key, ())):
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(message)

    def _event(self, event: str, session: Session, **extra) -> None:
        self.journal.write(event, session, **extra)
        self._publish(session)
        for listener in self.listeners:
            try:
                listener(event, session, extra)
            except Exception:
                log.exception("слушатель события %s упал", event)

    # --- чтение -------------------------------------------------------------

    def current(self, client_ip: str) -> Session | None:
        sid = self.by_ip.get(client_ip)
        return self.sessions.get(sid) if sid else None

    def recent(self, limit: int = 50) -> list[Session]:
        return sorted(self.sessions.values(), key=lambda s: s.created_at, reverse=True)[:limit]

    def active_windows(self) -> list[Session]:
        return sorted(
            (s for s in self.sessions.values() if s.state == State.OPEN),
            key=lambda s: s.expires_at or 0,
        )

    # --- переходы состояний --------------------------------------------------

    async def detect(self, client_ip: str, source: str, gate: Gate, host: str | None = None) -> Session:
        """Клиент начал сессию шлюза. Повторные сигналы не создают дублей.

        Если для IP уже есть не открытая сессия другого шлюза, она
        переключается на новый шлюз (пользователь выбрал другой сервис).
        """
        client_ip = validate_ipv4(client_ip)
        async with self._lock:
            existing = self.current(client_ip)
            if existing and existing.state == State.OPEN:
                return existing
            if existing and existing.gate_id != gate.id:
                existing.gate_id = gate.id
                existing.gate_name = gate.name
                existing.kind = gate.kind
                existing.host = host or existing.host
                self._publish(existing)
                return existing
            if existing:
                return existing
            session = Session(
                client_ip=client_ip, source=source, gate_id=gate.id,
                gate_name=gate.name, kind=gate.kind, host=host,
            )
            self.sessions[session.id] = session
            self.by_ip[client_ip] = session.id
            self._schedule(session, self.settings.detect_ttl_seconds, CloseReason.ABANDONED)
            self._event("detected", session)
            self._gc()
            return session

    async def open(self, client_ip: str, gate: Gate, source: str = "panel") -> Session:
        """Открыть окно шлюза для IP клиента (создаёт сессию, если её ещё нет)."""
        client_ip = validate_ipv4(client_ip)
        mac = await self.mac_for(client_ip)
        async with self._lock:
            existing = self.current(client_ip)
            if not existing or existing.state != State.OPEN:
                # Отказ по лимиту не должен оставлять за собой новую сессию.
                self._check_allowed(client_ip, mac)
        session = await self.detect(client_ip, source, gate)
        async with self._lock:
            if session.state == State.OPEN:
                return session
            if session.state == State.CLOSED:
                raise OpenRefused("сессия уже закрыта")
            self._check_allowed(session.client_ip, mac)
            session.mac = mac
            grant = self._grant(session, gate.targets, gate.window)
            try:
                session.handle = await self.driver.grant(grant)
            except DriverError as exc:
                session.error = str(exc)
                self._event("grant_failed", session, error=str(exc))
                raise OpenRefused(f"роутер не открыл доступ: {exc}") from exc
            now = time.time()
            self._opens[self._device(session.client_ip, mac)].append(now)
            session.state = State.OPEN
            session.error = None
            session.opened_at = now
            session.expires_at = now + gate.window
            session.window = gate.window
            self._schedule(session, gate.window, CloseReason.EXPIRED)
            self._remember(session, gate)
            self._event("opened", session, driver=self.driver.name, window=gate.window)
            return session

    async def extend(self, client_ip: str, gate: Gate) -> Session:
        """«Продлить»: добавить extend_seconds к открытому окну (max_extends раз)."""
        async with self._lock:
            session = self.current(client_ip)
            if not session or session.state != State.OPEN:
                raise OpenRefused("окно не открыто")
            if session.extends >= self.settings.max_extends:
                raise OpenRefused("окно уже продлено")
            now = time.time()
            expires = max(session.expires_at or now, now) + self.settings.extend_seconds
            grant = self._grant(session, gate.targets, expires - now)
            try:
                session.handle = await self.driver.extend(grant, session.handle or session.client_ip)
            except DriverError as exc:
                session.error = str(exc)
                self._event("extend_failed", session, error=str(exc))
                raise OpenRefused(f"роутер не продлил окно: {exc}") from exc
            session.extends += 1
            session.expires_at = expires
            session.window = (session.window or gate.window) + self.settings.extend_seconds
            self._schedule(session, expires - now, CloseReason.EXPIRED)
            self._remember(session, gate)
            self._event("extended", session, seconds=self.settings.extend_seconds)
            return session

    async def complete(self, client_ip: str) -> Session | None:
        """Пользователь ввёл код / подтвердил платёж: закрываем окно сразу."""
        session = self.current(client_ip)
        if session:
            await self.close(session.id, CloseReason.CODE_ENTERED)
        return session

    async def close(self, session_id: str, reason: CloseReason) -> Session | None:
        async with self._lock:
            session = self.sessions.get(session_id)
            if not session or session.state == State.CLOSED:
                return session
            timer = self._timers.pop(session_id, None)
            if timer and timer is not asyncio.current_task():
                timer.cancel()
            was_open = session.state == State.OPEN
            session.state = State.CLOSED
            session.close_reason = reason
            session.closed_at = time.time()
            if self.by_ip.get(session.client_ip) == session.id:
                del self.by_ip[session.client_ip]
            if was_open:
                self._last_close[self._device(session.client_ip, session.mac)] = session.closed_at
        if was_open:
            await self._revoke(session)
        self._event("closed", session, reason=reason.value)
        return session

    async def close_all(self, reason: CloseReason = CloseReason.REVOKED) -> int:
        windows = self.active_windows()
        for session in windows:
            await self.close(session.id, reason)
        return len(windows)

    async def shutdown(self) -> None:
        for session in list(self.sessions.values()):
            if session.state == State.OPEN:
                await self.close(session.id, CloseReason.SHUTDOWN)
        for timer in self._timers.values():
            timer.cancel()
        self._timers.clear()

    async def recover(self) -> int:
        """Закрыть окна, оставшиеся открытыми с прошлого запуска.

        Процесс мог упасть или роутер мог не ответить на откат. Записи из
        файла состояния удаляются с роутера и попадают в журнал как
        закрытые с причиной ``restart``.
        """
        stale = dict(self.store.windows)
        for session_id, record in stale.items():
            session = Session(
                client_ip=record["client_ip"], source="restart", gate_id=record["gate_id"],
                gate_name=record.get("gate_name", record["gate_id"]), kind=record.get("kind", "verify"),
                id=session_id, state=State.CLOSED, created_at=record.get("opened_at", time.time()),
                opened_at=record.get("opened_at"), expires_at=record.get("expires_at"),
                handle=record.get("handle"), mac=record.get("mac"),
                closed_at=time.time(), close_reason=CloseReason.RESTART,
            )
            try:
                await self.driver.revoke(session.client_ip, session.handle or session.client_ip)
            except DriverError as exc:
                session.error = str(exc)
                log.warning("окно %s с прошлого запуска не закрыто: %s", session_id, exc)
                self._event("revoke_failed", session, router_side_timeout=self.driver.router_side_timeout)
                if not self.driver.router_side_timeout:
                    continue  # попробуем снова при следующем старте
            self.store.forget_window(session_id)
            self._event("closed", session, reason=CloseReason.RESTART.value)
        return len(stale)

    # --- MAC ----------------------------------------------------------------

    async def mac_for(self, client_ip: str) -> str | None:
        cached = self._macs.get(client_ip)
        if cached and time.time() - cached[1] < MAC_TTL:
            return cached[0]
        mac = None
        try:
            mac = await asyncio.wait_for(self.driver.lookup_mac(client_ip), timeout=5)
        except (DriverError, asyncio.TimeoutError, OSError) as exc:
            log.debug("MAC для %s у роутера не получен: %s", client_ip, exc)
        mac = mac or arp_lookup(client_ip)
        self._macs[client_ip] = (mac, time.time())
        return mac

    # --- внутреннее ----------------------------------------------------------

    @staticmethod
    def _device(client_ip: str, mac: str | None) -> str:
        return mac or client_ip

    def _grant(self, session: Session, targets: tuple[str, ...], ttl: float) -> Grant:
        return Grant(
            client_ip=session.client_ip,
            targets=targets,
            ttl=ttl,
            comment=f"nonetpass {session.id} {session.gate_id}",
            gate=session.gate_id,
        )

    def _remember(self, session: Session, gate: Gate) -> None:
        self.store.remember_window(session.id, {
            "client_ip": session.client_ip, "gate_id": gate.id, "gate_name": gate.name,
            "kind": gate.kind, "handle": session.handle, "mac": session.mac,
            "opened_at": session.opened_at, "expires_at": session.expires_at,
        })

    def _check_allowed(self, client_ip: str, mac: str | None) -> None:
        if blocked := self.blocklist.match(client_ip, mac):
            raise OpenRefused(f"устройство {blocked} заблокировано администратором")
        device = self._device(client_ip, mac)
        now = time.time()
        last = self._last_close.get(device)
        if last and now - last < self.settings.cooldown_seconds:
            wait = int(self.settings.cooldown_seconds - (now - last)) + 1
            raise OpenRefused(f"повторное открытие через {wait} с")
        opens = self._opens[device]
        while opens and now - opens[0] > 3600:
            opens.popleft()
        if len(opens) >= self.settings.max_opens_per_hour:
            raise OpenRefused("превышен лимит открытий за час")

    def _schedule(self, session: Session, delay: float, reason: CloseReason) -> None:
        old = self._timers.pop(session.id, None)
        if old and old is not asyncio.current_task():
            old.cancel()

        async def fire() -> None:
            await asyncio.sleep(delay)
            await self.close(session.id, reason)

        self._timers[session.id] = asyncio.create_task(fire())

    async def _revoke(self, session: Session) -> None:
        """Откат с повторами. Если роутер держит таймаут сам, это страховка."""
        for attempt, pause in enumerate((0, *REVOKE_RETRIES)):
            if pause:
                await asyncio.sleep(pause)
            try:
                await self.driver.revoke(session.client_ip, session.handle or session.client_ip)
                session.error = None
                self.store.forget_window(session.id)
                return
            except DriverError as exc:
                session.error = str(exc)
                log.warning("откат %s не удался (попытка %d): %s", session.id, attempt + 1, exc)
        self._event("revoke_failed", session, router_side_timeout=self.driver.router_side_timeout)
        if self.driver.router_side_timeout:
            self.store.forget_window(session.id)
        else:
            session.close_reason = CloseReason.ERROR

    def _gc(self, keep: int = 500) -> None:
        closed = [s for s in self.sessions.values() if s.state == State.CLOSED]
        if len(closed) > keep:
            for s in sorted(closed, key=lambda s: s.created_at)[: len(closed) - keep]:
                del self.sessions[s.id]
