"""Сессии шлюзов, таймеры окон и автоматический откат."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque

from .config import Settings
from .drivers import DriverError, Grant, RouterDriver
from .drivers.base import validate_ipv4
from .gates import Gate
from .journal import SessionJournal
from .models import CloseReason, Session, State

log = logging.getLogger(__name__)

REVOKE_RETRIES = (1, 2, 5, 10, 30)
ALL = "*"


class OpenRefused(Exception):
    """Окно нельзя открыть: лимит, пауза или ошибка роутера."""


class SessionManager:
    def __init__(self, settings: Settings, driver: RouterDriver, journal: SessionJournal):
        self.settings = settings
        self.driver = driver
        self.journal = journal
        self.sessions: dict[str, Session] = {}
        self.by_ip: dict[str, str] = {}  # IP -> id активной сессии
        self._timers: dict[str, asyncio.Task] = {}
        self._opens: dict[str, deque[float]] = defaultdict(deque)
        self._last_close: dict[str, float] = {}
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

    # --- чтение -------------------------------------------------------------

    def current(self, client_ip: str) -> Session | None:
        sid = self.by_ip.get(client_ip)
        return self.sessions.get(sid) if sid else None

    def recent(self, limit: int = 50) -> list[Session]:
        return sorted(self.sessions.values(), key=lambda s: s.created_at, reverse=True)[:limit]

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
        async with self._lock:
            existing = self.current(client_ip)
            if not existing or existing.state != State.OPEN:
                # Отказ по лимиту не должен оставлять за собой новую сессию.
                self._check_limits(client_ip)
        session = await self.detect(client_ip, source, gate)
        async with self._lock:
            if session.state == State.OPEN:
                return session
            if session.state == State.CLOSED:
                raise OpenRefused("сессия уже закрыта")
            self._check_limits(session.client_ip)
            grant = Grant(
                client_ip=session.client_ip,
                targets=gate.targets,
                ttl=gate.window,
                comment=f"nonetpass {session.id} {gate.id}",
                gate=gate.id,
            )
            try:
                session.handle = await self.driver.grant(grant)
            except DriverError as exc:
                session.error = str(exc)
                self._event("grant_failed", session, error=str(exc))
                raise OpenRefused(f"роутер не открыл доступ: {exc}") from exc
            now = time.time()
            self._opens[session.client_ip].append(now)
            session.state = State.OPEN
            session.error = None
            session.opened_at = now
            session.expires_at = now + gate.window
            self._schedule(session, gate.window, CloseReason.EXPIRED)
            self._event("opened", session, driver=self.driver.name, window=gate.window)
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
                self._last_close[session.client_ip] = session.closed_at
        if was_open:
            await self._revoke(session)
        self._event("closed", session, reason=reason.value)
        return session

    async def shutdown(self) -> None:
        for session in list(self.sessions.values()):
            if session.state == State.OPEN:
                await self.close(session.id, CloseReason.SHUTDOWN)
        for timer in self._timers.values():
            timer.cancel()
        self._timers.clear()

    # --- внутреннее ----------------------------------------------------------

    def _check_limits(self, client_ip: str) -> None:
        now = time.time()
        last = self._last_close.get(client_ip)
        if last and now - last < self.settings.cooldown_seconds:
            wait = int(self.settings.cooldown_seconds - (now - last)) + 1
            raise OpenRefused(f"повторное открытие через {wait} с")
        opens = self._opens[client_ip]
        while opens and now - opens[0] > 3600:
            opens.popleft()
        if len(opens) >= self.settings.max_opens_per_hour:
            raise OpenRefused("превышен лимит открытий за час")

    def _schedule(self, session: Session, delay: float, reason: CloseReason) -> None:
        old = self._timers.pop(session.id, None)
        if old:
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
                return
            except DriverError as exc:
                session.error = str(exc)
                log.warning("откат %s не удался (попытка %d): %s", session.id, attempt + 1, exc)
        self._event("revoke_failed", session, router_side_timeout=self.driver.router_side_timeout)
        if not self.driver.router_side_timeout:
            session.close_reason = CloseReason.ERROR

    def _gc(self, keep: int = 500) -> None:
        closed = [s for s in self.sessions.values() if s.state == State.CLOSED]
        if len(closed) > keep:
            for s in sorted(closed, key=lambda s: s.created_at)[: len(closed) - keep]:
                del self.sessions[s.id]
