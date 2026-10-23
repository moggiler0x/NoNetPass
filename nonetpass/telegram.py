"""Telegram-бот администратора.

Бот пишет только администраторам из ``NONETPASS_TELEGRAM_ADMIN_IDS`` и
слушает только их: сообщение из чужого чата не выполняется, в личке бот
отвечает «нет доступа» и показывает chat_id, чтобы его было легко добавить.
В групповом чате из списка команды принимаются только от пользователей,
чей id тоже есть в списке.

Токен и chat_id задаются только переменными окружения. Машине с NoNetPass
нужен доступ к ``api.telegram.org`` (или прокси ``NONETPASS_TELEGRAM_PROXY``).

Команды: /status, /check, /alerts, /windows, /report [период], /hosts,
/block, /unblock, /blocklist, /reboot [цель], /help. Перезагрузка и
закрытие всех окон выполняются только после кнопки подтверждения, которая
действует 60 секунд и только для того, кто её вызвал.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass

import httpx

from . import __version__
from .control import RebootRefused
from .health import FAIL, OK, UNKNOWN
from .hostcheck import check_catalog, hosts_text
from .models import CloseReason
from .reports import build_report, parse_period, report_text

log = logging.getLogger(__name__)

CONFIRM_TTL = 60
COMMANDS = [
    ("status", "состояние системы"),
    ("check", "проверить всё сейчас"),
    ("alerts", "последние уведомления"),
    ("windows", "открытые окна"),
    ("report", "отчёт: /report, /report prev, /report 2026-10-01 2026-10-15"),
    ("hosts", "проверка узлов шлюзов"),
    ("reboot", "перезагрузить роутер или NoNetPass"),
    ("blocklist", "чёрный список"),
    ("block", "заблокировать: /block <MAC или IP> [заметка]"),
    ("unblock", "снять блокировку: /unblock <MAC или IP>"),
    ("help", "справка"),
]


@dataclass
class Pending:
    action: str
    target: str
    user_id: int
    chat_id: int
    expires: float


class TelegramBot:
    def __init__(self, ctx, transport: httpx.AsyncBaseTransport | None = None):
        self.ctx = ctx
        settings = ctx.settings
        self.admin_ids = set(settings.telegram_admin_ids)
        self.client = httpx.AsyncClient(
            base_url=f"{settings.telegram_api.rstrip('/')}/bot{settings.telegram_token}",
            timeout=httpx.Timeout(10, read=65),
            proxy=settings.telegram_proxy or None,
            transport=transport,
        )
        self.offset: int | None = None
        self.username: str | None = None
        self.last_ok: float | None = None
        self.last_error: str | None = None
        self.pending: dict[str, Pending] = {}
        self._task: asyncio.Task | None = None

    # --- Bot API --------------------------------------------------------------

    async def api(self, method: str, **params) -> dict | list | bool:
        try:
            resp = await self.client.post(f"/{method}", json=params)
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            raise
        if not data.get("ok"):
            self.last_error = f"{method}: {data.get('description')}"
            raise RuntimeError(self.last_error)
        self.last_ok = time.time()
        self.last_error = None
        return data["result"]

    async def send(self, chat_id: int, text: str, buttons: list[list[tuple[str, str]]] | None = None) -> None:
        params = {"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML", "disable_web_page_preview": True}
        if buttons:
            params["reply_markup"] = _keyboard(buttons)
        await self.api("sendMessage", **params)

    async def edit(self, chat_id: int, message_id: int, text: str, buttons=None) -> None:
        params = {"chat_id": chat_id, "message_id": message_id, "text": text[:4000], "parse_mode": "HTML"}
        params["reply_markup"] = _keyboard(buttons or [])
        try:
            await self.api("editMessageText", **params)
        except (RuntimeError, httpx.HTTPError):
            await self.send(chat_id, text, buttons)

    async def broadcast(self, text: str) -> None:
        for chat_id in self.admin_ids:
            try:
                await self.send(chat_id, text)
            except (RuntimeError, httpx.HTTPError) as exc:
                log.warning("уведомление в %s не отправлено: %s", chat_id, exc)

    async def notify(self, level: str, text: str) -> None:
        await self.broadcast(text)

    def probe(self) -> tuple[str, str]:
        """Статус бота для мониторинга."""
        if self.last_ok and time.time() - self.last_ok < 180:
            return OK, f"@{self.username}" if self.username else "на связи"
        if self.last_error:
            return FAIL, f"нет связи с api.telegram.org: {self.last_error}"
        return UNKNOWN, "ещё не подключился"

    # --- цикл -----------------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        await self.client.aclose()

    async def run(self) -> None:
        backoff = 1
        while True:
            try:
                if not self.username:
                    me = await self.api("getMe")
                    self.username = me.get("username")
                    await self.api("setMyCommands", commands=[{"command": c, "description": d} for c, d in COMMANDS])
                    log.info("Telegram-бот @%s запущен, администраторов: %d", self.username, len(self.admin_ids))
                    await self.broadcast(f"🟢 NoNetPass {__version__} запущен. /status")
                await self.poll_once(timeout=50)
                backoff = 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Telegram: %s, повтор через %d с", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def poll_once(self, timeout: int = 0) -> None:
        params = {"timeout": timeout, "allowed_updates": ["message", "callback_query"]}
        if self.offset is not None:
            params["offset"] = self.offset
        updates = await self.api("getUpdates", **params)
        for update in updates:
            self.offset = update["update_id"] + 1
            try:
                await self.handle(update)
            except Exception:
                log.exception("ошибка обработки обновления Telegram")

    # --- доступ ---------------------------------------------------------------

    def allowed(self, chat: dict, user: dict) -> bool:
        chat_id, user_id = chat.get("id"), user.get("id")
        if chat_id not in self.admin_ids:
            return False
        return chat.get("type") == "private" or user_id in self.admin_ids

    async def handle(self, update: dict) -> None:
        if query := update.get("callback_query"):
            message = query.get("message") or {}
            chat, user = message.get("chat") or {}, query.get("from") or {}
            if not self.allowed(chat, user):
                self._denied(chat, user, "кнопка")
                await self.api("answerCallbackQuery", callback_query_id=query["id"], text="Нет доступа")
                return
            await self.on_button(query, chat["id"], user["id"], message.get("message_id"))
            return
        message = update.get("message")
        if not message or "text" not in message:
            return
        chat, user = message.get("chat") or {}, message.get("from") or {}
        if not self.allowed(chat, user):
            self._denied(chat, user, message["text"][:40])
            if chat.get("type") == "private":
                await self.send(chat["id"], f"⛔ Нет доступа.\nВаш chat_id: <code>{chat['id']}</code>\n"
                                            "Чтобы управлять NoNetPass, добавьте его в NONETPASS_TELEGRAM_ADMIN_IDS.")
            return
        await self.on_command(message["text"], chat["id"], user.get("id"))

    def _denied(self, chat: dict, user: dict, what: str) -> None:
        log.warning("Telegram: отказ chat=%s user=%s (%s)", chat.get("id"), user.get("id"), what)
        self.ctx.journal.audit("telegram_denied", chat_id=chat.get("id"), user_id=user.get("id"),
                               username=user.get("username"))

    # --- команды --------------------------------------------------------------

    async def on_command(self, text: str, chat_id: int, user_id: int) -> None:
        if not text.startswith("/"):
            await self.send(chat_id, "Команды: /help")
            return
        head, _, arg = text.strip().partition(" ")
        command = head[1:].split("@", 1)[0].lower()
        arg = arg.strip()
        handler = getattr(self, f"cmd_{command}", None)
        if not handler:
            await self.send(chat_id, "Не знаю такую команду. /help")
            return
        await handler(chat_id, user_id, arg)

    async def cmd_start(self, chat_id, user_id, arg):
        await self.cmd_help(chat_id, user_id, arg)

    async def cmd_help(self, chat_id, user_id, arg):
        lines = ["🛡️ <b>NoNetPass</b>, бот администратора", f"Ваш chat_id: <code>{chat_id}</code>", ""]
        lines += [f"/{c} — {d}" for c, d in COMMANDS]
        await self.send(chat_id, "\n".join(lines))

    async def cmd_status(self, chat_id, user_id, arg):
        await self.send(chat_id, self.ctx.health.summary_text())

    async def cmd_check(self, chat_id, user_id, arg):
        await self.ctx.health.run_checks()
        await self.send(chat_id, self.ctx.health.summary_text())

    async def cmd_alerts(self, chat_id, user_id, arg):
        alerts = list(self.ctx.health.alerts)[-10:]
        if not alerts:
            await self.send(chat_id, "Уведомлений пока нет.")
            return
        lines = ["<b>Последние уведомления</b>"]
        for a in alerts:
            lines.append(f"{_clock(a['ts'], self.ctx.tz)} {_esc(a['text'])}")
        await self.send(chat_id, "\n".join(lines))

    async def cmd_windows(self, chat_id, user_id, arg):
        windows = self.ctx.manager.active_windows()
        if not windows:
            await self.send(chat_id, "Открытых окон нет.")
            return
        lines, buttons = [f"<b>Открытые окна: {len(windows)}</b>"], []
        now = time.time()
        for s in windows[:20]:
            left = max(0, int((s.expires_at or now) - now))
            lines.append(f"• {_esc(s.gate_name)} · {s.client_ip}{' · ' + s.mac if s.mac else ''} · осталось {left // 60}:{left % 60:02d}")
            buttons.append([(f"Закрыть {s.gate_name} {s.client_ip}", f"cl:{s.id}")])
        buttons.append([("Закрыть все окна", "ca")])
        await self.send(chat_id, "\n".join(lines), buttons)

    async def cmd_report(self, chat_id, user_id, arg):
        try:
            period = parse_period(arg, self.ctx.tz)
        except ValueError as exc:
            await self.send(chat_id, f"⚠️ {_esc(exc)}\nПримеры: /report, /report prev, /report 2026-09, "
                                     "/report 7d, /report 2026-10-01 2026-10-15")
            return
        await self.send(chat_id, report_text(build_report(self.ctx.journal, period)))

    async def cmd_hosts(self, chat_id, user_id, arg):
        await self.send(chat_id, "Проверяю узлы…")
        await self.send(chat_id, hosts_text(await check_catalog(self.ctx.catalog)))

    async def cmd_blocklist(self, chat_id, user_id, arg):
        entries = self.ctx.blocklist.entries()
        if not entries:
            await self.send(chat_id, "Чёрный список пуст.")
            return
        lines = ["<b>Чёрный список</b>"]
        for e in entries:
            note = f" — {_esc(e['note'])}" if e.get("note") else ""
            lines.append(f"• <code>{e['value']}</code>{note}")
        await self.send(chat_id, "\n".join(lines))

    async def cmd_block(self, chat_id, user_id, arg):
        value, _, note = arg.partition(" ")
        try:
            kind, key = self.ctx.blocklist.add(value, note.strip(), by=f"telegram:{user_id}")
        except ValueError as exc:
            await self.send(chat_id, f"⚠️ {_esc(exc)}. Пример: /block aa:bb:cc:dd:ee:ff спамит")
            return
        self.ctx.journal.audit("block", value=key, actor=f"telegram:{user_id}")
        closed = 0
        for s in self.ctx.manager.active_windows():
            if self.ctx.blocklist.match(s.client_ip, s.mac):
                await self.ctx.manager.close(s.id, CloseReason.REVOKED)
                closed += 1
        extra = f", закрыто окон: {closed}" if closed else ""
        await self.send(chat_id, f"🚫 <code>{key}</code> заблокирован{extra}")

    async def cmd_unblock(self, chat_id, user_id, arg):
        try:
            found = self.ctx.blocklist.remove(arg)
        except ValueError as exc:
            await self.send(chat_id, f"⚠️ {_esc(exc)}")
            return
        self.ctx.journal.audit("unblock", value=arg, actor=f"telegram:{user_id}")
        await self.send(chat_id, f"✅ <code>{_esc(arg)}</code> разблокирован" if found else "Такой записи нет.")

    async def cmd_reboot(self, chat_id, user_id, arg):
        targets = [t for t in self.ctx.control.targets() if t["available"]]
        if arg:
            await self.ask_reboot(chat_id, user_id, arg)
            return
        if not targets:
            await self.send(chat_id, "Перезагружать нечего: ни один роутер не поддерживает перезагрузку.")
            return
        buttons = [[(t["title"], f"rb:{t['id']}")] for t in targets]
        await self.send(chat_id, "Что перезагрузить?", buttons)

    async def ask_reboot(self, chat_id: int, user_id: int, target_id: str, message_id: int | None = None) -> None:
        target = self.ctx.control.target(target_id)
        if not target or not target["available"]:
            await self.send(chat_id, f"⚠️ Нельзя перезагрузить {_esc(target_id)}. Список: /reboot")
            return
        nonce = self._pending("reboot", target_id, user_id, chat_id)
        windows = len(self.ctx.manager.active_windows())
        warn = f"\nОткрытые окна ({windows}) будут закрыты." if windows and target.get("primary", target["kind"] != "router") else ""
        text = f"⚠️ Перезагрузить <b>{_esc(target['title'])}</b>?{warn}\nПодтвердите в течение {CONFIRM_TTL} с."
        buttons = [[("✅ Да, перезагрузить", f"ok:{nonce}"), ("Отмена", f"no:{nonce}")]]
        if message_id:
            await self.edit(chat_id, message_id, text, buttons)
        else:
            await self.send(chat_id, text, buttons)

    def _pending(self, action: str, target: str, user_id: int, chat_id: int) -> str:
        now = time.time()
        for key in [k for k, p in self.pending.items() if p.expires < now]:
            del self.pending[key]
        nonce = secrets.token_hex(6)
        self.pending[nonce] = Pending(action, target, user_id, chat_id, now + CONFIRM_TTL)
        return nonce

    # --- кнопки ---------------------------------------------------------------

    async def on_button(self, query: dict, chat_id: int, user_id: int, message_id: int | None) -> None:
        data = query.get("data") or ""
        kind, _, value = data.partition(":")
        answer = ""
        if kind == "rb":
            await self.ask_reboot(chat_id, user_id, value, message_id)
        elif kind == "ca":
            nonce = self._pending("close_all", "", user_id, chat_id)
            await self.edit(chat_id, message_id, "⚠️ Закрыть все открытые окна?",
                            [[("✅ Да, закрыть все", f"ok:{nonce}"), ("Отмена", f"no:{nonce}")]])
        elif kind == "cl":
            session = await self.ctx.manager.close(value, CloseReason.REVOKED)
            self.ctx.journal.audit("revoke", session=value, actor=f"telegram:{user_id}")
            answer = "Окно закрыто" if session else "Окно уже закрыто"
            await self.cmd_windows(chat_id, user_id, "")
        elif kind in ("ok", "no"):
            pending = self.pending.pop(value, None)
            if not pending or pending.expires < time.time():
                await self.edit(chat_id, message_id, "⌛ Подтверждение устарело, повторите команду.")
            elif pending.user_id != user_id or pending.chat_id != chat_id:
                self.pending[value] = pending
                answer = "Подтвердить может только тот, кто вызвал команду"
            elif kind == "no":
                await self.edit(chat_id, message_id, "Отменено.")
            else:
                await self.confirm(pending, chat_id, user_id, message_id)
        await self.api("answerCallbackQuery", callback_query_id=query["id"], text=answer)

    async def confirm(self, pending: Pending, chat_id: int, user_id: int, message_id: int | None) -> None:
        actor = f"telegram:{user_id}"
        if pending.action == "close_all":
            n = await self.ctx.manager.close_all(CloseReason.REVOKED)
            self.ctx.journal.audit("revoke_all", actor=actor, count=n)
            await self.edit(chat_id, message_id, f"Закрыто окон: {n}")
            return
        await self.edit(chat_id, message_id, "⏳ Отправляю команду…")
        try:
            result = await self.ctx.control.reboot(pending.target, actor)
        except RebootRefused as exc:
            await self.edit(chat_id, message_id, f"🔴 {_esc(exc)}")
            return
        await self.edit(chat_id, message_id, f"🔄 {_esc(result)}")
        others = self.admin_ids - {chat_id}
        for other in others:
            try:
                await self.send(other, f"🔄 {_esc(result)} (по команде {user_id})")
            except (RuntimeError, httpx.HTTPError):
                pass


def _keyboard(buttons: list[list[tuple[str, str]]]) -> dict:
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in buttons]}


def _esc(text) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clock(ts: float, tz) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(ts, tz).strftime("%d.%m %H:%M")
