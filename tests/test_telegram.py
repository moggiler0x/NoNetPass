import json

import httpx
import pytest

from nonetpass.app import build_context
from nonetpass.config import Settings
from nonetpass.drivers import MockDriver
from nonetpass.gates import load_catalog
from nonetpass.telegram import TelegramBot

ADMIN = 1001
STRANGER = 2002


class FakeTelegram:
    """Bot API в памяти: копит отправленные сообщения и отдаёт обновления."""

    def __init__(self):
        self.sent: list[dict] = []
        self.calls: list[str] = []
        self.updates: list[dict] = []
        self.next_id = 1

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        body = json.loads(request.content or b"{}")
        self.calls.append(method)
        if method == "getUpdates":
            out, self.updates = self.updates, []
            return httpx.Response(200, json={"ok": True, "result": out})
        if method in ("sendMessage", "editMessageText"):
            self.sent.append({"method": method, **body})
        if method == "getMe":
            return httpx.Response(200, json={"ok": True, "result": {"username": "nonetpass_bot"}})
        return httpx.Response(200, json={"ok": True, "result": True})

    def message(self, text: str, chat: int = ADMIN, user: int | None = None, chat_type: str = "private"):
        self.updates.append({"update_id": self.next_id, "message": {
            "message_id": self.next_id, "text": text,
            "chat": {"id": chat, "type": chat_type}, "from": {"id": user or chat}}})
        self.next_id += 1

    def press(self, data: str, chat: int = ADMIN, user: int | None = None):
        self.updates.append({"update_id": self.next_id, "callback_query": {
            "id": str(self.next_id), "data": data, "from": {"id": user or chat},
            "message": {"message_id": 77, "chat": {"id": chat, "type": "private"}}}})
        self.next_id += 1

    @property
    def last(self) -> dict:
        return self.sent[-1]

    def buttons(self) -> list[str]:
        markup = self.last.get("reply_markup") or {"inline_keyboard": []}
        return [b["callback_data"] for row in markup["inline_keyboard"] for b in row]


@pytest.fixture
def bot(tmp_path):
    settings = Settings(
        cooldown_seconds=0, telegram_token="T", telegram_admin_ids=[ADMIN],
        log_path=str(tmp_path / "log.jsonl"), state_path=str(tmp_path / "state.json"),
    )
    driver = MockDriver()
    ctx = build_context(settings, driver)
    fake = FakeTelegram()
    bot = TelegramBot(ctx, transport=httpx.MockTransport(fake.handler))
    ctx.bot = bot
    ctx.health.notifiers = [bot.notify]
    ctx.health.probes["telegram"] = ("Telegram-бот", bot.probe)
    return bot, fake, ctx, driver


async def test_stranger_is_refused_and_shown_chat_id(bot):
    bot, fake, ctx, driver = bot
    fake.message("/reboot main", chat=STRANGER)
    await bot.poll_once()
    assert "Нет доступа" in fake.last["text"] and str(STRANGER) in fake.last["text"]
    assert driver.reboots == 0
    # В группе из списка команда чужого участника не выполняется и молча игнорируется.
    ctx_group = -500
    bot.admin_ids.add(ctx_group)
    sent = len(fake.sent)
    fake.message("/status", chat=ctx_group, user=STRANGER, chat_type="group")
    await bot.poll_once()
    assert len(fake.sent) == sent
    assert [r["event"] for r in ctx.journal.tail(10, audit_only=True)] == ["telegram_denied", "telegram_denied"]


async def test_reboot_needs_confirmation(bot):
    bot, fake, ctx, driver = bot
    fake.message("/reboot")
    await bot.poll_once()
    assert "rb:main" in fake.buttons() and "rb:nonetpass" in fake.buttons()
    fake.press("rb:main")
    await bot.poll_once()
    ok, no = fake.buttons()
    assert ok.startswith("ok:") and no.startswith("no:")
    assert driver.reboots == 0
    # Чужой не может нажать «Да» за администратора.
    fake.press(ok, chat=STRANGER)
    await bot.poll_once()
    assert driver.reboots == 0
    fake.press(ok)
    await bot.poll_once()
    assert driver.reboots == 1
    assert "команда перезагрузки отправлена" in fake.last["text"]
    # Повторное нажатие той же кнопки не перезагружает второй раз.
    fake.press(ok)
    await bot.poll_once()
    assert driver.reboots == 1 and "устарело" in fake.last["text"]
    audit = [r["event"] for r in ctx.journal.tail(10, audit_only=True)]
    assert audit == ["telegram_denied", "reboot_requested", "reboot_sent"]


async def test_reboot_cancel_and_cooldown(bot):
    bot, fake, ctx, driver = bot
    fake.message("/reboot main")
    await bot.poll_once()
    _, no = fake.buttons()
    fake.press(no)
    await bot.poll_once()
    assert fake.last["text"] == "Отменено." and driver.reboots == 0
    for _ in range(2):
        fake.message("/reboot main")
        await bot.poll_once()
        fake.press(fake.buttons()[0])
        await bot.poll_once()
    assert driver.reboots == 1 and "повторная перезагрузка" in fake.last["text"]


async def test_restart_service(bot):
    bot, fake, ctx, driver = bot
    exits = []
    ctx.control.exit = lambda: exits.append(1)
    fake.message("/reboot nonetpass")
    await bot.poll_once()
    fake.press(fake.buttons()[0])
    await bot.poll_once()
    assert "перезапускается" in fake.last["text"]


async def test_status_report_windows(bot):
    bot, fake, ctx, driver = bot
    gate = ctx.catalog.get("vk")
    await ctx.manager.open("10.0.0.5", gate)
    await ctx.health.run_checks()
    fake.message("/status")
    await bot.poll_once()
    assert "всё работает" in fake.last["text"] and "Открытых окон: 1" in fake.last["text"]
    fake.message("/report")
    await bot.poll_once()
    assert "Авторизаций: <b>1</b>" in fake.last["text"] and "VK ID: 1" in fake.last["text"]
    fake.message("/report когда-нибудь")
    await bot.poll_once()
    assert "Примеры" in fake.last["text"]
    fake.message("/windows")
    await bot.poll_once()
    close = [b for b in fake.buttons() if b.startswith("cl:")][0]
    fake.press(close)
    await bot.poll_once()
    assert driver.active == {}
    await ctx.manager.shutdown()


async def test_block_command(bot):
    bot, fake, ctx, driver = bot
    fake.message("/block 10.0.0.66 тест")
    await bot.poll_once()
    assert "заблокирован" in fake.last["text"]
    assert ctx.blocklist.match("10.0.0.66", None) == "10.0.0.66"
    fake.message("/block что-то")
    await bot.poll_once()
    assert "не MAC и не IPv4" in fake.last["text"]
    fake.message("/unblock 10.0.0.66")
    await bot.poll_once()
    assert ctx.blocklist.match("10.0.0.66", None) is None


async def test_health_alert_goes_to_admin(bot):
    bot, fake, ctx, driver = bot
    ctx.settings.health_fail_after = 1
    await ctx.health.run_checks()
    driver.fail_check = True
    await ctx.health.run_checks()
    assert fake.last["chat_id"] == ADMIN and "Роутер main" in fake.last["text"]
    driver.fail_check = False
    await ctx.health.run_checks()
    assert "снова в норме" in fake.last["text"]


async def test_grant_failure_alert(bot):
    bot, fake, ctx, driver = bot
    import asyncio

    driver.fail_grant = True
    with pytest.raises(Exception):
        await ctx.manager.open("10.0.0.7", load_catalog().get("vk"))
    await asyncio.sleep(0.01)
    assert "не открыл окно" in fake.last["text"]
