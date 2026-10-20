import asyncio

import pytest

from nonetpass.config import Settings
from nonetpass.drivers import DriverError, MockDriver
from nonetpass.gates import Gate, PAY, VERIFY
from nonetpass.journal import SessionJournal
from nonetpass.models import CloseReason, State
from nonetpass.sessions import OpenRefused, SessionManager

IP = "192.168.1.23"
VK = Gate("vk", "VK", VERIFY, ("id.vk.com",), ("im.vk.com", "api.vk.com"), 0.2)
BANK = Gate("vtb-pay", "ВТБ", PAY, ("3ds.vtb.ru",), ("3ds.vtb.ru",), 0.4)
LONG = Gate("vk", "VK", VERIFY, ("id.vk.com",), ("im.vk.com",), 60)


def make(tmp_path, **overrides):
    settings = Settings(detect_ttl_seconds=5, cooldown_seconds=0, **overrides)
    driver = MockDriver()
    journal = SessionJournal(str(tmp_path / "log.jsonl"))
    return SessionManager(settings, driver, journal), driver


async def test_detect_is_deduplicated(tmp_path):
    manager, _ = make(tmp_path)
    a = await manager.detect(IP, "dnsmasq", VK, "id.vk.com")
    b = await manager.detect(IP, "webhook", VK, "id.vk.com")
    assert a.id == b.id and a.state == State.DETECTED and a.gate_id == "vk"


async def test_detect_switches_gate_until_open(tmp_path):
    manager, _ = make(tmp_path)
    a = await manager.detect(IP, "dnsmasq", VK)
    b = await manager.detect(IP, "panel", BANK)
    assert a.id == b.id and b.gate_id == "vtb-pay" and b.kind == PAY


async def test_window_uses_gate_duration_and_targets(tmp_path):
    manager, driver = make(tmp_path)
    session = await manager.open(IP, VK)
    assert session.state == State.OPEN
    assert driver.active[IP].targets == ("im.vk.com", "api.vk.com")
    assert driver.active[IP].ttl == 0.2
    await asyncio.sleep(0.4)
    assert session.close_reason == CloseReason.EXPIRED
    assert IP not in driver.active


async def test_pay_window_is_longer(tmp_path):
    manager, driver = make(tmp_path)
    session = await manager.open(IP, BANK)
    await asyncio.sleep(0.25)
    assert session.state == State.OPEN  # окно ВК уже закрылось бы
    await asyncio.sleep(0.3)
    assert session.close_reason == CloseReason.EXPIRED


async def test_code_entered_closes_immediately(tmp_path):
    manager, driver = make(tmp_path)
    await manager.open(IP, LONG)
    session = await manager.complete(IP)
    assert session.close_reason == CloseReason.CODE_ENTERED
    assert driver.calls == [("grant", IP), ("revoke", IP)]
    assert [r["event"] for r in manager.journal.tail()] == ["detected", "opened", "closed"]


async def test_open_is_idempotent(tmp_path):
    manager, driver = make(tmp_path)
    a = await manager.open(IP, LONG)
    b = await manager.open(IP, BANK)  # пока окно открыто, шлюз не меняется
    assert a.id == b.id and b.gate_id == "vk"
    assert driver.calls == [("grant", IP)]
    await manager.shutdown()
    assert driver.active == {}


async def test_cooldown_and_hourly_limit(tmp_path):
    manager, _ = make(tmp_path, max_opens_per_hour=2)
    manager.settings.cooldown_seconds = 30
    await manager.open(IP, LONG)
    await manager.complete(IP)
    with pytest.raises(OpenRefused, match="повторное"):
        await manager.open(IP, LONG)
    assert manager.current(IP) is None
    manager.settings.cooldown_seconds = 0
    await manager.open(IP, LONG)
    await manager.complete(IP)
    with pytest.raises(OpenRefused, match="лимит"):
        await manager.open(IP, LONG)


async def test_grant_failure_keeps_session_detected(tmp_path):
    manager, driver = make(tmp_path)
    driver.fail_grant = True
    with pytest.raises(OpenRefused):
        await manager.open(IP, LONG)
    assert manager.current(IP).state == State.DETECTED
    driver.fail_grant = False
    assert (await manager.open(IP, LONG)).state == State.OPEN
    await manager.shutdown()


async def test_revoke_is_retried(tmp_path, monkeypatch):
    monkeypatch.setattr("nonetpass.sessions.REVOKE_RETRIES", (0.01, 0.01))
    manager, driver = make(tmp_path)
    await manager.open(IP, LONG)
    driver.fail_revoke = 2
    await manager.complete(IP)
    assert IP not in driver.active


async def test_detected_session_is_abandoned(tmp_path):
    manager, driver = make(tmp_path)
    manager.settings.detect_ttl_seconds = 0.1
    session = await manager.detect(IP, "dnsmasq", VK)
    await asyncio.sleep(0.25)
    assert session.close_reason == CloseReason.ABANDONED
    assert driver.calls == []


async def test_rejects_non_ip(tmp_path):
    manager, _ = make(tmp_path)
    with pytest.raises(DriverError):
        await manager.detect("1.2.3.4; reboot", "webhook", VK)


async def test_subscribers_get_events(tmp_path):
    manager, _ = make(tmp_path)
    queue = manager.subscribe(IP)
    other = manager.subscribe("192.168.1.99")
    await manager.detect(IP, "dnsmasq", VK)
    msg = queue.get_nowait()
    assert msg["session"]["state"] == "detected" and msg["session"]["gate_name"] == "VK"
    assert other.empty()
