import asyncio

import pytest

from authpass.config import Settings
from authpass.drivers import MockDriver
from authpass.journal import SessionJournal
from authpass.models import CloseReason, State
from authpass.sessions import OpenRefused, SessionManager

IP = "192.168.1.23"


def make(tmp_path, **overrides):
    settings = Settings(window_seconds=0.2, detect_ttl_seconds=5, cooldown_seconds=0, **overrides)
    driver = MockDriver()
    journal = SessionJournal(str(tmp_path / "log.jsonl"))
    return SessionManager(settings, driver, journal), driver


async def test_detect_is_deduplicated(tmp_path):
    manager, _ = make(tmp_path)
    a = await manager.detect(IP, "dnsmasq", "id.vk.com")
    b = await manager.detect(IP, "webhook", "id.vk.com")
    assert a.id == b.id and a.state == State.DETECTED


async def test_window_auto_revokes(tmp_path):
    manager, driver = make(tmp_path)
    session = await manager.open(IP)
    assert session.state == State.OPEN
    assert IP in driver.active
    assert driver.active[IP].targets == ("im.vk.com", "api.vk.com")
    await asyncio.sleep(0.4)
    assert session.state == State.CLOSED
    assert session.close_reason == CloseReason.EXPIRED
    assert IP not in driver.active
    assert manager.current(IP) is None


async def test_code_entered_closes_immediately(tmp_path):
    manager, driver = make(tmp_path, )
    manager.settings.window_seconds = 60
    await manager.open(IP)
    session = await manager.complete(IP)
    assert session.close_reason == CloseReason.CODE_ENTERED
    assert driver.calls == [("grant", IP), ("revoke", IP)]
    events = [r["event"] for r in manager.journal.tail()]
    assert events == ["detected", "opened", "closed"]


async def test_open_is_idempotent(tmp_path):
    manager, driver = make(tmp_path)
    manager.settings.window_seconds = 60
    a = await manager.open(IP)
    b = await manager.open(IP)
    assert a.id == b.id
    assert driver.calls == [("grant", IP)]
    await manager.shutdown()
    assert driver.active == {}


async def test_cooldown_and_hourly_limit(tmp_path):
    manager, _ = make(tmp_path, max_opens_per_hour=2)
    manager.settings.cooldown_seconds = 30
    await manager.open(IP)
    await manager.complete(IP)
    with pytest.raises(OpenRefused, match="повторное"):
        await manager.open(IP)
    manager.settings.cooldown_seconds = 0
    await manager.open(IP)
    await manager.complete(IP)
    with pytest.raises(OpenRefused, match="лимит"):
        await manager.open(IP)


async def test_grant_failure_keeps_session_detected(tmp_path):
    manager, driver = make(tmp_path)
    driver.fail_grant = True
    with pytest.raises(OpenRefused):
        await manager.open(IP)
    assert manager.current(IP).state == State.DETECTED
    driver.fail_grant = False
    assert (await manager.open(IP)).state == State.OPEN
    await manager.shutdown()


async def test_revoke_is_retried(tmp_path, monkeypatch):
    monkeypatch.setattr("authpass.sessions.REVOKE_RETRIES", (0.01, 0.01))
    manager, driver = make(tmp_path)
    manager.settings.window_seconds = 60
    await manager.open(IP)
    driver.fail_revoke = 2
    await manager.complete(IP)
    assert IP not in driver.active


async def test_detected_session_is_abandoned(tmp_path):
    manager, driver = make(tmp_path)
    manager.settings.detect_ttl_seconds = 0.1
    session = await manager.detect(IP, "dnsmasq")
    await asyncio.sleep(0.25)
    assert session.close_reason == CloseReason.ABANDONED
    assert driver.calls == []


async def test_rejects_non_ip(tmp_path):
    manager, _ = make(tmp_path)
    from authpass.drivers import DriverError

    with pytest.raises(DriverError):
        await manager.detect("1.2.3.4; reboot", "webhook")


async def test_subscribers_get_events(tmp_path):
    manager, _ = make(tmp_path)
    queue = manager.subscribe(IP)
    other = manager.subscribe("192.168.1.99")
    await manager.detect(IP, "dnsmasq")
    msg = queue.get_nowait()
    assert msg["session"]["state"] == "detected"
    assert other.empty()
