import time

from fastapi.testclient import TestClient

from nonetpass.app import create_app
from nonetpass.config import Settings
from nonetpass.drivers import MockDriver

PANEL = {"X-NoNetPass": "1"}


def make_client(tmp_path, driver=None, **kw):
    settings = Settings(
        cooldown_seconds=0, admin_token="a", admin_pin="2468", trust_forwarded=True,
        log_path=str(tmp_path / "log.jsonl"), state_path=str(tmp_path / "state.json"),
        login_max_failures=3, **kw,
    )
    driver = driver or MockDriver(macs={"10.0.0.5": "aa:bb:cc:00:00:05"})
    app = create_app(settings, driver, background=False)
    return TestClient(app), driver, app.state.ctx


def login(client):
    assert client.post("/api/admin/login", json={"pin": "2468"}).status_code == 200


def test_pin_login_lockout_and_cookie(tmp_path):
    client, _, ctx = make_client(tmp_path)
    with client:
        assert client.get("/api/admin/overview").status_code == 401
        assert client.get("/admin").status_code == 200
        for _ in range(3):
            assert client.post("/api/admin/login", json={"pin": "0000"}).status_code == 401
        # Адрес заблокирован даже с верным PIN.
        assert client.post("/api/admin/login", json={"pin": "2468"}).status_code == 429
    client, _, _ = make_client(tmp_path)
    with client:
        login(client)
        assert client.get("/api/admin/overview").status_code == 200
        # Изменение из панели без заголовка X-NoNetPass отклоняется.
        assert client.put("/api/admin/settings", json={"cooldown_seconds": 5}).status_code == 403
        client.post("/api/admin/logout", headers=PANEL)
        client.cookies.clear()
        assert client.get("/api/admin/overview").status_code == 401


def test_forged_cookie_rejected(tmp_path):
    client, _, _ = make_client(tmp_path, secret="s1")
    with client:
        login(client)
        token = client.cookies.get("nonetpass_admin")
    other, _, _ = make_client(tmp_path, secret="s2")
    with other:
        other.cookies.set("nonetpass_admin", token)
        assert other.get("/api/admin/overview").status_code == 401


def test_admin_networks(tmp_path):
    client, _, _ = make_client(tmp_path, admin_networks=["192.168.10.0/24"])
    with client:
        r = client.post("/api/admin/login", json={"pin": "2468"}, headers={"X-Forwarded-For": "192.168.110.7"})
        assert r.status_code == 403
        r = client.post("/api/admin/login", json={"pin": "2468"}, headers={"X-Forwarded-For": "192.168.10.7"})
        assert r.status_code == 200


def test_settings_change_windows_and_persist(tmp_path):
    client, driver, _ = make_client(tmp_path)
    with client:
        login(client)
        r = client.put("/api/admin/settings", json={"verify_window": 90, "max_opens_per_hour": 2}, headers=PANEL)
        assert r.json()["verify_window"] == 90 and r.json()["max_opens_per_hour"] == 2
        client.post("/api/me/open", json={"gate": "vk"}, headers={"X-Forwarded-For": "10.0.0.9"})
        assert driver.active["10.0.0.9"].ttl == 90
        assert client.put("/api/admin/settings", json={"verify_window": 1}, headers=PANEL).status_code == 422
    # После перезапуска настройки панели сохраняются.
    client, _, _ = make_client(tmp_path)
    with client:
        gates = {g["id"]: g for g in client.get("/api/gates").json()}
        assert gates["vk"]["window"] == 90 and gates["vtb-pay"]["window"] == 300


def test_blocklist_by_mac_closes_and_refuses(tmp_path):
    client, driver, _ = make_client(tmp_path)
    user = {"X-Forwarded-For": "10.0.0.5"}
    with client:
        login(client)
        assert client.post("/api/me/open", json={"gate": "vk"}, headers=user).json()["mac"] == "aa:bb:cc:00:00:05"
        r = client.post("/api/admin/blocklist", json={"value": "AA-BB-CC-00-00-05", "note": "спам"}, headers=PANEL)
        assert r.json() == {"kind": "macs", "value": "aa:bb:cc:00:00:05", "closed": 1}
        assert driver.active == {}
        r = client.post("/api/me/open", json={"gate": "vk"}, headers=user)
        assert r.status_code == 409 and "заблокировано" in r.json()["detail"]
        assert client.post("/api/admin/blocklist", json={"value": "nope"}, headers=PANEL).status_code == 422
        assert client.delete("/api/admin/blocklist/aa:bb:cc:00:00:05", headers=PANEL).status_code == 200
        assert client.post("/api/me/open", json={"gate": "vk"}, headers=user).status_code == 200
        assert "open_refused_total{reason=\"blocked\"} 1" in client.get("/metrics").text


def test_close_all_and_audit(tmp_path):
    client, driver, _ = make_client(tmp_path)
    with client:
        login(client)
        for ip in ("10.0.0.21", "10.0.0.22"):
            client.post("/api/me/open", json={"gate": "vk"}, headers={"X-Forwarded-For": ip})
        assert len(client.get("/api/admin/windows").json()) == 2
        assert client.post("/api/admin/windows/close-all", headers=PANEL).json() == {"closed": 2}
        assert driver.active == {}
        audit = [r["event"] for r in client.get("/api/admin/journal?audit=true").json()]
        assert audit == ["admin_login", "revoke_all"]
        # Журнал сессий не смешивается с аудитом.
        assert all(not r.get("audit") for r in client.get("/api/admin/journal").json())


def test_report_and_csv(tmp_path):
    client, _, _ = make_client(tmp_path)
    auth = {"Authorization": "Bearer a"}
    with client:
        client.post("/api/me/open", json={"gate": "vk"}, headers={"X-Forwarded-For": "10.0.0.31"})
        client.post("/api/me/done", headers={"X-Forwarded-For": "10.0.0.31"})
        client.post("/api/me/open", json={"gate": "vtb-pay"}, headers={"X-Forwarded-For": "10.0.0.32"})
        today = time.strftime("%Y-%m-%d")
        r = client.get(f"/api/admin/report?start={today}&end={today}", headers=auth).json()
        assert r["authorizations"] == 2 and r["verify"] == 1 and r["pay"] == 1 and r["confirmed"] == 1
        assert {g["gate"] for g in r["by_gate"]} == {"VK ID", "ВТБ"}
        csv_text = client.get("/api/admin/report.csv?period=today", headers=auth).text
        assert "Авторизаций;2" in csv_text
        journal = client.get("/api/admin/journal.csv?period=7d", headers=auth)
        assert journal.headers["content-disposition"].startswith("attachment")
        assert journal.text.count(";opened;") == 2
        assert client.get("/api/admin/report?period=nonsense", headers=auth).status_code == 422


def test_reboot_requires_confirm_and_cooldown(tmp_path):
    client, driver, ctx = make_client(tmp_path)
    auth = {"Authorization": "Bearer a"}
    with client:
        targets = {t["id"]: t for t in client.get("/api/admin/reboot", headers=auth).json()}
        assert targets["main"]["available"] and targets["nonetpass"]["available"]
        assert not targets["host"]["available"]
        assert client.post("/api/admin/reboot/main", json={"confirm": "x"}, headers=auth).status_code == 422
        r = client.post("/api/admin/reboot/main", json={"confirm": "main"}, headers=auth)
        assert r.status_code == 200 and driver.reboots == 1
        r = client.post("/api/admin/reboot/main", json={"confirm": "main"}, headers=auth)
        assert r.status_code == 409 and "повторная" in r.json()["detail"]
        assert client.post("/api/admin/reboot/host", json={"confirm": "host"}, headers=auth).status_code == 409
        exits = []
        ctx.control.exit = lambda: exits.append(1)
        assert client.post("/api/admin/reboot/nonetpass", json={"confirm": "nonetpass"}, headers=auth).status_code == 200


def test_health_endpoint_reports_router_failure(tmp_path):
    driver = MockDriver()
    client, _, _ = make_client(tmp_path, driver=driver, health_fail_after=2)
    auth = {"Authorization": "Bearer a"}
    with client:
        driver.fail_check = True
        first = client.post("/api/admin/health/check", headers=auth).json()
        router = next(c for c in first["checks"] if c["id"] == "router:main")
        assert router["status"] == "unknown"  # одна неудача ещё не сбой
        second = client.post("/api/admin/health/check", headers=auth).json()
        assert second["status"] == "fail" and second["alerts"][0]["check"] == "router:main"
        assert 'nonetpass_router_up{router="main"} 0' in client.get("/metrics").text
        driver.fail_check = False
        third = client.post("/api/admin/health/check", headers=auth).json()
        assert third["status"] == "ok" and "снова в норме" in third["alerts"][0]["text"]


def test_metrics_token(tmp_path):
    client, _, _ = make_client(tmp_path, metrics_token="m")
    with client:
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer m"}).status_code == 200


def test_extend_once(tmp_path):
    client, driver, _ = make_client(tmp_path, extend_seconds=30)
    user = {"X-Forwarded-For": "10.0.0.41"}
    with client:
        assert client.post("/api/me/extend", headers=user).status_code == 409
        first = client.post("/api/me/open", json={"gate": "vk"}, headers=user).json()
        r = client.post("/api/me/extend", headers=user)
        assert r.status_code == 200 and r.json()["extends"] == 1
        assert r.json()["expires_at"] - first["expires_at"] == 30
        assert driver.active["10.0.0.41"].ttl > 120
        r = client.post("/api/me/extend", headers=user)
        assert r.status_code == 409 and "уже продлено" in r.json()["detail"]
        assert client.get("/api/me", headers=user).json()["extend"] == {"seconds": 30, "max": 1}
