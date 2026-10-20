from fastapi.testclient import TestClient

from nonetpass.app import create_app
from nonetpass.config import Settings
from nonetpass.drivers import MockDriver


def make_client(tmp_path, **kw):
    settings = Settings(
        cooldown_seconds=0, detect_token="d", admin_token="a",
        trust_forwarded=True, log_path=str(tmp_path / "log.jsonl"), **kw,
    )
    driver = MockDriver()
    return TestClient(create_app(settings, driver)), driver


def test_gates_endpoint(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        gates = {g["id"]: g for g in client.get("/api/gates").json()}
        assert gates["vk"]["kind"] == "verify" and gates["vk"]["window"] == 20
        assert gates["tbank-pay"]["kind"] == "pay" and gates["tbank-pay"]["window"] == 60


def test_panel_open_and_done(tmp_path):
    client, driver = make_client(tmp_path)
    headers = {"X-Forwarded-For": "10.0.0.5"}
    with client:
        assert client.get("/").status_code == 200
        r = client.post("/api/me/open", json={"gate": "sber-pay"}, headers=headers)
        assert r.status_code == 200 and r.json()["state"] == "open"
        assert r.json()["kind"] == "pay"
        assert driver.active["10.0.0.5"].ttl == 60
        me = client.get("/api/me", headers=headers).json()
        assert me["session"]["gate_id"] == "sber-pay" and len(me["gates"]) == 9
        client.post("/api/me/done", headers=headers)
        assert driver.active == {}


def test_open_unknown_gate(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        assert client.post("/api/me/open", json={"gate": "nope"}).status_code == 404


def test_detect_maps_host_to_gate(tmp_path):
    client, _ = make_client(tmp_path)
    auth = {"Authorization": "Bearer d"}
    with client:
        body = {"client_ip": "10.0.0.7", "host": "passport.yandex.ru"}
        assert client.post("/api/detect", json=body).status_code == 401
        r = client.post("/api/detect", json=body, headers=auth)
        assert r.json()["gate_id"] == "yandex-id"
        r = client.post("/api/detect", json={**body, "host": "example.com"}, headers=auth)
        assert r.json() == {"ignored": True}
        r = client.post("/api/detect", json={"client_ip": "10.0.0.8", "gate": "vtb-pay"}, headers=auth)
        assert r.json()["gate_id"] == "vtb-pay"
        r = client.post("/api/detect", json={**body, "client_ip": "nope"}, headers=auth)
        assert r.status_code == 422


def test_admin(tmp_path):
    client, driver = make_client(tmp_path)
    with client:
        sid = client.post("/api/me/open", json={"gate": "vk"}, headers={"X-Forwarded-For": "10.0.0.9"}).json()["id"]
        assert client.get("/api/admin/sessions").status_code == 401
        auth = {"Authorization": "Bearer a"}
        assert len(client.get("/api/admin/sessions", headers=auth).json()) == 1
        r = client.post(f"/api/admin/sessions/{sid}/revoke", headers=auth)
        assert r.json()["close_reason"] == "revoked"
        assert driver.active == {}
        events = [e["event"] for e in client.get("/api/admin/journal", headers=auth).json()]
        assert events == ["detected", "opened", "closed"]


def test_websocket_pushes_state(tmp_path):
    client, _ = make_client(tmp_path)
    headers = {"X-Forwarded-For": "10.0.0.11"}
    with client, client.websocket_connect("/ws", headers=headers) as ws:
        first = ws.receive_json()
        assert first["type"] == "state" and first["client_ip"] == "10.0.0.11"
        assert first["session"] is None and len(first["gates"]) == 9
        client.post("/api/me/open", json={"gate": "alfa-id"}, headers=headers)
        msgs = [ws.receive_json()["session"] for _ in range(2)]
        assert [m["state"] for m in msgs] == ["detected", "open"]
        assert msgs[1]["gate_name"] == "Альфа ID"
        ws.send_text("ping")
        assert ws.receive_json() == {"type": "pong"}


def test_shutdown_revokes(tmp_path):
    client, driver = make_client(tmp_path)
    with client:
        client.post("/api/me/open", json={"gate": "vk"}, headers={"X-Forwarded-For": "10.0.0.12"})
        assert driver.active
    assert driver.active == {}


def test_healthz(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        h = client.get("/healthz").json()
        assert h["driver"] == "mock" and h["gates"] == 9
