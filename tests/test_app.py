from fastapi.testclient import TestClient

from authpass.app import create_app
from authpass.config import Settings
from authpass.drivers import MockDriver



def make_client(tmp_path, **kw):
    settings = Settings(
        window_seconds=60, cooldown_seconds=0, detect_token="d", admin_token="a",
        trust_forwarded=True, log_path=str(tmp_path / "log.jsonl"), **kw,
    )
    driver = MockDriver()
    return TestClient(create_app(settings, driver)), driver


def test_panel_open_and_done(tmp_path):
    client, driver = make_client(tmp_path)
    headers = {"X-Forwarded-For": "10.0.0.5"}
    with client:
        assert client.get("/").status_code == 200
        r = client.post("/api/me/open", headers=headers)
        assert r.status_code == 200 and r.json()["state"] == "open"
        assert "10.0.0.5" in driver.active
        assert client.get("/api/me", headers=headers).json()["session"]["state"] == "open"
        client.post("/api/me/done", headers=headers)
        assert driver.active == {}


def test_detect_requires_token_and_gateway(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        body = {"client_ip": "10.0.0.7", "host": "id.vk.com"}
        assert client.post("/api/detect", json=body).status_code == 401
        r = client.post("/api/detect", json=body, headers={"Authorization": "Bearer d"})
        assert r.json()["state"] == "detected"
        r = client.post("/api/detect", json={**body, "host": "example.com"}, headers={"Authorization": "Bearer d"})
        assert r.json() == {"ignored": True}
        r = client.post("/api/detect", json={**body, "client_ip": "nope"}, headers={"Authorization": "Bearer d"})
        assert r.status_code == 422


def test_admin(tmp_path):
    client, driver = make_client(tmp_path)
    with client:
        sid = client.post("/api/me/open", headers={"X-Forwarded-For": "10.0.0.9"}).json()["id"]
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
        assert first["session"] is None
        client.post("/api/me/open", headers=headers)
        states = [ws.receive_json()["session"]["state"] for _ in range(2)]
        assert states == ["detected", "open"]
        ws.send_text("ping")
        assert ws.receive_json() == {"type": "pong"}


def test_shutdown_revokes(tmp_path):
    client, driver = make_client(tmp_path)
    with client:
        client.post("/api/me/open", headers={"X-Forwarded-For": "10.0.0.12"})
        assert driver.active
    assert driver.active == {}


def test_healthz(tmp_path):
    client, _ = make_client(tmp_path)
    with client:
        assert client.get("/healthz").json()["driver"] == "mock"
