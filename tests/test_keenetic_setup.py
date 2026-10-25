import time
import json
from pathlib import Path

import httpx
import pytest

from nonetpass.drivers.keenetic import challenge_password
from nonetpass.gates import load_catalog
from nonetpass.keenetic_config import KeeneticSetup
from nonetpass.keenetic_setup import AutoSetup, SetupError

from test_admin import PANEL, login, make_client

BASE = (Path(__file__).parent / "data" / "keenetic-startup-config.txt").read_text()
PC = "192.168.1.50"


class FakeKeenetic:
    """RCI роутера: вход по challenge, show-команды и parse; Captive portal ставится компонентом."""

    def __init__(self, captive=False, component="chilli", pc_known=True, os5=False):
        self.captive, self.component, self.pc_known, self.os5 = captive, component, pc_known, os5
        self.commands: list[str] = []
        self.users = {"admin": "secret"}
        self.down = 0  # сколько проверок роутер «перезагружается»

    def __call__(self, request: httpx.Request):
        path = request.url.path
        if self.down:
            self.down -= 1
            raise httpx.ConnectError("reboot")
        if path == "/auth":
            if request.method == "GET":
                return httpx.Response(401, headers={"X-NDM-Realm": "Keenetic Air", "X-NDM-Challenge": "C"})
            body = json.loads(request.content)
            pw = self.users.get(body["login"])
            ok = pw is not None and body["password"] == challenge_password(body["login"], pw, "Keenetic Air", "C")
            return httpx.Response(200 if ok else 401)
        if path == "/rci/show/version":
            return httpx.Response(200, json={"model": "Keenetic Air", "title": "4.3.6"})
        comps = [{"name": "base", "installed": "4.3.6"}] + ([{"name": self.component}] if self.component else [])
        if path == "/rci/components/list":
            # KeeneticOS 5 не отдаёт components list через GET.
            return httpx.Response(404) if self.os5 else httpx.Response(200, json={"component": comps})
        if path == "/rci/show/ip/arp":
            rows = [{"ip": PC, "mac": "AA:BB:CC:00:00:50"}] if self.pc_known else []
            return httpx.Response(200, json=rows)
        if path == "/rci/show/running-config":
            return httpx.Response(200, json={"message": BASE.splitlines()})
        if path == "/rci/user":
            return httpx.Response(404)
        results = []
        for item in json.loads(request.content):
            cmd = item["parse"]
            self.commands.append(cmd)
            status, extra = [], {}
            if cmd == "components list" and self.os5:
                extra = {"component": comps}
            elif cmd == "components list":
                status = [{"status": "error", "message": "unknown command"}]
            if cmd.startswith("interface Chilli0") and not self.captive:
                status = [{"status": "error", "message": "no such command: Chilli0"}]
            if cmd.startswith("access-list ") and cmd in self.commands[:-1]:
                status = [{"status": "error", "message": "a duplicate was found for the rule being set"}]
            if cmd.startswith("user nonetpass password "):
                if self.os5:  # KeeneticOS 5.1 не принимает пароль одной строкой
                    status = [{"status": "error", "message": "no such command: " + cmd.split()[-1]}]
                else:
                    self.users["nonetpass"] = cmd.split()[-1]
            if cmd == "components commit":
                self.captive, self.down = True, 2
            results.append({"parse": {"status": status, **extra}})
        return httpx.Response(200, json=results)


def make_job(fake, password="secret"):
    setup = KeeneticSetup(nas_id="Sv1", mode="server", portal=PC, rci_password="rci-pass-123")

    async def no_sleep(_):
        pass

    return AutoSetup("http://192.168.1.1", "admin", password, setup, load_catalog(),
                     transport=httpx.MockTransport(fake), sleep=no_sleep, poll_interval=0)


async def test_full_setup_from_scratch_installs_captive_portal():
    fake = FakeKeenetic(captive=False)
    job = make_job(fake)
    env = await job.run()
    assert [s.state for s in job.steps] == ["ok"] * 5 and job.done and not job.error
    assert job.steps[0].detail == "Keenetic Air, KeeneticOS 4.3.6"
    cmds = fake.commands
    assert cmds.index("components install chilli") < cmds.index("components commit")
    assert "ip dhcp host nonetpass aa:bb:cc:00:00:50 192.168.1.50" in cmds
    assert "interface Chilli0 chilli radiusnasid Sv1" in cmds
    assert "interface Bridge1 ip access-group _NONETPASS_PORTAL in" in cmds
    assert "user nonetpass password rci-pass-123" in cmds
    assert cmds[-1] == "system configuration save"
    assert env["NONETPASS_ROUTER_USER"] == "nonetpass" and env["NONETPASS_DRIVER"] == "keenetic"


async def test_setup_on_keeneticos5_lists_components_via_parse():
    fake = FakeKeenetic(captive=False, os5=True, component="captive-portal")
    job = make_job(fake)
    await job.run()
    assert [s.state for s in job.steps] == ["ok"] * 5
    assert fake.commands.index("components install captive-portal") < fake.commands.index("components commit")
    # Пользователь nonetpass не создался: NoNetPass входит под администратором.
    assert job.admin_fallback and job.env["NONETPASS_ROUTER_USER"] == "admin"
    assert job.env["NONETPASS_ROUTER_PASSWORD"] == "secret" and "no user nonetpass" in fake.commands


async def test_setup_runs_again_over_its_own_settings():
    fake = FakeKeenetic(captive=True)
    await make_job(fake).run()
    job = make_job(fake)
    await job.run()
    assert [s.state for s in job.steps] == ["ok"] * 5


async def test_setup_reports_wrong_password_and_missing_pc():
    job = make_job(FakeKeenetic(captive=True), password="wrong")
    with pytest.raises(SetupError, match="неверный пароль"):
        await job.run()
    assert job.steps[0].state == "fail" and job.done
    job = make_job(FakeKeenetic(captive=True, pc_known=False))
    with pytest.raises(SetupError, match="не видит компьютер"):
        await job.run()
    assert [s.state for s in job.steps[:3]] == ["ok", "ok", "fail"]


async def test_setup_without_captive_component_asks_for_manual_install():
    job = make_job(FakeKeenetic(captive=False, component=None))
    with pytest.raises(SetupError, match="вручную.*base"):
        await job.run()


async def test_admin_runs_setup_and_applies_env(tmp_path, monkeypatch):
    fake = FakeKeenetic(captive=True)
    real = AutoSetup.__init__

    def init(self, *a, **kw):
        real(self, *a, **kw)
        self.transport = httpx.MockTransport(fake)

    monkeypatch.setattr(AutoSetup, "__init__", init)
    env_file = tmp_path / "nonetpass.env"
    env_file.write_text("NONETPASS_DRIVER=mock\n")
    client, _, ctx = make_client(tmp_path, env_file=str(env_file))
    exits = []
    ctx.control.exit = lambda: exits.append(1)
    with client:
        login(client)
        body = {"router_url": "http://192.168.1.1", "admin_password": "secret", "nas_id": "Sv1", "portal": PC}
        assert client.post("/api/admin/keenetic-setup", json=body, headers=PANEL).status_code == 200
        for _ in range(50):
            state = client.get("/api/admin/keenetic-setup").json()
            if state["done"]:
                break
            time.sleep(0.05)
        assert state["done"] and not state["error"] and state["restart"]
    assert "NONETPASS_DRIVER=\"keenetic\"" in env_file.read_text()
