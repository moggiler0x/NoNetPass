import io
import subprocess
import tarfile
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest
from test_admin import PANEL, login, make_client

from nonetpass.gates import load_catalog
from nonetpass.keenetic_config import (
    ConfigError,
    KeeneticSetup,
    bundle,
    cli_commands,
    nonetpass_env,
    parse,
    patch_startup_config,
)
from nonetpass.keenetic_usb import SOURCE, setup_script
from nonetpass.keenetic_wizard import run

BASE = (Path(__file__).parent / "data" / "keenetic-startup-config.txt").read_text()


def block(text: str, head: str) -> list[str]:
    for item in parse(text):
        if item.head == head:
            return item.children
    raise AssertionError(f"нет блока {head}")


def test_patch_follows_clientpulse_guide():
    out = patch_startup_config(BASE, KeeneticSetup(nas_id="Sv12345", ssid="Free WiFi"), load_catalog())
    chilli = block(out, "interface Chilli0")
    assert chilli[:4] == ["chilli profile Clientpulse", "chilli radiusnasid Sv12345",
                          "chilli dhcpif Bridge1", "chilli uamallowed 10.1.30.1"]
    assert "chilli uamdomain id.vk.ru" in chilli and chilli[-1] == "up"
    # Обе гостевые точки доступа: новое имя сети, открытая сеть, включены.
    for ap in ("WifiMaster0/AccessPoint1", "WifiMaster1/AccessPoint1"):
        children = block(out, f"interface {ap}")
        assert 'ssid "Free WiFi"' in children and children[-1] == "up"
        assert not any(c.startswith(("authentication", "encryption")) for c in children)
    heads = [i.head for i in parse(out)]
    assert heads.index("interface Chilli0") == heads.index("interface Bridge1") + 1
    assert heads.index("ip nat Chilli0") == heads.index("ip nat Guest") + 1
    assert "ip host nonetpass.lan 10.1.30.1" in heads
    assert "user nonetpass" not in heads  # режим router: локальный RCI без пароля


def test_patch_keeps_everything_else():
    out = patch_startup_config(BASE, KeeneticSetup(nas_id="Sv12345"), load_catalog())
    # Интернет, домашняя сеть и пароль администратора не тронуты.
    for head in ("interface GigabitEthernet1", "interface Bridge0", "user admin", "interface WifiMaster0/AccessPoint0"):
        assert block(out, head) == block(BASE, head)
    assert out.startswith("! $$$ Model: Keenetic Giga\n")
    assert "! NoNetPass: Captive portal Clientpulse, NAS ID Sv12345" in out


def test_patch_is_idempotent_and_merges_existing_chilli():
    setup = KeeneticSetup(nas_id="Sv12345", wifi_password="guestpass1")
    once = patch_startup_config(BASE, setup, load_catalog())
    assert patch_startup_config(once, setup, load_catalog()) == once
    ap = block(once, "interface WifiMaster0/AccessPoint1")
    assert ap[-4:] == ["authentication wpa-psk guestpass1", "encryption enable", "encryption wpa2", "up"]
    # Captive portal, уже настроенный в веб-интерфейсе: NAS ID меняется, своё остаётся.
    configured = once.replace("    chilli radiusnasid Sv12345\n", "    chilli radiusnasid OLD\n    chilli uamsecret s3cr3t\n")
    out = patch_startup_config(configured, KeeneticSetup(nas_id="Sv999"), load_catalog())
    chilli = block(out, "interface Chilli0")
    assert "chilli radiusnasid Sv999" in chilli and "chilli radiusnasid OLD" not in chilli
    assert "chilli uamsecret s3cr3t" in chilli
    assert out.count("ip host nonetpass.lan") == 1 and out.count("ip nat Chilli0") == 1


def test_server_mode_adds_rci_user():
    setup = KeeneticSetup(nas_id="Sv1", mode="server", portal="10.1.30.10", rci_password="rci-pass-123")
    out = patch_startup_config(BASE, setup, load_catalog())
    assert block(out, "user nonetpass") == ["password rci-pass-123", "tag http"]
    heads = [i.head for i in parse(out)]
    assert heads.index("user nonetpass") < heads.index("service dhcp")
    assert "chilli uamallowed 10.1.30.10" in block(out, "interface Chilli0")
    env = nonetpass_env(setup, "http://192.168.1.1")
    assert "NONETPASS_ROUTER_USER=nonetpass" in env and "NONETPASS_ROUTER_PASSWORD=rci-pass-123" in env
    assert 'NONETPASS_DRIVER_OPT_GRANT_CMD="interface Chilli0 chilli uamallowed {dst}"' in env


@pytest.mark.parametrize("kw", [
    {"nas_id": ""},
    {"nas_id": "Sv1\nuser evil"},
    {"nas_id": 'Sv1"'},
    {"nas_id": "Sv1", "ssid": 'a"b'},
    {"nas_id": "Sv1", "wifi_password": "short"},
    {"nas_id": "Sv1", "mode": "server", "rci_password": "longenough1"},  # нет IP NoNetPass
    {"nas_id": "Sv1", "portal": "nonetpass.lan"},
])
def test_rejects_bad_values(kw):
    with pytest.raises(ConfigError):
        KeeneticSetup(**kw).validate()


def test_rejects_foreign_or_guestless_config():
    setup = KeeneticSetup(nas_id="Sv1")
    with pytest.raises(ConfigError, match="startup-config"):
        patch_startup_config("/ip hotspot\nadd name=x\n", setup, load_catalog())
    guestless = BASE.replace("    include WifiMaster0/AccessPoint1\n", "")
    with pytest.raises(ConfigError, match="гостевой сети"):
        patch_startup_config(guestless, setup, load_catalog())


def test_commands_without_config():
    files = bundle(KeeneticSetup(nas_id="Sv1"), load_catalog())
    assert "startup-config.txt" not in files
    cmds = files["keenetic-commands.txt"].splitlines()
    assert "interface Chilli0 chilli radiusnasid Sv1" in cmds
    assert "opkg disk NONETPASS:/" in cmds
    assert cmds[-1] == "system configuration save"
    assert "Конфиг роутера не передан" in files["README.txt"]
    assert "chilli dhcpif Bridge1" in cli_commands(KeeneticSetup(nas_id="Sv1"), load_catalog(), BASE)


def _args(tmp_path, **kw):
    base = dict(nas_id=None, base=None, ssid=None, wifi_password=None, profile=None, mode=None,
                portal=None, rci_password=None, router_url="http://192.168.1.1", out=str(tmp_path / "out"),
                no_download=True)
    return Namespace(**{**base, **kw})


def test_wizard_asks_nas_id_first(tmp_path):
    cfg = tmp_path / "startup-config.txt"
    cfg.write_text(BASE)
    asked = []
    answers = {"RADIUS NAS ID": "Sv777", "Файл startup-config": str(cfg)}

    def ask(prompt, default=""):
        asked.append(prompt)
        return next((v for k, v in answers.items() if prompt.startswith(k)), default)

    fake = b"\x1f\x8bentware"
    assert run(_args(tmp_path, no_download=False), load_catalog(), ask=ask, interactive=True,
               download=lambda: fake) == 0
    assert asked[0].startswith("RADIUS NAS ID")
    out = tmp_path / "out"
    assert "chilli radiusnasid Sv777" in (out / "startup-config.txt").read_text()
    assert (out / "usb/install/aarch64-installer.tar.gz").read_bytes() == fake
    assert (out / "usb/install/nonetpass.tgz").stat().st_size > 0


def test_wizard_flags_and_errors(tmp_path, capsys):
    assert run(_args(tmp_path), load_catalog(), interactive=False) == 2
    assert run(_args(tmp_path, nas_id="bad id"), load_catalog(), interactive=False) == 1
    assert "NAS ID" in capsys.readouterr().err
    assert run(_args(tmp_path, nas_id="Sv1"), load_catalog(), interactive=False) == 0
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["README.txt", "keenetic-commands.txt", "usb"]
    assert "Установщика Entware в архиве нет" in (tmp_path / "out" / "README.txt").read_text()


def test_admin_endpoint_returns_zip(tmp_path, monkeypatch):
    def offline(**kw):
        raise OSError("нет сети")

    monkeypatch.setattr("nonetpass.admin.download_installer", offline)
    client, _, ctx = make_client(tmp_path)
    with client:
        body = {"nas_id": "Sv42", "base": BASE}
        assert client.post("/api/admin/keenetic-config", json=body, headers=PANEL).status_code == 401
        login(client)
        r = client.post("/api/admin/keenetic-config", json=body, headers=PANEL)
        assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        assert "nonetpass-keenetic/startup-config.txt" in names
        assert "nonetpass-keenetic/usb/install/nonetpass.tgz" in names
        bad = client.post("/api/admin/keenetic-config", json={"nas_id": "a b"}, headers=PANEL)
        assert bad.status_code == 422 and "NAS ID" in bad.json()["detail"]
        assert any(e.get("event") == "keenetic_config" for e in ctx.journal.tail(20, audit_only=True))


def test_router_mode_points_opkg_at_usb():
    out = patch_startup_config(BASE, KeeneticSetup(nas_id="Sv1"), load_catalog())
    heads = [i.head for i in parse(out)]
    assert heads.count("opkg disk NONETPASS:/") == 1
    assert patch_startup_config(out, KeeneticSetup(nas_id="Sv1"), load_catalog()) == out
    server = KeeneticSetup(nas_id="Sv1", mode="server", portal="10.1.30.10", rci_password="rci-pass-123")
    assert "opkg disk" not in patch_startup_config(BASE, server, load_catalog())


def test_existing_entware_disk_is_kept():
    base = BASE.replace("isolate-private\n", "isolate-private\nopkg disk MYDISK:/\n")
    files = bundle(KeeneticSetup(nas_id="Sv1"), load_catalog(), base, installer=b"\x1f\x8bx")
    heads = [i.head for i in parse(files["startup-config.txt"])]
    assert "opkg disk MYDISK:/" in heads and "opkg disk NONETPASS:/" not in heads
    assert "usb/install/aarch64-installer.tar.gz" not in files  # Entware уже стоит
    assert "opkg disk MYDISK:/" in files["README.txt"]
    assert "opkg disk" not in files["keenetic-commands.txt"]


def test_usb_package_installs_and_starts_nonetpass():
    files = bundle(KeeneticSetup(nas_id="Sv1"), load_catalog(), BASE, installer=b"\x1f\x8bx", pin="135790")
    assert files["usb/install/aarch64-installer.tar.gz"] == b"\x1f\x8bx"
    assert "PIN 135790" in files["README.txt"]
    with tarfile.open(fileobj=io.BytesIO(files["usb/install/nonetpass.tgz"])) as tar:
        members = {m.name: m for m in tar.getmembers()}
        read = lambda name: tar.extractfile(name).read().decode()
        env, setup, init = (read(f"opt/etc/{n}") for n in ("nonetpass.env", "init.d/S98nonetpass-setup",
                                                          "init.d/S99nonetpass"))
    assert members["opt/etc/init.d/S98nonetpass-setup"].mode == 0o755
    assert members["opt/etc/nonetpass.env"].mode == 0o600
    assert "NONETPASS_ADMIN_PIN=135790" in env and "NONETPASS_DRIVER=keenetic" in env
    assert "NONETPASS_ROUTER_URL=http://127.0.0.1:79" in env
    assert "opkg install python3 python3-pip" in setup
    assert 'pip3 install --no-cache-dir "$SOURCE"' in setup and SOURCE in setup
    assert init == (Path(__file__).parent.parent / "deploy" / "keenetic" / "S99nonetpass").read_text()


def test_usb_scripts_are_valid_sh(tmp_path):
    script = tmp_path / "setup.sh"
    script.write_text(setup_script())
    assert subprocess.run(["sh", "-n", str(script)], check=False).returncode == 0
