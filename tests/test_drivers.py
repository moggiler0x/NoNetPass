import asyncio
import json

import httpx
import pytest

from nonetpass.config import Settings
from nonetpass.detect import parse_dnsmasq_line
from nonetpass.gates import load_catalog
from nonetpass.drivers import DRIVERS, DriverError, Grant, build_driver
from nonetpass.drivers.keenetic import KeeneticDriver, challenge_password
from nonetpass.drivers.local import IpsetDriver, NftablesDriver
from nonetpass.drivers.mikrotik import (
    MikroTikApiDriver,
    MikroTikRestDriver,
    encode_length,
    encode_sentence,
    read_length,
)
from nonetpass.drivers.openwrt import OpenWrtDriver
from nonetpass.drivers.opnsense import OPNsenseDriver

GRANT = Grant("192.168.1.23", ("im.vk.com", "api.vk.com"), 60, "nonetpass abc", gate="vk")


async def fake_resolver(hosts):
    return ["87.240.1.1", "87.240.1.2"]


async def test_mikrotik_rest():
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.method, request.url.path, request.content))
        if request.method == "GET":
            return httpx.Response(200, json=[])
        if request.method == "PUT":
            return httpx.Response(201, json={".id": "*1A"})
        return httpx.Response(204)

    driver = MikroTikRestDriver("https://r", "u", "p", "nonetpass-clients", transport=httpx.MockTransport(handler))
    assert await driver.grant(GRANT) == "*1A"
    body = json.loads(seen[1][2])
    assert body == {"list": "nonetpass-clients-vk", "address": "192.168.1.23", "timeout": "70s", "comment": "nonetpass abc"}
    await driver.revoke("192.168.1.23", "*1A")
    assert seen[-1][:2] == ("DELETE", "/rest/ip/firewall/address-list/*1A")


async def test_mikrotik_rest_revoke_404_is_ok():
    driver = MikroTikRestDriver(
        "https://r", "u", "p", "l", transport=httpx.MockTransport(lambda r: httpx.Response(404))
    )
    await driver.revoke("192.168.1.23", "*1")


@pytest.mark.parametrize("n", [0, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x10000000])
async def test_routeros_length_roundtrip(n):
    reader = asyncio.StreamReader()
    reader.feed_data(encode_length(n))
    assert await read_length(reader) == n


async def test_mikrotik_api_against_fake_router():
    received = []

    async def read_sentence(reader):
        words = []
        while (length := await read_length(reader)) != 0:
            words.append((await reader.readexactly(length)).decode())
        return words

    async def handle(reader, writer):
        while True:
            try:
                words = await read_sentence(reader)
            except asyncio.IncompleteReadError:
                break
            received.append(words)
            if words[0] == "/ip/firewall/address-list/add":
                writer.write(encode_sentence(["!done", "=ret=*2B"]))
            elif words[0] == "/ip/firewall/address-list/remove":
                writer.write(encode_sentence(["!trap", "=message=no such item"]) + encode_sentence(["!done"]))
            else:
                writer.write(encode_sentence(["!done"]))
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        driver = MikroTikApiDriver(f"api://127.0.0.1:{port}", "admin", "pw", "nonetpass-clients")
        assert await driver.grant(GRANT) == "*2B"
        await driver.revoke("192.168.1.23", "*2B")  # «no such item» не ошибка
    commands = [w for w in received if w[0] != "/login"]
    assert commands[1] == [
        "/ip/firewall/address-list/add", "=list=nonetpass-clients-vk", "=address=192.168.1.23",
        "=timeout=70s", "=comment=nonetpass abc",
    ]
    assert ["/login", "=name=admin", "=password=pw"] in received


async def test_keenetic_auth_and_acl(tmp_path):
    calls = []
    state = {"authed": False}

    def handler(request: httpx.Request):
        if request.url.path == "/auth":
            if request.method == "GET":
                return httpx.Response(401, headers={"X-NDM-Realm": "Keenetic", "X-NDM-Challenge": "CH"})
            body = json.loads(request.content)
            assert body["password"] == challenge_password("admin", "pw", "Keenetic", "CH")
            state["authed"] = True
            return httpx.Response(200)
        assert state["authed"]
        calls.append([c["parse"] for c in json.loads(request.content)])
        return httpx.Response(200, json=[{"parse": {"status": []}} for _ in calls[-1]])

    async def resolver(hosts):
        return ["87.240.1.1", "87.240.1.2"]

    driver = KeeneticDriver(
        "http://r", "admin", "pw", "nonetpass", state_file=str(tmp_path / "s.json"),
        resolver=resolver, transport=httpx.MockTransport(handler),
    )
    handle = await driver.grant(GRANT)
    assert calls[0] == [
        "access-list nonetpass permit ip 192.168.1.23 255.255.255.255 87.240.1.1 255.255.255.255",
        "access-list nonetpass permit ip 192.168.1.23 255.255.255.255 87.240.1.2 255.255.255.255",
    ]
    assert json.loads((tmp_path / "s.json").read_text()) == {"192.168.1.23": ["87.240.1.1", "87.240.1.2"]}
    await driver.revoke("192.168.1.23", handle)
    assert calls[-1][0].startswith("access-list nonetpass no permit ip 192.168.1.23")
    assert json.loads((tmp_path / "s.json").read_text()) == {}


async def test_keenetic_cleanup_stale(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"192.168.1.5": ["1.1.1.1"]}))
    calls = []

    def handler(request):
        calls.append(json.loads(request.content)[0]["parse"])
        return httpx.Response(200, json=[{"parse": {}}])

    driver = KeeneticDriver("http://127.0.0.1:79", None, None, "nonetpass", state_file=str(tmp_path / "s.json"),
                            transport=httpx.MockTransport(handler))
    assert await driver.cleanup_stale() == 1
    assert calls == ["access-list nonetpass no permit ip 192.168.1.5 255.255.255.255 1.1.1.1 255.255.255.255"]


async def test_openwrt_ubus():
    calls = []

    def handler(request):
        body = json.loads(request.content)
        _, obj, method, args = body["params"]
        calls.append((obj, method, args))
        if obj == "session":
            return httpx.Response(200, json={"result": [0, {"ubus_rpc_session": "S"}]})
        return httpx.Response(200, json={"result": [0, {"code": 0}]})

    driver = OpenWrtDriver("http://r", "nonetpass", "pw", "nonetpass_pairs",
                           transport=httpx.MockTransport(handler), resolver=fake_resolver)
    handle = await driver.grant(GRANT)
    assert calls[1] == ("file", "exec", {
        "command": "/usr/sbin/nft",
        "params": ["add", "element", "inet", "fw4", "nonetpass_pairs",
                   "{ 192.168.1.23 . 87.240.1.1 timeout 70s, 192.168.1.23 . 87.240.1.2 timeout 70s }"],
    })
    await driver.revoke("192.168.1.23", handle)
    assert [c[2]["params"][-1] for c in calls[-2:]] == [
        "{ 192.168.1.23 . 87.240.1.1 }", "{ 192.168.1.23 . 87.240.1.2 }",
    ]


async def test_opnsense():
    seen = []

    def handler(request):
        seen.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"status": "done"})

    driver = OPNsenseDriver("https://fw", "k", "s", "nonetpass_clients", transport=httpx.MockTransport(handler))
    pay = Grant("192.168.1.23", ("3ds.vtb.ru",), 60, "c", gate="vtb-pay")
    handle = await driver.grant(pay)
    await driver.revoke("192.168.1.23", handle)
    assert seen == [
        ("/api/firewall/alias_util/add/nonetpass_clients_vtb_pay", {"address": "192.168.1.23"}),
        ("/api/firewall/alias_util/delete/nonetpass_clients_vtb_pay", {"address": "192.168.1.23"}),
    ]


async def test_local_drivers_pairs():
    calls = []

    async def runner(*argv):
        calls.append(argv)
        return (1, "Error: No such file or directory") if argv[1] == "delete" else (0, "")

    nft = NftablesDriver("nonetpass_pairs", runner=runner, resolver=fake_resolver)
    handle = await nft.grant(GRANT)
    await nft.revoke("192.168.1.23", handle)  # «No such file» не ошибка
    ipset = IpsetDriver("nonetpass_pairs", runner=runner, resolver=fake_resolver)
    await ipset.grant(GRANT)
    assert calls == [
        ("nft", "add", "element", "inet", "fw4", "nonetpass_pairs",
         "{ 192.168.1.23 . 87.240.1.1 timeout 70s, 192.168.1.23 . 87.240.1.2 timeout 70s }"),
        ("nft", "delete", "element", "inet", "fw4", "nonetpass_pairs", "{ 192.168.1.23 . 87.240.1.1 }"),
        ("nft", "delete", "element", "inet", "fw4", "nonetpass_pairs", "{ 192.168.1.23 . 87.240.1.2 }"),
        ("ipset", "add", "nonetpass_pairs", "192.168.1.23,87.240.1.1", "timeout", "70", "-exist"),
        ("ipset", "add", "nonetpass_pairs", "192.168.1.23,87.240.1.2", "timeout", "70", "-exist"),
    ]


async def test_drivers_reject_bad_ip():
    nft = NftablesDriver("s", runner=None)
    with pytest.raises(DriverError):
        await nft.grant(Grant("1.2.3.4 }; flush ruleset; {", (), 60, ""))


def test_build_driver_all_names():
    for name in DRIVERS:
        settings = Settings(driver=name, router_url="http://r", router_user="u", router_password="p")
        assert build_driver(settings).name == name
    with pytest.raises(ValueError):
        build_driver(Settings(driver="mikrotik"))


def test_dnsmasq_parsing():
    line = "Oct 20 18:00:01 dnsmasq[123]: query[A] id.vk.com from 192.168.1.23"
    assert parse_dnsmasq_line(line) == ("id.vk.com", "192.168.1.23")
    assert parse_dnsmasq_line("dnsmasq[1]: reply id.vk.com is 1.2.3.4") is None
    catalog = load_catalog()
    assert catalog.for_host("id.vk.com").id == "vk"
    assert catalog.for_host("login.id.vk.com").id == "vk"
    assert catalog.for_host("notid.vk.com") is None
    assert catalog.for_host("secure.tbank.ru").id == "tbank-pay"
