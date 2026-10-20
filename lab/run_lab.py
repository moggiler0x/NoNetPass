"""Стенд AuthPass на настоящем nftables ядра Linux.

Запуск (нужен root; всё происходит в отдельных сетевом и mount namespace,
файрвол и /etc/hosts хоста не трогаются):

    sudo unshare -nm python3 lab/run_lab.py

Что моделируется:
* «роутер» — таблица inet fw4 с наборами AuthPass и правилом-окном; трафик
  к узлам доставки VK отклоняется, как в закрытом контуре;
* «VK» — HTTPS-серверы im.vk.com и api.vk.com (127.0.0.50 и .51),
  отдают код подтверждения;
* «устройства» — 127.0.0.23 (пользователь), 127.0.0.24 и 127.0.0.99
  (соседи). Браузер каждого устройства ходит в сеть только со своего адреса;
* AuthPass с драйвером nftables и детекцией по логу dnsmasq.

Скрипт проходит сценарий, проверяет доступ с каждого устройства и снимает
скриншоты панели в docs/screenshots.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "screenshots"
HOSTS = {"im.vk.com": "127.0.0.50", "api.vk.com": "127.0.0.51", "id.vk.com": "127.0.0.52"}
USER, OTHER, NEIGHBOUR = "127.0.0.23", "127.0.0.24", "127.0.0.99"
PORT = 8080
WINDOW = 30
# Свой Chromium (например, /opt/pw-browsers/chromium); иначе тот, что ставит playwright install.
CHROMIUM = os.environ.get("CHROMIUM") or None

RULESET = f"""
table inet fw4 {{
    set authpass_clients {{ type ipv4_addr; flags timeout; }}
    set authpass_targets {{ type ipv4_addr; flags timeout; }}
    chain output {{
        type filter hook output priority filter; policy accept;
        ip saddr @authpass_clients ip daddr @authpass_targets accept
        ip daddr {{ {HOSTS['im.vk.com']}, {HOSTS['api.vk.com']} }} reject with tcp reset
    }}
}}
"""

report: list[str] = []
local = httpx.Client(base_url=f"http://127.0.0.1:{PORT}", trust_env=False)


def say(line: str = "") -> None:
    print(line, flush=True)
    report.append(line)


# --- окружение ----------------------------------------------------------------


def lo_up() -> None:
    s = socket.socket()
    ifr = struct.pack("16sH", b"lo", 0)
    flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, ifr))[1]
    fcntl.ioctl(s, 0x8914, struct.pack("16sH", b"lo", flags | 1))


def fake_dns(tmp: Path) -> None:
    hosts = tmp / "hosts"
    hosts.write_text("127.0.0.1 localhost\n" + "".join(f"{ip} {name}\n" for name, ip in HOSTS.items()))
    subprocess.run(["mount", "--bind", str(hosts), "/etc/hosts"], check=True)


def nft(*args: str) -> str:
    return subprocess.run(["nft", *args], check=True, capture_output=True, text=True).stdout


def set_elements(name: str) -> str:
    items = json.loads(nft("-j", "list", "set", "inet", "fw4", name))["nftables"][1]["set"].get("elem", [])
    shown = []
    for item in items:
        elem = item.get("elem", item)
        if isinstance(elem, dict):
            shown.append(f"{elem['val']} (timeout {elem.get('timeout')}s)")
        else:
            shown.append(str(elem))
    return ", ".join(shown) or "пусто"


class FakeVK(BaseHTTPRequestHandler):
    def do_GET(self):
        body = "Код подтверждения VK: 482913".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_fake_vk(tmp: Path) -> None:
    cert, key = tmp / "vk.crt", tmp / "vk.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=vk.com", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    for ip in (HOSTS["im.vk.com"], HOSTS["api.vk.com"]):
        server = ThreadingHTTPServer((ip, 443), FakeVK)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()


def reach(source_ip: str, host: str = "im.vk.com") -> str:
    transport = httpx.HTTPTransport(local_address=source_ip, verify=False)
    try:
        with httpx.Client(transport=transport, timeout=3, trust_env=False) as client:
            r = client.get(f"https://{host}/")
        return f"ДОСТУПЕН ({r.text.strip()})"
    except httpx.HTTPError as exc:
        return f"заблокирован ({type(exc).__name__})"


def check(*ips: str) -> None:
    for ip in ips:
        say(f"  {ip:<11} → im.vk.com: {reach(ip)}")
    say(f"  nft authpass_clients: {set_elements('authpass_clients')}")


# --- «устройства» ---------------------------------------------------------------


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _splice(a: socket.socket, b: socket.socket) -> None:
    threading.Thread(target=_pipe, args=(a, b), daemon=True).start()
    threading.Thread(target=_pipe, args=(b, a), daemon=True).start()


def _listen(handler) -> int:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def serve() -> None:
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


class Device:
    """Сетевой адрес устройства в LAN.

    На loopback ядро подставляет источник 127.0.0.1, поэтому браузер ходит
    через два маленьких посредника, которые открывают соединения уже с адреса
    устройства: TCP-форвардер к панели (AuthPass видит настоящий IP клиента)
    и CONNECT-прокси для HTTPS (проверка «узлы доставки» идёт через файрвол).
    """

    def __init__(self, ip: str):
        self.ip = ip
        self.panel_port = _listen(self._panel)
        self.proxy_port = _listen(self._proxy)

    def _panel(self, conn: socket.socket) -> None:
        _splice(conn, socket.create_connection(("127.0.0.1", PORT), source_address=(self.ip, 0)))

    def _proxy(self, conn: socket.socket) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return conn.close()
            head += chunk
        method, target = head.split(b" ", 2)[:2]
        host, _, port = target.decode().rpartition(":")
        if method != b"CONNECT":
            return conn.close()
        try:
            upstream = socket.create_connection((host, int(port)), timeout=3, source_address=(self.ip, 0))
            upstream.settimeout(None)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return conn.close()
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _splice(conn, upstream)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.panel_port}/"

    def browser(self, pw):
        return pw.chromium.launch(
            executable_path=CHROMIUM,
            args=[
                "--ignore-certificate-errors",
                f"--proxy-server=https=127.0.0.1:{self.proxy_port}",
                "--proxy-bypass-list=127.0.0.1",
            ],
        )


def open_panel(browser, device: Device, dark: bool = False):
    page = browser.new_page(
        viewport={"width": 420, "height": 560}, device_scale_factor=2,
        color_scheme="dark" if dark else "light",
    )
    page.goto(device.url)
    page.wait_for_selector("#link:text-is('есть')")
    return page


def shot(page, name: str) -> None:
    page.locator("main").screenshot(path=SHOTS / f"{name}.png")


def overview(names: list[str]) -> None:
    images = [Image.open(SHOTS / f"{n}.png") for n in names]
    gap = 24
    height = max(im.height for im in images)
    out = Image.new("RGB", (sum(im.width for im in images) + gap * (len(images) + 1), height + 2 * gap), "#e9ecf0")
    x = gap
    for im in images:
        column = Image.new("RGB", (im.width, height), im.getpixel((2, 2)))
        column.paste(im, (0, 0))
        out.paste(column, (x, gap))
        x += im.width + gap
    out.save(SHOTS / "overview.png", optimize=True)


# --- сценарий -----------------------------------------------------------------


def start_authpass(tmp: Path) -> subprocess.Popen:
    env = {
        **os.environ,
        "AUTHPASS_DRIVER": "nftables",
        "AUTHPASS_WINDOW_SECONDS": str(WINDOW),
        "AUTHPASS_COOLDOWN_SECONDS": "15",
        "AUTHPASS_ADMIN_TOKEN": "lab-admin",
        "AUTHPASS_LOG_PATH": str(tmp / "sessions.jsonl"),
        "AUTHPASS_DNS_LOG_PATH": str(tmp / "dnsmasq.log"),
    }
    (tmp / "dnsmasq.log").write_text("")
    proc = subprocess.Popen(
        [sys.executable, "-m", "authpass", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=ROOT, env=env, stdout=open(tmp / "authpass.log", "w"), stderr=subprocess.STDOUT,
    )
    for _ in range(50):
        try:
            local.get("/healthz", timeout=1)
            return proc
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError((tmp / "authpass.log").read_text())


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="authpass-lab-"))
    lo_up()
    fake_dns(tmp)
    subprocess.run(["nft", "-f", "-"], input=RULESET, text=True, check=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    start_fake_vk(tmp)
    authpass = start_authpass(tmp)
    health = local.get("/healthz").json()
    say(f"AuthPass {health['version']}, драйвер {health['driver']}, роутер ok={health['router']['ok']}")
    user, other = Device(USER), Device(OTHER)

    try:
        with sync_playwright() as pw:
            browser = user.browser(pw)
            page = open_panel(browser, user)

            say("\n1. Устройство в закрытом контуре, окно закрыто")
            check(USER, NEIGHBOUR)
            shot(page, "1-closed")

            say("\n2. Пользователь открывает id.vk.com (запрос виден в логе dnsmasq)")
            with open(tmp / "dnsmasq.log", "a") as fh:
                fh.write(f"Oct 20 18:40:01 dnsmasq[812]: query[A] id.vk.com from {USER}\n")
            page.wait_for_selector("#title:has-text('Обнаружен')", timeout=5000)
            say("  панель: " + page.text_content("#title"))
            shot(page, "2-detected")

            say("\n3. Пользователь нажимает «Получить код»")
            page.click("#open")
            page.wait_for_selector("#reach:text-is('доступны')", timeout=8000)
            check(USER, NEIGHBOUR)
            say(f"  nft authpass_targets: {set_elements('authpass_targets')}")
            say(f"  панель: {page.text_content('#title')}, узлы доставки {page.text_content('#reach')}, "
                f"таймер {page.text_content('#timer')}")
            shot(page, "3-open")

            say("\n4. Код получен, пользователь нажимает «Я ввёл код»")
            page.click("#done")
            page.wait_for_selector("#hint:has-text('Готово')")
            check(USER, NEIGHBOUR)
            shot(page, "4-done")

            say("\n5. Повторное открытие сразу же (защита от злоупотреблений)")
            page.click("#open")
            page.wait_for_selector("#msg:has-text('повторное')")
            say("  панель: " + page.text_content("#msg"))
            shot(page, "5-cooldown")
            browser.close()

            say(f"\n6. Окно истекает само: устройство {OTHER}, окно {WINDOW} с, ничего не нажимает")
            browser = other.browser(pw)
            page = open_panel(browser, other, dark=True)
            page.click("#open")
            page.wait_for_selector("#reach:text-is('доступны')", timeout=8000)
            page.wait_for_timeout(1200)
            shot(page, "6-open-dark")
            say(f"  сразу:      {OTHER} → im.vk.com: {reach(OTHER)}")
            page.wait_for_selector("#title:text-is('Шлюз закрыт')", timeout=(WINDOW + 10) * 1000)
            say(f"  через {WINDOW} с: {OTHER} → im.vk.com: {reach(OTHER)}")
            say(f"  nft authpass_clients: {set_elements('authpass_clients')}")
            browser.close()

        say("\n7. Журнал сессий (/api/admin/journal)")
        journal = local.get("/api/admin/journal", headers={"Authorization": "Bearer lab-admin"}).json()
        for rec in journal:
            reason = f" ({rec['close_reason']})" if rec.get("close_reason") else ""
            src = f", источник {rec['source']}" if rec["event"] == "detected" else ""
            stamp = time.strftime("%H:%M:%S", time.localtime(rec["ts"]))
            say(f"  {stamp}  {rec['client_ip']:<11} {rec['event']}{reason}{src}")
    finally:
        authpass.terminate()
        authpass.wait(10)

    overview(["2-detected", "3-open", "4-done"])
    (SHOTS / "lab-report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
