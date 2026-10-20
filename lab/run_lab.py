"""Стенд NoNetPass на настоящем nftables ядра Linux.

Запуск (нужен root; всё происходит в отдельных сетевом и mount namespace,
файрвол и /etc/hosts хоста не трогаются):

    sudo unshare -nm python3 lab/run_lab.py

Что моделируется:
* «роутер» — таблица inet fw4 с набором пар NoNetPass и правилом-окном;
  трафик к узлам сервисов отклоняется, как в закрытом контуре;
* сервисы — HTTPS-серверы VK (im.vk.com, api.vk.com, login.vk.com) и ВТБ
  (3ds.vtb.ru, api.vtb.ru), отдают код подтверждения и страницу оплаты;
* «устройства» — 127.0.0.23 (пользователь), 127.0.0.24, 127.0.0.25 и
  127.0.0.99 (соседи). Браузер каждого устройства ходит в сеть только со
  своего адреса;
* NoNetPass с драйвером nftables, детекцией по логу dnsmasq и каталогом
  шлюзов по умолчанию (вход в сеть 20 с, оплата 60 с).

Скрипт проходит сценарий, проверяет доступ с каждого устройства к каждому
сервису и снимает скриншоты портала в docs/screenshots.
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
# Узлы сервисов в «интернете» стенда.
HOSTS = {
    "id.vk.com": "127.0.0.52",
    "im.vk.com": "127.0.0.50",
    "api.vk.com": "127.0.0.51",
    "login.vk.com": "127.0.0.53",
    "online.vtb.ru": "127.0.0.62",
    "3ds.vtb.ru": "127.0.0.60",
    "api.vtb.ru": "127.0.0.61",
}
BODIES = {
    "vk": "Код подтверждения VK: 482913",
    "vtb": "ВТБ: подтверждение платежа 1 290 ₽",
}
SERVED = {"im.vk.com": "vk", "api.vk.com": "vk", "login.vk.com": "vk", "3ds.vtb.ru": "vtb", "api.vtb.ru": "vtb"}
USER, PAYER, LATE, NEIGHBOUR = "127.0.0.23", "127.0.0.24", "127.0.0.25", "127.0.0.99"
PORT = 8080
VERIFY_WINDOW, PAY_WINDOW = 20, 60
# Свой Chromium (например, /opt/pw-browsers/chromium); иначе тот, что ставит playwright install.
CHROMIUM = os.environ.get("CHROMIUM") or None

BLOCKED = ", ".join(HOSTS[h] for h in SERVED)
RULESET = f"""
table inet fw4 {{
    set nonetpass_pairs {{ type ipv4_addr . ipv4_addr; flags timeout; }}
    chain output {{
        type filter hook output priority filter; policy accept;
        ip saddr . ip daddr @nonetpass_pairs accept
        ip daddr {{ {BLOCKED} }} reject with tcp reset
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


def pairs() -> str:
    items = json.loads(nft("-j", "list", "set", "inet", "fw4", "nonetpass_pairs"))["nftables"][1]["set"].get("elem", [])
    names = {ip: name for name, ip in HOSTS.items()}
    shown = []
    for item in items:
        elem = item.get("elem", item)
        client, target = elem["val"]["concat"]
        shown.append(f"{client} · {names.get(target, target)} ({elem.get('timeout')} с)")
    return ", ".join(shown) or "пусто"


def make_handler(body: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    return Handler


def start_services(tmp: Path) -> None:
    cert, key = tmp / "svc.crt", tmp / "svc.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=lab", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    for host, service in SERVED.items():
        server = ThreadingHTTPServer((HOSTS[host], 443), make_handler(BODIES[service]))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()


def reach(source_ip: str, host: str) -> str:
    transport = httpx.HTTPTransport(local_address=source_ip, verify=False)
    try:
        with httpx.Client(transport=transport, timeout=3, trust_env=False) as client:
            r = client.get(f"https://{host}/")
        return f"ДОСТУПЕН ({r.text.strip()})"
    except httpx.HTTPError as exc:
        return f"заблокирован ({type(exc).__name__})"


def check(*ips: str) -> None:
    for ip in ips:
        for host in ("im.vk.com", "3ds.vtb.ru"):
            say(f"  {ip:<11} → {host:<11} {reach(ip, host)}")
    say(f"  nft nonetpass_pairs: {pairs()}")


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
    устройства: TCP-форвардер к порталу (NoNetPass видит настоящий IP клиента)
    и CONNECT-прокси для HTTPS (проверка «узлы доступны» идёт через файрвол).
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


def open_portal(browser, device: Device, dark: bool = True):
    page = browser.new_page(
        viewport={"width": 390, "height": 780}, device_scale_factor=2,
        color_scheme="dark" if dark else "light", reduced_motion="no-preference",
    )
    page.goto(device.url)
    page.wait_for_selector("#link:text-is('есть')")
    page.wait_for_selector(".gate")
    return page


def to_gates(page) -> None:
    page.evaluate("window.scrollTo(0, document.querySelector('main').offsetTop - 24)")
    page.wait_for_timeout(500)


def shot(page, name: str) -> None:
    page.screenshot(path=SHOTS / f"{name}.png")


def overview(names: list[str]) -> None:
    images = [Image.open(SHOTS / f"{n}.png") for n in names]
    images = [im.resize((im.width // 2, im.height // 2), Image.LANCZOS) for im in images]
    gap = 28
    height = max(im.height for im in images)
    out = Image.new("RGB", (sum(im.width for im in images) + gap * (len(images) + 1), height + 2 * gap), "#05070b")
    x = gap
    for im in images:
        out.paste(im, (x, gap))
        x += im.width + gap
    out.save(SHOTS / "overview.png", optimize=True)


# --- сценарий -----------------------------------------------------------------


def start_nonetpass(tmp: Path) -> subprocess.Popen:
    env = {
        **os.environ,
        "NONETPASS_DRIVER": "nftables",
        "NONETPASS_VERIFY_WINDOW_SECONDS": str(VERIFY_WINDOW),
        "NONETPASS_PAY_WINDOW_SECONDS": str(PAY_WINDOW),
        "NONETPASS_COOLDOWN_SECONDS": "15",
        "NONETPASS_ADMIN_TOKEN": "lab-admin",
        "NONETPASS_LOG_PATH": str(tmp / "sessions.jsonl"),
        "NONETPASS_DNS_LOG_PATH": str(tmp / "dnsmasq.log"),
    }
    (tmp / "dnsmasq.log").write_text("")
    proc = subprocess.Popen(
        [sys.executable, "-m", "nonetpass", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=ROOT, env=env, stdout=open(tmp / "nonetpass.log", "w"), stderr=subprocess.STDOUT,
    )
    for _ in range(50):
        try:
            local.get("/healthz", timeout=1)
            return proc
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError((tmp / "nonetpass.log").read_text())


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="nonetpass-lab-"))
    lo_up()
    fake_dns(tmp)
    subprocess.run(["nft", "-f", "-"], input=RULESET, text=True, check=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    start_services(tmp)
    nonetpass = start_nonetpass(tmp)
    health = local.get("/healthz").json()
    say(f"NoNetPass {health['version']}, драйвер {health['driver']}, шлюзов {health['gates']}, "
        f"роутер ok={health['router']['ok']}")
    user, payer, late = Device(USER), Device(PAYER), Device(LATE)

    try:
        with sync_playwright() as pw:
            browser = user.browser(pw)
            page = open_portal(browser, user)

            say("\n1. Устройство в закрытом контуре, все шлюзы закрыты")
            check(USER, NEIGHBOUR)
            shot(page, "1-portal")
            to_gates(page)
            shot(page, "2-gates")

            say("\n2. Пользователь открывает id.vk.com (запрос виден в логе dnsmasq)")
            with open(tmp / "dnsmasq.log", "a") as fh:
                fh.write(f"Oct 20 18:40:01 dnsmasq[812]: query[A] id.vk.com from {USER}\n")
            page.wait_for_selector("#overlay.show", timeout=5000)
            page.wait_for_timeout(400)
            say("  портал: " + page.text_content("#svc-name") + " — " + page.text_content("#lead"))
            shot(page, "3-detected")

            say(f"\n3. Сервис просит код, пользователь нажимает «{page.text_content('#open')}»")
            page.click("#open")
            page.wait_for_selector("#reach:text-is('узлы доступны')", timeout=8000)
            check(USER, NEIGHBOUR)
            say(f"  портал: {page.text_content('#lead')} Таймер {page.text_content('#num')}")
            shot(page, "4-open-verify")

            say("\n4. Код пришёл, пользователь нажимает «Я ввёл код»")
            page.click("#done")
            page.wait_for_selector("#lead:text-is('Готово. Доступ закрыт.')")
            page.wait_for_timeout(300)
            shot(page, "5-done")
            page.wait_for_selector("#overlay", state="hidden")
            check(USER)

            say("\n5. Повторное открытие сразу же (защита от злоупотреблений)")
            page.click("#verify-grid .gate:has-text('VK')")
            page.wait_for_selector("#toast.show")
            say("  портал: " + page.text_content("#toast"))
            shot(page, "6-cooldown")
            browser.close()

            say(f"\n6. Другое устройство {PAYER} выбирает «ВТБ» (оплата, окно {PAY_WINDOW} с)")
            browser = payer.browser(pw)
            page = open_portal(browser, payer, dark=False)
            to_gates(page)
            page.click("#pay-grid .gate:has-text('ВТБ')")
            page.wait_for_selector("#reach:text-is('узлы доступны')", timeout=8000)
            page.wait_for_timeout(1200)
            shot(page, "7-open-pay")
            check(PAYER)
            say(f"  портал: {page.text_content('#lead')} Таймер {page.text_content('#num')}")

            say(f"\n7. Окна истекают сами: {LATE} открывает «VK» и ничего не нажимает")
            late_browser = late.browser(pw)
            late_page = open_portal(late_browser, late)
            late_page.click("#verify-grid .gate:has-text('VK')")
            late_page.wait_for_selector("#reach:text-is('узлы доступны')", timeout=8000)
            say(f"  сразу:            {LATE} → im.vk.com  {reach(LATE, 'im.vk.com')}")
            late_page.wait_for_selector("#overlay", state="hidden", timeout=(VERIFY_WINDOW + 10) * 1000)
            say(f"  после {VERIFY_WINDOW} с:      {LATE} → im.vk.com  {reach(LATE, 'im.vk.com')}")
            say(f"  в это время ВТБ:  {PAYER} → 3ds.vtb.ru {reach(PAYER, '3ds.vtb.ru')}")
            page.wait_for_selector("#overlay", state="hidden", timeout=(PAY_WINDOW + 10) * 1000)
            say(f"  после {PAY_WINDOW} с:      {PAYER} → 3ds.vtb.ru {reach(PAYER, '3ds.vtb.ru')}")
            say(f"  nft nonetpass_pairs: {pairs()}")
            late_browser.close()
            browser.close()

        say("\n8. Журнал сессий (/api/admin/journal)")
        journal = local.get("/api/admin/journal", headers={"Authorization": "Bearer lab-admin"}).json()
        for rec in journal:
            reason = f" ({rec['close_reason']})" if rec.get("close_reason") else ""
            src = f", источник {rec['source']}" if rec["event"] == "detected" else ""
            stamp = time.strftime("%H:%M:%S", time.localtime(rec["ts"]))
            say(f"  {stamp}  {rec['client_ip']:<11} {rec['gate_name']:<5} {rec['event']}{reason}{src}")
    finally:
        nonetpass.terminate()
        nonetpass.wait(10)

    overview(["2-gates", "4-open-verify", "7-open-pay"])
    (SHOTS / "lab-report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
