"""Генератор настройки Keenetic: Captive portal ClientPulse + NoNetPass.

Повторяет инструкцию ClientPulse «Настройка авторизации на Keenetic WiFly»
(гостевая сеть, Captive portal с профилем Clientpulse и RADIUS NAS ID зоны)
и добавляет то, что нужно NoNetPass:

* портал NoNetPass доступен гостям до входа (``chilli uamallowed``) и по
  имени ``nonetpass.lan`` (``ip host``);
* страницы входа шлюзов открыты всегда (``chilli uamdomain``), как walled
  garden у провайдера на MikroTik;
* окна NoNetPass открывает через RCI командами ``chilli uamallowed`` и сам
  закрывает их; без ``system configuration save``, поэтому перезагрузка
  тоже закрывает окно;
* для NoNetPass на отдельной машине создаётся пользователь ``nonetpass``
  с доступом к RCI (тег ``http``).

Результат:

* ``startup-config.txt`` — текущий конфиг роутера с изменениями, если его
  передали. Файл целиком заменяет настройки роутера, поэтому собирается
  только из настоящего конфига этого же роутера: так сохраняются интернет,
  пароль администратора и остальное;
* ``keenetic-commands.txt`` — те же изменения командами CLI, их можно
  вставить в командную строку веб-интерфейса без конфига;
* ``nonetpass.env`` — настройки NoNetPass под этот роутер;
* ``README.txt`` — порядок действий.

Команды взяты из справочника CLI KeeneticOS 4.x (разделы interface chilli,
interface ssid/authentication/encryption, ip host, ip nat, user). Компонент
«Captive portal» в конфиге не включается: его ставят в «Общих настройках»,
как в шагах 2-4 инструкции ClientPulse.
"""

from __future__ import annotations

import io
import ipaddress
import re
import zipfile
from dataclasses import dataclass

from .gates import VERIFY, GateCatalog

CHILLI = "interface Chilli0"
AP_24 = "WifiMaster0/AccessPoint1"
AP_5 = "WifiMaster1/AccessPoint1"
DEFAULT_BRIDGE = "Bridge1"
DEFAULT_GUEST_IP = "10.1.30.1"  # адрес гостевого сегмента Keenetic по умолчанию
LOCAL_RCI = "http://127.0.0.1:79"

GRANT_CMD = "interface Chilli0 chilli uamallowed {dst}"
REVOKE_CMD = "interface Chilli0 no chilli uamallowed {dst}"

MODES = ("router", "server")

# Значения попадают в конфиг как аргументы команд: без кавычек и переводов строк.
_SAFE = re.compile(r"^[^\s\"'\\!#]+$")
_SSID = re.compile(r"^[^\"\\\r\n]{1,32}$")


class ConfigError(ValueError):
    """Неверные параметры или конфиг, который нельзя безопасно поправить."""


@dataclass(frozen=True)
class KeeneticSetup:
    nas_id: str  # RADIUS NAS ID: идентификатор зоны от ClientPulse
    ssid: str = "Guest"
    wifi_password: str = ""  # пусто: открытая сеть, как в инструкции ClientPulse
    profile: str = "Clientpulse"  # профиль Captive portal (show chilli profiles)
    mode: str = "router"  # router: NoNetPass на роутере (Entware); server: на отдельной машине
    portal: str = ""  # IP NoNetPass; пусто в режиме router: адрес гостевого сегмента
    portal_port: int = 8080
    portal_name: str = "nonetpass.lan"
    rci_password: str = ""  # режим server: пароль пользователя nonetpass на роутере

    def validate(self) -> None:
        if not self.nas_id or not _SAFE.match(self.nas_id) or len(self.nas_id) > 64:
            raise ConfigError("RADIUS NAS ID: от 1 до 64 символов, без пробелов и кавычек")
        if not _SSID.match(self.ssid):
            raise ConfigError("имя сети: от 1 до 32 символов, без кавычек")
        if self.wifi_password and (not 8 <= len(self.wifi_password) <= 63 or not _SAFE.match(self.wifi_password)):
            raise ConfigError("пароль Wi-Fi: от 8 до 63 символов без пробелов и кавычек, или пусто для открытой сети")
        if not self.profile or not _SAFE.match(self.profile):
            raise ConfigError("профиль Captive portal: без пробелов и кавычек")
        if self.mode not in MODES:
            raise ConfigError(f"режим: {' или '.join(MODES)}")
        if self.portal:
            try:
                ipaddress.IPv4Address(self.portal)
            except ValueError:
                raise ConfigError("адрес NoNetPass: нужен IPv4, например 10.1.30.10") from None
        elif self.mode == "server":
            raise ConfigError("режим server: укажите IP машины с NoNetPass")
        if not 1 <= self.portal_port <= 65535:
            raise ConfigError("порт NoNetPass: от 1 до 65535")
        if not _SAFE.match(self.portal_name):
            raise ConfigError("имя портала: без пробелов и кавычек")
        if self.mode == "server" and (len(self.rci_password) < 8 or not _SAFE.match(self.rci_password)):
            raise ConfigError("режим server: пароль пользователя nonetpass от 8 символов без пробелов и кавычек")


def _quote(value: str) -> str:
    return f'"{value}"' if " " in value else value


# --- разбор startup-config ---------------------------------------------------
#
# startup-config — последовательность команд. Команда без отступа либо
# одиночная (ip nat Home), либо открывает блок: вложенные команды идут с
# отступом в 4 пробела, блок закрывается строкой «!». Строки, начинающиеся
# с «!», парсер Keenetic игнорирует.


@dataclass
class Item:
    head: str
    children: list[str]
    closed: bool = False

    @property
    def is_block(self) -> bool:
        return self.closed or bool(self.children)

    def lines(self) -> list[str]:
        out = [self.head] + [f"    {c}" for c in self.children]
        if self.closed:
            out.append("!")
        return out


def parse(text: str) -> list[Item]:
    items: list[Item] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        if line[0] in " \t":
            if not items or items[-1].closed or items[-1].head.startswith("!"):
                raise ConfigError(f"не похоже на startup-config Keenetic: строка {line.strip()!r} вне блока")
            items[-1].children.append(line.strip())
        elif line == "!" and items and not items[-1].closed and not items[-1].head.startswith("!"):
            items[-1].closed = True
        else:
            items.append(Item(line, []))
    return items


def render(items: list[Item]) -> str:
    return "\n".join(line for item in items for line in item.lines()) + "\n"


def _find(items: list[Item], head: str) -> int | None:
    for i, item in enumerate(items):
        if item.head == head:
            return i
    return None


def _merge(item: Item, drop: tuple[str, ...], add: list[str]) -> None:
    """Убрать вложенные команды с префиксами из drop и дописать add (``up`` — последней)."""

    def dropped(child: str) -> bool:
        return child == "up" or child in add or any(child == p or child.startswith(p + " ") for p in drop)

    keep = [c for c in item.children if not dropped(c)]
    item.children = keep + [c for c in add if c != "up"] + (["up"] if "up" in add else [])
    item.closed = True


def guest_segment(items: list[Item]) -> tuple[str, str, str]:
    """Имя интерфейса, псевдоним и адрес гостевого сегмента (мост с гостевой точкой доступа)."""
    for item in items:
        if item.head.startswith("interface Bridge") and f"include {AP_24}" in item.children:
            iface = item.head.split()[1]
            alias = next((c.split(None, 1)[1] for c in item.children if c.startswith("name ")), iface)
            addr = next((c.split()[2] for c in item.children if c.startswith("ip address ")), DEFAULT_GUEST_IP)
            return iface, alias, addr
    raise ConfigError(
        "в конфиге нет гостевой сети: включите «Гостевую сеть» в веб-интерфейсе "
        "(«Мои сети и Wi-Fi»), сохраните и скачайте startup-config заново"
    )


# --- что настраиваем ---------------------------------------------------------


def login_domains(catalog: GateCatalog) -> list[str]:
    """Страницы входа шлюзов верификации: открыты до входа всегда."""
    out: list[str] = []
    for gate in catalog.all:
        if gate.kind == VERIFY:
            out += [h for h in gate.gateways if h not in out]
    return out


def _ap_lines(setup: KeeneticSetup) -> tuple[tuple[str, ...], list[str]]:
    drop = ("ssid", "authentication wpa-psk", "encryption")
    add = [f"ssid {_quote(setup.ssid)}"]
    if setup.wifi_password:
        add += [f"authentication wpa-psk {setup.wifi_password}", "encryption enable", "encryption wpa2"]
    return drop, add + ["up"]


def _chilli_lines(setup: KeeneticSetup, catalog: GateCatalog, bridge: str, portal: str) -> list[str]:
    return [
        f"chilli profile {setup.profile}",
        f"chilli radiusnasid {setup.nas_id}",
        f"chilli dhcpif {bridge}",
        f"chilli uamallowed {portal}",
        *[f"chilli uamdomain {d}" for d in login_domains(catalog)],
        "up",
    ]


def _user_lines(setup: KeeneticSetup) -> list[str]:
    return [f"password {setup.rci_password}", "tag http"]


def patch_startup_config(text: str, setup: KeeneticSetup, catalog: GateCatalog) -> str:
    """Внести гостевую сеть, Captive portal и NoNetPass в startup-config роутера."""
    setup.validate()
    items = parse(text)
    if not any(i.head.startswith("! $$$ Model:") for i in items) or _find(items, "system") is None:
        raise ConfigError("не похоже на startup-config Keenetic: нет заголовка «! $$$ Model» или блока system")
    bridge, alias, guest_ip = guest_segment(items)
    portal = setup.portal or guest_ip

    drop, add = _ap_lines(setup)
    for ap in (AP_24, AP_5):  # 5 ГГц есть не у всех моделей
        i = _find(items, f"interface {ap}")
        if i is not None:
            _merge(items[i], drop, add)

    i = _find(items, CHILLI)
    chilli = items[i] if i is not None else Item(CHILLI, [])
    _merge(chilli, ("chilli profile", "chilli radiusnasid", "chilli dhcpif", f"chilli uamallowed {portal}"),
           _chilli_lines(setup, catalog, bridge, portal))
    if i is None:
        items.insert(_find(items, f"interface {bridge}") + 1, chilli)

    # Одиночные команды ставим рядом с ip nat гостевого сегмента.
    nats = [n for n, it in enumerate(items) if it.head.startswith("ip nat ")]
    at = (nats[-1] + 1) if nats else _find(items, CHILLI) + 1
    items = [it for it in items if not it.head.startswith(f"ip host {setup.portal_name} ")]
    if _find(items, "ip nat Chilli0") is None:
        items.insert(at, Item("ip nat Chilli0", []))
        at += 1
    items.insert(at, Item(f"ip host {setup.portal_name} {portal}", []))

    if setup.mode == "server":
        i = _find(items, "user nonetpass")
        if i is None:
            services = [n for n, it in enumerate(items) if it.head.startswith("service ")]
            i = services[0] if services else len(items)
            items.insert(i, Item("user nonetpass", []))
        _merge(items[i], ("password", "tag"), _user_lines(setup))

    items = [it for it in items if not it.head.startswith("! NoNetPass:")]
    header = [n for n, it in enumerate(items) if it.head.startswith("! $$$")]
    items.insert(header[-1] + 1, Item(f"! NoNetPass: Captive portal {setup.profile}, NAS ID {setup.nas_id}", []))
    return render(items)


def cli_commands(setup: KeeneticSetup, catalog: GateCatalog, base: str | None = None) -> str:
    """Те же изменения командами CLI: для командной строки веб-интерфейса или RCI."""
    setup.validate()
    if base:
        bridge, _, guest_ip = guest_segment(parse(base))
    else:
        bridge, guest_ip = DEFAULT_BRIDGE, DEFAULT_GUEST_IP
    portal = setup.portal or guest_ip
    lines = [
        f"# NoNetPass + Captive portal {setup.profile}, NAS ID {setup.nas_id}.",
        "# Выполняйте по одной команде в командной строке веб-интерфейса",
        "# (my.keenetic.net/webcli) после установки компонента «Captive portal».",
        f"# Гостевой сегмент: {bridge}, адрес {guest_ip}.",
    ]
    _, add = _ap_lines(setup)
    for ap in (AP_24, AP_5):
        lines += [f"interface {ap} {c}" for c in add]
    lines.append(CHILLI)
    lines += [f"{CHILLI} {c}" for c in _chilli_lines(setup, catalog, bridge, portal)]
    lines += ["ip nat Chilli0", f"ip host {setup.portal_name} {portal}"]
    if setup.mode == "server":
        lines.append("user nonetpass")
        lines += [f"user nonetpass {c}" for c in _user_lines(setup)]
    lines.append("system configuration save")
    return "\n".join(lines) + "\n"


def nonetpass_env(setup: KeeneticSetup, router_url: str = "http://192.168.1.1") -> str:
    lines = [
        "# Настройки NoNetPass для Keenetic с Captive portal (дописать в nonetpass.env).",
        "NONETPASS_DRIVER=keenetic",
        f'NONETPASS_DRIVER_OPT_GRANT_CMD="{GRANT_CMD}"',
        f'NONETPASS_DRIVER_OPT_REVOKE_CMD="{REVOKE_CMD}"',
    ]
    if setup.mode == "router":
        lines += ["# NoNetPass на роутере: локальный RCI без пароля.", f"NONETPASS_ROUTER_URL={LOCAL_RCI}"]
    else:
        lines += [
            f"NONETPASS_ROUTER_URL={router_url}",
            "NONETPASS_ROUTER_USER=nonetpass",
            f"NONETPASS_ROUTER_PASSWORD={setup.rci_password}",
        ]
    return "\n".join(lines) + "\n"


def readme(setup: KeeneticSetup, has_config: bool) -> str:
    install = (
        "NoNetPass на роутере (Entware): deploy/keenetic/README.md, вариант А.\n"
        "   nonetpass.env положите в /opt/etc/nonetpass.env, S99nonetpass подхватит его."
        if setup.mode == "router" else
        "NoNetPass на отдельной машине: sudo ./install.sh, затем допишите nonetpass.env\n"
        "   в /etc/nonetpass.env и перезапустите службу nonetpass."
    )
    upload = (
        "3. «Управление» → «Параметры системы» → «Файлы»: startup-config → «Заменить файл»,\n"
        "   выберите startup-config.txt. Если роутер не перезагрузится сам, перезагрузите его.\n"
        "   Если что-то пойдёт не так, верните старый файл тем же способом."
        if has_config else
        "3. Конфиг роутера не передан, поэтому готового startup-config нет.\n"
        "   Выполните keenetic-commands.txt в командной строке веб-интерфейса\n"
        "   (my.keenetic.net/webcli) или скачайте startup-config («Управление» →\n"
        "   «Параметры системы» → «Файлы») и запустите генератор ещё раз."
    )
    return (
        f"NoNetPass для Keenetic: Captive portal {setup.profile}, NAS ID {setup.nas_id}\n"
        "\n"
        "1. Обновите KeeneticOS до 4.3 или новее («Общие настройки»).\n"
        "2. «Общие настройки» → «Изменить набор компонентов»: установите «Captive portal».\n"
        "   Без компонента роутер пропустит команды chilli.\n"
        f"{upload}\n"
        f"4. {install}\n"
        f"5. Подключитесь к сети «{setup.ssid}»: должна открыться страница ClientPulse,\n"
        f"   портал NoNetPass доступен по адресу http://{setup.portal_name}:{setup.portal_port}.\n"
        "\n"
        "Если устройство долго не получает IP, выключите Captive portal в настройках\n"
        "гостевой сети, сохраните и включите снова (совет из инструкции ClientPulse).\n"
    )


def bundle(setup: KeeneticSetup, catalog: GateCatalog, base: str | None = None,
           router_url: str = "http://192.168.1.1") -> dict[str, str]:
    files = {}
    if base:
        files["startup-config.txt"] = patch_startup_config(base, setup, catalog)
    files["keenetic-commands.txt"] = cli_commands(setup, catalog, base)
    files["nonetpass.env"] = nonetpass_env(setup, router_url)
    files["README.txt"] = readme(setup, bool(base))
    return files


def bundle_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(f"nonetpass-keenetic/{name}", content)
    return buf.getvalue()
