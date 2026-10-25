"""Мастер ``nonetpass keenetic-config``: спрашивает NAS ID и остальное, пишет файлы.

    nonetpass keenetic-config                       вопросы по очереди, первым NAS ID
    nonetpass keenetic-config --nas-id Sv123 --base startup-config.txt --out keenetic
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from . import keenetic_usb
from .gates import GateCatalog
from .keenetic_config import (
    ConfigError,
    KeeneticSetup,
    bundle,
    existing_opkg_disk,
    parse,
)


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    answer = input(f"{prompt}{hint}: ").strip()
    return answer or default


def _read_base(path: str) -> str:
    try:
        return Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"не удалось прочитать {path}: {exc.strerror}") from None


def _installer(download) -> bytes | None:
    print("Скачиваю установщик Entware…")
    try:
        return download()
    except OSError as exc:
        print(f"не удалось скачать установщик Entware ({exc}); в README.txt написано, что положить на флешку",
              file=sys.stderr)
        return None


def run(args, catalog: GateCatalog, ask=_ask, interactive: bool | None = None,
        download=keenetic_usb.download_installer) -> int:
    if interactive is None:
        interactive = args.nas_id is None and sys.stdin.isatty()
    if args.nas_id is None and not interactive:
        print("нужен --nas-id (RADIUS NAS ID от ClientPulse)", file=sys.stderr)
        return 2

    if interactive:
        print("Конфиг Keenetic: Captive portal ClientPulse + NoNetPass\n")
        nas_id = ask("RADIUS NAS ID (идентификатор зоны от ClientPulse)")
        ssid = ask("Имя гостевой сети", args.ssid or "Guest")
        wifi_password = ask("Пароль гостевой сети (Enter: открытая сеть)", args.wifi_password or "")
        profile = ask("Профиль Captive portal", args.profile or "Clientpulse")
        mode = ask("Где работает NoNetPass: router (на роутере) или server (отдельная машина)",
                   args.mode or "router")
        portal = rci_password = ""
        if mode == "server":
            portal = ask("IP машины с NoNetPass", args.portal or "")
            rci_password = ask("Пароль пользователя nonetpass на роутере",
                               args.rci_password or secrets.token_urlsafe(12))
        else:
            portal = ask("IP NoNetPass (Enter: адрес гостевого сегмента)", args.portal or "")
        base_path = ask("Файл startup-config роутера (Enter: без него, только команды)", args.base or "")
    else:
        nas_id, ssid, wifi_password = args.nas_id, args.ssid or "Guest", args.wifi_password or ""
        profile, mode, portal = args.profile or "Clientpulse", args.mode or "router", args.portal or ""
        rci_password = args.rci_password or (secrets.token_urlsafe(12) if mode == "server" else "")
        base_path = args.base or ""

    setup = KeeneticSetup(nas_id=nas_id, ssid=ssid, wifi_password=wifi_password, profile=profile,
                          mode=mode, portal=portal, rci_password=rci_password)
    try:
        setup.validate()
        base = _read_base(base_path) if base_path else None
        installer = None
        if setup.mode == "router" and not args.no_download and not (base and existing_opkg_disk(parse(base))):
            installer = _installer(download)
        files = bundle(setup, catalog, base, args.router_url, installer)
    except ConfigError as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    print(f"\nГотово, файлы в {out}/:")
    for name in files:
        print(f"  {name}")
    if setup.mode == "router":
        print(f"\nСодержимое {out}/usb скопируйте на флешку ext4 с меткой {setup.usb_label}.")
    print(f"Дальше: {out}/README.txt")
    return 0
