"""Мастер ``nonetpass keenetic-config``: спрашивает NAS ID и остальное, пишет файлы.

    nonetpass keenetic-config                       вопросы по очереди, первым NAS ID
    nonetpass keenetic-config --nas-id Sv123 --base startup-config.txt --out keenetic
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from .gates import GateCatalog
from .keenetic_config import ConfigError, KeeneticSetup, bundle


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    answer = input(f"{prompt}{hint}: ").strip()
    return answer or default


def _read_base(path: str) -> str:
    try:
        return Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"не удалось прочитать {path}: {exc.strerror}") from None


def run(args, catalog: GateCatalog, ask=_ask, interactive: bool | None = None) -> int:
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
        base = _read_base(base_path) if base_path else None
        files = bundle(setup, catalog, base, args.router_url)
    except ConfigError as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_text(content, encoding="utf-8")
    print(f"\nГотово, файлы в {out}/:")
    for name in files:
        print(f"  {name}")
    print(f"\nДальше: {out}/README.txt")
    return 0
