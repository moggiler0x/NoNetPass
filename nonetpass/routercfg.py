"""Генерация разовой настройки роутера из каталога шлюзов.

    nonetpass router-config mikrotik  > nonetpass.rsc   (опции: --hotspot-server, --hotspot-net, --portal)
    nonetpass router-config nftables  > /etc/nonetpass/sets.nft
    nonetpass router-config ipset     > /opt/etc/ndm/netfilter.d/50-nonetpass.sh
"""

from __future__ import annotations

from dataclasses import dataclass

from .drivers import PAIRS_SET
from .drivers.mikrotik import gate_list
from .gates import GateCatalog


@dataclass(frozen=True)
class HotspotSetup:
    """Сеть Captive Portal на MikroTik по инструкции провайдера (Hotspot + RADIUS)."""

    server: str = "hotspot1"  # /ip hotspot, имя после /ip hotspot setup
    network: str = "192.168.110.0/24"  # адрес bridge-hotspot
    portal: str = "172.17.0.2"  # где запущен NoNetPass (контейнер или отдельная машина)
    portal_port: int = 8080
    portal_name: str = "nonetpass.lan"  # имя портала NoNetPass в DNS роутера


def mikrotik(catalog: GateCatalog, client_list: str = "nonetpass-clients",
             hotspot: HotspotSetup | None = None) -> str:
    hs = hotspot or HotspotSetup()
    targets = lambda gate: gate_list("nonetpass-targets", gate.id)  # noqa: E731
    clients = lambda gate: gate_list(client_list, gate.id)  # noqa: E731
    lines = [
        "# NoNetPass для MikroTik с Captive Portal провайдера (Hotspot + RADIUS).",
        "# Сгенерировано: nonetpass router-config mikrotik. Импорт: /import nonetpass.rsc",
        "#",
        "# Выполняется ПОСЛЕ шагов 1-6 инструкции провайдера: bridge-hotspot,",
        f"# сеть {hs.network}, /ip hotspot setup, RADIUS и walled garden страниц входа.",
        "# Страницы входа (id.vk.ru, id.sber.ru, passport.yandex.ru, ...) провайдер",
        "# открывает в walled garden всегда. NoNetPass дополнительно и только на время",
        "# окна открывает узлы, через которые приходит код или подтверждение оплаты.",
        "",
        "# 1. Узлы каждого шлюза. RouterOS 7 сам резолвит FQDN в address-list.",
        "/ip firewall address-list",
    ]
    for gate in catalog.all:
        for host in gate.targets:
            lines.append(f'add list={targets(gate)} address={host} comment="nonetpass: {gate.name}"')
    lines += [
        "",
        "# 2. Окна для клиентов, ещё не прошедших вход в Hotspot. Hotspot перехватывает",
        "#    их трафик раньше /ip firewall filter, поэтому пропуск делается через",
        "#    walled garden ip. NoNetPass кладёт IP клиента в nonetpass-clients-<шлюз>",
        "#    с timeout, и роутер сам закроет окно даже без NoNetPass.",
        "/ip hotspot walled-garden ip",
    ]
    for gate in catalog.all:
        lines.append(
            f"add action=accept server={hs.server} src-address-list={clients(gate)} "
            f'dst-address-list={targets(gate)} comment="nonetpass: окно {gate.name} ({int(gate.window)} с)"'
        )
    lines += [
        "",
        "# 3. Портал NoNetPass доступен до входа в Hotspot.",
        f"add action=accept server={hs.server} dst-address={hs.portal} protocol=tcp "
        f'dst-port={hs.portal_port} comment="nonetpass: портал"',
        "/ip dns static",
        f'add name={hs.portal_name} address={hs.portal} comment="nonetpass: портал"',
        "",
        "# 4. Для клиентов, уже прошедших вход: если провайдер или вы закрываете",
        "#    эти сервисы в forward, правила ниже открывают окно и для них.",
        "#    Переместите их выше запрещающих правил.",
        "/ip firewall filter",
    ]
    for gate in catalog.all:
        lines.append(
            f"add chain=forward action=accept src-address-list={clients(gate)} "
            f'dst-address-list={targets(gate)} comment="nonetpass: окно {gate.name}"'
        )
    lines += [
        "",
        "# 5. NoNetPass должен видеть настоящий IP клиента. /ip hotspot setup",
        f"#    добавляет masquerade для {hs.network}, поэтому трафик к порталу",
        "#    исключаем из него (правило ставится первым в srcnat).",
        "/ip firewall nat",
        f"add chain=srcnat src-address={hs.network} dst-address={hs.portal} action=accept "
        'place-before=0 comment="nonetpass: без masquerade к порталу"',
        "",
        "# 6. Доступ NoNetPass к роутеру. Инструкция провайдера отключает api и",
        "#    api-ssl, поэтому NoNetPass работает через REST (драйвер mikrotik, служба",
        "#    www-ssl). Пускаем к ней только адрес NoNetPass. Право reboot нужно",
        "#    для перезагрузки роутера из админ-панели и Telegram-бота.",
        "#    Замените CHANGE_ME на свой пароль до импорта.",
        "/user group add name=nonetpass policy=read,write,api,rest-api,reboot",
        f"/user add name=nonetpass group=nonetpass password=CHANGE_ME address={hs.portal}/32",
        "/certificate add name=nonetpass-rest common-name=nonetpass-rest days-valid=3650",
        "/certificate sign nonetpass-rest",
        f"/ip service set www-ssl disabled=no certificate=nonetpass-rest address={hs.portal}/32",
    ]
    return "\n".join(lines) + "\n"


def nftables(catalog: GateCatalog) -> str:
    return (
        "# /etc/nonetpass/sets.nft — подключается в таблицу inet fw4 (position table-pre).\n"
        "# Пары «IP клиента . IP узла шлюза» с таймаутом: окно открывает только\n"
        "# узлы выбранного шлюза.\n"
        f"set {PAIRS_SET} {{\n"
        "    type ipv4_addr . ipv4_addr\n"
        "    flags timeout\n"
        "}\n"
    )


def ipset(catalog: GateCatalog) -> str:
    return (
        "#!/bin/sh\n"
        "# /opt/etc/ndm/netfilter.d/50-nonetpass.sh — правило-окно NoNetPass для Keenetic/Entware.\n"
        "# Пары «IP клиента,IP узла шлюза» с таймаутом: окно открывает только узлы\n"
        "# выбранного шлюза.\n"
        '[ "$type" = "ip6tables" ] && exit 0\n'
        '[ "$table" = "filter" ] || exit 0\n'
        "\n"
        f"ipset create {PAIRS_SET} hash:net,net timeout 0 -exist\n"
        "\n"
        f'RULE="FORWARD -m set --match-set {PAIRS_SET} src,dst -j ACCEPT"\n'
        "iptables -C $RULE 2>/dev/null || iptables -I $RULE\n"
        "exit 0\n"
    )


GENERATORS = {"mikrotik": mikrotik, "nftables": nftables, "ipset": ipset}
